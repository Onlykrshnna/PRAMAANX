"""
PRAMAANX - Digital Document & Image Forensics Platform API (Phase 5)
====================================================================
Production-oriented FastAPI backend providing secure, static & ML-driven
forensic analysis for documents, images, and batch archives.

Endpoints:
----------
1. GET  /                         - Platform identification & service discovery
2. GET  /health                   - System status & readiness check
3. GET  /api/v1/health            - Versioned health check with model & capability inventory
4. POST /api/v1/analyze           - Single-file forensic inspection
5. POST /api/v1/analyze/batch     - Concurrent batch inspection (up to 10 files)
6. POST /api/v1/analyze/archive   - Hardened ZIP batch inspection (pre-extraction safety)
7. GET  /api/v1/evidence/{type}/{id} - Safe visual evidence retrieval (Grad-CAM & ELA)
"""

from contextlib import asynccontextmanager
from datetime import datetime
import io
import os
from pathlib import Path
import re
import tempfile
from typing import Any, Dict, List, Literal, Optional, Tuple
import uuid
import zipfile

from fastapi import (
    FastAPI,
    File,
    HTTPException,
    Request,
    UploadFile,
    status,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.utils import get_openapi
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field

from backend.config import (
    ALLOWED_EXTENSIONS,
    ARTIFACTS_DIR,
    EVIDENCE_DIR,
    MAX_BATCH_FILES,
    MAX_BATCH_TOTAL_BYTES,
    MAX_UPLOAD_SIZE_BYTES,
    MAX_ZIP_ENTRIES,
    MAX_ZIP_UNCOMPRESSED_BYTES,
    UPLOAD_TEMP_DIR,
)
from backend.analyzers.common import (
    AnalysisResult,
    Finding,
    detect_magic_bytes,
    safe_extract_zip,
    validate_zip_safety,
)
from backend.analyzers.image import MODEL_PATH as IMAGE_MODEL_PATH
from backend.analyzers.malpdf import MODEL_PATH as PDF_XGB_MODEL_PATH
from backend.database import check_db_health, init_db
from backend.pipeline import ForensicPipeline
from backend.routes.investigations import router as investigations_router
from backend.routes.reports import reports_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initializes SQLite database and vault directories on startup."""
    init_db()
    yield


# ==============================================================================
# Pydantic Response Schemas (OpenAPI Documentation)
# ==============================================================================

class ErrorDetail(BaseModel):
    code: str = Field(..., description="Machine-readable error classification code")
    message: str = Field(..., description="Human-readable error description")
    details: Dict[str, Any] = Field(default_factory=dict, description="Additional context")


class ErrorResponse(BaseModel):
    success: bool = False
    error: ErrorDetail


class FileInfo(BaseModel):
    filename: str
    detected_type: str
    detected_mime: str
    size_bytes: int
    sha256: str


class VisualEvidenceLinks(BaseModel):
    original_url: Optional[str] = None
    gradcam_url: Optional[str] = None
    ela_url: Optional[str] = None


class AnalysisDetail(BaseModel):
    risk_score: int
    risk_category: Literal["Low", "Medium", "High"]
    entropy: float
    findings: List[Finding]
    metadata_timeline: List[Dict[str, Any]] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    visual_evidence: VisualEvidenceLinks = Field(default_factory=VisualEvidenceLinks)
    plain_summary: str = ""
    # Additive fields (Tasks 1, 2, 3, 4)
    verdict: Literal["no_signs", "limited_evidence", "review_recommended", "high_risk"] = "no_signs"
    verdict_copy: str = ""
    reliability: Literal["high", "medium", "low"] = "high"
    ai_status: str = "active"
    ai_status_reason: Optional[str] = None
    jpeg_structure: Optional[Dict[str, Any]] = None


class SingleAnalysisResponse(BaseModel):
    success: bool = True
    file: FileInfo
    analysis: AnalysisDetail


class BatchItemResult(BaseModel):
    filename: str
    status: Literal["success", "failed"]
    file: Optional[FileInfo] = None
    analysis: Optional[AnalysisDetail] = None
    error: Optional[ErrorDetail] = None


class BatchSummary(BaseModel):
    total_files: int
    successful_analyses: int
    failed_analyses: int
    highest_risk_score: int
    highest_risk_category: str
    average_risk_score: float
    high_risk_count: int
    medium_risk_count: int
    low_risk_count: int


class BatchAnalysisResponse(BaseModel):
    success: bool = True
    summary: BatchSummary
    results: List[BatchItemResult]


class ArchiveSafetySummary(BaseModel):
    is_safe: bool
    total_entries_found: int
    safe_entries_count: int
    findings: List[Finding] = Field(default_factory=list)


class ArchiveAnalysisResponse(BaseModel):
    success: bool = True
    archive_filename: str
    archive_safety: ArchiveSafetySummary
    archive_metadata: Dict[str, Any] = Field(default_factory=dict)
    summary: BatchSummary
    results: List[BatchItemResult]


class ModelStatusInfo(BaseModel):
    status: str
    details: Dict[str, Any] = Field(default_factory=dict)


class HealthResponse(BaseModel):
    status: str
    engine: str
    version: str
    timestamp: str
    models: Dict[str, ModelStatusInfo]
    capabilities: List[str]


# ==============================================================================
# Application Setup & Middleware
# ==============================================================================

app = FastAPI(
    title="PRAMAANX Forensics Engine",
    description=(
        "Production-grade, zero-cost, self-owned AI & heuristic digital document "
        "and image forensics platform."
    ),
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# Configure CORS origins from environment variable or defaults
raw_origins = os.getenv("ALLOWED_ORIGINS", "").strip()
if raw_origins:
    allowed_origins = [orig.strip() for orig in raw_origins.split(",") if orig.strip()]
else:
    allowed_origins = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ]

is_wildcard = "*" in allowed_origins

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins if not is_wildcard else ["*"],
    allow_origin_regex=r"https:\/\/.*\.vercel\.app" if not is_wildcard else None,
    allow_credentials=not is_wildcard,
    allow_methods=["*"],
    allow_headers=["*"],
)

pipeline_instance = ForensicPipeline()


def custom_openapi():
    """
    Ensures Swagger UI renders interactive multiple-file upload controls
    (<input type="file" multiple>) for batch endpoints instead of text inputs.

    Technical Context:
    FastAPI / Pydantic v2 generates OpenAPI 3.1.0 schemas using
    'contentMediaType: application/octet-stream' for UploadFile parameters.
    While standards-compliant, Swagger UI's array-item widget requires 'format: binary'
    on array items to display the file picker button instead of 'array<string>' text fields.
    """
    if app.openapi_schema:
        return app.openapi_schema

    openapi_schema = get_openapi(
        title=app.title,
        version=app.version,
        openapi_version=app.openapi_version,
        description=app.description,
        routes=app.routes,
    )

    for schema_def in openapi_schema.get("components", {}).get("schemas", {}).values():
        properties = schema_def.get("properties", {})
        for prop in properties.values():
            if prop.get("type") == "array" and "items" in prop:
                items = prop["items"]
                if items.get("contentMediaType") == "application/octet-stream":
                    items["format"] = "binary"
            elif prop.get("contentMediaType") == "application/octet-stream":
                prop["format"] = "binary"

    app.openapi_schema = openapi_schema
    return app.openapi_schema


app.openapi = custom_openapi

# Mount investigation & vault routes
app.include_router(investigations_router)
app.include_router(reports_router)


# ==============================================================================
# Exception Handlers
# ==============================================================================

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Formats all HTTPExceptions into standardized ErrorResponse schema."""
    code_map = {
        400: "BAD_REQUEST",
        404: "NOT_FOUND",
        413: "PAYLOAD_TOO_LARGE",
        415: "UNSUPPORTED_MEDIA_TYPE",
        422: "UNPROCESSABLE_ENTITY",
        500: "INTERNAL_SERVER_ERROR",
    }
    error_code = code_map.get(exc.status_code, "ERROR")

    # If detail is already a structured dict, use it
    if isinstance(exc.detail, dict):
        message = exc.detail.get("message", "An error occurred")
        details = exc.detail.get("details", {})
        error_code = exc.detail.get("code", error_code)
    else:
        message = str(exc.detail)
        details = {}

    return JSONResponse(
        status_code=exc.status_code,
        content={
            "success": False,
            "error": {
                "code": error_code,
                "message": message,
                "details": details,
            },
        },
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    """Guarantees internal stack traces and filesystem paths are never leaked."""
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "success": False,
            "error": {
                "code": "INTERNAL_SERVER_ERROR",
                "message": "An unexpected error occurred during forensic processing.",
                "details": {},
            },
        },
    )


# ==============================================================================
# Helper Utilities
# ==============================================================================

def _save_upload_stream_safely(
    upload_file: UploadFile,
    max_bytes: int = MAX_UPLOAD_SIZE_BYTES,
) -> Tuple[Path, int]:
    """
    Streams upload data into a temporary file in 64 KB chunks,
    enforcing maximum size ceiling before loading large payloads into memory.
    """
    safe_name = f"{uuid.uuid4().hex}.tmp"
    temp_path = UPLOAD_TEMP_DIR / safe_name
    bytes_read = 0

    try:
        with open(temp_path, "wb") as f:
            while chunk := upload_file.file.read(65536):
                bytes_read += len(chunk)
                if bytes_read > max_bytes:
                    f.close()
                    temp_path.unlink(missing_ok=True)
                    raise HTTPException(
                        status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                        detail={
                            "code": "PAYLOAD_TOO_LARGE",
                            "message": f"File exceeds maximum permitted size of {max_bytes / (1024*1024):.0f} MB.",
                            "details": {"max_bytes": max_bytes, "received_bytes": bytes_read},
                        },
                    )
                f.write(chunk)
    except Exception:
        temp_path.unlink(missing_ok=True)
        raise

    return temp_path, bytes_read


def _build_evidence_links(visual_evidence: Dict[str, str]) -> VisualEvidenceLinks:
    """Converts internal filesystem paths of visual evidence into safe API routes."""
    original_url = None
    gradcam_url = None
    ela_url = None

    if "original" in visual_evidence:
        filename = Path(visual_evidence["original"]).name
        original_url = f"/api/v1/evidence/original/{filename}"

    if "gradcam" in visual_evidence:
        filename = Path(visual_evidence["gradcam"]).name
        gradcam_url = f"/api/v1/evidence/gradcam/{filename}"

    if "ela" in visual_evidence:
        filename = Path(visual_evidence["ela"]).name
        ela_url = f"/api/v1/evidence/ela/{filename}"

    return VisualEvidenceLinks(
        original_url=original_url,
        gradcam_url=gradcam_url,
        ela_url=ela_url,
    )


def _format_analysis_result(result: AnalysisResult) -> SingleAnalysisResponse:
    """Constructs SingleAnalysisResponse from pipeline AnalysisResult."""
    file_info = FileInfo(
        filename=result.filename,
        detected_type=result.detected_ext.lstrip(".") or "unknown",
        detected_mime=result.detected_mime,
        size_bytes=result.file_size_bytes,
        sha256=result.sha256,
    )
    analysis_detail = AnalysisDetail(
        risk_score=result.risk_score,
        risk_category=result.risk_band,
        entropy=result.entropy,
        findings=result.findings,
        metadata_timeline=result.metadata_timeline,
        metadata=getattr(result, "metadata", {}),
        visual_evidence=_build_evidence_links(result.visual_evidence),
        plain_summary=result.plain_summary,
        verdict=getattr(result, "verdict", "no_signs"),
        verdict_copy=getattr(result, "verdict_copy", ""),
        reliability=getattr(result, "reliability", "high"),
        ai_status=getattr(result, "ai_status", "active"),
        ai_status_reason=getattr(result, "ai_status_reason", None),
        jpeg_structure=getattr(result, "jpeg_structure", None),
    )
    return SingleAnalysisResponse(success=True, file=file_info, analysis=analysis_detail)


def _compute_batch_summary(results: List[BatchItemResult]) -> BatchSummary:
    """Computes aggregate forensic statistics across batch results."""
    total = len(results)
    successes = sum(1 for r in results if r.status == "success")
    failures = total - successes

    scores = [r.analysis.risk_score for r in results if r.status == "success" and r.analysis]
    highest_score = max(scores) if scores else 0
    avg_score = round(sum(scores) / len(scores), 1) if scores else 0.0

    if highest_score <= 30:
        highest_cat = "Low"
    elif highest_score <= 60:
        highest_cat = "Medium"
    else:
        highest_cat = "High"

    high_count = sum(1 for s in scores if s > 60)
    med_count = sum(1 for s in scores if 30 < s <= 60)
    low_count = sum(1 for s in scores if s <= 30)

    return BatchSummary(
        total_files=total,
        successful_analyses=successes,
        failed_analyses=failures,
        highest_risk_score=highest_score,
        highest_risk_category=highest_cat,
        average_risk_score=avg_score,
        high_risk_count=high_count,
        medium_risk_count=med_count,
        low_risk_count=low_count,
    )


# ==============================================================================
# Health & Service Discovery Endpoints
# ==============================================================================

@app.get("/", tags=["General"])
def root():
    """Service status and platform identification (Backward compatible)."""
    return {
        "platform": "PRAMAANX",
        "role": "AI Digital Document & Image Forensics",
        "status": "operational",
        "phase": 5,
        "supported_formats": [
            "JPG/JPEG", "PNG", "BMP", "TIFF",
            "PDF", "DOCX", "XLSX", "PPTX", "DOC", "XLS", "PPT",
            "ZIP (safe archives)",
        ],
    }


@app.get("/health", tags=["Health"])
def health_check():
    """Basic healthcheck endpoint (Backward compatible)."""
    return {
        "status": "healthy",
        "engine": "pramaanx-core",
        "database": check_db_health(),
        "phase1_subsystems": {
            "sha256": "active",
            "magic_bytes": "active",
            "shannon_entropy": "active",
            "extension_spoof_detection": "active",
            "zip_safety_screener": "active",
            "noisy_or_scoring": "active",
        },
    }


@app.get("/api/v1/health/db", tags=["Health"])
def api_v1_health_db():
    """Database connectivity, latency, and metrics health probe."""
    return check_db_health()


@app.get("/api/v1/health", response_model=HealthResponse, tags=["Health"])
def api_v1_health():
    """
    Production health endpoint providing complete model availability,
    engine status, and active analyzer capabilities.
    """
    image_model_active = IMAGE_MODEL_PATH.is_file()
    pdf_xgb_active = PDF_XGB_MODEL_PATH.is_file()

    models_info = {
        "image_tampering_efficientnet_b0": ModelStatusInfo(
            status="active" if image_model_active else "missing_checkpoint",
            details={
                "architecture": "efficientnet_b0",
                "dataset": "CASIA 2.0 (fine-tuned)",
                "test_accuracy": 0.7137 if image_model_active else 0.0,
            },
        ),
        "malicious_pdf_xgboost": ModelStatusInfo(
            status="active" if pdf_xgb_active else "pending_training",
            details={
                "features": "22-dimensional static structural extractor operational",
                "training_corpus": "CIC-Evasive-PDF / Contagio (planned)",
            },
        ),
    }

    capabilities = [
        "sha256_integrity",
        "magic_byte_identification",
        "shannon_entropy_analysis",
        "extension_spoof_detection",
        "pdf_forensics_structural",
        "office_openxml_and_ole_forensics",
        "remote_template_injection_detection",
        "cloaked_macro_detection",
        "efficientnet_image_tamper_inference",
        "gradcam_attention_visualization",
        "error_level_analysis_ela",
        "exif_metadata_extraction",
        "recursive_embedded_image_screening",
        "zip_slip_and_bomb_screener",
        "noisy_or_risk_scoring",
    ]

    return HealthResponse(
        status="healthy",
        engine="pramaanx-core",
        version="1.0.0",
        timestamp=datetime.utcnow().isoformat() + "Z",
        models=models_info,
        capabilities=capabilities,
    )


# ==============================================================================
# Single File Forensic Analysis
# ==============================================================================

@app.post(
    "/api/v1/analyze",
    response_model=SingleAnalysisResponse,
    responses={
        400: {"model": ErrorResponse, "description": "Invalid or corrupt file"},
        413: {"model": ErrorResponse, "description": "File size exceeds 20 MB"},
        415: {"model": ErrorResponse, "description": "Unsupported file format"},
    },
    tags=["Forensic Analysis"],
)
def analyze_single_file(file: UploadFile = File(..., description="File to inspect")):
    """
    Analyzes an uploaded document or image file using the multi-engine forensic pipeline.

    Enforces 20 MB size ceiling, validates magic bytes, screens for steganography / exploits,
    runs deep ML tamper inference where applicable, and calculates cumulative Noisy-OR risk score.
    """
    original_name = file.filename or "unknown_upload"
    claimed_ext = Path(original_name).suffix.lower()
    temp_path, size_bytes = _save_upload_stream_safely(file, max_bytes=MAX_UPLOAD_SIZE_BYTES)

    try:
        # Validate format compatibility
        magic_res = detect_magic_bytes(temp_path)
        # Reject files whose claimed extension AND detected content are both unsupported.
        # Files with a claimed supported extension (e.g. .pdf) but alien magic bytes (e.g. MZ)
        # are permitted through to allow the pipeline to perform extension-spoofing detection.
        if claimed_ext not in ALLOWED_EXTENSIONS and not magic_res.is_supported:
            raise HTTPException(
                status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
                detail={
                    "code": "UNSUPPORTED_FILE_FORMAT",
                    "message": f"File format '{magic_res.detected_mime}' with extension '{claimed_ext}' is not supported for forensic inspection.",
                    "details": {"detected_mime": magic_res.detected_mime, "filename": original_name, "claimed_extension": claimed_ext},
                },
            )

        # Run pipeline
        result = pipeline_instance.analyze_file(temp_path, original_filename=original_name)
        return _format_analysis_result(result)

    finally:
        # Clean up temporary upload file immediately
        temp_path.unlink(missing_ok=True)


# ==============================================================================
# Batch Forensic Analysis
# ==============================================================================

@app.post(
    "/api/v1/analyze/batch",
    response_model=BatchAnalysisResponse,
    responses={
        400: {"model": ErrorResponse, "description": "Batch constraint violation"},
        413: {"model": ErrorResponse, "description": "Total batch size exceeds 100 MB"},
    },
    tags=["Forensic Analysis"],
)
def analyze_batch(
    files: list[UploadFile] = File(..., description="Up to 10 files for batch inspection"),
):
    """
    Inspects multiple files concurrently (up to 10 files, max 100 MB aggregate).
    Independent execution ensures a failure in one file does not halt the others.
    """
    if len(files) > MAX_BATCH_FILES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "code": "BATCH_LIMIT_EXCEEDED",
                "message": f"Batch request contains {len(files)} files, which exceeds maximum limit of {MAX_BATCH_FILES}.",
                "details": {"max_files": MAX_BATCH_FILES, "submitted_files": len(files)},
            },
        )

    batch_results: List[BatchItemResult] = []
    aggregate_bytes = 0

    for upload_file in files:
        orig_name = upload_file.filename or "batch_item"
        claimed_ext = Path(orig_name).suffix.lower()
        temp_path = None
        try:
            temp_path, file_size = _save_upload_stream_safely(
                upload_file, max_bytes=MAX_UPLOAD_SIZE_BYTES
            )
            aggregate_bytes += file_size
            if aggregate_bytes > MAX_BATCH_TOTAL_BYTES:
                temp_path.unlink(missing_ok=True)
                raise HTTPException(
                    status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                    detail={
                        "code": "AGGREGATE_BATCH_SIZE_EXCEEDED",
                        "message": f"Total batch size exceeded maximum limit of {MAX_BATCH_TOTAL_BYTES / (1024*1024):.0f} MB.",
                        "details": {"max_bytes": MAX_BATCH_TOTAL_BYTES},
                    },
                )

            # Validate format compatibility
            magic_res = detect_magic_bytes(temp_path)
            if claimed_ext not in ALLOWED_EXTENSIONS and not magic_res.is_supported:
                raise HTTPException(
                    status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
                    detail={
                        "code": "UNSUPPORTED_FILE_FORMAT",
                        "message": f"File '{orig_name}' is not a supported document or image format.",
                        "details": {"detected_mime": magic_res.detected_mime, "claimed_extension": claimed_ext},
                    },
                )

            # Analyze file
            result = pipeline_instance.analyze_file(temp_path, original_filename=orig_name)
            single_resp = _format_analysis_result(result)

            batch_results.append(
                BatchItemResult(
                    filename=orig_name,
                    status="success",
                    file=single_resp.file,
                    analysis=single_resp.analysis,
                )
            )
        except HTTPException as http_exc:
            detail_msg = http_exc.detail.get("message", "Error") if isinstance(http_exc.detail, dict) else str(http_exc.detail)
            code_msg = http_exc.detail.get("code", "ERROR") if isinstance(http_exc.detail, dict) else "ERROR"
            batch_results.append(
                BatchItemResult(
                    filename=orig_name,
                    status="failed",
                    error=ErrorDetail(code=code_msg, message=detail_msg),
                )
            )
        except Exception as e:
            batch_results.append(
                BatchItemResult(
                    filename=orig_name,
                    status="failed",
                    error=ErrorDetail(code="PROCESSING_FAILED", message="Forensic analysis failed for this item."),
                )
            )
        finally:
            if temp_path:
                temp_path.unlink(missing_ok=True)

    summary = _compute_batch_summary(batch_results)
    return BatchAnalysisResponse(success=True, summary=summary, results=batch_results)


# ==============================================================================
# Hardened ZIP Archive Batch Analysis
# ==============================================================================

@app.post(
    "/api/v1/analyze/archive",
    response_model=ArchiveAnalysisResponse,
    responses={
        400: {"model": ErrorResponse, "description": "ZIP safety violation or corrupted archive"},
        413: {"model": ErrorResponse, "description": "ZIP archive exceeds size limit"},
    },
    tags=["Forensic Analysis"],
)
def analyze_zip_archive(
    file: UploadFile = File(..., description="ZIP archive containing supported documents/images"),
):
    """
    Inspects a ZIP archive containing multiple supported documents and images.

    Pre-extraction Security Defenses:
    - Neutralizes Zip Slip (directory traversal sequences)
    - Enforces entry limit (<= 200 entries)
    - Enforces uncompressed ceiling (<= 100 MB)
    - Flags anomalous compression ratios (> 10:1)
    - Rejects executable payload extraction
    - Isolates extraction in a sandbox directory with reliable cleanup
    """
    archive_name = file.filename or "archive.zip"
    temp_zip_path, _ = _save_upload_stream_safely(file, max_bytes=MAX_UPLOAD_SIZE_BYTES)

    try:
        # Pre-extraction security screening
        is_safe, zip_findings, safe_entries = validate_zip_safety(temp_zip_path)

        safety_summary = ArchiveSafetySummary(
            is_safe=is_safe,
            total_entries_found=len(safe_entries),
            safe_entries_count=len(safe_entries),
            findings=zip_findings,
        )

        if not is_safe:
            # Rejection: Zip Slip, bomb, or entry flood
            critical_finding = next((f for f in zip_findings if f.weight >= 0.90), zip_findings[0] if zip_findings else None)
            detail_msg = critical_finding.detail if critical_finding else "Archive failed pre-extraction security screening."
            title_code = critical_finding.title.upper().replace(" ", "_") if critical_finding else "ZIP_SECURITY_VIOLATION"

            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "code": title_code,
                    "message": detail_msg,
                    "details": {"findings": [f.model_dump() for f in zip_findings]},
                },
            )

        # Safe extraction into an isolated temporary directory
        with tempfile.TemporaryDirectory(dir=UPLOAD_TEMP_DIR) as extract_dir:
            extract_path = Path(extract_dir)
            extracted_files = safe_extract_zip(temp_zip_path, extract_path)

            results: List[BatchItemResult] = []
            for ext_file in extracted_files:
                try:
                    res = pipeline_instance.analyze_file(ext_file, original_filename=ext_file.name)
                    single_resp = _format_analysis_result(res)
                    results.append(
                        BatchItemResult(
                            filename=ext_file.name,
                            status="success",
                            file=single_resp.file,
                            analysis=single_resp.analysis,
                        )
                    )
                except Exception:
                    results.append(
                        BatchItemResult(
                            filename=ext_file.name,
                            status="failed",
                            error=ErrorDetail(code="PROCESSING_ERROR", message="Failed to analyze archive member."),
                        )
                    )

            summary = _compute_batch_summary(results)
            archive_meta = {}
            try:
                with zipfile.ZipFile(temp_zip_path, "r") as zf:
                    entries_list = []
                    total_uncompressed = 0
                    total_compressed = 0
                    for info in zf.infolist():
                        total_uncompressed += info.file_size
                        total_compressed += info.compress_size
                        date_str = (
                            f"{info.date_time[0]:04d}-{info.date_time[1]:02d}-{info.date_time[2]:02d} "
                            f"{info.date_time[3]:02d}:{info.date_time[4]:02d}:{info.date_time[5]:02d}"
                        )
                        entries_list.append({
                            "name": info.filename,
                            "timestamp": date_str,
                            "compress_type": "Deflate" if info.compress_type == 8 else "Store" if info.compress_type == 0 else str(info.compress_type),
                            "crc32": f"0x{info.CRC:08X}",
                            "file_size": info.file_size,
                            "compress_size": info.compress_size,
                        })
                    archive_meta = {
                        "entry_count": len(entries_list),
                        "entries": entries_list,
                        "total_uncompressed_bytes": total_uncompressed,
                        "total_compressed_bytes": total_compressed,
                        "comment": zf.comment.decode("utf-8", errors="ignore") if zf.comment else None,
                    }
            except Exception:
                pass

            return ArchiveAnalysisResponse(
                success=True,
                archive_filename=archive_name,
                archive_safety=safety_summary,
                archive_metadata=archive_meta,
                summary=summary,
                results=results,
            )

    finally:
        temp_zip_path.unlink(missing_ok=True)


# ==============================================================================
# Visual Evidence Delivery (Grad-CAM, ELA & Original Specimen)
# ==============================================================================

VALID_EVIDENCE_FILENAME = re.compile(
    r"^[a-zA-Z0-9\-\_]+_(gradcam|ela|original)\.(png|jpg|jpeg|bmp|tiff|tif|webp)$",
    re.IGNORECASE,
)


@app.get(
    "/api/v1/evidence/{evidence_type}/{filename}",
    responses={
        200: {"description": "Visual evidence or original specimen image"},
        400: {"model": ErrorResponse, "description": "Invalid evidence parameter"},
        404: {"model": ErrorResponse, "description": "Evidence file not found"},
    },
    tags=["Visual Evidence"],
)
def get_visual_evidence(
    evidence_type: Literal["gradcam", "ela", "original"],
    filename: str,
):
    """
    Safely serves generated Grad-CAM attention overlays, ELA differential maps,
    and original evidence specimens from temporary uploads or the persistent visual evidence vault.

    Security Guarantees:
    - Strictly restricts access to files matching generated forensic patterns
    - Prevents directory traversal (`..` or subdirectories)
    - Confines paths within the server-side evidence cache and artifacts vault
    """
    # 1. Parameter Validation
    if evidence_type not in ("gradcam", "ela", "original"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "code": "INVALID_EVIDENCE_TYPE",
                "message": f"Evidence type '{evidence_type}' is invalid. Allowed: 'gradcam', 'ela', 'original'.",
            },
        )

    if not VALID_EVIDENCE_FILENAME.match(filename):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "code": "INVALID_EVIDENCE_IDENTIFIER",
                "message": "Malformed evidence identifier.",
            },
        )

    # 2. Path Traversal & Existence Check (Checks persistent vault first, then temp cache)
    evidence_file = None
    candidate_vault = (ARTIFACTS_DIR / filename).resolve()
    candidate_evidence = (EVIDENCE_DIR / filename).resolve()
    candidate_temp = (UPLOAD_TEMP_DIR / filename).resolve()

    if candidate_vault.is_relative_to(ARTIFACTS_DIR.resolve()) and candidate_vault.is_file():
        evidence_file = candidate_vault
    elif candidate_evidence.is_relative_to(EVIDENCE_DIR.resolve()) and candidate_evidence.is_file():
        evidence_file = candidate_evidence
    elif candidate_temp.is_relative_to(UPLOAD_TEMP_DIR.resolve()) and candidate_temp.is_file():
        evidence_file = candidate_temp
    else:
        # Ephemeral disk recovery: attempt retrieval from Supabase Storage
        from backend.storage import (
            BUCKET_ARTIFACTS,
            BUCKET_EVIDENCE,
            download_from_storage,
            is_supabase_storage_enabled,
        )
        if is_supabase_storage_enabled():
            bucket = BUCKET_EVIDENCE if evidence_type == "original" else BUCKET_ARTIFACTS
            content = download_from_storage(bucket, filename)
            if content:
                dest = (EVIDENCE_DIR if evidence_type == "original" else ARTIFACTS_DIR) / filename
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(content)
                evidence_file = dest

    if not evidence_file:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "code": "EVIDENCE_NOT_FOUND",
                "message": f"Requested {evidence_type} evidence file does not exist or has expired.",
            },
        )

    ext = evidence_file.suffix.lower()
    media_map = {
        ".png": "image/png",
        ".jpg": "image/jpeg",
        ".jpeg": "image/jpeg",
        ".bmp": "image/bmp",
        ".webp": "image/webp",
        ".tiff": "image/tiff",
        ".tif": "image/tiff",
    }
    media_type = media_map.get(ext, "image/png")

    return FileResponse(
        path=evidence_file,
        media_type=media_type,
        filename=filename,
    )
