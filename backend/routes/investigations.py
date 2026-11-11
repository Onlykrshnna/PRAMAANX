"""
PRAMAANX - Investigation & Evidence Vault API Endpoints (Milestone D)
=====================================================================
REST API endpoints supporting:
- Complete investigation (case) lifecycle: create, search, filter, update, reopen, archive
- Secure evidence ingestion into local vault storage
- Non-destructive historical examination records
- Cryptographic hash re-verification and tamper detection
- Auditable forensic activity tracking
- Evidence file download with path traversal prevention
"""

from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional
import uuid

from fastapi import (
    APIRouter,
    File,
    HTTPException,
    Query,
    UploadFile,
    status,
)
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from backend.config import (
    ALLOWED_EXTENSIONS,
    MAX_UPLOAD_SIZE_BYTES,
    UPLOAD_TEMP_DIR,
)
from backend.analyzers.common import detect_magic_bytes
from backend.database import (
    create_analysis_record,
    create_investigation,
    get_analysis_record,
    get_audit_logs,
    get_evidence_file_path,
    get_evidence_item,
    get_investigation,
    list_analysis_records,
    list_evidence_items,
    list_investigations,
    store_evidence_file,
    update_investigation,
    verify_evidence_integrity,
)
from backend.pipeline import ForensicPipeline


router = APIRouter(prefix="/api/v1", tags=["Investigations & Evidence Vault"])


# ==============================================================================
# Pydantic Schemas
# ==============================================================================

class InvestigationCreate(BaseModel):
    title: str = Field(..., min_length=1, max_length=200, description="Investigation case title")
    description: Optional[str] = Field(default="", description="Case narrative or scope")
    investigator: Optional[str] = Field(default="Analyst", description="Assigned lead investigator")
    tags: Optional[List[str]] = Field(default_factory=list, description="Case classification tags")
    case_id: Optional[str] = Field(default=None, description="Optional custom case ID (defaults to auto-generated CAS-YYYY-XXXX)")


class InvestigationUpdate(BaseModel):
    title: Optional[str] = Field(default=None, max_length=200)
    description: Optional[str] = None
    status: Optional[Literal["open", "in_progress", "closed", "archived"]] = None
    investigator: Optional[str] = None
    tags: Optional[List[str]] = None


# ==============================================================================
# Investigation Endpoints
# ==============================================================================

@router.get("/investigations", summary="List and search forensic investigations")
def get_investigations_list(
    status: Optional[str] = Query(default=None, description="Status filter: open, in_progress, closed, archived, ALL"),
    search: Optional[str] = Query(default=None, description="Text search term"),
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
):
    """Retrieves paginated list of investigations with computed evidence counts and highest risk scores."""
    items, total = list_investigations(
        status_filter=status,
        search=search,
        limit=limit,
        offset=offset,
    )
    return {
        "success": True,
        "total": total,
        "limit": limit,
        "offset": offset,
        "investigations": items,
    }


@router.post("/investigations", status_code=status.HTTP_201_CREATED, summary="Create a new forensic investigation")
def create_new_investigation(payload: InvestigationCreate):
    """Creates a new persistent investigation record."""
    try:
        case = create_investigation(
            title=payload.title,
            description=payload.description or "",
            investigator=payload.investigator or "Analyst",
            tags=payload.tags or [],
            case_id=payload.case_id,
        )
        return {
            "success": True,
            "investigation": case,
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "CASE_CREATION_FAILED", "message": str(e)},
        )


@router.get("/investigations/{case_id}", summary="Get detailed investigation profile")
def get_investigation_detail(case_id: str):
    """Retrieves an investigation with its associated evidence items and audit trail."""
    case = get_investigation(case_id)
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "CASE_NOT_FOUND", "message": f"Investigation '{case_id}' was not found."},
        )

    evidence, _ = list_evidence_items(investigation_id=case_id, limit=100)
    audit = get_audit_logs(investigation_id=case_id, limit=50)

    return {
        "success": True,
        "investigation": case,
        "evidence": evidence,
        "audit_logs": audit,
    }


@router.patch("/investigations/{case_id}", summary="Update investigation properties or status")
def update_investigation_detail(case_id: str, payload: InvestigationUpdate):
    """Updates mutable fields (title, description, status, investigator, tags) of an investigation."""
    case = update_investigation(
        case_id=case_id,
        title=payload.title,
        description=payload.description,
        status=payload.status,
        investigator=payload.investigator,
        tags=payload.tags,
    )
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "CASE_NOT_FOUND", "message": f"Investigation '{case_id}' was not found."},
        )

    return {
        "success": True,
        "investigation": case,
    }


# ==============================================================================
# Evidence Ingestion & Vault Endpoints
# ==============================================================================

@router.get("/evidence", summary="List all evidence items in vault")
def get_all_vault_evidence(
    investigation_id: Optional[str] = Query(default=None, description="Optional case filter"),
    search: Optional[str] = Query(default=None, description="Filename or SHA-256 search"),
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
):
    """Retrieves all registered evidence items across the entire Evidence Vault."""
    items, total = list_evidence_items(
        investigation_id=investigation_id,
        search=search,
        limit=limit,
        offset=offset,
    )
    return {
        "success": True,
        "total": total,
        "limit": limit,
        "offset": offset,
        "items": items,
    }


@router.post("/investigations/{case_id}/evidence", status_code=status.HTTP_201_CREATED, summary="Ingest evidence into case and execute analysis")
def ingest_evidence_file(
    case_id: str,
    file: UploadFile = File(...),
):
    """
    Uploads a file into an investigation's vault, stores raw bytes immutably with
    read-only protection, executes deep forensic analysis, and records initial examination.
    """
    case = get_investigation(case_id)
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "CASE_NOT_FOUND", "message": f"Investigation '{case_id}' was not found."},
        )

    file_bytes = file.file.read()
    if len(file_bytes) > MAX_UPLOAD_SIZE_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail={
                "code": "FILE_TOO_LARGE",
                "message": f"File size exceeds maximum {MAX_UPLOAD_SIZE_BYTES // (1024*1024)} MB limit.",
            },
        )

    filename = file.filename or "uploaded_evidence.bin"
    suffix = Path(filename).suffix.lower()
    magic = detect_magic_bytes(file_bytes)

    if suffix not in ALLOWED_EXTENSIONS and not magic.is_supported:
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail={
                "code": "UNSUPPORTED_MEDIA",
                "message": f"File format '{suffix}' is not supported.",
            },
        )

    # 1. Store evidence binary in the vault
    evidence_item = store_evidence_file(
        investigation_id=case_id,
        original_filename=filename,
        file_bytes=file_bytes,
        actor=case.get("investigator", "Analyst"),
    )

    # 2. Execute forensic pipeline on stored evidence
    vault_file_path = get_evidence_file_path(evidence_item["id"])
    pipeline = ForensicPipeline()
    analysis_result = pipeline.analyze_file(vault_file_path, original_filename=filename)

    # 3. Record immutable examination entry in historical registry
    analysis_record = create_analysis_record(
        investigation_id=case_id,
        evidence_id=evidence_item["id"],
        analysis_data=analysis_result.model_dump(),
        analyzer_version="2.0.0",
        actor=case.get("investigator", "Analyst"),
    )

    return {
        "success": True,
        "evidence": evidence_item,
        "analysis": analysis_record,
    }


@router.get("/evidence/{evidence_id}", summary="Get evidence item details")
def get_evidence_detail(evidence_id: str):
    """Retrieves an evidence item with disk existence status."""
    item = get_evidence_item(evidence_id)
    if not item:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "EVIDENCE_NOT_FOUND", "message": f"Evidence item '{evidence_id}' was not found."},
        )
    return {
        "success": True,
        "evidence": item,
    }


@router.get("/evidence/{evidence_id}/download", summary="Download original evidence file")
def download_evidence_file(evidence_id: str):
    """
    Downloads original evidence file from the vault.
    Enforces strict path-traversal prevention.
    """
    try:
        safe_path = get_evidence_file_path(evidence_id)
        item = get_evidence_item(evidence_id)
        original_name = item["original_filename"] if item else safe_path.name

        return FileResponse(
            path=safe_path,
            filename=original_name,
            media_type="application/octet-stream",
        )
    except FileNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "FILE_NOT_FOUND", "message": str(e)},
        )
    except PermissionError as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "PATH_TRAVERSAL_DETECTED", "message": str(e)},
        )


@router.post("/evidence/{evidence_id}/verify", summary="Verify evidence cryptographic integrity")
def verify_integrity(evidence_id: str):
    """
    Recalculates cryptographic SHA-256 hash of the stored file on disk,
    compares it with the baseline acquisition hash, detects any tampering or file corruption,
    and logs the audit outcome.
    """
    try:
        report = verify_evidence_integrity(evidence_id)
        return {
            "success": True,
            "verification": report,
        }
    except FileNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "EVIDENCE_NOT_FOUND", "message": str(e)},
        )


# ==============================================================================
# Examination History & Re-Analysis Endpoints
# ==============================================================================

@router.get("/investigations/{case_id}/evidence/{evidence_id}/history", summary="Get examination history for evidence item")
def get_evidence_analysis_history(case_id: str, evidence_id: str):
    """Retrieves all chronological examination records for an evidence item."""
    records = list_analysis_records(evidence_id)
    return {
        "success": True,
        "investigation_id": case_id,
        "evidence_id": evidence_id,
        "total_records": len(records),
        "history": records,
    }


@router.get("/analyses/{analysis_id}", summary="Get specific historical analysis record")
def get_single_analysis_record(analysis_id: str):
    """Retrieves a historical analysis record by ID."""
    record = get_analysis_record(analysis_id)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "ANALYSIS_RECORD_NOT_FOUND", "message": f"Analysis record '{analysis_id}' was not found."},
        )
    return {
        "success": True,
        "analysis": record,
    }


@router.post("/investigations/{case_id}/evidence/{evidence_id}/reanalyze", status_code=status.HTTP_201_CREATED, summary="Re-analyze evidence file")
def reanalyze_evidence(case_id: str, evidence_id: str):
    """
    Re-runs the forensic analysis pipeline on an existing stored evidence binary
    and appends a new examination record to the history (never overwriting prior results).
    """
    case = get_investigation(case_id)
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "CASE_NOT_FOUND", "message": f"Investigation '{case_id}' was not found."},
        )

    item = get_evidence_item(evidence_id)
    if not item:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "EVIDENCE_NOT_FOUND", "message": f"Evidence '{evidence_id}' was not found."},
        )

    try:
        safe_path = get_evidence_file_path(evidence_id)
        pipeline = ForensicPipeline()
        analysis_result = pipeline.analyze_file(safe_path, original_filename=item["original_filename"])

        record = create_analysis_record(
            investigation_id=case_id,
            evidence_id=evidence_id,
            analysis_data=analysis_result.model_dump(),
            analyzer_version="2.0.0",
            actor=case.get("investigator", "Analyst"),
        )

        return {
            "success": True,
            "message": "Evidence re-analyzed successfully. New examination record appended.",
            "analysis": record,
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"code": "REANALYSIS_FAILED", "message": str(e)},
        )


@router.get("/investigations/{case_id}/audit", summary="Get audit activity trail for investigation")
def get_case_audit_logs(case_id: str, limit: int = Query(default=50, ge=1, le=200)):
    """Retrieves immutable audit trail for an investigation."""
    case = get_investigation(case_id)
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "CASE_NOT_FOUND", "message": f"Investigation '{case_id}' was not found."},
        )

    logs = get_audit_logs(investigation_id=case_id, limit=limit)
    return {
        "success": True,
        "investigation_id": case_id,
        "total_logs": len(logs),
        "audit_logs": logs,
    }
