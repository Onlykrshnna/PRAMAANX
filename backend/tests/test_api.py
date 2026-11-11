"""
PRAMAANX - API & Endpoints Unit Test Suite (Phase 5)
====================================================
Tests healthchecks, single file uploads (PDF, DOCX, Image), batch processing,
ZIP archive safety screening, visual evidence retrieval, size guardrails,
and error handling.
"""

import inspect
import io
from pathlib import Path
import zipfile
from fastapi import HTTPException, UploadFile
from PIL import Image
import pytest
import pymupdf

from backend.main import (
    analyze_batch,
    analyze_single_file,
    analyze_zip_archive,
    api_v1_health,
    app,
    get_visual_evidence,
    health_check,
    root,
)
from backend.config import UPLOAD_TEMP_DIR


# ==============================================================================
# 1. Health & Discovery Endpoints
# ==============================================================================

def test_api_root_status():
    """Verify root endpoint returns platform metadata and active operational status."""
    data = root()
    assert data["platform"] == "PRAMAANX"
    assert data["status"] == "operational"
    assert data["phase"] == 5
    assert "PDF" in data["supported_formats"]


def test_api_health_check_legacy():
    """Verify legacy healthcheck endpoint reports healthy status."""
    data = health_check()
    assert data["status"] == "healthy"
    assert data["engine"] == "pramaanx-core"
    assert data["phase1_subsystems"]["sha256"] == "active"


def test_api_v1_health_full_inventory():
    """Verify versioned /api/v1/health provides model statuses and capabilities."""
    resp = api_v1_health()
    assert resp.status == "healthy"
    assert resp.version == "1.0.0"
    assert "image_tampering_efficientnet_b0" in resp.models
    assert resp.models["image_tampering_efficientnet_b0"].status == "active"
    assert "malicious_pdf_xgboost" in resp.models
    assert len(resp.capabilities) >= 10


# ==============================================================================
# 2. Single-File Analysis (PDF, Office, Image)
# ==============================================================================

def test_analyze_single_pdf_success():
    """Tests successful single-file forensic upload and analysis of a PDF."""
    buf = io.BytesIO()
    doc = pymupdf.open()
    page = doc.new_page()
    page.insert_text((72, 72), "Official Quarterly Balance Sheet")
    doc.save(buf)
    doc.close()
    buf.seek(0)

    upload = UploadFile(filename="financials.pdf", file=buf)
    resp = analyze_single_file(upload)

    assert resp.success is True
    assert resp.file.filename == "financials.pdf"
    assert resp.file.detected_type == "pdf"
    assert resp.file.detected_mime == "application/pdf"
    assert resp.file.size_bytes > 0
    assert len(resp.file.sha256) == 64
    assert resp.analysis.risk_category in ("Low", "Medium", "High")
    assert 0 <= resp.analysis.risk_score <= 100


def test_analyze_single_docx_success():
    """Tests successful single-file forensic upload and analysis of a DOCX."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("[Content_Types].xml", "<Types></Types>")
        zf.writestr("word/document.xml", "<w:document><w:body><w:p><w:r><w:t>Hello</w:t></w:r></w:p></w:body></w:document>")
        zf.writestr("docProps/core.xml", "<cp:coreProperties xmlns:cp='http://schemas.openxmlformats.org/package/2006/metadata/core-properties'></cp:coreProperties>")
    buf.seek(0)

    upload = UploadFile(filename="memo.docx", file=buf)
    resp = analyze_single_file(upload)

    assert resp.success is True
    assert resp.file.detected_type == "docx"
    assert "wordprocessingml" in resp.file.detected_mime


def test_analyze_single_image_success():
    """Tests successful single-file upload of an image with ML and visual evidence."""
    buf = io.BytesIO()
    img = Image.new("RGB", (224, 224), color=(150, 100, 200))
    img.save(buf, format="JPEG")
    buf.seek(0)

    upload = UploadFile(filename="evidence.jpg", file=buf)
    resp = analyze_single_file(upload)

    assert resp.success is True
    assert resp.file.detected_type == "jpg"
    assert resp.file.detected_mime == "image/jpeg"
    assert resp.analysis.entropy > 0.0


# ==============================================================================
# 3. Guardrails: Unsupported & Oversized Upload Rejections
# ==============================================================================

def test_analyze_unsupported_file_rejection():
    """Rejects unsupported raw binary or plain text file with 415 status."""
    buf = io.BytesIO(b"Just arbitrary text notes without an approved header signature.")
    upload = UploadFile(filename="notes.txt", file=buf)

    with pytest.raises(HTTPException) as exc_info:
        analyze_single_file(upload)

    assert exc_info.value.status_code == 415
    assert exc_info.value.detail["code"] == "UNSUPPORTED_FILE_FORMAT"


def test_analyze_oversized_file_rejection():
    """Rejects files exceeding the 20 MB ceiling with 413 status."""
    # Create stream simulating > 20 MB
    large_buf = io.BytesIO(b"x" * (20 * 1024 * 1024 + 1024))
    upload = UploadFile(filename="huge.pdf", file=large_buf)

    with pytest.raises(HTTPException) as exc_info:
        analyze_single_file(upload)

    assert exc_info.value.status_code == 413
    assert exc_info.value.detail["code"] == "PAYLOAD_TOO_LARGE"


# ==============================================================================
# 4. Batch Analysis Endpoints
# ==============================================================================

def test_analyze_batch_success():
    """Tests batch processing of multiple uploaded files."""
    # File 1: PDF
    buf1 = io.BytesIO()
    doc = pymupdf.open()
    doc.new_page().insert_text((72, 72), "Page 1")
    doc.save(buf1)
    doc.close()
    buf1.seek(0)

    # File 2: PNG
    buf2 = io.BytesIO()
    img = Image.new("RGB", (64, 64), color="blue")
    img.save(buf2, format="PNG")
    buf2.seek(0)

    uploads = [
        UploadFile(filename="doc1.pdf", file=buf1),
        UploadFile(filename="pic1.png", file=buf2),
    ]

    resp = analyze_batch(uploads)
    assert resp.success is True
    assert resp.summary.total_files == 2
    assert resp.summary.successful_analyses == 2
    assert resp.summary.failed_analyses == 0
    assert len(resp.results) == 2


def test_analyze_batch_limit_exceeded():
    """Rejects batch requests with more than 10 files with 400 status."""
    uploads = [
        UploadFile(filename=f"file_{i}.pdf", file=io.BytesIO(b"%PDF-1.4\n"))
        for i in range(12)
    ]
    with pytest.raises(HTTPException) as exc_info:
        analyze_batch(uploads)

    assert exc_info.value.status_code == 400
    assert exc_info.value.detail["code"] == "BATCH_LIMIT_EXCEEDED"


def test_analyze_batch_mixed_inputs():
    """Tests that a failure in one batch file does not block other valid files."""
    # File 1: Valid PDF
    buf1 = io.BytesIO()
    doc = pymupdf.open()
    doc.new_page().insert_text((72, 72), "Valid PDF")
    doc.save(buf1)
    doc.close()
    buf1.seek(0)

    # File 2: Unsupported file
    buf2 = io.BytesIO(b"Unsupported random string data")

    uploads = [
        UploadFile(filename="good.pdf", file=buf1),
        UploadFile(filename="bad.txt", file=buf2),
    ]

    resp = analyze_batch(uploads)
    assert resp.summary.total_files == 2
    assert resp.summary.successful_analyses == 1
    assert resp.summary.failed_analyses == 1

    good_item = next(r for r in resp.results if r.filename == "good.pdf")
    bad_item = next(r for r in resp.results if r.filename == "bad.txt")

    assert good_item.status == "success"
    assert bad_item.status == "failed"


def test_batch_endpoint_signature_and_types():
    """Verifies that the batch endpoint uses list[UploadFile] and File(...)."""
    sig = inspect.signature(analyze_batch)
    assert "files" in sig.parameters
    param = sig.parameters["files"]

    # Verify type hint is list[UploadFile]
    assert param.annotation == list[UploadFile]

    # Verify default parameter value is a FastAPI File
    assert hasattr(param.default, "__class__")
    assert param.default.__class__.__name__ in ("File", "FieldInfo")


def test_batch_endpoint_openapi_schema_multifile_upload_spec():
    """Verifies OpenAPI schema correctly advertises multi-file upload for Swagger UI."""
    schema = app.openapi()
    path_item = schema["paths"].get("/api/v1/analyze/batch")
    assert path_item is not None
    post_op = path_item.get("post")
    assert post_op is not None

    # Check requestBody content type is multipart/form-data
    content = post_op.get("requestBody", {}).get("content", {})
    assert "multipart/form-data" in content

    # Check schema definition for files array
    body_schema_ref = content["multipart/form-data"]["schema"]["$ref"]
    schema_name = body_schema_ref.split("/")[-1]
    batch_schema = schema["components"]["schemas"][schema_name]

    files_prop = batch_schema["properties"]["files"]
    assert files_prop["type"] == "array"
    assert "items" in files_prop
    assert files_prop["items"]["type"] == "string"
    assert files_prop["items"]["format"] == "binary"
    assert "files" in batch_schema.get("required", [])


def test_analyze_batch_multi_format_submission():
    """Verifies submitting multiple diverse actual files (PDF, PNG, DOCX) in a batch."""
    # 1. PDF
    buf_pdf = io.BytesIO()
    doc = pymupdf.open()
    doc.new_page().insert_text((72, 72), "Multi batch PDF test")
    doc.save(buf_pdf)
    doc.close()
    buf_pdf.seek(0)

    # 2. PNG
    buf_png = io.BytesIO()
    img = Image.new("RGB", (64, 64), color="red")
    img.save(buf_png, format="PNG")
    buf_png.seek(0)

    # 3. DOCX
    buf_docx = io.BytesIO()
    with zipfile.ZipFile(buf_docx, "w") as zf:
        zf.writestr("[Content_Types].xml", "<Types></Types>")
        zf.writestr("word/document.xml", "<w:document><w:body><w:p><w:r><w:t>Batch doc</w:t></w:r></w:p></w:body></w:document>")
        zf.writestr("docProps/core.xml", "<cp:coreProperties xmlns:cp='http://schemas.openxmlformats.org/package/2006/metadata/core-properties'></cp:coreProperties>")
    buf_docx.seek(0)

    uploads = [
        UploadFile(filename="batch_doc.pdf", file=buf_pdf),
        UploadFile(filename="batch_img.png", file=buf_png),
        UploadFile(filename="batch_office.docx", file=buf_docx),
    ]

    resp = analyze_batch(uploads)
    assert resp.success is True
    assert resp.summary.total_files == 3
    assert resp.summary.successful_analyses == 3
    assert resp.summary.failed_analyses == 0
    assert len(resp.results) == 3

    types_found = {r.file.detected_type for r in resp.results if r.file}
    assert types_found == {"pdf", "png", "docx"}


# ==============================================================================
# 5. ZIP Archive Batch Analysis
# ==============================================================================

def test_analyze_zip_archive_success():
    """Tests archive analysis on a safe ZIP containing multiple documents."""
    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, "w") as zf:
        # Member 1: PDF
        p_buf = io.BytesIO()
        d = pymupdf.open()
        d.new_page().insert_text((50, 50), "PDF in ZIP")
        d.save(p_buf)
        d.close()
        zf.writestr("report.pdf", p_buf.getvalue())

        # Member 2: PNG
        img_buf = io.BytesIO()
        im = Image.new("RGB", (50, 50), color="green")
        im.save(img_buf, format="PNG")
        zf.writestr("photo.png", img_buf.getvalue())

    zip_buf.seek(0)
    upload = UploadFile(filename="evidence_bundle.zip", file=zip_buf)
    resp = analyze_zip_archive(upload)

    assert resp.success is True
    assert resp.archive_safety.is_safe is True
    assert resp.summary.total_files == 2
    assert resp.summary.successful_analyses == 2


def test_analyze_zip_archive_traversal_rejection():
    """Rejects ZIP archives containing Zip Slip directory traversal (../)."""
    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, "w") as zf:
        zf.writestr("../../etc/shadow", "malicious payload")
    zip_buf.seek(0)

    upload = UploadFile(filename="malicious_slip.zip", file=zip_buf)
    with pytest.raises(HTTPException) as exc_info:
        analyze_zip_archive(upload)

    assert exc_info.value.status_code == 400
    assert "ZIP" in exc_info.value.detail["code"] or "SLIP" in exc_info.value.detail["code"] or "TRAVERSAL" in exc_info.value.detail["code"]


# ==============================================================================
# 6. Visual Evidence Delivery & Traversal Protection
# ==============================================================================

def test_get_visual_evidence_success(tmp_path: Path):
    """Verifies retrieval of a generated visual evidence file."""
    # Create dummy evidence file matching pattern: 16-hex_ela.png
    safe_filename = "0123456789abcdef_ela.png"
    target_file = UPLOAD_TEMP_DIR / safe_filename
    target_file.write_bytes(b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR" + b"\x00" * 20)

    try:
        resp = get_visual_evidence(evidence_type="ela", filename=safe_filename)
        assert resp.media_type == "image/png"
        assert Path(resp.path).resolve() == target_file.resolve()
    finally:
        target_file.unlink(missing_ok=True)


def test_get_visual_evidence_original_specimen(tmp_path: Path):
    """Verifies retrieval of preserved original evidence specimen."""
    safe_orig = "fedcba9876543210_original.jpg"
    target_file = UPLOAD_TEMP_DIR / safe_orig
    target_file.write_bytes(b"\xff\xd8\xff\xe0" + b"\x00" * 20)

    try:
        resp = get_visual_evidence(evidence_type="original", filename=safe_orig)
        assert resp.media_type == "image/jpeg"
        assert Path(resp.path).resolve() == target_file.resolve()
    finally:
        target_file.unlink(missing_ok=True)


def test_get_visual_evidence_not_found():
    """Returns 404 for non-existent evidence identifiers."""
    with pytest.raises(HTTPException) as exc_info:
        get_visual_evidence(evidence_type="ela", filename="0000000000000000_ela.png")
    assert exc_info.value.status_code == 404


def test_get_visual_evidence_path_traversal_rejection():
    """Rejects traversal patterns and malformed filenames with 400."""
    with pytest.raises(HTTPException) as exc_info:
        get_visual_evidence(evidence_type="ela", filename="../../secret.png")
    assert exc_info.value.status_code == 400
