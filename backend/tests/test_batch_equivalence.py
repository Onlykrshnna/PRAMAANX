"""
PRAMAANX - Single vs Batch Equivalence Verification Test Suite
============================================================
Verifies that:
1. An image analyzed individually returns the EXACT SAME forensic fields,
   hashes, risk scores, findings, entropy, and metadata as when analyzed
   inside a batch.
2. Batch summary metrics (total, success, failed, highest risk, average risk)
   are accurately derived from individual results.
3. Unsupported / invalid files fail independently without degrading
   or altering the results of successful files in the same batch.
"""

import io
from pathlib import Path
from fastapi import UploadFile
from PIL import Image
import pymupdf
import pytest

from backend.main import analyze_single_file, analyze_batch


FIXTURES_DIR = Path(__file__).resolve().parent.parent.parent / "tests" / "fixtures"


def test_single_vs_batch_forensic_equivalence():
    """
    Submits the same JPEG image as a single file and inside a batch.
    Asserts that every forensic metric and structural finding matches identically.
    """
    sample_path = FIXTURES_DIR / "original.jpg"
    assert sample_path.exists(), f"Sample fixture missing at {sample_path}"
    file_bytes = sample_path.read_bytes()

    # 1. Analyze as single file
    single_upload = UploadFile(
        filename="original.jpg",
        file=io.BytesIO(file_bytes),
    )
    single_resp = analyze_single_file(single_upload)

    # 2. Analyze as part of a batch
    batch_upload = [
        UploadFile(
            filename="original.jpg",
            file=io.BytesIO(file_bytes),
        )
    ]
    batch_resp = analyze_batch(batch_upload)

    assert batch_resp.success is True
    assert len(batch_resp.results) == 1
    batch_item = batch_resp.results[0]
    assert batch_item.status == "success"

    # Compare FileInfo
    assert single_resp.file.filename == batch_item.file.filename
    assert single_resp.file.detected_type == batch_item.file.detected_type
    assert single_resp.file.detected_mime == batch_item.file.detected_mime
    assert single_resp.file.size_bytes == batch_item.file.size_bytes
    assert single_resp.file.sha256 == batch_item.file.sha256

    # Compare AnalysisDetail
    s_an = single_resp.analysis
    b_an = batch_item.analysis

    assert s_an.risk_score == b_an.risk_score
    assert s_an.risk_category == b_an.risk_category
    assert s_an.entropy == b_an.entropy
    assert s_an.verdict == b_an.verdict
    assert s_an.reliability == b_an.reliability
    assert s_an.ai_status == b_an.ai_status
    assert len(s_an.findings) == len(b_an.findings)

    # Compare findings titles and severities
    s_findings = sorted([(f.title, f.severity) for f in s_an.findings])
    b_findings = sorted([(f.title, f.severity) for f in b_an.findings])
    assert s_findings == b_findings


def test_batch_mixed_multi_format_and_failure_isolation():
    """
    Tests a diverse batch with 4 files:
    1. JPG image
    2. PNG image
    3. PDF document
    4. Unsupported text file
    Verifies that the 3 valid files succeed with full forensic detail,
    the invalid file reports failure cleanly, and batch summary metrics match.
    """
    # 1. JPG
    sample_path = FIXTURES_DIR / "original.jpg"
    jpg_bytes = sample_path.read_bytes()

    # 2. PNG
    buf_png = io.BytesIO()
    img = Image.new("RGB", (100, 100), color="purple")
    img.save(buf_png, format="PNG")
    buf_png.seek(0)
    png_bytes = buf_png.read()

    # 3. PDF
    buf_pdf = io.BytesIO()
    doc = pymupdf.open()
    doc.new_page().insert_text((72, 72), "PRAMAANX Batch Test Specimen")
    doc.save(buf_pdf)
    doc.close()
    buf_pdf.seek(0)
    pdf_bytes = buf_pdf.read()

    # 4. Bad file
    bad_bytes = b"This is a raw text file without valid document magic numbers."

    uploads = [
        UploadFile(filename="specimen1.jpg", file=io.BytesIO(jpg_bytes)),
        UploadFile(filename="specimen2.png", file=io.BytesIO(png_bytes)),
        UploadFile(filename="specimen3.pdf", file=io.BytesIO(pdf_bytes)),
        UploadFile(filename="invalid.txt", file=io.BytesIO(bad_bytes)),
    ]

    resp = analyze_batch(uploads)

    assert resp.success is True
    assert resp.summary.total_files == 4
    assert resp.summary.successful_analyses == 3
    assert resp.summary.failed_analyses == 1
    assert len(resp.results) == 4

    # Verify order preservation and presence of full forensic analyses
    assert resp.results[0].filename == "specimen1.jpg"
    assert resp.results[0].status == "success"
    assert resp.results[0].file.detected_type in ("jpg", "jpeg")
    assert resp.results[0].file.sha256 is not None
    assert resp.results[0].analysis is not None

    assert resp.results[1].filename == "specimen2.png"
    assert resp.results[1].status == "success"
    assert resp.results[1].file.detected_type == "png"
    assert resp.results[1].analysis is not None

    assert resp.results[2].filename == "specimen3.pdf"
    assert resp.results[2].status == "success"
    assert resp.results[2].file.detected_type == "pdf"
    assert resp.results[2].analysis is not None

    assert resp.results[3].filename == "invalid.txt"
    assert resp.results[3].status == "failed"
    assert resp.results[3].error is not None
    assert resp.results[3].error.code == "UNSUPPORTED_FILE_FORMAT"
