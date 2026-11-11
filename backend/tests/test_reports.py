"""
PRAMAANX - Forensic Report Generation & Integrity Tests (Milestone E)
====================================================================
Tests PDF report compilation, executive vs detailed formatting,
cryptographic SHA-256 export verification, immutability, and API endpoints.
"""

import hashlib
import io
import json
from pathlib import Path
import pytest
import pymupdf

from backend.config import REPORTS_DIR
from backend.database import (
    create_investigation,
    get_report_by_id,
    init_db,
    list_reports,
    store_evidence_file,
    create_analysis_record,
    get_report_file_path,
)
from backend.reporting.generator import generate_case_report
from backend.routes.reports import (
    create_investigation_report,
    download_report_pdf,
    get_report_metadata,
    get_reports_catalog,
    preview_report_pdf,
    GenerateReportRequest,
)


@pytest.fixture(autouse=True)
def setup_test_vault(tmp_path: Path, monkeypatch):
    """Isolates DB and vault storage in a clean temporary directory for each test."""
    test_db = tmp_path / "test_pramaanx.db"
    test_evidence = tmp_path / "vault" / "evidence"
    test_artifacts = tmp_path / "vault" / "artifacts"
    test_reports = tmp_path / "vault" / "reports"
    test_evidence.mkdir(parents=True, exist_ok=True)
    test_artifacts.mkdir(parents=True, exist_ok=True)
    test_reports.mkdir(parents=True, exist_ok=True)

    monkeypatch.setattr("backend.database.DB_PATH", test_db)
    monkeypatch.setattr("backend.database.EVIDENCE_DIR", test_evidence)
    monkeypatch.setattr("backend.database.ARTIFACTS_DIR", test_artifacts)
    monkeypatch.setattr("backend.database.REPORTS_DIR", test_reports)

    monkeypatch.setattr("backend.config.DB_PATH", test_db)
    monkeypatch.setattr("backend.config.EVIDENCE_DIR", test_evidence)
    monkeypatch.setattr("backend.config.ARTIFACTS_DIR", test_artifacts)
    monkeypatch.setattr("backend.config.REPORTS_DIR", test_reports)

    monkeypatch.setattr("backend.reporting.generator.REPORTS_DIR", test_reports)

    init_db()
    yield


def test_empty_investigation_report_generation():
    """Verifies report generation handles cases with zero evidence items gracefully."""
    case = create_investigation("Empty Cold Case", "Case with zero files", "Detective Smith")
    cid = case["id"]

    # 1. Executive report
    exec_rep = generate_case_report(cid, report_type="executive", generated_by="Detective Smith")
    assert exec_rep["id"].startswith("REP-")
    assert exec_rep["report_type"] == "executive"
    assert exec_rep["investigation_id"] == cid
    assert exec_rep["file_size_bytes"] > 0
    assert len(exec_rep["sha256"]) == 64

    # 2. Detailed report
    det_rep = generate_case_report(cid, report_type="detailed", generated_by="Detective Smith")
    assert det_rep["id"].startswith("REP-")
    assert det_rep["report_type"] == "detailed"
    assert det_rep["id"] != exec_rep["id"]


def test_evidence_and_findings_traceability_in_pdf():
    """Verifies that evidence metadata, byte offsets, and findings are rendered in the PDF."""
    case = create_investigation("Traceability Test Case", "Verifying byte offsets", "Analyst Doe")
    cid = case["id"]

    # Ingest a mock PDF
    pdf_bytes = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\nxref\n0 1\n0000000000 65535 f\ntrailer\n<< /Size 1 >>\nstartxref\n50\n%%EOF\n"
    ev = store_evidence_file(cid, "contract_revised.pdf", pdf_bytes, actor="Analyst Doe")
    eid = ev["id"]

    # Attach analysis record with specific findings and byte offsets
    findings = [
        {
            "id": "pdf_struct_001",
            "name": "Incremental Revisions Detected",
            "severity": "high",
            "category": "structural",
            "description": "Second %%EOF trailer detected indicating append alteration.",
            "offset": "0x000032",
            "object_id": "1 0 obj",
            "why_it_matters": "Document content was modified after original signature.",
            "recommended_action": "Inspect incremental body stream difference.",
        },
        {
            "id": "pdf_entropy_001",
            "name": "Elevated Stream Entropy",
            "severity": "medium",
            "category": "statistical",
            "description": "Entropy of 7.82 bits indicates compressed or packed stream.",
            "offset": "0x000010",
            "why_it_matters": "Possible encrypted payload or compressed stream.",
        },
    ]

    create_analysis_record(
        investigation_id=cid,
        evidence_id=eid,
        analysis_data={
            "risk_score": 75,
            "risk_category": "High",
            "entropy": 7.82,
            "findings": findings,
            "plain_summary": "High-severity structural alteration detected.",
        },
    )

    # Generate Detailed Report
    rep = generate_case_report(cid, report_type="detailed", generated_by="Analyst Doe")
    pdf_path = get_report_file_path(rep["id"])
    assert pdf_path.exists()

    # Open PDF with PyMuPDF and verify text extracts
    doc = pymupdf.open(str(pdf_path))
    assert len(doc) >= 1

    all_text = ""
    for page in doc:
        all_text += page.get_text()

    assert rep["id"] in all_text
    assert cid in all_text
    assert "contract_revised.pdf" in all_text
    assert "0x000032" in all_text
    assert "1 0 obj" in all_text
    assert "Incremental Revisions Detected" in all_text
    assert "75/100" in all_text
    assert "SCIENTIFIC LIMITATIONS" in all_text


def test_report_export_sha256_hash_integrity():
    """Verifies that the database SHA-256 hash matches the exact byte digest of the generated file."""
    case = create_investigation("Cryptographic Test Case", "Hash check", "Examiner Bob")
    cid = case["id"]

    rep = generate_case_report(cid, report_type="executive", generated_by="Examiner Bob")
    pdf_path = get_report_file_path(rep["id"])

    # Compute hash directly from disk
    hasher = hashlib.sha256()
    with open(pdf_path, "rb") as f:
        hasher.update(f.read())
    disk_hash = hasher.hexdigest()

    assert rep["sha256"] == disk_hash
    assert rep["file_size_bytes"] == pdf_path.stat().st_size


def test_historical_accuracy_reanalysis_does_not_modify_existing_report():
    """Verifies that later re-analysis or new evidence does not mutate an already generated report."""
    case = create_investigation("Historical Snapshot Case", "Preservation test", "Examiner Charlie")
    cid = case["id"]

    ev = store_evidence_file(cid, "doc_v1.pdf", b"%PDF-1.4 Mock", actor="Examiner Charlie")
    create_analysis_record(
        investigation_id=cid,
        evidence_id=ev["id"],
        analysis_data={
            "risk_score": 20,
            "risk_category": "Low",
            "entropy": 4.5,
            "findings": [],
            "plain_summary": "Benign file.",
        },
    )

    # Generate Report 1
    rep1 = generate_case_report(cid, report_type="detailed", title="Initial Inspection")
    hash_before = rep1["sha256"]
    size_before = rep1["file_size_bytes"]

    # Re-analyze with new risk score and new findings
    create_analysis_record(
        investigation_id=cid,
        evidence_id=ev["id"],
        analysis_data={
            "risk_score": 90,
            "risk_category": "High",
            "entropy": 7.9,
            "findings": [{"name": "Severe Splicing", "severity": "high"}],
            "plain_summary": "Malicious alteration.",
        },
    )

    # Verify Report 1 in DB and on disk remains identical
    rep1_check = get_report_by_id(rep1["id"])
    assert rep1_check["sha256"] == hash_before
    assert rep1_check["file_size_bytes"] == size_before

    # Verify file content didn't change
    pdf_path = get_report_file_path(rep1["id"])
    hasher = hashlib.sha256()
    with open(pdf_path, "rb") as f:
        hasher.update(f.read())
    assert hasher.hexdigest() == hash_before

    # Generate Report 2 (which reflects updated analysis)
    rep2 = generate_case_report(cid, report_type="detailed", title="Follow-up Inspection")
    assert rep2["id"] != rep1["id"]
    assert rep2["sha256"] != rep1["sha256"]


def test_api_report_generation_and_catalog():
    """Tests the FastAPI route handlers for creating and listing reports."""
    case = create_investigation("API Report Case", "Endpoints testing", "Inspector Gadget")
    cid = case["id"]

    req = GenerateReportRequest(
        report_type="executive",
        title="Custom Executive Brief",
        examiner="Inspector Gadget",
    )
    res = create_investigation_report(cid, req)
    assert res["status"] == "success"
    rep_meta = res["report"]
    assert rep_meta["title"] == "Custom Executive Brief"
    assert rep_meta["report_type"] == "executive"

    # Catalog listing
    catalog = get_reports_catalog(case_id=cid)
    assert catalog["status"] == "success"
    assert catalog["total"] >= 1
    assert any(r["id"] == rep_meta["id"] for r in catalog["reports"])

    # Detail query
    detail = get_report_metadata(rep_meta["id"])
    assert detail["status"] == "success"
    assert detail["report"]["id"] == rep_meta["id"]


def test_api_report_download_and_preview_responses():
    """Tests FileResponse generation for download and preview."""
    case = create_investigation("Download Case", "Download endpoint test", "Agent 007")
    cid = case["id"]

    rep = generate_case_report(cid, report_type="executive")
    rid = rep["id"]

    # Test Download
    dl_resp = download_report_pdf(rid)
    assert dl_resp.media_type == "application/pdf"
    assert dl_resp.status_code == 200

    # Test Preview
    prev_resp = preview_report_pdf(rid)
    assert prev_resp.media_type == "application/pdf"
    assert "inline" in prev_resp.headers.get("Content-Disposition", "")


def test_api_invalid_report_type_rejection():
    """Verifies that unsupported report types return HTTP 400."""
    case = create_investigation("Validation Case", "Testing input checks")
    req = GenerateReportRequest(report_type="unsupported_type")

    with pytest.raises(Exception) as exc:
        create_investigation_report(case["id"], req)
    assert "400" in str(exc.value) or "Invalid report_type" in str(exc.value)
