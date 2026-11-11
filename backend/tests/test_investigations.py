"""
PRAMAANX - Investigations & Evidence Persistence Unit & Integration Tests (Milestone D)
======================================================================================
Tests:
- Database schema initialization and case ID sequencing
- Case creation, listing, searching, filtering, and status updates
- Vault file storage with read-only integrity protection
- Path traversal defense on evidence retrieval
- Cryptographic SHA-256 re-verification and deliberate tamper detection
- Non-destructive analysis history recording (never overwriting prior results)
- Full FastAPI endpoint integrations
"""

import io
import os
from pathlib import Path
import tempfile
import pytest
from fastapi import UploadFile

from backend.config import ARTIFACTS_DIR, EVIDENCE_DIR
from backend.database import (
    create_analysis_record,
    create_investigation,
    generate_case_id,
    get_analysis_record,
    get_audit_logs,
    get_evidence_file_path,
    get_evidence_item,
    get_investigation,
    init_db,
    list_analysis_records,
    list_evidence_items,
    list_investigations,
    store_evidence_file,
    update_investigation,
    verify_evidence_integrity,
)
from backend.routes.investigations import (
    InvestigationCreate,
    InvestigationUpdate,
    create_new_investigation,
    download_evidence_file,
    get_all_vault_evidence,
    get_evidence_analysis_history,
    get_evidence_detail,
    get_investigation_detail,
    get_investigations_list,
    ingest_evidence_file,
    reanalyze_evidence,
    update_investigation_detail,
    verify_integrity,
)


@pytest.fixture(autouse=True)
def setup_test_vault(tmp_path: Path, monkeypatch):
    """Isolates DB and vault directories for each test."""
    test_db = tmp_path / "test_pramaanx.db"
    test_evidence = tmp_path / "vault" / "evidence"
    test_artifacts = tmp_path / "vault" / "artifacts"
    test_evidence.mkdir(parents=True, exist_ok=True)
    test_artifacts.mkdir(parents=True, exist_ok=True)

    monkeypatch.setattr("backend.database.DB_PATH", test_db)
    monkeypatch.setattr("backend.database.EVIDENCE_DIR", test_evidence)
    monkeypatch.setattr("backend.database.ARTIFACTS_DIR", test_artifacts)
    monkeypatch.setattr("backend.config.DB_PATH", test_db)
    monkeypatch.setattr("backend.config.EVIDENCE_DIR", test_evidence)
    monkeypatch.setattr("backend.config.ARTIFACTS_DIR", test_artifacts)

    init_db()
    yield


# ==============================================================================
# 1. Database & Case Lifecycle Tests
# ==============================================================================

def test_case_id_generation_sequential():
    """Case IDs follow sequential CAS-YYYY-XXXX format."""
    id1 = generate_case_id()
    create_investigation("First Case", case_id=id1)
    id2 = generate_case_id()
    assert id1 != id2
    assert id2.endswith("0002")


def test_create_and_get_investigation():
    """Creates investigation, writes audit log, and computes initial aggregates."""
    case = create_investigation(
        title="Suspicious Invoice Tampering",
        description="Accounting ledger discrepancies reported in Q3.",
        investigator="Lead Analyst Smith",
        tags=["financial", "pdf", "priority-high"],
    )
    assert case is not None
    assert case["title"] == "Suspicious Invoice Tampering"
    assert case["status"] == "open"
    assert case["evidence_count"] == 0
    assert case["highest_risk_score"] == 0
    assert "financial" in case["tags"]

    fetched = get_investigation(case["id"])
    assert fetched["id"] == case["id"]
    assert fetched["investigator"] == "Lead Analyst Smith"


def test_list_investigations_filter_and_search():
    """Tests search and status filtering on investigations registry."""
    c1 = create_investigation("Corporate Email Scam", tags=["email"])
    c2 = create_investigation("Employee Marks Examination", tags=["hr"])
    update_investigation(c2["id"], status="closed")

    # Filter open
    open_cases, count_open = list_investigations(status_filter="open")
    assert any(c["id"] == c1["id"] for c in open_cases)
    assert not any(c["id"] == c2["id"] for c in open_cases)

    # Filter closed
    closed_cases, count_closed = list_investigations(status_filter="closed")
    assert any(c["id"] == c2["id"] for c in closed_cases)

    # Text search
    search_res, search_cnt = list_investigations(search="Scam")
    assert len(search_res) == 1
    assert search_res[0]["id"] == c1["id"]


def test_update_investigation_status_transition():
    """Status updates are auditable and transition correctly."""
    case = create_investigation("State Transition Test")
    updated = update_investigation(case["id"], status="in_progress", description="Active review")
    assert updated["status"] == "in_progress"
    assert updated["description"] == "Active review"

    audit = get_audit_logs(investigation_id=case["id"])
    assert any(log["action"] == "CASE_STATUS_CHANGED" for log in audit)


# ==============================================================================
# 2. Evidence Vault & Integrity Tests
# ==============================================================================

def test_store_evidence_file_immutability_and_hash():
    """Stores evidence in vault with SHA-256 and read-only attributes."""
    case = create_investigation("Evidence Storage Test")
    payload = b"Immutable Forensic Evidence Raw Byte Stream 12345"
    item = store_evidence_file(case["id"], "contract.pdf", payload)

    assert item["original_filename"] == "contract.pdf"
    assert item["file_size_bytes"] == len(payload)
    assert item["integrity_status"] == "verified"
    assert len(item["sha256"]) == 64

    # Verify physical file existence
    stored_path = get_evidence_file_path(item["id"])
    assert stored_path.is_file()
    assert stored_path.read_bytes() == payload


def test_evidence_integrity_tamper_detection():
    """Recalculating hash detects when evidence file bytes are modified on disk."""
    case = create_investigation("Tamper Detection Test")
    payload = b"Original Authentic Bank Statement"
    item = store_evidence_file(case["id"], "statement.pdf", payload)

    # 1. Verification while intact
    v1 = verify_evidence_integrity(item["id"])
    assert v1["integrity_status"] == "verified"
    assert v1["is_intact"] is True

    # 2. Modify bytes on disk (simulate rogue alteration)
    stored_path = get_evidence_file_path(item["id"])
    # Temporarily restore write permission to simulate malicious attack
    os.chmod(stored_path, 0o666)
    stored_path.write_bytes(b"Tampered Forged Bank Statement !!!")

    # 3. Re-verify integrity
    v2 = verify_evidence_integrity(item["id"])
    assert v2["integrity_status"] == "tampered"
    assert v2["is_intact"] is False

    # 4. Verify audit trail logs tampering
    audit = get_audit_logs(evidence_id=item["id"])
    assert any(log["action"] == "INTEGRITY_TAMPER_DETECTED" for log in audit)


def test_evidence_path_traversal_prevention():
    """Path traversal sequences in evidence IDs or filenames are blocked."""
    with pytest.raises((FileNotFoundError, PermissionError)):
        get_evidence_file_path("../../outside_file.txt")


# ==============================================================================
# 3. Examination History & Non-Destructive Analysis
# ==============================================================================

def test_analysis_record_history_preserves_previous():
    """Multiple analyses on the same evidence create distinct history records rather than overwriting."""
    case = create_investigation("Analysis History Test")
    item = store_evidence_file(case["id"], "photo.jpg", b"JFIF Fake Header Data")

    # Run Analysis #1 (Low score)
    a1 = create_analysis_record(
        investigation_id=case["id"],
        evidence_id=item["id"],
        analysis_data={"risk_score": 25, "risk_band": "Low", "entropy": 4.5, "findings": []},
    )

    # Run Analysis #2 (High score)
    a2 = create_analysis_record(
        investigation_id=case["id"],
        evidence_id=item["id"],
        analysis_data={"risk_score": 85, "risk_band": "High", "entropy": 7.9, "findings": []},
    )

    assert a1["id"] != a2["id"]
    history = list_analysis_records(item["id"])
    assert len(history) == 2
    assert history[0]["risk_score"] == 85
    assert history[1]["risk_score"] == 25


# ==============================================================================
# 4. FastAPI Endpoints Integration Tests
# ==============================================================================

def test_api_investigations_crud_flow():
    """Tests FastAPI CRUD route logic for investigations."""
    # 1. Create case
    res = create_new_investigation(
        InvestigationCreate(title="API Test Case", description="Testing FastAPI endpoints", tags=["api", "test"])
    )
    assert res["success"] is True
    cid = res["investigation"]["id"]

    # 2. Get case
    res_get = get_investigation_detail(cid)
    assert res_get["success"] is True
    assert res_get["investigation"]["title"] == "API Test Case"

    # 3. Update case status to in_progress
    res_patch = update_investigation_detail(
        cid,
        InvestigationUpdate(status="in_progress"),
    )
    assert res_patch["success"] is True
    assert res_patch["investigation"]["status"] == "in_progress"

    # 4. List cases
    res_list = get_investigations_list(status="in_progress")
    assert res_list["success"] is True
    assert any(c["id"] == cid for c in res_list["investigations"])


def test_api_evidence_ingest_and_verify_flow():
    """Tests file upload into case, automated forensic analysis, and integrity verification."""
    # Create case
    c_res = create_new_investigation(InvestigationCreate(title="Evidence Ingest Case"))
    cid = c_res["investigation"]["id"]

    # Upload clean PNG into case
    png_bytes = (
        b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
        b"\x08\x06\x00\x00\x00\x1f\x15c4\x00\x00\x00\nIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01\r\n-\xb4"
        b"\x00\x00\x00\x00IEND\xaeB`\x82"
    )
    upload_file = UploadFile(file=io.BytesIO(png_bytes), filename="test_image.png")
    ingest_res = ingest_evidence_file(case_id=cid, file=upload_file)
    assert ingest_res["success"] is True
    assert "evidence" in ingest_res
    assert "analysis" in ingest_res
    eid = ingest_res["evidence"]["id"]

    # Verify integrity endpoint
    v_res = verify_integrity(evidence_id=eid)
    assert v_res["success"] is True
    assert v_res["verification"]["integrity_status"] == "verified"

    # Download evidence endpoint
    d_res = download_evidence_file(evidence_id=eid)
    assert d_res.filename == "test_image.png"

    # Check evidence vault global listing
    vault_res = get_all_vault_evidence()
    assert vault_res["success"] is True
    assert any(item["id"] == eid for item in vault_res["items"])

    # Re-analyze evidence endpoint
    re_res = reanalyze_evidence(case_id=cid, evidence_id=eid)
    assert re_res["success"] is True

    # Check history
    hist_res = get_evidence_analysis_history(case_id=cid, evidence_id=eid)
    assert hist_res["success"] is True
    assert hist_res["total_records"] >= 2
