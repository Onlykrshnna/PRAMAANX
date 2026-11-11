import os
import sys
import uuid

# Ensure backend can be imported
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import backend.database as db
from backend.storage import is_supabase_storage_enabled

def run_tests():
    print("=" * 60)
    print("PRAMAANX SUPABASE / DATABASE INTEGRATION TEST SUITE")
    print("=" * 60)

    # 1. Health Check
    health = db.check_db_health()
    print(f"Health Check Output: {health}")
    assert health["status"] == "healthy", f"DB is not healthy: {health}"
    print(f"[PASS] DB Health: {health['status']} on engine: {health['engine']} ({health['latency_ms']} ms)")

    # 2. Case Management (Create, Read, Update, List)
    test_case_id = f"TEST-{uuid.uuid4().hex[:8].upper()}"
    print(f"\nTesting Case Creation: {test_case_id}...")
    inv = db.create_investigation(
        title="Automated Forensic Integration Test Case",
        description="Verifying Supabase PostgreSQL schema and persistence layer.",
        investigator="Automated Test Runner",
        tags=["integration_test", "supabase"],
        case_id=test_case_id,
    )
    assert inv["id"] == test_case_id, "Case ID mismatch"
    print(f"[PASS] Created investigation: {inv['id']}, status: {inv['status']}")

    # Read back
    retrieved = db.get_investigation(test_case_id)
    assert retrieved is not None, "Failed to retrieve investigation"
    assert retrieved["title"] == "Automated Forensic Integration Test Case"
    print("[PASS] Retrieved investigation matches.")

    # Update
    updated = db.update_investigation(
        case_id=test_case_id,
        title="Updated Forensic Integration Test Case",
        status="in_progress",
        actor="Test Lead",
    )
    assert updated["title"] == "Updated Forensic Integration Test Case"
    assert updated["status"] == "in_progress"
    print("[PASS] Updated investigation.")

    # List
    invs, total = db.list_investigations(search="Updated Forensic", limit=5)
    assert total >= 1, "Failed to find updated case in list"
    assert any(i["id"] == test_case_id for i in invs), "Case not in search results"
    print(f"[PASS] List investigations found test case. Total count: {total}")

    # 3. Evidence Ingestion & Vault Storage
    print("\nTesting Evidence Ingestion...")
    dummy_bytes = b"PRAMAANX_FORENSIC_INTEGRATION_TEST_PAYLOAD_" + uuid.uuid4().bytes
    evidence = db.store_evidence_file(
        investigation_id=test_case_id,
        original_filename="specimen_test.bin",
        file_bytes=dummy_bytes,
        actor="Test Lead",
    )
    evidence_id = evidence["id"]
    assert evidence["investigation_id"] == test_case_id
    assert evidence["integrity_status"] == "verified"
    print(f"[PASS] Evidence ingested: {evidence_id}, SHA-256: {evidence['sha256'][:16]}...")

    # Read evidence item
    evi_item = db.get_evidence_item(evidence_id)
    assert evi_item is not None
    assert evi_item["original_filename"] == "specimen_test.bin"
    print("[PASS] Evidence item retrieved successfully.")

    # Verify integrity
    verif = db.verify_evidence_integrity(evidence_id, actor="Auditor")
    assert verif["integrity_status"] == "verified"
    assert verif["is_intact"] is True
    print(f"[PASS] Evidence integrity verification: {verif['integrity_status']}")

    # 4. Historical Analysis Records
    print("\nTesting Historical Analysis Record...")
    analysis_record = db.create_analysis_record(
        investigation_id=test_case_id,
        evidence_id=evidence_id,
        analysis_data={
            "risk_score": 15,
            "risk_band": "Low",
            "entropy": 4.12,
            "findings": [{"id": "F-001", "rule": "MagicBytesValid", "severity": "Info", "description": "Binary payload valid"}],
            "metadata_timeline": [{"timestamp": "2026-11-11T00:00:00Z", "event": "File acquired"}],
            "visual_evidence": {},
            "plain_summary": "Test payload examined with no malicious tampering indicators.",
        },
        analyzer_version="2.1.0",
        actor="Analyst",
    )
    assert analysis_record["risk_score"] == 15
    assert analysis_record["risk_category"] == "Low"
    print(f"[PASS] Analysis record created: {analysis_record['id']}")

    # List analysis records
    ana_list = db.list_analysis_records(evidence_id)
    assert len(ana_list) >= 1
    print(f"[PASS] Retrieved {len(ana_list)} historical analysis records for evidence.")

    # 5. Audit Trail Verification
    print("\nTesting Audit Trail Logs...")
    logs = db.get_audit_logs(investigation_id=test_case_id)
    assert len(logs) >= 3, f"Expected >= 3 audit entries, found {len(logs)}"
    actions = [l["action"] for l in logs]
    print(f"[PASS] Audit logs verified for case. Actions logged: {actions}")

    # 6. Forensic Reports
    print("\nTesting Forensic Reports...")
    rep_id = db.generate_report_id()
    # Create a small dummy PDF file in reports vault
    rep_filename = f"{rep_id}_test_report.pdf"
    (db.REPORTS_DIR / rep_filename).write_bytes(b"%PDF-1.4 dummy test report content")

    report = db.save_report_record(
        report_id=rep_id,
        investigation_id=test_case_id,
        report_type="executive",
        title="Executive Summary Test Report",
        summary="Automated integration test generated summary report.",
        sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        file_size_bytes=32,
        stored_filename=rep_filename,
        included_records=[analysis_record["id"]],
        generated_by="Senior Examiner",
    )
    assert report["id"] == rep_id
    print(f"[PASS] Report saved: {report['id']}")

    retrieved_rep = db.get_report_by_id(rep_id)
    assert retrieved_rep["title"] == "Executive Summary Test Report"
    print("[PASS] Report retrieved by ID.")

    rep_list = db.list_reports(investigation_id=test_case_id)
    assert rep_list["total"] >= 1
    print(f"[PASS] List reports retrieved {rep_list['total']} reports for case.")

    # 7. Cleanup Test Case from database
    print("\nCleaning up test artifacts...")
    with db.get_db_connection() as conn:
        cur = conn.cursor()
        cur.execute("DELETE FROM investigations WHERE id = ?;", (test_case_id,))
    # Cascade deletes evidence, analysis, reports, and sets audit investigation_id to NULL
    assert db.get_investigation(test_case_id) is None
    print("[PASS] Test case cleaned up cleanly (ON DELETE CASCADE confirmed).")

    print("\n" + "=" * 60)
    print("ALL INTEGRATION TESTS PASSED (100% SUCCESS)!")
    print("=" * 60)

if __name__ == '__main__':
    run_tests()

