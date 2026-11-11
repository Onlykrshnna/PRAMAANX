"""
PRAMAANX - Persistence & Forensic Evidence Vault Database (Milestone D)
=======================================================================
Provides a reliable local-first SQLite relational persistence layer for:
- Investigation (Case) lifecycle management (create, search, filter, reopen, archive)
- Immutable evidence item registry and physical vault storage
- Historic analysis examination records (never overwriting prior results)
- Cryptographic hash re-verification and tamper detection
- Auditable forensic activity logging

Security Guarantees:
--------------------
1. Zero Silent Overwrite: Every ingestion or analysis run creates a distinct,
   traceable record.
2. Read-Only Protection: Evidence binaries in the vault are marked read-only on disk
   to prevent accidental modification.
3. Path Traversal Defense: Filenames are sanitized and storage paths are strictly
   contained within configured vault directories.
4. Auditable Activity: Key events (case creation, ingestion, analysis, hash verification)
   are committed to the immutable audit trail.
"""

from contextlib import contextmanager
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
from typing import Any, Dict, Generator, List, Optional, Tuple, Union
import uuid

from backend.config import (
    ARTIFACTS_DIR,
    DB_PATH,
    EVIDENCE_DIR,
    REPORTS_DIR,
    VAULT_DIR,
)
from backend.analyzers.common import compute_sha256, detect_magic_bytes


def _get_utc_now() -> str:
    """Returns current UTC timestamp in ISO 8601 format."""
    return datetime.now(timezone.utc).isoformat()


@contextmanager
def get_db_connection() -> Generator[sqlite3.Connection, None, None]:
    """
    Context manager yielding a thread-safe SQLite connection with WAL mode,
    foreign key enforcement, and dictionary row access.
    """
    conn = sqlite3.connect(str(DB_PATH), timeout=30.0)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db() -> None:
    """
    Initializes database schema and indexes if they do not exist.
    Safe to invoke repeatedly (idempotent).
    """
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    with get_db_connection() as conn:
        cursor = conn.cursor()

        # 1. Investigations Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS investigations (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT DEFAULT '',
                status TEXT NOT NULL DEFAULT 'open',
                investigator TEXT DEFAULT 'Analyst',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                tags TEXT DEFAULT '[]'
            );
        """)

        # 2. Evidence Items Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS evidence_items (
                id TEXT PRIMARY KEY,
                investigation_id TEXT NOT NULL,
                original_filename TEXT NOT NULL,
                file_size_bytes INTEGER NOT NULL,
                sha256 TEXT NOT NULL,
                detected_mime TEXT NOT NULL,
                detected_ext TEXT NOT NULL,
                stored_filename TEXT NOT NULL,
                acquired_at TEXT NOT NULL,
                integrity_status TEXT DEFAULT 'verified',
                last_verified_at TEXT,
                FOREIGN KEY (investigation_id) REFERENCES investigations(id) ON DELETE CASCADE
            );
        """)

        # 3. Analysis Records Table (Historical examinations)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS analysis_records (
                id TEXT PRIMARY KEY,
                investigation_id TEXT NOT NULL,
                evidence_id TEXT NOT NULL,
                analyzed_at TEXT NOT NULL,
                analyzer_version TEXT NOT NULL DEFAULT '2.0.0',
                risk_score INTEGER NOT NULL,
                risk_category TEXT NOT NULL,
                entropy REAL NOT NULL,
                findings_json TEXT NOT NULL,
                metadata_timeline_json TEXT NOT NULL DEFAULT '[]',
                visual_evidence_json TEXT NOT NULL DEFAULT '{}',
                plain_summary TEXT DEFAULT '',
                FOREIGN KEY (investigation_id) REFERENCES investigations(id) ON DELETE CASCADE,
                FOREIGN KEY (evidence_id) REFERENCES evidence_items(id) ON DELETE CASCADE
            );
        """)

        # 4. Audit Trail Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                investigation_id TEXT,
                evidence_id TEXT,
                action TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                actor TEXT DEFAULT 'Analyst',
                details_json TEXT DEFAULT '{}',
                FOREIGN KEY (investigation_id) REFERENCES investigations(id) ON DELETE SET NULL,
                FOREIGN KEY (evidence_id) REFERENCES evidence_items(id) ON DELETE SET NULL
            );
        """)

        # 5. Forensic Reports Table (Milestone E)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS reports (
                id TEXT PRIMARY KEY,
                investigation_id TEXT NOT NULL,
                report_type TEXT NOT NULL,
                title TEXT NOT NULL,
                summary TEXT DEFAULT '',
                sha256 TEXT NOT NULL,
                file_size_bytes INTEGER NOT NULL,
                stored_filename TEXT NOT NULL,
                included_records_json TEXT NOT NULL DEFAULT '[]',
                generated_by TEXT DEFAULT 'Forensic Analyst',
                created_at TEXT NOT NULL,
                FOREIGN KEY (investigation_id) REFERENCES investigations(id) ON DELETE CASCADE
            );
        """)

        # Indexes for fast search and relations
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_investigations_status ON investigations(status);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_investigations_created ON investigations(created_at);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_evidence_investigation ON evidence_items(investigation_id);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_evidence_sha256 ON evidence_items(sha256);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_analysis_evidence ON analysis_records(evidence_id);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_analysis_investigation ON analysis_records(investigation_id);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_investigation ON audit_logs(investigation_id);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_reports_investigation ON reports(investigation_id);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_reports_created ON reports(created_at);")


# ==============================================================================
# Investigation Management
# ==============================================================================

def generate_case_id() -> str:
    """Generates a sequential human-readable case identifier e.g. CAS-2026-0001."""
    year = datetime.now(timezone.utc).year
    prefix = f"CAS-{year}-"
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id FROM investigations WHERE id LIKE ? ORDER BY id DESC LIMIT 1;",
            (f"{prefix}%",),
        )
        row = cursor.fetchone()
        if row and row["id"]:
            try:
                last_num = int(row["id"].split("-")[-1])
                return f"{prefix}{last_num + 1:04d}"
            except (ValueError, IndexError):
                pass
        return f"{prefix}0001"


def create_investigation(
    title: str,
    description: str = "",
    investigator: str = "Analyst",
    tags: Optional[List[str]] = None,
    case_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Creates a new investigation record and writes initial audit log."""
    now = _get_utc_now()
    cid = case_id if case_id else generate_case_id()
    tags_json = json.dumps(tags or [])

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO investigations (id, title, description, status, investigator, created_at, updated_at, tags)
            VALUES (?, ?, ?, 'open', ?, ?, ?, ?);
            """,
            (cid, title.strip(), description.strip(), investigator.strip(), now, now, tags_json),
        )

        cursor.execute(
            """
            INSERT INTO audit_logs (investigation_id, evidence_id, action, timestamp, actor, details_json)
            VALUES (?, NULL, 'CASE_CREATED', ?, ?, ?);
            """,
            (cid, now, investigator.strip(), json.dumps({"title": title, "tags": tags or []})),
        )

    return get_investigation(cid)  # type: ignore


def get_investigation(case_id: str) -> Optional[Dict[str, Any]]:
    """Retrieves an investigation record with computed aggregates."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM investigations WHERE id = ?;", (case_id,))
        row = cursor.fetchone()
        if not row:
            return None

        case_dict = dict(row)
        case_dict["tags"] = json.loads(case_dict["tags"] or "[]")

        # Aggregate evidence item count
        cursor.execute("SELECT COUNT(*) AS cnt FROM evidence_items WHERE investigation_id = ?;", (case_id,))
        case_dict["evidence_count"] = cursor.fetchone()["cnt"]

        # Aggregate highest risk score from analysis records
        cursor.execute(
            """
            SELECT MAX(risk_score) AS max_risk, COUNT(*) AS analysis_count
            FROM analysis_records WHERE investigation_id = ?;
            """,
            (case_id,),
        )
        agg = cursor.fetchone()
        case_dict["highest_risk_score"] = agg["max_risk"] if agg["max_risk"] is not None else 0
        case_dict["total_analyses"] = agg["analysis_count"]

        return case_dict


def list_investigations(
    status_filter: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
) -> Tuple[List[Dict[str, Any]], int]:
    """Lists investigations with optional status and text search filtering."""
    query = """
        SELECT i.*,
               (SELECT COUNT(*) FROM evidence_items e WHERE e.investigation_id = i.id) AS evidence_count,
               (SELECT MAX(a.risk_score) FROM analysis_records a WHERE a.investigation_id = i.id) AS highest_risk_score,
               (SELECT COUNT(*) FROM analysis_records a WHERE a.investigation_id = i.id) AS total_analyses
        FROM investigations i
        WHERE 1=1
    """
    params: List[Any] = []

    if status_filter and isinstance(status_filter, str) and status_filter.upper() != "ALL":
        query += " AND i.status = ?"
        params.append(status_filter.lower())

    if search and isinstance(search, str) and search.strip():
        term = f"%{search.strip().lower()}%"
        query += " AND (LOWER(i.id) LIKE ? OR LOWER(i.title) LIKE ? OR LOWER(i.description) LIKE ? OR LOWER(i.investigator) LIKE ?)"
        params.extend([term, term, term, term])

    count_query = f"SELECT COUNT(*) as total FROM ({query})"

    safe_limit = limit if isinstance(limit, int) else 50
    safe_offset = offset if isinstance(offset, int) else 0

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(count_query, params)
        total = cursor.fetchone()["total"]

        query += " ORDER BY i.created_at DESC LIMIT ? OFFSET ?;"
        params.extend([safe_limit, safe_offset])

        cursor.execute(query, params)
        rows = cursor.fetchall()
        results = []
        for r in rows:
            d = dict(r)
            d["tags"] = json.loads(d["tags"] or "[]")
            d["highest_risk_score"] = d["highest_risk_score"] if d["highest_risk_score"] is not None else 0
            results.append(d)

        return results, total


def update_investigation(
    case_id: str,
    title: Optional[str] = None,
    description: Optional[str] = None,
    status: Optional[str] = None,
    investigator: Optional[str] = None,
    tags: Optional[List[str]] = None,
    actor: str = "Analyst",
) -> Optional[Dict[str, Any]]:
    """Updates mutable fields on an investigation and records audit log."""
    existing = get_investigation(case_id)
    if not existing:
        return None

    now = _get_utc_now()
    updates = []
    params: List[Any] = []
    audit_changes: Dict[str, Any] = {}

    if title is not None and title.strip():
        updates.append("title = ?")
        params.append(title.strip())
        audit_changes["title"] = title.strip()

    if description is not None:
        updates.append("description = ?")
        params.append(description.strip())
        audit_changes["description"] = description.strip()

    if status is not None and status.lower() in ("open", "in_progress", "closed", "archived"):
        updates.append("status = ?")
        params.append(status.lower())
        audit_changes["status_transition"] = f"{existing['status']} -> {status.lower()}"

    if investigator is not None and investigator.strip():
        updates.append("investigator = ?")
        params.append(investigator.strip())
        audit_changes["investigator"] = investigator.strip()

    if tags is not None:
        updates.append("tags = ?")
        params.append(json.dumps(tags))
        audit_changes["tags"] = tags

    if not updates:
        return existing

    updates.append("updated_at = ?")
    params.append(now)
    params.append(case_id)

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(f"UPDATE investigations SET {', '.join(updates)} WHERE id = ?;", params)

        action = "CASE_STATUS_CHANGED" if "status_transition" in audit_changes else "CASE_UPDATED"
        cursor.execute(
            """
            INSERT INTO audit_logs (investigation_id, evidence_id, action, timestamp, actor, details_json)
            VALUES (?, NULL, ?, ?, ?, ?);
            """,
            (case_id, action, now, actor, json.dumps(audit_changes)),
        )

    return get_investigation(case_id)


# ==============================================================================
# Evidence Ingestion & Vault Storage
# ==============================================================================

def sanitize_filename(filename: str) -> str:
    """Sanitizes filename against path traversal characters."""
    clean = Path(filename).name
    clean = re.sub(r"[^\w\.\-\_]", "_", clean)
    return clean or "unnamed_evidence.bin"


def store_evidence_file(
    investigation_id: str,
    original_filename: str,
    file_bytes: bytes,
    actor: str = "Analyst",
) -> Dict[str, Any]:
    """
    Ingests an evidence binary into the evidence vault directory.
    
    Security:
    - Verifies parent case exists.
    - Writes file atomically into `EVIDENCE_DIR`.
    - Generates immutable SHA-256 hash.
    - Strips write permissions where supported (read-only protection).
    - Records audit log entry.
    """
    case = get_investigation(investigation_id)
    if not case:
        raise ValueError(f"Investigation '{investigation_id}' does not exist.")

    evidence_id = str(uuid.uuid4())
    safe_name = sanitize_filename(original_filename)
    stored_filename = f"{evidence_id}_{safe_name}"
    stored_path = EVIDENCE_DIR / stored_filename

    # Write file to vault
    stored_path.write_bytes(file_bytes)

    # Protect file integrity: strip write permission (make read-only)
    try:
        os.chmod(stored_path, 0o444)
    except Exception:
        pass

    file_size = len(file_bytes)
    sha256_hash = compute_sha256(file_bytes)
    magic = detect_magic_bytes(file_bytes)
    now = _get_utc_now()

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO evidence_items (
                id, investigation_id, original_filename, file_size_bytes, sha256,
                detected_mime, detected_ext, stored_filename, acquired_at,
                integrity_status, last_verified_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'verified', ?);
            """,
            (
                evidence_id,
                investigation_id,
                original_filename,
                file_size,
                sha256_hash,
                magic.detected_mime,
                magic.detected_ext,
                stored_filename,
                now,
                now,
            ),
        )

        cursor.execute(
            """
            INSERT INTO audit_logs (investigation_id, evidence_id, action, timestamp, actor, details_json)
            VALUES (?, ?, 'EVIDENCE_INGESTED', ?, ?, ?);
            """,
            (
                investigation_id,
                evidence_id,
                now,
                actor,
                json.dumps({
                    "original_filename": original_filename,
                    "sha256": sha256_hash,
                    "size_bytes": file_size,
                    "detected_mime": magic.detected_mime,
                }),
            ),
        )

    return get_evidence_item(evidence_id)  # type: ignore


def get_evidence_item(evidence_id: str) -> Optional[Dict[str, Any]]:
    """Retrieves an evidence item record."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM evidence_items WHERE id = ?;", (evidence_id,))
        row = cursor.fetchone()
        if not row:
            return None
        d = dict(row)
        stored_path = EVIDENCE_DIR / d["stored_filename"]
        d["file_exists_on_disk"] = stored_path.is_file()
        return d


def get_evidence_file_path(evidence_id: str) -> Path:
    """Returns safe filesystem path to stored evidence item, preventing path traversal."""
    item = get_evidence_item(evidence_id)
    if not item:
        raise FileNotFoundError(f"Evidence record '{evidence_id}' not found.")
    
    safe_path = (EVIDENCE_DIR / item["stored_filename"]).resolve()
    # Confirm path stays strictly inside EVIDENCE_DIR
    if not str(safe_path).startswith(str(EVIDENCE_DIR.resolve())):
        raise PermissionError("Path traversal violation attempting to escape evidence vault.")

    if not safe_path.is_file():
        raise FileNotFoundError(f"Evidence file for record '{evidence_id}' is missing from vault.")

    return safe_path


def list_evidence_items(
    investigation_id: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
) -> Tuple[List[Dict[str, Any]], int]:
    """Lists evidence items across investigations or within a single investigation."""
    query = """
        SELECT e.*, i.title AS investigation_title, i.status AS investigation_status,
               (SELECT COUNT(*) FROM analysis_records a WHERE a.evidence_id = e.id) AS analysis_count,
               (SELECT MAX(a.risk_score) FROM analysis_records a WHERE a.evidence_id = e.id) AS latest_risk_score,
               (SELECT a.risk_category FROM analysis_records a WHERE a.evidence_id = e.id ORDER BY a.analyzed_at DESC LIMIT 1) AS latest_risk_category
        FROM evidence_items e
        JOIN investigations i ON e.investigation_id = i.id
        WHERE 1=1
    """
    params: List[Any] = []

    if investigation_id and isinstance(investigation_id, str):
        query += " AND e.investigation_id = ?"
        params.append(investigation_id)

    if search and isinstance(search, str) and search.strip():
        term = f"%{search.strip().lower()}%"
        query += " AND (LOWER(e.original_filename) LIKE ? OR LOWER(e.sha256) LIKE ? OR LOWER(e.id) LIKE ? OR LOWER(i.title) LIKE ?)"
        params.extend([term, term, term, term])

    count_query = f"SELECT COUNT(*) as total FROM ({query})"

    safe_limit = limit if isinstance(limit, int) else 50
    safe_offset = offset if isinstance(offset, int) else 0

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(count_query, params)
        total = cursor.fetchone()["total"]

        query += " ORDER BY e.acquired_at DESC LIMIT ? OFFSET ?;"
        params.extend([safe_limit, safe_offset])

        cursor.execute(query, params)
        rows = cursor.fetchall()
        results = [dict(r) for r in rows]
        return results, total


def verify_evidence_integrity(evidence_id: str, actor: str = "Analyst") -> Dict[str, Any]:
    """
    Recalculates cryptographic SHA-256 hash of the stored evidence binary on disk
    and verifies it against the acquisition baseline.
    
    Detects unauthorized modification, byte alteration, or file loss.
    Records audit entry with verification outcome.
    """
    item = get_evidence_item(evidence_id)
    if not item:
        raise FileNotFoundError(f"Evidence record '{evidence_id}' not found.")

    stored_path = EVIDENCE_DIR / item["stored_filename"]
    now = _get_utc_now()

    if not stored_path.is_file():
        status_result = "missing"
        details = {
            "error": "File missing from disk vault storage",
            "expected_sha256": item["sha256"],
        }
        action = "INTEGRITY_FILE_MISSING"
    else:
        current_hash = compute_sha256(stored_path)
        if current_hash.lower() == item["sha256"].lower():
            status_result = "verified"
            details = {
                "verified_hash": current_hash,
                "baseline_hash": item["sha256"],
                "status": "Match verified. Evidence integrity intact.",
            }
            action = "INTEGRITY_VERIFIED"
        else:
            status_result = "tampered"
            details = {
                "computed_hash": current_hash,
                "baseline_hash": item["sha256"],
                "warning": "CRITICAL: Stored evidence bytes have been altered since acquisition!",
            }
            action = "INTEGRITY_TAMPER_DETECTED"

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE evidence_items
            SET integrity_status = ?, last_verified_at = ?
            WHERE id = ?;
            """,
            (status_result, now, evidence_id),
        )

        cursor.execute(
            """
            INSERT INTO audit_logs (investigation_id, evidence_id, action, timestamp, actor, details_json)
            VALUES (?, ?, ?, ?, ?, ?);
            """,
            (item["investigation_id"], evidence_id, action, now, actor, json.dumps(details)),
        )

    return {
        "evidence_id": evidence_id,
        "filename": item["original_filename"],
        "integrity_status": status_result,
        "is_intact": status_result == "verified",
        "last_verified_at": now,
        "details": details,
    }


# ==============================================================================
# Historical Analysis Records (Immutable Examination Registry)
# ==============================================================================

def create_analysis_record(
    investigation_id: str,
    evidence_id: str,
    analysis_data: Dict[str, Any],
    analyzer_version: str = "2.0.0",
    actor: str = "Analyst",
) -> Dict[str, Any]:
    """
    Saves an immutable examination record for an evidence item.
    Never overwrites previous analyses; creates a new chronological entry.
    Decouples visual artifacts (Grad-CAM, ELA) into the persistent vault.
    """
    analysis_id = str(uuid.uuid4())
    now = _get_utc_now()

    findings = analysis_data.get("findings", [])
    findings_json = json.dumps([f if isinstance(f, dict) else f.model_dump() for f in findings])
    metadata_timeline = json.dumps(analysis_data.get("metadata_timeline", []))
    visual_evidence = analysis_data.get("visual_evidence", {})

    # Move visual evidence artifacts into ARTIFACTS_DIR if present
    persistent_visuals = {}
    for key, path_str in visual_evidence.items():
        if path_str and Path(path_str).is_file():
            src = Path(path_str)
            dest_name = f"{analysis_id}_{src.name}"
            dest = ARTIFACTS_DIR / dest_name
            shutil.copyfile(src, dest)
            persistent_visuals[key] = f"/api/v1/evidence/{key}/{dest_name}"
        elif isinstance(path_str, str) and path_str.startswith("/api/v1/"):
            persistent_visuals[key] = path_str

    visual_json = json.dumps(persistent_visuals)

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO analysis_records (
                id, investigation_id, evidence_id, analyzed_at, analyzer_version,
                risk_score, risk_category, entropy, findings_json, metadata_timeline_json,
                visual_evidence_json, plain_summary
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """,
            (
                analysis_id,
                investigation_id,
                evidence_id,
                now,
                analyzer_version,
                int(analysis_data.get("risk_score", 0)),
                str(analysis_data.get("risk_band") or analysis_data.get("risk_category") or "Low"),
                float(analysis_data.get("entropy", 0.0)),
                findings_json,
                metadata_timeline,
                visual_json,
                str(analysis_data.get("plain_summary", "")),
            ),
        )

        cursor.execute(
            """
            INSERT INTO audit_logs (investigation_id, evidence_id, action, timestamp, actor, details_json)
            VALUES (?, ?, 'ANALYSIS_EXECUTED', ?, ?, ?);
            """,
            (
                investigation_id,
                evidence_id,
                now,
                actor,
                json.dumps({
                    "analysis_id": analysis_id,
                    "risk_score": analysis_data.get("risk_score", 0),
                    "risk_category": str(analysis_data.get("risk_band") or "Low"),
                    "finding_count": len(findings),
                }),
            ),
        )

    return get_analysis_record(analysis_id)  # type: ignore


def get_analysis_record(analysis_id: str) -> Optional[Dict[str, Any]]:
    """Retrieves a historical analysis record."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT a.*, e.original_filename, e.sha256, e.detected_mime, e.file_size_bytes, i.title AS investigation_title
            FROM analysis_records a
            JOIN evidence_items e ON a.evidence_id = e.id
            JOIN investigations i ON a.investigation_id = i.id
            WHERE a.id = ?;
            """,
            (analysis_id,),
        )
        row = cursor.fetchone()
        if not row:
            return None

        d = dict(row)
        d["findings"] = json.loads(d["findings_json"] or "[]")
        d["metadata_timeline"] = json.loads(d["metadata_timeline_json"] or "[]")
        d["visual_evidence"] = json.loads(d["visual_evidence_json"] or "{}")
        return d


def list_analysis_records(evidence_id: str) -> List[Dict[str, Any]]:
    """Lists all historical examination records for a given evidence item."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT * FROM analysis_records
            WHERE evidence_id = ?
            ORDER BY analyzed_at DESC;
            """,
            (evidence_id,),
        )
        rows = cursor.fetchall()
        results = []
        for r in rows:
            d = dict(r)
            d["findings"] = json.loads(d["findings_json"] or "[]")
            d["metadata_timeline"] = json.loads(d["metadata_timeline_json"] or "[]")
            d["visual_evidence"] = json.loads(d["visual_evidence_json"] or "{}")
            results.append(d)
        return results


# ==============================================================================
# Audit Trail Queries
# ==============================================================================

def get_audit_logs(
    investigation_id: Optional[str] = None,
    evidence_id: Optional[str] = None,
    limit: int = 50,
) -> List[Dict[str, Any]]:
    """Retrieves immutable audit logs for case or evidence."""
    query = "SELECT * FROM audit_logs WHERE 1=1"
    params: List[Any] = []

    if investigation_id:
        query += " AND investigation_id = ?"
        params.append(investigation_id)

    if evidence_id:
        query += " AND evidence_id = ?"
        params.append(evidence_id)

    query += " ORDER BY timestamp DESC LIMIT ?;"
    params.append(limit)

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(query, params)
        rows = cursor.fetchall()
        results = []
        for r in rows:
            d = dict(r)
            d["details"] = json.loads(d["details_json"] or "{}")
            results.append(d)
        return results


# ==============================================================================
# Forensic Reports Persistence (Milestone E)
# ==============================================================================

def generate_report_id() -> str:
    """Generates a sequential human-readable report identifier e.g. REP-2026-0001."""
    year = datetime.now(timezone.utc).year
    prefix = f"REP-{year}-"
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id FROM reports WHERE id LIKE ? ORDER BY id DESC LIMIT 1;",
            (f"{prefix}%",),
        )
        row = cursor.fetchone()
        if row and row["id"]:
            try:
                last_num = int(row["id"].split("-")[-1])
                return f"{prefix}{last_num + 1:04d}"
            except (ValueError, IndexError):
                pass
        return f"{prefix}0001"


def save_report_record(
    report_id: str,
    investigation_id: str,
    report_type: str,
    title: str,
    summary: str,
    sha256_hash: str,
    file_size_bytes: int,
    stored_filename: str,
    included_records: List[str],
    generated_by: str = "Forensic Analyst",
) -> Dict[str, Any]:
    """
    Persists report metadata and writes an immutable audit log entry.
    """
    now = _get_utc_now()
    records_json = json.dumps(included_records or [])

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO reports (
                id, investigation_id, report_type, title, summary,
                sha256, file_size_bytes, stored_filename, included_records_json,
                generated_by, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """,
            (
                report_id,
                investigation_id,
                report_type,
                title.strip(),
                summary.strip(),
                sha256_hash,
                file_size_bytes,
                stored_filename,
                records_json,
                generated_by.strip(),
                now,
            ),
        )

        # Record audit log
        cursor.execute(
            """
            INSERT INTO audit_logs (investigation_id, evidence_id, action, timestamp, actor, details_json)
            VALUES (?, NULL, 'report_generated', ?, ?, ?);
            """,
            (
                investigation_id,
                now,
                generated_by.strip(),
                json.dumps({
                    "report_id": report_id,
                    "report_type": report_type,
                    "sha256": sha256_hash,
                    "records_count": len(included_records or []),
                }),
            ),
        )

    return get_report_by_id(report_id) or {}


def get_report_by_id(report_id: str) -> Optional[Dict[str, Any]]:
    """Retrieves report metadata by report ID."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT r.*, i.title as investigation_title
            FROM reports r
            JOIN investigations i ON r.investigation_id = i.id
            WHERE r.id = ?;
            """,
            (report_id,),
        )
        row = cursor.fetchone()
        if not row:
            return None
        d = dict(row)
        d["included_records"] = json.loads(d["included_records_json"] or "[]")
        return d


def list_reports(
    investigation_id: Optional[str] = None,
    report_type: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
) -> Dict[str, Any]:
    """Retrieves paginated list of generated reports with total count."""
    clean_limit = limit if isinstance(limit, int) else 50
    clean_offset = offset if isinstance(offset, int) else 0

    base_query = """
        FROM reports r
        JOIN investigations i ON r.investigation_id = i.id
        WHERE 1=1
    """
    params: List[Any] = []

    if investigation_id and isinstance(investigation_id, str) and investigation_id.strip():
        base_query += " AND r.investigation_id = ?"
        params.append(investigation_id.strip())

    if report_type and isinstance(report_type, str) and report_type.strip():
        base_query += " AND r.report_type = ?"
        params.append(report_type.strip().lower())

    count_query = f"SELECT COUNT(*) as count {base_query};"
    data_query = f"""
        SELECT r.*, i.title as investigation_title
        {base_query}
        ORDER BY r.created_at DESC
        LIMIT ? OFFSET ?;
    """

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(count_query, params)
        total = cursor.fetchone()["count"]

        data_params = list(params) + [clean_limit, clean_offset]
        cursor.execute(data_query, data_params)
        rows = cursor.fetchall()
        reports = []
        for r in rows:
            d = dict(r)
            d["included_records"] = json.loads(d["included_records_json"] or "[]")
            reports.append(d)

        return {"reports": reports, "total": total}


def get_report_file_path(report_id: str) -> Path:
    """
    Resolves the physical PDF report file path and validates directory traversal containment.
    Raises FileNotFoundError if file is absent, PermissionError if traversal is attempted.
    """
    rec = get_report_by_id(report_id)
    if not rec:
        raise FileNotFoundError(f"Report '{report_id}' not found in database.")

    stored_filename = rec["stored_filename"]
    # Path traversal check
    if ".." in stored_filename or "/" in stored_filename or "\\" in stored_filename:
        raise PermissionError("Directory traversal detected in stored report filename.")

    file_path = (REPORTS_DIR / stored_filename).resolve()
    base_vault = REPORTS_DIR.resolve()

    if not str(file_path).startswith(str(base_vault)):
        raise PermissionError("Attempted path traversal outside of reports vault.")

    if not file_path.exists():
        raise FileNotFoundError(f"Physical report file does not exist at {file_path}")

    return file_path

