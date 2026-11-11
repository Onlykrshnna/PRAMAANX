"""
PRAMAANX - Persistence & Forensic Evidence Vault Database
=========================================================
Dual-mode enterprise persistence layer supporting:
1. Supabase PostgreSQL (Cloud production & networked deployment)
2. Local SQLite (WAL-mode local development & offline fallback)

Features:
- Thread-safe connection pooling
- Seamless transparent query translation (? to %s for PostgreSQL)
- Immutable evidence item registry and physical vault storage
- Integrated Supabase Storage support for private cloud buckets
- Historic analysis examination records (never overwriting prior results)
- Cryptographic hash re-verification and tamper detection
- Auditable forensic activity logging
- Database health check and diagnostic monitoring
"""

from contextlib import contextmanager
from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path
import re
import shutil
import sqlite3
import time
from typing import Any, Dict, Generator, List, Optional, Tuple, Union
import uuid

from dotenv import load_dotenv

# Load backend environment variables if present
_env_path = Path(__file__).resolve().parent / ".env"
if _env_path.is_file():
    load_dotenv(dotenv_path=_env_path)

from backend.config import (
    ARTIFACTS_DIR,
    DB_PATH,
    EVIDENCE_DIR,
    REPORTS_DIR,
    VAULT_DIR,
)
from backend.analyzers.common import compute_sha256, detect_magic_bytes
from backend.storage import (
    BUCKET_ARTIFACTS,
    BUCKET_EVIDENCE,
    download_from_storage,
    is_supabase_storage_enabled,
    upload_to_storage,
)

logger = logging.getLogger("pramaanx.database")

# Check Supabase Database configuration
SUPABASE_DB_URL = os.getenv("SUPABASE_DB_URL", "").strip()

# PostgreSQL driver imports
_pg_pool = None
_use_postgres = False

if SUPABASE_DB_URL:
    try:
        import psycopg2
        import psycopg2.extras
        import psycopg2.pool

        # Initialize connection pool (1 to 10 connections)
        _pg_pool = psycopg2.pool.ThreadedConnectionPool(
            minconn=1,
            maxconn=10,
            dsn=SUPABASE_DB_URL,
            connect_timeout=10,
        )
        _use_postgres = True
        logger.info("Connected to Supabase PostgreSQL connection pool.")
    except Exception as exc:
        logger.warning(
            f"Failed to connect to Supabase PostgreSQL ({exc}). Falling back to local SQLite."
        )
        _pg_pool = None
        _use_postgres = False


_ORIGINAL_DB_PATH = Path(DB_PATH)

def _should_use_postgres() -> bool:
    """
    Returns True only if Supabase PostgreSQL is configured AND
    DB_PATH has not been redirected/monkeypatched for isolated testing.
    """
    return bool(_use_postgres and _pg_pool and Path(DB_PATH) == _ORIGINAL_DB_PATH)


def _get_utc_now() -> str:
    """Returns current UTC timestamp in ISO 8601 format."""
    return datetime.now(timezone.utc).isoformat()


def _safe_parse_json(val: Any, default: Any) -> Any:
    """Safely handles JSON deserialization for both TEXT (SQLite) and JSONB (PostgreSQL)."""
    if val is None:
        return default
    if isinstance(val, (dict, list)):
        return val
    if isinstance(val, str):
        try:
            return json.loads(val)
        except (json.JSONDecodeError, ValueError):
            return default
    return default


def _format_timestamp(val: Any) -> str:
    """Ensures timestamp is returned as ISO 8601 string across both engines."""
    if val is None:
        return ""
    if hasattr(val, "isoformat"):
        return val.isoformat()
    return str(val)


def get_active_db_engine() -> str:
    """Returns 'postgresql' if connected to Supabase, else 'sqlite'."""
    return "postgresql" if _should_use_postgres() else "sqlite"


class PgCursorWrapper:
    """
    Wraps a psycopg2 cursor to provide uniform parameter syntax (?)
    and dictionary-like row access compatible with sqlite3.Row.
    """

    def __init__(self, raw_cursor):
        self._cur = raw_cursor

    def execute(self, query: str, params: Any = None):
        # Convert SQLite-style ? placeholders to PostgreSQL %s
        pg_query = query.replace("?", "%s")
        if params is not None:
            # Convert list params to tuple if necessary
            if isinstance(params, list):
                params = tuple(params)
            return self._cur.execute(pg_query, params)
        return self._cur.execute(pg_query)

    def executemany(self, query: str, seq_of_parameters):
        pg_query = query.replace("?", "%s")
        return self._cur.executemany(pg_query, seq_of_parameters)

    def fetchone(self):
        return self._cur.fetchone()

    def fetchall(self):
        return self._cur.fetchall()

    def fetchmany(self, size: Optional[int] = None):
        return self._cur.fetchmany(size) if size else self._cur.fetchmany()

    @property
    def rowcount(self):
        return self._cur.rowcount

    @property
    def lastrowid(self):
        return getattr(self._cur, "lastrowid", None)

    def __getattr__(self, name):
        return getattr(self._cur, name)


class PgConnectionWrapper:
    """Wraps a psycopg2 connection to yield PgCursorWrapper and handle pooling."""

    def __init__(self, raw_conn, pool=None):
        self._conn = raw_conn
        self._pool = pool

    def cursor(self):
        import psycopg2.extras
        return PgCursorWrapper(
            self._conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        )

    def commit(self):
        return self._conn.commit()

    def rollback(self):
        return self._conn.rollback()

    def close(self):
        if self._pool:
            try:
                self._pool.putconn(self._conn)
            except Exception:
                pass
        else:
            try:
                self._conn.close()
            except Exception:
                pass

    def execute(self, query: str, params: Any = None):
        cur = self.cursor()
        cur.execute(query, params)
        return cur

    def __getattr__(self, name):
        return getattr(self._conn, name)


@contextmanager
def get_db_connection() -> Generator[Any, None, None]:
    """
    Context manager yielding a thread-safe connection with dictionary-like row access.
    Automatically connects to Supabase PostgreSQL if configured, or falls back to SQLite.
    """
    global _pg_pool, _use_postgres

    if _should_use_postgres():
        raw_conn = None
        try:
            raw_conn = _pg_pool.getconn()
            wrapper = PgConnectionWrapper(raw_conn, pool=_pg_pool)
            yield wrapper
            wrapper.commit()
        except Exception:
            if raw_conn:
                try:
                    raw_conn.rollback()
                except Exception:
                    pass
            raise
        finally:
            if raw_conn and _pg_pool:
                try:
                    _pg_pool.putconn(raw_conn)
                except Exception:
                    pass
    else:
        # SQLite connection
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


def check_db_health() -> Dict[str, Any]:
    """
    Diagnostic probe that verifies database connectivity, measures query latency,
    and returns engine metrics.
    """
    start_time = time.perf_counter()
    engine = get_active_db_engine()

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT 1 AS alive;")
            row = cursor.fetchone()
            latency_ms = (time.perf_counter() - start_time) * 1000.0

            cursor.execute("SELECT COUNT(*) AS cnt FROM investigations;")
            inv_cnt = cursor.fetchone()["cnt"]

            cursor.execute("SELECT COUNT(*) AS cnt FROM evidence_items;")
            evi_cnt = cursor.fetchone()["cnt"]

            return {
                "status": "healthy",
                "engine": engine,
                "latency_ms": round(latency_ms, 2),
                "timestamp": _get_utc_now(),
                "metrics": {
                    "investigations_count": inv_cnt,
                    "evidence_items_count": evi_cnt,
                    "storage_integration": is_supabase_storage_enabled(),
                },
            }
    except Exception as exc:
        latency_ms = (time.perf_counter() - start_time) * 1000.0
        return {
            "status": "unhealthy",
            "engine": engine,
            "latency_ms": round(latency_ms, 2),
            "timestamp": _get_utc_now(),
            "error": str(exc),
        }


def init_db() -> None:
    """
    Initializes database schema and indexes if they do not exist.
    Safe to invoke repeatedly (idempotent).
    """
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    if _should_use_postgres():
        # Schema migration on PostgreSQL is executed explicitly via migration runner
        # or when AUTO_APPLY_MIGRATIONS=true. Do not auto-execute unapproved DDL.
        if os.getenv("AUTO_APPLY_MIGRATIONS", "").lower() in ("true", "1"):
            migration_file = Path(__file__).resolve().parent / "migrations" / "001_initial_supabase_schema.sql"
            if migration_file.is_file():
                sql = migration_file.read_text(encoding="utf-8")
                with get_db_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute(sql)
        return

    # SQLite Schema Initialization
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
                storage_bucket TEXT DEFAULT 'pramaanx_evidence',
                storage_path TEXT,
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

        # 5. Forensic Reports Table
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
                storage_bucket TEXT DEFAULT 'pramaanx_artifacts',
                storage_path TEXT,
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
        case_dict["tags"] = _safe_parse_json(case_dict.get("tags"), [])
        case_dict["created_at"] = _format_timestamp(case_dict.get("created_at"))
        case_dict["updated_at"] = _format_timestamp(case_dict.get("updated_at"))

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

    count_query = f"SELECT COUNT(*) as total FROM ({query}) AS _count_sub"

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
            d["tags"] = _safe_parse_json(d.get("tags"), [])
            d["created_at"] = _format_timestamp(d.get("created_at"))
            d["updated_at"] = _format_timestamp(d.get("updated_at"))
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
    Ingests an evidence binary into the evidence vault directory and optionally Supabase Storage.
    """
    case = get_investigation(investigation_id)
    if not case:
        raise ValueError(f"Investigation '{investigation_id}' does not exist.")

    evidence_id = str(uuid.uuid4())
    safe_name = sanitize_filename(original_filename)
    stored_filename = f"{evidence_id}_{safe_name}"
    stored_path = EVIDENCE_DIR / stored_filename

    # Write file to local disk vault
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

    storage_bucket = BUCKET_EVIDENCE
    storage_path = f"{investigation_id}/{stored_filename}"

    # Upload to Supabase Storage if enabled
    if is_supabase_storage_enabled():
        upload_to_storage(storage_bucket, storage_path, file_bytes, content_type=magic.detected_mime)

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO evidence_items (
                id, investigation_id, original_filename, file_size_bytes, sha256,
                detected_mime, detected_ext, stored_filename, acquired_at,
                integrity_status, last_verified_at, storage_bucket, storage_path
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'verified', ?, ?, ?);
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
                storage_bucket,
                storage_path,
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
                    "storage_path": storage_path,
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
        d["acquired_at"] = _format_timestamp(d.get("acquired_at"))
        if d.get("last_verified_at"):
            d["last_verified_at"] = _format_timestamp(d["last_verified_at"])
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
        # Ephemeral disk recovery: pull from Supabase Storage if available
        if is_supabase_storage_enabled() and item.get("storage_path"):
            bucket = item.get("storage_bucket") or BUCKET_EVIDENCE
            content = download_from_storage(bucket, item["storage_path"])
            if content:
                safe_path.parent.mkdir(parents=True, exist_ok=True)
                safe_path.write_bytes(content)
                return safe_path
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

    count_query = f"SELECT COUNT(*) as total FROM ({query}) AS _count_sub"

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
        results = []
        for r in rows:
            d = dict(r)
            d["acquired_at"] = _format_timestamp(d.get("acquired_at"))
            if d.get("last_verified_at"):
                d["last_verified_at"] = _format_timestamp(d["last_verified_at"])
            results.append(d)
        return results, total


def verify_evidence_integrity(evidence_id: str, actor: str = "Analyst") -> Dict[str, Any]:
    """
    Recalculates cryptographic SHA-256 hash of the stored evidence binary on disk
    and verifies it against the acquisition baseline.
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

            if is_supabase_storage_enabled():
                upload_to_storage(
                    BUCKET_ARTIFACTS,
                    f"{investigation_id}/{dest_name}",
                    dest.read_bytes(),
                    content_type="image/png",
                )
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
        d["findings"] = _safe_parse_json(d.get("findings_json"), [])
        d["metadata_timeline"] = _safe_parse_json(d.get("metadata_timeline_json"), [])
        d["visual_evidence"] = _safe_parse_json(d.get("visual_evidence_json"), {})
        d["analyzed_at"] = _format_timestamp(d.get("analyzed_at"))
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
            d["findings"] = _safe_parse_json(d.get("findings_json"), [])
            d["metadata_timeline"] = _safe_parse_json(d.get("metadata_timeline_json"), [])
            d["visual_evidence"] = _safe_parse_json(d.get("visual_evidence_json"), {})
            d["analyzed_at"] = _format_timestamp(d.get("analyzed_at"))
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
            d["details"] = _safe_parse_json(d.get("details_json"), {})
            d["timestamp"] = _format_timestamp(d.get("timestamp"))
            results.append(d)
        return results


# ==============================================================================
# Forensic Reports Persistence
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
    storage_bucket = BUCKET_ARTIFACTS
    storage_path = f"{investigation_id}/{stored_filename}"

    # Upload report to Supabase Storage if enabled
    if is_supabase_storage_enabled():
        report_file = REPORTS_DIR / stored_filename
        if report_file.is_file():
            upload_to_storage(
                storage_bucket,
                storage_path,
                report_file.read_bytes(),
                content_type="application/pdf",
            )

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO reports (
                id, investigation_id, report_type, title, summary,
                sha256, file_size_bytes, stored_filename, included_records_json,
                generated_by, created_at, storage_bucket, storage_path
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
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
                storage_bucket,
                storage_path,
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
                    "storage_path": storage_path,
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
        d["included_records"] = _safe_parse_json(d.get("included_records_json"), [])
        d["created_at"] = _format_timestamp(d.get("created_at"))
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
            d["included_records"] = _safe_parse_json(d.get("included_records_json"), [])
            d["created_at"] = _format_timestamp(d.get("created_at"))
            reports.append(d)

        return {"reports": reports, "total": total}


def get_report_file_path(report_id: str) -> Path:
    """
    Resolves the physical PDF report file path and validates directory traversal containment.
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
        # Ephemeral disk recovery: pull from Supabase Storage if available
        if is_supabase_storage_enabled() and rec.get("storage_path"):
            bucket = rec.get("storage_bucket") or BUCKET_ARTIFACTS
            content = download_from_storage(bucket, rec["storage_path"])
            if content:
                file_path.parent.mkdir(parents=True, exist_ok=True)
                file_path.write_bytes(content)
                return file_path
        raise FileNotFoundError(f"Physical report file does not exist at {file_path}")

    return file_path
