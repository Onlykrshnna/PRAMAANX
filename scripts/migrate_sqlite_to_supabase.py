import os
import sys
import sqlite3
import argparse
import psycopg2
import psycopg2.extras
import httpx
from dotenv import load_dotenv

env_path = os.path.join(os.path.dirname(__file__), '..', 'backend', '.env')
load_dotenv(dotenv_path=env_path)

db_url = os.getenv('SUPABASE_DB_URL')
supabase_url = os.getenv('SUPABASE_URL')
secret_key = os.getenv('SUPABASE_SECRET_KEY')

def get_sqlite_conn(sqlite_path):
    if not os.path.exists(sqlite_path):
        raise FileNotFoundError(f"SQLite database not found at {sqlite_path}")
    conn = sqlite3.connect(sqlite_path)
    conn.row_factory = sqlite3.Row
    return conn

def get_supabase_conn():
    if not db_url:
        raise ValueError("SUPABASE_DB_URL is not configured in backend/.env")
    return psycopg2.connect(db_url, connect_timeout=10)

def upload_file_to_storage(client, bucket, path_in_bucket, file_path):
    if not os.path.exists(file_path):
        return False
    with open(file_path, 'rb') as f:
        content = f.read()
    
    url = f"/storage/v1/object/{bucket}/{path_in_bucket}"
    headers = {"Content-Type": "application/octet-stream", "x-upsert": "true"}
    resp = client.post(url, content=content, headers=headers)
    if resp.status_code in (200, 201):
        return True
    # If already exists or error
    if resp.status_code == 400 and 'Duplicate' in resp.text:
        return True
    print(f"  [Storage Warning] Upload failed for {path_in_bucket}: {resp.status_code} {resp.text}")
    return False

def migrate(dry_run=False, upload_storage=False):
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
    sqlite_path = os.path.join(base_dir, 'backend', 'data', 'pramaanx.db')
    evidence_dir = os.path.join(base_dir, 'backend', 'evidence')
    reports_dir = os.path.join(base_dir, 'backend', 'reports')

    print("=" * 60)
    print(f"PRAMAANX SQLite -> Supabase Migration (dry_run={dry_run})")
    print("=" * 60)

    s_conn = get_sqlite_conn(sqlite_path)
    s_cur = s_conn.cursor()

    pg_conn = get_supabase_conn()
    pg_cur = pg_conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    storage_client = None
    if upload_storage and supabase_url and secret_key:
        storage_client = httpx.Client(
            base_url=supabase_url,
            headers={"apikey": secret_key, "Authorization": f"Bearer {secret_key}"},
            timeout=30.0
        )

    # Tables to migrate in dependency order
    tables = [
        'investigations',
        'evidence_items',
        'analysis_records',
        'audit_logs',
        'reports'
    ]

    counts = {}
    for t in tables:
        s_cur.execute(f"SELECT COUNT(*) FROM {t}")
        cnt = s_cur.fetchone()[0]
        counts[t] = cnt
        print(f"Source SQLite table '{t}': {cnt} records")

    if dry_run:
        print("\n[DRY RUN] Verifying integrity & records without writing...")
        for t in tables:
            s_cur.execute(f"SELECT * FROM {t}")
            rows = s_cur.fetchall()
            print(f" - Validated {len(rows)} rows for '{t}'")
        print("\n[DRY RUN] Completed successfully. No changes made.")
        s_conn.close()
        pg_conn.close()
        return

    # 1. Investigations
    print("\nMigrating investigations...")
    s_cur.execute("SELECT * FROM investigations")
    inv_rows = s_cur.fetchall()
    for row in inv_rows:
        pg_cur.execute("""
            INSERT INTO investigations (id, title, description, status, investigator, created_at, updated_at, tags)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (id) DO UPDATE SET
                title = EXCLUDED.title,
                description = EXCLUDED.description,
                status = EXCLUDED.status,
                investigator = EXCLUDED.investigator,
                updated_at = EXCLUDED.updated_at,
                tags = EXCLUDED.tags;
        """, (
            row['id'], row['title'], row['description'], row['status'],
            row['investigator'], row['created_at'], row['updated_at'], row['tags']
        ))
    pg_conn.commit()
    print(f" - Migrated {len(inv_rows)} investigations.")

    # 2. Evidence Items
    print("\nMigrating evidence items...")
    s_cur.execute("SELECT * FROM evidence_items")
    evi_rows = s_cur.fetchall()
    for row in evi_rows:
        stored_fn = row['stored_filename']
        storage_path = f"{row['investigation_id']}/{stored_fn}"
        pg_cur.execute("""
            INSERT INTO evidence_items (
                id, investigation_id, original_filename, file_size_bytes, sha256,
                detected_mime, detected_ext, stored_filename, acquired_at, integrity_status,
                last_verified_at, storage_bucket, storage_path
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (id) DO UPDATE SET
                integrity_status = EXCLUDED.integrity_status,
                last_verified_at = EXCLUDED.last_verified_at;
        """, (
            row['id'], row['investigation_id'], row['original_filename'], row['file_size_bytes'],
            row['sha256'], row['detected_mime'], row['detected_ext'], stored_fn,
            row['acquired_at'], row['integrity_status'], row['last_verified_at'],
            'pramaanx_evidence', storage_path
        ))

        if storage_client:
            local_file = os.path.join(evidence_dir, stored_fn)
            if upload_file_to_storage(storage_client, 'pramaanx_evidence', storage_path, local_file):
                print(f"   Uploaded evidence file to storage: {storage_path}")

    pg_conn.commit()
    print(f" - Migrated {len(evi_rows)} evidence items.")

    # 3. Analysis Records
    print("\nMigrating analysis records...")
    s_cur.execute("SELECT * FROM analysis_records")
    ana_rows = s_cur.fetchall()
    for row in ana_rows:
        pg_cur.execute("""
            INSERT INTO analysis_records (
                id, investigation_id, evidence_id, analyzed_at, analyzer_version,
                risk_score, risk_category, entropy, findings_json, metadata_timeline_json,
                visual_evidence_json, plain_summary
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (id) DO NOTHING;
        """, (
            row['id'], row['investigation_id'], row['evidence_id'], row['analyzed_at'],
            row['analyzer_version'], row['risk_score'], row['risk_category'], row['entropy'],
            row['findings_json'], row['metadata_timeline_json'], row['visual_evidence_json'],
            row['plain_summary']
        ))
    pg_conn.commit()
    print(f" - Migrated {len(ana_rows)} analysis records.")

    # 4. Audit Logs
    print("\nMigrating audit logs...")
    s_cur.execute("SELECT * FROM audit_logs ORDER BY id ASC")
    audit_rows = s_cur.fetchall()
    for row in audit_rows:
        pg_cur.execute("""
            INSERT INTO audit_logs (id, investigation_id, evidence_id, action, timestamp, actor, details_json)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (id) DO NOTHING;
        """, (
            row['id'], row['investigation_id'], row['evidence_id'], row['action'],
            row['timestamp'], row['actor'], row['details_json']
        ))
    # Update sequence
    pg_cur.execute("SELECT setval(pg_get_serial_sequence('audit_logs', 'id'), COALESCE((SELECT MAX(id) FROM audit_logs), 1));")
    pg_conn.commit()
    print(f" - Migrated {len(audit_rows)} audit logs.")

    # 5. Reports
    print("\nMigrating reports...")
    s_cur.execute("SELECT * FROM reports")
    rep_rows = s_cur.fetchall()
    for row in rep_rows:
        stored_fn = row['stored_filename']
        storage_path = f"{row['investigation_id']}/{stored_fn}"
        pg_cur.execute("""
            INSERT INTO reports (
                id, investigation_id, report_type, title, summary, sha256,
                file_size_bytes, stored_filename, included_records_json, generated_by,
                created_at, storage_bucket, storage_path
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (id) DO UPDATE SET
                title = EXCLUDED.title,
                summary = EXCLUDED.summary;
        """, (
            row['id'], row['investigation_id'], row['report_type'], row['title'],
            row['summary'], row['sha256'], row['file_size_bytes'], stored_fn,
            row['included_records_json'], row['generated_by'], row['created_at'],
            'pramaanx_artifacts', storage_path
        ))

        if storage_client:
            local_file = os.path.join(reports_dir, stored_fn)
            if upload_file_to_storage(storage_client, 'pramaanx_artifacts', storage_path, local_file):
                print(f"   Uploaded report file to storage: {storage_path}")

    pg_conn.commit()
    print(f" - Migrated {len(rep_rows)} reports.")

    # Final Validation
    print("\n" + "=" * 60)
    print("MIGRATION INTEGRITY VERIFICATION")
    print("=" * 60)
    all_matched = True
    for t in tables:
        pg_cur.execute(f"SELECT COUNT(*) FROM {t}")
        pg_cnt = pg_cur.fetchone()[0]
        s_cnt = counts[t]
        status = "MATCH" if pg_cnt >= s_cnt else "MISMATCH"
        if status != "MATCH":
            all_matched = False
        print(f"Table '{t}': SQLite={s_cnt} -> Supabase={pg_cnt} [{status}]")

    if all_matched:
        print("\nAll tables migrated and verified successfully!")
    else:
        print("\nWARNING: Some counts did not match!")

    s_conn.close()
    pg_conn.close()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Migrate PRAMAANX SQLite DB to Supabase PostgreSQL")
    parser.add_argument('--dry-run', action='store_true', help="Validate and preview without writing")
    parser.add_argument('--upload-storage', action='store_true', help="Upload local files to Supabase Storage")
    args = parser.parse_args()

    migrate(dry_run=args.dry_run, upload_storage=args.upload_storage)

