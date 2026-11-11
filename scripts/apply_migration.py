import os
import sys
import psycopg2
from dotenv import load_dotenv

env_path = os.path.join(os.path.dirname(__file__), '..', 'backend', '.env')
load_dotenv(dotenv_path=env_path)

db_url = os.getenv('SUPABASE_DB_URL')
if not db_url:
    print("ERROR: SUPABASE_DB_URL missing in backend/.env")
    sys.exit(1)

migration_file = os.path.join(os.path.dirname(__file__), '..', 'backend', 'migrations', '001_initial_supabase_schema.sql')

with open(migration_file, 'r', encoding='utf-8') as f:
    sql = f.read()

print("Applying migration to Supabase PostgreSQL...")
try:
    conn = psycopg2.connect(db_url, connect_timeout=10)
    conn.autocommit = True
    cursor = conn.cursor()
    cursor.execute(sql)
    print("MIGRATION APPLIED SUCCESSFULLY!")

    # Verify tables
    cursor.execute("""
        SELECT table_name 
        FROM information_schema.tables 
        WHERE table_schema = 'public' 
        ORDER BY table_name;
    """)
    tables = [row[0] for row in cursor.fetchall()]
    print(f"Verified tables in public schema ({len(tables)}):")
    for t in tables:
        cursor.execute(f"SELECT COUNT(*) FROM {t}")
        cnt = cursor.fetchone()[0]
        print(f" - {t}: {cnt} rows")

    conn.close()
except Exception as e:
    print(f"ERROR: Migration failed: {e}")
    sys.exit(1)

