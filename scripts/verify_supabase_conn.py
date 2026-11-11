import os
import sys
import psycopg2
from dotenv import load_dotenv

# Load backend/.env
env_path = os.path.join(os.path.dirname(__file__), '..', 'backend', '.env')
load_dotenv(dotenv_path=env_path)

db_url = os.getenv('SUPABASE_DB_URL')
supabase_url = os.getenv('SUPABASE_URL')
secret_key = os.getenv('SUPABASE_SECRET_KEY')

print(f"SUPABASE_URL present: {bool(supabase_url)}")
print(f"SUPABASE_SECRET_KEY present: {bool(secret_key)}")
print(f"SUPABASE_DB_URL present: {bool(db_url)}")

if not db_url:
    print("ERROR: SUPABASE_DB_URL is missing!")
    sys.exit(1)

try:
    # Connect with timeout
    conn = psycopg2.connect(db_url, connect_timeout=10)
    cursor = conn.cursor()

    # PostgreSQL Version
    cursor.execute("SELECT version();")
    pg_version = cursor.fetchone()[0]
    print(f"SUCCESS: Connected to PostgreSQL.")
    print(f"Version: {pg_version.split(',')[0]}")

    # Current database and user
    cursor.execute("SELECT current_database(), current_user;")
    db_name, db_user = cursor.fetchone()
    print(f"Database: {db_name}, Current User: {db_user}")

    # Installed extensions
    cursor.execute("SELECT extname, extversion FROM pg_extension ORDER BY extname;")
    extensions = cursor.fetchall()
    print("Installed Extensions:")
    for ext, ver in extensions:
        print(f" - {ext} ({ver})")

    # Existing tables in public schema
    cursor.execute("""
        SELECT table_name 
        FROM information_schema.tables 
        WHERE table_schema = 'public' 
        ORDER BY table_name;
    """)
    tables = cursor.fetchall()
    print("Existing tables in public schema:")
    if tables:
        for t in tables:
            print(f" - {t[0]}")
    else:
        print(" (No tables found in public schema)")

    conn.close()
except Exception as e:
    print(f"ERROR: PostgreSQL connection failed: {type(e).__name__}: {e}")
    sys.exit(1)

