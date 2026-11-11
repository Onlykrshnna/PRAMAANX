import sqlite3
import shutil
import os
import datetime

db_path = 'backend/data/pramaanx.db'
if os.path.exists(db_path):
    ts = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    backup_path = f'backend/data/pramaanx_backup_{ts}.db'
    shutil.copy2(db_path, backup_path)
    print(f'BACKUP_CREATED: {backup_path}')

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = [row[0] for row in cursor.fetchall() if not row[0].startswith('sqlite_')]
    print('SQLite Tables found:')
    for t in tables:
        cursor.execute(f"SELECT COUNT(*) FROM {t}")
        cnt = cursor.fetchone()[0]
        print(f" - {t}: {cnt} rows")
    conn.close()
else:
    print(f'No existing sqlite db found at {db_path}')

