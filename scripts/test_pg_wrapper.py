import os
import time
import psycopg2
import psycopg2.extras
import psycopg2.pool
from dotenv import load_dotenv

load_dotenv('backend/.env')
db_url = os.getenv('SUPABASE_DB_URL')

class PgCursorWrapper:
    def __init__(self, raw_cursor):
        self._cur = raw_cursor

    def execute(self, query, params=None):
        pg_query = query.replace("?", "%s")
        if params is not None:
            return self._cur.execute(pg_query, params)
        return self._cur.execute(pg_query)

    def executemany(self, query, seq_of_parameters):
        pg_query = query.replace("?", "%s")
        return self._cur.executemany(pg_query, seq_of_parameters)

    def fetchone(self):
        return self._cur.fetchone()

    def fetchall(self):
        return self._cur.fetchall()

    def fetchmany(self, size=None):
        return self._cur.fetchmany(size) if size else self._cur.fetchmany()

    @property
    def rowcount(self):
        return self._cur.rowcount

    def __getattr__(self, name):
        return getattr(self._cur, name)

pool = psycopg2.pool.ThreadedConnectionPool(1, 5, db_url)
raw_conn = pool.getconn()
cur = PgCursorWrapper(raw_conn.cursor(cursor_factory=psycopg2.extras.DictCursor))

# Test query with ? placeholder
cur.execute("SELECT * FROM investigations WHERE status = ? LIMIT 1;", ("active",))
row = cur.fetchone()
if row:
    print("Found row via wrapper:", row["id"], dict(row)["title"])
else:
    print("No active investigations found, wrapper ran OK.")

# Test subquery with alias
query = "SELECT i.* FROM investigations i WHERE 1=1 AND i.status = ?"
count_query = f"SELECT COUNT(*) as total FROM ({query}) AS _count_sub"
cur.execute(count_query, ["active"])
total = cur.fetchone()["total"]
print("Total matching investigations:", total)

pool.putconn(raw_conn)
print("Pool putconn OK.")

