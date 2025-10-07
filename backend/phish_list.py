import sqlite3
import sys
import requests
from datetime import datetime, timezone
from urllib.parse import urlparse

# ---------------------------
# CONFIG
# ---------------------------

DB_PATH = "phish_urls_simple.db"

SOURCES = [
    "https://github.com/Phishing-Database/Phishing.Database/blob/master/phishing-links-ACTIVE.txt"
]


BATCH_SIZE = 9000

# HTTP timeout for requests
REQUEST_TIMEOUT = 10

# ---------------------------
# DB helpers
# ---------------------------

def init_db(path=DB_PATH):
    conn = sqlite3.connect(path, timeout=60)
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS entries (
            url TEXT PRIMARY KEY,
            source TEXT,
            last_seen TEXT
        );
    """)
    cur.execute("PRAGMA journal_mode=WAL;")
    cur.execute("PRAGMA synchronous=NORMAL;")
    conn.commit()
    return conn

# ---------------------------
# URL helpers
# ---------------------------

def to_raw_github_url(url: str) -> str:
    """
    Convert a GitHub 'blob' URL to raw.githubusercontent.com form.
    If not a GitHub blob URL, returns original.
    """
    if "github.com" not in url:
        return url
    parsed = urlparse(url)
    parts = parsed.path.split("/")
    # minimal validation
    try:
        blob_index = parts.index("blob")
    except ValueError:
        return url  # not a blob link
    owner = parts[1]
    repo = parts[2]
    branch = parts[blob_index + 1]
    path = "/".join(parts[blob_index + 2 :])
    raw = f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{path}"
    return raw

# ---------------------------
# Fetch + store (streaming)
# ---------------------------

def stream_and_store_source(conn, src_url: str, batch_size=BATCH_SIZE):
    src_for_db = src_url  # store source as given (raw version)
    raw_url = to_raw_github_url(src_url)
    if raw_url != src_url:
        src_for_db = raw_url

    print(f"[INFO] Fetching: {raw_url}")
    with requests.get(raw_url, stream=True, timeout=REQUEST_TIMEOUT) as r:
        r.raise_for_status()
        cur = conn.cursor()
        insert_sql = "INSERT OR IGNORE INTO entries(url, source, last_seen) VALUES (?, ?, ?)"
        buffer = []
        count_total = 0
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        for raw_line in r.iter_lines(decode_unicode=True):
            if raw_line is None:
                continue
            line = raw_line.strip()
            if not line:
                continue

            if line.startswith("#") or line.startswith("//"):
                continue

            buffer.append((line, src_for_db, now))
            count_total += 1
            if len(buffer) >= batch_size:
                cur.executemany(insert_sql, buffer)
                conn.commit()
                print(f"[INFO] inserted {count_total} rows so far from this source...", end="\r")
                buffer = []
        if buffer:
            cur.executemany(insert_sql, buffer)
            conn.commit()
        print(f"\n[INFO] Done {count_total} lines from {raw_url}")
        return count_total

def update_all_sources(conn):
    total = 0
    for s in SOURCES:
        try:
            inserted = stream_and_store_source(conn, s)
            total += inserted
        except Exception as e:
            print(f"[WARN] failed to fetch/store from {s}: {e}")
    print(f"[INFO] Total lines processed across sources: {total}")
    return total

# ---------------------------
# Lookup
# ---------------------------

def lookup_url(conn, url: str):
    cur = conn.cursor()
    cur.execute("SELECT url, source, last_seen FROM entries WHERE url = ? LIMIT 1", (url,))
    row = cur.fetchone()
    if row:
        return {"matched": True, "match": row}
    return {"matched": False}

# ---------------------------
# CLI
# ---------------------------

def main():
    if len(sys.argv) < 2:
        print("Usage: python phish_list_simple.py [update|lookup <url>]")
        return
    cmd = sys.argv[1].lower()
    conn = init_db()
    if cmd == "update":
        update_all_sources(conn)
    elif cmd == "lookup":
        if len(sys.argv) < 3:
            print("Usage: python phish_list_simple.py lookup <url>")
            return
        url = sys.argv[2]
        res = lookup_url(conn, url)
        print(res)
    else:
        print("Unknown command:", cmd)

if __name__ == "__main__":
    main()
