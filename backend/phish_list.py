# phish_list_simple.py
import sqlite3
from urllib.parse import urlparse
import requests
from datetime import datetime, timezone

DB_SCHEMA = """
CREATE TABLE IF NOT EXISTS entries (
    url TEXT PRIMARY KEY,
    source TEXT,
    last_seen TEXT
);
"""

# You can edit or add Github raw sources here (raw URLs). Use raw.githubusercontent.com preferred.
DEFAULT_SOURCES = [
    # raw Github URL for the phishing list (example)
    "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-links-ACTIVE.txt"
]

REQUEST_TIMEOUT = 10
BATCH_SIZE = 9000

def init_db(path="phish_urls_simple.db"):
    conn = sqlite3.connect(path, timeout=60, check_same_thread=False)
    cur = conn.cursor()
    cur.execute(DB_SCHEMA)
    cur.execute("PRAGMA journal_mode=WAL;")
    cur.execute("PRAGMA synchronous=NORMAL;")
    conn.commit()
    return conn

def to_raw_github_url(url: str) -> str:
    # Convert a GitHub blob URL if necessary. If already raw, return it.
    if "raw.githubusercontent.com" in url:
        return url
    if "github.com" not in url:
        return url
    parsed = urlparse(url)
    parts = parsed.path.split("/")
    try:
        blob_index = parts.index("blob")
    except ValueError:
        return url
    owner = parts[1]
    repo = parts[2]
    branch = parts[blob_index + 1]
    path = "/".join(parts[blob_index + 2 :])
    raw = f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{path}"
    return raw

def stream_and_store_source(conn, src_url: str, batch_size=BATCH_SIZE):
    src_for_db = src_url
    raw_url = to_raw_github_url(src_url)
    if raw_url != src_url:
        src_for_db = raw_url

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
                buffer = []
        if buffer:
            cur.executemany(insert_sql, buffer)
            conn.commit()
    return count_total

def update_all_sources(conn, sources=None):
    if sources is None:
        sources = DEFAULT_SOURCES
    total = 0
    for s in sources:
        try:
            inserted = stream_and_store_source(conn, s)
            total += inserted
        except Exception as e:
            # do not stop entire update if one source fails
            print(f"[WARN] failed to fetch/store from {s}: {e}")
    return total

def lookup_url(conn, url: str):
    cur = conn.cursor()
    # Try exact match first, then host match
    cur.execute("SELECT url, source, last_seen FROM entries WHERE url = ? LIMIT 1", (url,))
    row = cur.fetchone()
    if row:
        return {"matched": True, "match": row}
    # attempt host-based lookup
    hostname = url
    if "://" in url or "/" in url:
        try:
            hostname = urlparse(url).hostname or url
        except Exception:
            hostname = url
    cur.execute("SELECT url, source, last_seen FROM entries WHERE url = ? LIMIT 1", (hostname,))
    row = cur.fetchone()
    if row:
        return {"matched": True, "match": row}
    return {"matched": False}
