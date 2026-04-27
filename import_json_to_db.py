import os, re, json
from pathlib import Path
import psycopg2
from psycopg2.extras import Json, execute_values

DATA_DIR = Path("results")

def derive_app_id(fname: str) -> str:
    """
    Derives 'com.foo.bar' from 'com.foo.bar.apk.json'
    or 'com.foo.bar.json'.
    """
    base = re.sub(r"\.json$", "", fname, flags=re.IGNORECASE)
    if base.endswith(".apk"):
        base = base[:-4]
    return base

def clean_json_file(path: Path):
    """Reads and parses a JSON file, retrying after removing control characters."""
    raw = path.read_text(encoding="utf-8", errors="replace")
    # Remove common control characters (NUL is handled again in strip_nuls)
    raw = re.sub(r"[\x00-\x1F\x7F]", "", raw)
    return json.loads(raw)

def strip_nuls(obj):
    """Recursively traverses a Python object to remove NUL (\x00) and '\\u0000' from strings."""
    if obj is None:
        return None
    if isinstance(obj, str):
        s = obj.replace("\x00", "").replace("\\u0000", "")
        return s
    if isinstance(obj, list):
        return [strip_nuls(x) for x in obj]
    if isinstance(obj, dict):
        return { (k if not isinstance(k, str) else k.replace("\x00", "").replace("\\u0000","")):
                 strip_nuls(v) for k, v in obj.items() }
    return obj

def main():
    # Recommended to use environment variables: PG_DSN="dbname=iot_security user=postgres password=*** host=localhost port=5432"
    dsn = os.environ.get(
        "PG_DSN",
        "dbname=iot_security user=postgres password=password options='-c statement_timeout=0'"
    )
    conn = psycopg2.connect(dsn)
    conn.autocommit = False
    cur = conn.cursor()

    # 1) Load the set of app_ids from play_apps (as the reference set)
    cur.execute("select app_id from public.play_apps")
    allowed_ids = {row[0] for row in cur.fetchall()}
    if not allowed_ids:
        print("[ABORT] No app_ids found in play_apps.")
        cur.close(); conn.close()
        return

    # 2) Scan files and collect only those present in allowed_ids
    rows = []
    kept = 0
    skipped = 0
    for fname in os.listdir(DATA_DIR):
        if not fname.lower().endswith(".json"):
            continue
        app_id = derive_app_id(fname)
        if app_id not in allowed_ids:
            skipped += 1
            continue

        path = DATA_DIR / fname
        try:
            data = clean_json_file(path)          # Parse
            data = strip_nuls(data)               # Remove NUL characters
        except Exception as e:
            print(f"[SKIP:parse] {fname}: {e}")
            skipped += 1
            continue

        rows.append((app_id, Json(data)))         # Pass the Python object directly to Json()
        kept += 1

    if not rows:
        print("[DONE] No rows to upsert (0 after filtering).")
        cur.close(); conn.close()
        return

    # 3) UPSERT (only for app_ids from files that are also in play_apps)
    try:
        upsert_sql = """
            insert into public.app_analysis (app_id, data)
            values %s
            on conflict (app_id) do update set data = excluded.data
        """
        # Adjust batch size for large JSON objects, e.g., 50-200
        BATCH = 100
        for i in range(0, len(rows), BATCH):
            execute_values(cur, upsert_sql, rows[i:i+BATCH], template="(%s, %s)")

        conn.commit()
        print(f"[OK] Upserted {kept} rows from files; skipped {skipped} (not in play_apps or parse error).")
    except Exception as e:
        conn.rollback()
        print("ERROR during upsert:", e)
        raise
    finally:
        cur.close()
        conn.close()

if __name__ == "__main__":
    main()
