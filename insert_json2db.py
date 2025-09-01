import os, re, json
from pathlib import Path
import psycopg2
from psycopg2.extras import Json, execute_values

DATA_DIR = Path("results")

def derive_app_id(fname: str) -> str:
    """
    파일명이 'com.foo.bar.apk.json' -> 'com.foo.bar'
          또는 'com.foo.bar.json'   -> 'com.foo.bar'
    """
    base = re.sub(r"\.json$", "", fname, flags=re.IGNORECASE)
    if base.endswith(".apk"):
        base = base[:-4]
    return base

def clean_json_file(path: Path):
    """파일을 읽어 JSON 파싱. 제어문자 제거 후 재시도."""
    raw = path.read_text(encoding="utf-8", errors="replace")
    # 흔한 제어문자 제거 (NUL은 이후 strip_nuls에서 한 번 더 방어)
    raw = re.sub(r"[\x00-\x1F\x7F]", "", raw)
    return json.loads(raw)

def strip_nuls(obj):
    """파싱된 파이썬 객체를 재귀적으로 순회하며 문자열 내 NUL(\x00) 및 '\\u0000' 제거."""
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
    # 환경변수 권장: PG_DSN="dbname=iot_security user=postgres password=*** host=localhost port=5432"
    dsn = os.environ.get(
        "PG_DSN",
        "dbname=iot_security user=postgres password=dud0926! options='-c statement_timeout=0'"
    )
    conn = psycopg2.connect(dsn)
    conn.autocommit = False
    cur = conn.cursor()

    # 1) play_apps에서 app_id 목록 로드 (기준 집합)
    cur.execute("select app_id from public.play_apps")
    allowed_ids = {row[0] for row in cur.fetchall()}
    if not allowed_ids:
        print("[ABORT] play_apps에 app_id가 없습니다.")
        cur.close(); conn.close()
        return

    # 2) 파일들 스캔 → allowed_ids 에 있는 것만 수집
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
            data = clean_json_file(path)          # 파싱
            data = strip_nuls(data)               # NUL 제거
        except Exception as e:
            print(f"[SKIP:parse] {fname}: {e}")
            skipped += 1
            continue

        rows.append((app_id, Json(data)))         # 파이썬 객체 그대로 Json()에
        kept += 1

    if not rows:
        print("[DONE] 업서트할 행이 없습니다. (필터 결과 0)")
        cur.close(); conn.close()
        return

    # 3) UPSERT (파일에 있는 것 중 play_apps에 있는 app_id만)
    try:
        upsert_sql = """
            insert into public.app_analysis (app_id, data)
            values %s
            on conflict (app_id) do update set data = excluded.data
        """
        # JSON이 크면 50~200 정도로 batch 조절
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
