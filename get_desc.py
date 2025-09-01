
import csv
import os
import sys
from datetime import datetime, timezone
from slugify import slugify
import psycopg2
import psycopg2.extras
from google_play_scraper import app as play_app

PG_DSN = os.getenv(
    "PG_DSN",
    "dbname=iot_security user=postgres password=dud0926! host=127.0.0.1 port=5432"
)

def normalize_pkg(line: str) -> str:
    s = (line or "").strip()
    if not s:
        return ""
    # strip .apk suffix if present
    if s.lower().endswith(".apk"):
        s = s[:-4]
    # some lines may include spaces or bad chars
    return s

def to_ts(dt_val):
    """google-play-scraper 'updated'는 문자열일 수도, datetime일 수도 있어 방어적으로 처리"""
    if not dt_val:
        return None
    if isinstance(dt_val, datetime):
        # naive → UTC로 간주
        if dt_val.tzinfo is None:
            return dt_val.replace(tzinfo=timezone.utc)
        return dt_val
    # 문자열이면 최대한 파싱(간단 처리)
    try:
        # 예: 'August 20, 2025' 같은 포맷
        return datetime.strptime(str(dt_val), "%B %d, %Y").replace(tzinfo=timezone.utc)
    except Exception:
        return None

UPSERT_SQL = """
INSERT INTO play_apps (
  app_id, title, developer, developer_id, genre, genre_id, score, ratings, reviews,
  installs, min_installs, max_installs, price, free, currency, updated, version,
  android_ver, contains_ads, offers_iap, url, icon, hist, fetched_at
) VALUES (
  %(app_id)s, %(title)s, %(developer)s, %(developer_id)s, %(genre)s, %(genre_id)s, %(score)s, %(ratings)s, %(reviews)s,
  %(installs)s, %(min_installs)s, %(max_installs)s, %(price)s, %(free)s, %(currency)s, %(updated)s, %(version)s,
  %(android_ver)s, %(contains_ads)s, %(offers_iap)s, %(url)s, %(icon)s, %(hist)s, now()
) ON CONFLICT (app_id) DO UPDATE SET
  title        = EXCLUDED.title,
  developer    = EXCLUDED.developer,
  developer_id = EXCLUDED.developer_id,
  genre        = EXCLUDED.genre,
  genre_id     = EXCLUDED.genre_id,
  score        = EXCLUDED.score,
  ratings      = EXCLUDED.ratings,
  reviews      = EXCLUDED.reviews,
  installs     = EXCLUDED.installs,
  min_installs = EXCLUDED.min_installs,
  max_installs = EXCLUDED.max_installs,
  price        = EXCLUDED.price,
  free         = EXCLUDED.free,
  currency     = EXCLUDED.currency,
  updated      = EXCLUDED.updated,
  version      = EXCLUDED.version,
  android_ver  = EXCLUDED.android_ver,
  contains_ads = EXCLUDED.contains_ads,
  offers_iap   = EXCLUDED.offers_iap,
  url          = EXCLUDED.url,
  icon         = EXCLUDED.icon,
  hist         = EXCLUDED.hist,
  fetched_at   = now();
"""

def fetch_one(app_id: str, lang="en", country="us"):
    # google-play-scraper는 지역/언어에 따라 결과가 달라짐
    data = play_app(app_id, lang=lang, country=country)
    # 관심 필드 추출 (없는 경우 대비 .get 사용)
    rec = {
        "app_id":       app_id,
        "title":        data.get("title"),
        "developer":    data.get("developer"),
        "developer_id": data.get("developerId"),
        "genre":        data.get("genre"),
        "genre_id":     data.get("genreId"),
        "score":        data.get("score"),
        "ratings":      data.get("ratings"),
        "reviews":      data.get("reviews"),
        "installs":     data.get("installs"),
        "min_installs": data.get("minInstalls"),
        "max_installs": data.get("maxInstalls"),
        "price":        data.get("price"),     # USD 기준 금액(무료면 0)
        "free":         data.get("free"),
        "currency":     data.get("currency"),
        "updated":      to_ts(data.get("updated")),
        "version":      data.get("version"),
        "android_ver":  data.get("androidVersion"),
        "contains_ads": data.get("containsAds"),
        "offers_iap":   data.get("offersIAP"),
        "url":          data.get("url"),
        "icon":         data.get("icon"),
        "hist":         psycopg2.extras.Json(data),  # 전체 원본 저장
    }
    return rec

def main():
    # 입력 파일
    pkgs_file = sys.argv[1] if len(sys.argv) > 1 else "list.csv"
    if not os.path.exists(pkgs_file):
        print(f"[!] packages file not found: {pkgs_file}")
        sys.exit(1)

    # 패키지 목록 읽기 & 정리
    raw_lines = [l.strip() for l in open(pkgs_file, encoding="utf-8") if l.strip()]
    app_ids = []
    for line in raw_lines:
        pkg = normalize_pkg(line)
        if pkg and "." in pkg:
            app_ids.append(pkg)

    if not app_ids:
        print("[!] No valid app IDs found.")
        sys.exit(1)

    # PG 연결
    conn = psycopg2.connect(PG_DSN)
    conn.autocommit = False

    ok, err = 0, 0
    with conn, conn.cursor() as cur:
        for app_id in app_ids:
            try:
                rec = fetch_one(app_id, lang="en", country="us")
                cur.execute(UPSERT_SQL, rec)
                ok += 1
                # 간단한 진행 로그
                print(f"[OK] {app_id} - {rec.get('title')}")
            except Exception as e:
                conn.rollback()
                err += 1
                # 실패 시 기본 정보만 기록할 수도 있음(옵션)
                print(f"[ERR] {app_id} - {e}")
            else:
                conn.commit()

    print(f"\nDone. success={ok}, error={err}")

if __name__ == "__main__":
    main()
