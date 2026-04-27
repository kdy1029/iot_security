import json
import os
import re
import glob
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Tuple
from psycopg2.extras import Json, execute_values
import psycopg2
import psycopg2.extras
import pandas as pd
from google_play_scraper import app as play_app
from .database import get_connection

# ---------- Google Play Metadata Fetcher ----------

def normalize_pkg(line: str) -> str:
    s = (line or "").strip()
    if not s: return ""
    if s.lower().endswith(".apk"): s = s[:-4]
    return s

def to_ts(dt_val):
    if not dt_val: return None
    if isinstance(dt_val, datetime):
        return dt_val if dt_val.tzinfo else dt_val.replace(tzinfo=timezone.utc)

    s = str(dt_val).strip()
    fmts = ["%B %d, %Y", "%b %d, %Y", "%Y-%m-%d"]
    for f in fmts:
        try: return datetime.strptime(s, f).replace(tzinfo=timezone.utc)
        except Exception: pass
    return None

def fetch_one_app(app_id: str, lang="en", country="us"):
    data = play_app(app_id, lang=lang, country=country)
    return {
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
        "price":        data.get("price"),
        "free":         data.get("free"),
        "currency":     data.get("currency"),
        "updated":      to_ts(data.get("updated")),
        "version":      data.get("version"),
        "android_ver":  data.get("androidVersion"),
        "contains_ads": data.get("containsAds"),
        "offers_iap":   data.get("offersIAP"),
        "url":          data.get("url"),
        "icon":         data.get("icon"),
        "hist":         psycopg2.extras.Json(data),
    }

def fetch_play_metadata(pkgs_file: str):
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
      updated      = COALESCE(EXCLUDED.updated, play_apps.updated),
      version      = COALESCE(EXCLUDED.version, play_apps.version),
      android_ver  = COALESCE(EXCLUDED.android_ver, play_apps.android_ver),
      contains_ads = EXCLUDED.contains_ads,
      offers_iap   = EXCLUDED.offers_iap,
      url          = EXCLUDED.url,
      icon         = EXCLUDED.icon,
      hist         = EXCLUDED.hist,
      fetched_at   = now();
    """
    if not os.path.exists(pkgs_file):
        print(f"[!] packages file not found: {pkgs_file}")
        return

    raw_lines = [l.strip() for l in open(pkgs_file, encoding="utf-8") if l.strip()]
    app_ids = [normalize_pkg(l) for l in raw_lines if normalize_pkg(l) and "." in normalize_pkg(l)]

    if not app_ids:
        print("[!] No valid app IDs found.")
        return

    conn = get_connection()
    conn.autocommit = False
    ok, err = 0, 0
    
    with conn, conn.cursor() as cur:
        for app_id in app_ids:
            try:
                rec = fetch_one_app(app_id)
                cur.execute(UPSERT_SQL, rec)
                ok += 1
                print(f"[OK] Fetched metadata: {app_id} - {rec.get('title')}")
            except Exception as e:
                conn.rollback()
                err += 1
                print(f"[ERR] Failed to fetch {app_id} - {e}")
            else:
                conn.commit()
    print(f"\nDone fetching metadata. success={ok}, error={err}")


# ---------- MobSF JSON Import ----------

def derive_app_id(fname: str) -> str:
    """Derives 'com.foo.bar' from 'com.foo.bar.apk.json' or 'com.foo.bar.json'."""
    base = re.sub(r"\.json$", "", fname, flags=re.IGNORECASE)
    if base.endswith(".apk"):
        base = base[:-4]
    return base

def clean_json_file(path: Path):
    """Reads and parses a JSON file, retrying after removing control characters."""
    raw = path.read_text(encoding="utf-8", errors="replace")
    raw = re.sub(r"[\x00-\x1F\x7F]", "", raw)
    return json.loads(raw)

def strip_nuls(obj):
    """Recursively traverses a Python object to remove NUL (\x00) and '\\u0000' from strings."""
    if obj is None:
        return None
    if isinstance(obj, str):
        return obj.replace("\x00", "").replace("\\u0000", "")
    if isinstance(obj, list):
        return [strip_nuls(x) for x in obj]
    if isinstance(obj, dict):
        return {
            (k if not isinstance(k, str) else k.replace("\x00", "").replace("\\u0000", "")):
            strip_nuls(v) for k, v in obj.items()
        }
    return obj

def import_mobsf_json_to_db(data_dir: str):
    """Imports MobSF JSON analysis results into the database."""
    conn = get_connection()
    conn.autocommit = False
    
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT app_id FROM public.play_apps")
            allowed_ids = {row[0] for row in cur.fetchall()}
            
            if not allowed_ids:
                print("[ABORT] No app_ids found in play_apps. Please fetch metadata first.")
                return

            rows = []
            kept = 0
            skipped = 0
            
            for fname in os.listdir(data_dir):
                if not fname.lower().endswith(".json"):
                    continue
                
                app_id = derive_app_id(fname)
                if app_id not in allowed_ids:
                    skipped += 1
                    continue

                path = Path(data_dir) / fname
                try:
                    data = clean_json_file(path)          
                    data = strip_nuls(data)               
                except Exception as e:
                    print(f"[SKIP:parse] {fname}: {e}")
                    skipped += 1
                    continue

                rows.append((app_id, Json(data)))         
                kept += 1

            if not rows:
                print("[DONE] No valid JSON files found to upsert.")
                return

            upsert_sql = """
                INSERT INTO public.app_analysis (app_id, data)
                VALUES %s
                ON CONFLICT (app_id) DO UPDATE SET data = EXCLUDED.data
            """
            BATCH = 100
            for i in range(0, len(rows), BATCH):
                execute_values(cur, upsert_sql, rows[i:i+BATCH], template="(%s, %s)")
            
            conn.commit()
            print(f"[OK] Upserted {kept} rows from MobSF files; skipped {skipped}.")
            
    except Exception as e:
        conn.rollback()
        print(f"[ERROR] Database error during import: {e}")
        raise
    finally:
        conn.close()


# ---------- Drozer Log Parser ----------

# Common Patterns
ATTACK_SURFACE_HEADER = re.compile(r'^\s*Attack Surface\s*$', re.IGNORECASE)
SECTION_LINE = re.compile(r'^\s*(Activities|Services|Receivers|Providers)\s*$', re.IGNORECASE)
EXPORTED_LINE = re.compile(r'\bexported\s*=\s*(true|false)', re.IGNORECASE)
EXPORTED_INLINE = re.compile(r'\bexported\b[^a-zA-Z0-9]+(true|false)', re.IGNORECASE)

AS_SUM_ACT = re.compile(r'^\s*(\d+)\s+activities\s+exported\b', re.IGNORECASE)
AS_SUM_RCV = re.compile(r'^\s*(\d+)\s+broadcast\s+receivers\s+exported\b', re.IGNORECASE)
AS_SUM_PROV = re.compile(r'^\s*(\d+)\s+content\s+providers\s+exported\b', re.IGNORECASE)
AS_SUM_SVC = re.compile(r'^\s*(\d+)\s+services\s+exported\b', re.IGNORECASE)

CLASS_ACTIVITY = re.compile(r'^\s+[A-Za-z0-9._$]+\.[A-Za-z0-9_$]*Activity[^\S\r\n]*.*$', re.IGNORECASE)
CLASS_SERVICE  = re.compile(r'^\s+[A-Za-z0-9._$]+\.[A-Za-z0-9_$]*Service[^\S\r\n]*.*$',  re.IGNORECASE)
CLASS_RECEIVER = re.compile(r'^\s+[A-Za-z0-9._$]+\.[A-Za-z0-9_$]*Receiver[^\S\r\n]*.*$', re.IGNORECASE)

PROVIDER_PKG_HEADER = re.compile(r'^\s*Package:\s+(\S+)\s*$', re.IGNORECASE)
PROVIDER_AUTH_LINE  = re.compile(r'^\s*Authority:\s+([A-Za-z0-9._-]+)\s*$', re.IGNORECASE)

URI_PATTERN = re.compile(r'content://[A-Za-z0-9._~\-%/]+')
SQLI_HIT = re.compile(r'(SQLi|Injection.*(possible|vulnerable)|\bVULNERABLE\b)', re.IGNORECASE)
TRAVERSAL_HIT = re.compile(r'(Path\s*Traversal|traversal.*(possible|vulnerable))', re.IGNORECASE)

def parse_attack_surface(text: str) -> Dict[str, int]:
    lines = text.splitlines()

    sum_act = sum_rcv = sum_prov = sum_svc = None
    for line in lines:
        if sum_act is None:
            m = AS_SUM_ACT.match(line)
            if m: sum_act = int(m.group(1)); continue
        if sum_rcv is None:
            m = AS_SUM_RCV.match(line)
            if m: sum_rcv = int(m.group(1)); continue
        if sum_prov is None:
            m = AS_SUM_PROV.match(line)
            if m: sum_prov = int(m.group(1)); continue
        if sum_svc is None:
            m = AS_SUM_SVC.match(line)
            if m: sum_svc = int(m.group(1)); continue

    if any(v is not None for v in (sum_act, sum_rcv, sum_prov, sum_svc)):
        return {
            'exported_activities': sum_act or 0,
            'exported_services':  sum_svc or 0,
            'exported_receivers': sum_rcv or 0,
            'exported_providers': sum_prov or 0,
            'total_activities': None,
            'total_services':  None,
            'total_receivers': None,
            'total_providers': None,
            'unknown_exported_true': 0,
        }

    exported = {'activities': 0, 'services': 0, 'receivers': 0, 'providers': 0}
    totals   = {'activities': 0, 'services': 0, 'receivers': 0, 'providers': 0}
    n = len(lines)
    i = 0
    found_block = False
    current = None

    while i < n:
        if ATTACK_SURFACE_HEADER.search(lines[i]):
            found_block = True
            i += 1
            while i < n:
                line = lines[i].rstrip()
                m = SECTION_LINE.match(line)
                if m:
                    current = m.group(1).lower()
                    i += 1
                    continue

                low = line.strip().lower()
                if low.startswith('run ') or low.startswith('scanning') or low.startswith('dz>'):
                    break

                if current and line.strip():
                    totals[current] += 1
                    if (EXPORTED_LINE.search(line) or EXPORTED_INLINE.search(line)) and 'true' in line.lower():
                        exported[current] += 1
                i += 1
            break
        i += 1

    if not found_block:
        true_hits = len(re.findall(r'\bexported\b[^a-zA-Z0-9]+true', text, flags=re.IGNORECASE))
        return {
            'exported_activities': 0, 'exported_services': 0,
            'exported_receivers': 0, 'exported_providers': 0,
            'total_activities': None, 'total_services': None,
            'total_receivers': None, 'total_providers': None,
            'unknown_exported_true': true_hits,
        }

    return {
        'exported_activities': exported['activities'],
        'exported_services':  exported['services'],
        'exported_receivers': exported['receivers'],
        'exported_providers': exported['providers'],
        'total_activities': totals['activities'],
        'total_services':  totals['services'],
        'total_receivers': totals['receivers'],
        'total_providers': totals['providers'],
        'unknown_exported_true': 0,
    }

def derive_totals_from_classnames(text: str) -> Dict[str, int]:
    lines = text.splitlines()
    return {
        'total_activities_from_info': sum(1 for ln in lines if CLASS_ACTIVITY.match(ln)),
        'total_services_from_info':   sum(1 for ln in lines if CLASS_SERVICE.match(ln)),
        'total_receivers_from_info':  sum(1 for ln in lines if CLASS_RECEIVER.match(ln)),
    }

def derive_totals_from_provider_info(text: str, pkg: str) -> int:
    lines = text.splitlines()
    in_pkg = False
    count = 0
    for ln in lines:
        m_pkg = PROVIDER_PKG_HEADER.match(ln)
        if m_pkg:
            in_pkg = (m_pkg.group(1) == pkg)
            continue
        if in_pkg and PROVIDER_AUTH_LINE.match(ln):
            count += 1
    return count

def parse_scanners(text: str) -> Tuple[int, int, List[str]]:
    uris = sorted(set(URI_PATTERN.findall(text)))
    sqli = len(SQLI_HIT.findall(text))
    trav = len(TRAVERSAL_HIT.findall(text))
    return sqli, trav, uris

def parse_single_app(log_path: Path) -> Tuple[Dict, List[Dict]]:
    app_id = log_path.parent.name
    text = log_path.read_text(errors='ignore')

    attack = parse_attack_surface(text)
    totals_from_info = derive_totals_from_classnames(text)
    
    if (attack['total_activities'] in (None, 0)) and totals_from_info['total_activities_from_info'] > 0:
        attack['total_activities'] = totals_from_info['total_activities_from_info']
    if (attack['total_services'] in (None, 0)) and totals_from_info['total_services_from_info'] > 0:
        attack['total_services'] = totals_from_info['total_services_from_info']
    if (attack['total_receivers'] in (None, 0)) and totals_from_info['total_receivers_from_info'] > 0:
        attack['total_receivers'] = totals_from_info['total_receivers_from_info']

    prov_total = derive_totals_from_provider_info(text, app_id)
    if (attack['total_providers'] in (None, 0)) and prov_total > 0:
        attack['total_providers'] = prov_total

    sqli, trav, uris = parse_scanners(text)

    rec = {
        'app_id': app_id,
        'total_activities': attack['total_activities'],
        'exported_activities': attack['exported_activities'],
        'total_services': attack['total_services'],
        'exported_services': attack['exported_services'],
        'total_receivers': attack['total_receivers'],
        'exported_receivers': attack['exported_receivers'],
        'total_providers': attack['total_providers'],
        'exported_providers': attack['exported_providers'],
        'unknown_exported_true': attack['unknown_exported_true'],
        'uris_found': len(uris),
        'sqli_hits': sqli,
        'traversal_hits': trav,
    }
    uri_rows = [{'app_id': app_id, 'uri': u} for u in uris]
    return rec, uri_rows

def parse_drozer_logs(root_glob: str, outdir: str = 'outputs'):
    os.makedirs(outdir, exist_ok=True)
    
    logs = []
    for root in glob.glob(root_glob):
        for p in Path(root).rglob('drozer_raw.log'):
            logs.append(p)
            
    if not logs:
        print(f'[WARN] No drozer_raw.log found under: {root_glob}')
        return

    rows = []
    uri_rows = []
    for log in logs:
        rec, uris = parse_single_app(log)
        rows.append(rec)
        uri_rows.extend(uris)

    df = pd.DataFrame(rows).sort_values('app_id')
    df_uris = pd.DataFrame(uri_rows).sort_values(['app_id', 'uri'])

    # export rate
    for comp in ('activities', 'services', 'receivers', 'providers'):
        denom = df[f'total_{comp}'].replace(0, pd.NA)
        df[f'export_rate_{comp}'] = (df[f'exported_{comp}'] / denom).fillna(0)

    # riskish
    df['riskish'] = (
        df[['exported_activities','exported_services','exported_receivers','exported_providers']].fillna(0).sum(axis=1)
        + df['sqli_hits'].fillna(0) + df['traversal_hits'].fillna(0)
    )

    df.to_csv(f"{outdir}/dz_parsed_summary.csv", index=False)
    df_uris.to_csv(f"{outdir}/dz_uris.csv", index=False)
    print(f"[OK] Saved Drozer summaries to {outdir}/")
