#!/usr/bin/env python3
"""
parse_drozer_logs.py — A parser for Drozer results (final version)
Supports:
  • Attack Surface summary format (“… activities exported …”) + section-based format (Activities/Services/Receivers/Providers)
  • Complements total_* counts using class name counts from app.activity.info / app.service.info / app.broadcast.info
  • Complements total_providers by counting 'Authority:' lines from app.provider.info
  • Collects URIs and aggregates hits from provider scanners (finduris / injection / traversal)

Output:
  - outputs/dz_parsed_summary.csv
  - outputs/dz_uris.csv
  - outputs/dz_summary.md (requires tabulate)
  - outputs/dz_summary.tex

Usage:
  pip install pandas tabulate
  python parse_drozer_logs.py --root "dz_out_*"
"""

import argparse
import glob
import os
import re
from pathlib import Path
from typing import Dict, List, Tuple

import pandas as pd

# ---------- Common Patterns ----------
# Attack Surface (Section-based)
ATTACK_SURFACE_HEADER = re.compile(r'^\s*Attack Surface\s*$', re.IGNORECASE)
SECTION_LINE = re.compile(r'^\s*(Activities|Services|Receivers|Providers)\s*$', re.IGNORECASE)
EXPORTED_LINE = re.compile(r'\bexported\s*=\s*(true|false)', re.IGNORECASE)
EXPORTED_INLINE = re.compile(r'\bexported\b[^a-zA-Z0-9]+(true|false)', re.IGNORECASE)

# Attack Surface (Summary-style, single line format)
AS_SUM_ACT = re.compile(r'^\s*(\d+)\s+activities\s+exported\b', re.IGNORECASE)
AS_SUM_RCV = re.compile(r'^\s*(\d+)\s+broadcast\s+receivers\s+exported\b', re.IGNORECASE)
AS_SUM_PROV = re.compile(r'^\s*(\d+)\s+content\s+providers\s+exported\b', re.IGNORECASE)
AS_SUM_SVC = re.compile(r'^\s*(\d+)\s+services\s+exported\b', re.IGNORECASE)

# app.*.info class name lines (to supplement total counts; allows for minor trailing text)
CLASS_ACTIVITY = re.compile(r'^\s+[A-Za-z0-9._$]+\.[A-Za-z0-9_$]*Activity[^\S\r\n]*.*$', re.IGNORECASE)
CLASS_SERVICE  = re.compile(r'^\s+[A-Za-z0-9._$]+\.[A-Za-z0-9_$]*Service[^\S\r\n]*.*$',  re.IGNORECASE)
CLASS_RECEIVER = re.compile(r'^\s+[A-Za-z0-9._$]+\.[A-Za-z0-9_$]*Receiver[^\S\r\n]*.*$', re.IGNORECASE)

# For provider info blocks
PROVIDER_PKG_HEADER = re.compile(r'^\s*Package:\s+(\S+)\s*$', re.IGNORECASE)
PROVIDER_AUTH_LINE  = re.compile(r'^\s*Authority:\s+([A-Za-z0-9._-]+)\s*$', re.IGNORECASE)

# Common for Provider-related scanners
URI_PATTERN = re.compile(r'content://[A-Za-z0-9._~\-%/]+')
SQLI_HIT = re.compile(r'(SQLi|Injection.*(possible|vulnerable)|\bVULNERABLE\b)', re.IGNORECASE)
TRAVERSAL_HIT = re.compile(r'(Path\s*Traversal|traversal.*(possible|vulnerable))', re.IGNORECASE)


# ---------- Parsing Logic ----------
def parse_attack_surface(text: str) -> Dict[str, int]:
    """
    Parses the Attack Surface section:
      1) If summary style (“… activities exported …”) is found, confirms only exported_* counts.
      2) If section-based (Activities/Services/Receivers/Providers) is found, calculates total_* + exported_*.
      3) If neither is found, records an estimate of exported=true from the entire file.
    """
    lines = text.splitlines()

    # 1) Summary style
    sum_act = sum_rcv = sum_prov = sum_svc = None
    for line in lines:
        if sum_act is None:
            m = AS_SUM_ACT.match(line)
            if m:
                sum_act = int(m.group(1))
                continue
        if sum_rcv is None:
            m = AS_SUM_RCV.match(line)
            if m:
                sum_rcv = int(m.group(1))
                continue
        if sum_prov is None:
            m = AS_SUM_PROV.match(line)
            if m:
                sum_prov = int(m.group(1))
                continue
        if sum_svc is None:
            m = AS_SUM_SVC.match(line)
            if m:
                sum_svc = int(m.group(1))
                continue

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

    # 2) Section-based
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
    """Supplements total counts by counting class name lines from app.activity.info / app.service.info / app.broadcast.info."""
    lines = text.splitlines()
    tot_act = sum(1 for ln in lines if CLASS_ACTIVITY.match(ln))
    tot_svc = sum(1 for ln in lines if CLASS_SERVICE.match(ln))
    tot_rcv = sum(1 for ln in lines if CLASS_RECEIVER.match(ln))
    return {
        'total_activities_from_info': tot_act,
        'total_services_from_info':   tot_svc,
        'total_receivers_from_info':  tot_rcv,
    }


def derive_totals_from_provider_info(text: str, pkg: str) -> int:
    """
    Calculates the total number of providers by counting 'Authority' lines within the corresponding package block from the app.provider.info output.
    Example format:
      Package: com.foo.bar
        Authority: com.foo.bar.provider
        Permission Read: ...
        Permission Write: ...
    """
    lines = text.splitlines()
    in_pkg = False
    count = 0
    for ln in lines:
        m_pkg = PROVIDER_PKG_HEADER.match(ln)
        if m_pkg:
            in_pkg = (m_pkg.group(1) == pkg)
            continue
        if in_pkg:
            if PROVIDER_AUTH_LINE.match(ln):
                count += 1
            # The loop handles exiting the block automatically when the next 'Package:' line is found (in_pkg becomes False).
    return count


def parse_scanners(text: str) -> Tuple[int, int, List[str]]:
    """Provider scanner results: SQLi/Traversal hit count, list of content:// URIs."""
    uris = sorted(set(URI_PATTERN.findall(text)))
    sqli = len(SQLI_HIT.findall(text))
    trav = len(TRAVERSAL_HIT.findall(text))
    return sqli, trav, uris


def parse_single_app(log_path: Path) -> Tuple[Dict, List[Dict]]:
    app_id = log_path.parent.name
    text = log_path.read_text(errors='ignore')

    # 1) Attack Surface
    attack = parse_attack_surface(text)

    # 2) Supplement totals based on class names (activity/service/receiver)
    totals_from_info = derive_totals_from_classnames(text)
    if (attack['total_activities'] in (None, 0)) and totals_from_info['total_activities_from_info'] > 0:
        attack['total_activities'] = totals_from_info['total_activities_from_info']
    if (attack['total_services'] in (None, 0)) and totals_from_info['total_services_from_info'] > 0:
        attack['total_services'] = totals_from_info['total_services_from_info']
    if (attack['total_receivers'] in (None, 0)) and totals_from_info['total_receivers_from_info'] > 0:
        attack['total_receivers'] = totals_from_info['total_receivers_from_info']

    # 3) Supplement total provider count (from Authority count)
    prov_total = derive_totals_from_provider_info(text, app_id)
    if (attack['total_providers'] in (None, 0)) and prov_total > 0:
        attack['total_providers'] = prov_total

    # 4) Provider scanners
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


def collect_logs(root_glob: str) -> List[Path]:
    paths: List[Path] = []
    for root in glob.glob(root_glob):
        for p in Path(root).rglob('drozer_raw.log'):
            paths.append(p)
    return paths


def try_merge_batch_summary(df: pd.DataFrame, roots: List[str]) -> pd.DataFrame:
    """Merges with summary.csv if it was created by dz_batch/single_dz."""
    found = []
    for r in roots:
        p = Path(r) / 'summary.csv'
        if p.exists():
            try:
                t = pd.read_csv(p)
                t['source_summary_dir'] = str(p.parent)
                found.append(t)
            except Exception:
                pass
    if found:
        merged = pd.concat(found, ignore_index=True)
        df = df.merge(merged, on='app_id', how='left', suffixes=('', '_batch'))
    return df


# ---------- Main ----------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--root', required=True, help="dz_out_* directory or glob (e.g., 'dz_out_*')")
    ap.add_argument('--outdir', default='outputs', help='Output folder (default: outputs)')
    args = ap.parse_args()

    os.makedirs(args.outdir, exist_ok=True)

    logs = collect_logs(args.root)
    if not logs:
        print(f'No drozer_raw.log found under: {args.root}')
        return

    rows: List[Dict] = []
    uri_rows: List[Dict] = []
    for log in logs:
        rec, uris = parse_single_app(log)
        rows.append(rec)
        uri_rows.extend(uris)

    df = pd.DataFrame(rows).sort_values('app_id')
    df_uris = pd.DataFrame(uri_rows).sort_values(['app_id', 'uri'])

    # Merge summary.csv (if it exists)
    unique_roots = list({str(p.parent) for p in logs})
    df = try_merge_batch_summary(df, unique_roots)

    # Calculate export rate (treat as 0 if total is empty or 0)
    for comp in ('activities', 'services', 'receivers', 'providers'):
        tot = f'total_{comp}'
        exp = f'exported_{comp}'
        rate = f'export_rate_{comp}'
        denom = df[tot].replace(0, pd.NA)
        df[rate] = (df[exp] / denom).fillna(0)

    # Simple risk indicator
    df['riskish'] = (
        df[['exported_activities','exported_services','exported_receivers','exported_providers']].fillna(0).sum(axis=1)
        + df['sqli_hits'].fillna(0) + df['traversal_hits'].fillna(0)
    )

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    summary_csv = outdir / 'dz_parsed_summary.csv'
    uris_csv = outdir / 'dz_uris.csv'
    df.to_csv(summary_csv, index=False)
    df_uris.to_csv(uris_csv, index=False)

    # Top 20 table (requires tabulate)
    cols = [
        'app_id',
        'uris_found','sqli_hits','traversal_hits',
        'total_activities','exported_activities','export_rate_activities',
        'total_services','exported_services','export_rate_services',
        'total_receivers','exported_receivers','export_rate_receivers',
        'total_providers','exported_providers','export_rate_providers',
        'unknown_exported_true','riskish',
    ]
    top = df.sort_values(['riskish','uris_found'], ascending=[False, False]).head(20)

    try:
        md_path = outdir / 'dz_summary.md'
        with open(md_path, 'w', encoding='utf-8') as f:
            f.write('# Drozer Parsed Summary (Top 20)\n\n')
            f.write(top[cols].to_markdown(index=False))
    except Exception as e:
        print(f"[warn] Markdown export skipped ({e}). Install `tabulate` to enable Markdown.")

    try:
        tex_path = outdir / 'dz_summary.tex'
        with open(tex_path, 'w', encoding='utf-8') as f:
            f.write(top[cols].to_latex(index=False, escape=True))
    except Exception as e:
        print(f"[warn] LaTeX export skipped ({e}).")

    print(f"[OK] Saved:\n - {summary_csv}\n - {uris_csv}\n - {outdir/'dz_summary.md'}\n - {outdir/'dz_summary.tex'}")


if __name__ == '__main__':
    main()
