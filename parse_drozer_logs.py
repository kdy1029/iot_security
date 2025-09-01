#!/usr/bin/env python3
"""
parse_drozer_logs.py — Drozer 결과 파서 (완성본)
지원:
  • Attack Surface 요약형(“… activities exported …”) + 섹션형(Activities/Services/Receivers/Providers)
  • app.activity.info / app.service.info / app.broadcast.info 클래스명 카운트로 total_* 보완
  • app.provider.info 의 'Authority:' 라인 카운트로 total_providers 보완
  • provider 스캐너(finduris / injection / traversal)에서 URI 수집 및 히트 수 집계

출력:
  - outputs/dz_parsed_summary.csv
  - outputs/dz_uris.csv
  - outputs/dz_summary.md (tabulate 필요)
  - outputs/dz_summary.tex

사용:
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

# ---------- 공통 패턴 ----------
# Attack Surface 섹션형
ATTACK_SURFACE_HEADER = re.compile(r'^\s*Attack Surface\s*$', re.IGNORECASE)
SECTION_LINE = re.compile(r'^\s*(Activities|Services|Receivers|Providers)\s*$', re.IGNORECASE)
EXPORTED_LINE = re.compile(r'\bexported\s*=\s*(true|false)', re.IGNORECASE)
EXPORTED_INLINE = re.compile(r'\bexported\b[^a-zA-Z0-9]+(true|false)', re.IGNORECASE)

# Attack Surface 요약형(샘플과 같은 줄 형식)
AS_SUM_ACT = re.compile(r'^\s*(\d+)\s+activities\s+exported\b', re.IGNORECASE)
AS_SUM_RCV = re.compile(r'^\s*(\d+)\s+broadcast\s+receivers\s+exported\b', re.IGNORECASE)
AS_SUM_PROV = re.compile(r'^\s*(\d+)\s+content\s+providers\s+exported\b', re.IGNORECASE)
AS_SUM_SVC = re.compile(r'^\s*(\d+)\s+services\s+exported\b', re.IGNORECASE)

# app.*.info 클래스명 라인(총 개수 보완용; 뒤에 설명이 조금 붙어도 허용)
CLASS_ACTIVITY = re.compile(r'^\s+[A-Za-z0-9._$]+\.[A-Za-z0-9_$]*Activity[^\S\r\n]*.*$', re.IGNORECASE)
CLASS_SERVICE  = re.compile(r'^\s+[A-Za-z0-9._$]+\.[A-Za-z0-9_$]*Service[^\S\r\n]*.*$',  re.IGNORECASE)
CLASS_RECEIVER = re.compile(r'^\s+[A-Za-z0-9._$]+\.[A-Za-z0-9_$]*Receiver[^\S\r\n]*.*$', re.IGNORECASE)

# provider info 블록용
PROVIDER_PKG_HEADER = re.compile(r'^\s*Package:\s+(\S+)\s*$', re.IGNORECASE)
PROVIDER_AUTH_LINE  = re.compile(r'^\s*Authority:\s+([A-Za-z0-9._-]+)\s*$', re.IGNORECASE)

# Provider 관련 스캐너 공통
URI_PATTERN = re.compile(r'content://[A-Za-z0-9._~\-%/]+')
SQLI_HIT = re.compile(r'(SQLi|Injection.*(possible|vulnerable)|\bVULNERABLE\b)', re.IGNORECASE)
TRAVERSAL_HIT = re.compile(r'(Path\s*Traversal|traversal.*(possible|vulnerable))', re.IGNORECASE)


# ---------- 파싱 로직 ----------
def parse_attack_surface(text: str) -> Dict[str, int]:
    """
    Attack Surface 파싱:
      1) 요약형(“… activities exported …”) 발견 시 exported_*만 확정
      2) 섹션형(Activities/Services/Receivers/Providers) 발견 시 total_* + exported_* 계산
      3) 둘 다 없으면 파일 전체에서 exported=true 추정치만 기록
    """
    lines = text.splitlines()

    # 1) 요약형
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

    # 2) 섹션형
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
    """app.activity.info / app.service.info / app.broadcast.info의 클래스명 라인을 세어 totals 보완."""
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
    app.provider.info 출력에서 해당 패키지 블록의 Authority 라인 개수를 총 provider 수로 계산.
    포맷 예:
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
            # 다음 Package 블록 시작 시 자동 종료는 위 루프에서 처리됨(다음 m_pkg에서 in_pkg False)
    return count


def parse_scanners(text: str) -> Tuple[int, int, List[str]]:
    """provider 스캐너 결과: SQLi/Traversal 히트 수, content:// URI 목록."""
    uris = sorted(set(URI_PATTERN.findall(text)))
    sqli = len(SQLI_HIT.findall(text))
    trav = len(TRAVERSAL_HIT.findall(text))
    return sqli, trav, uris


def parse_single_app(log_path: Path) -> Tuple[Dict, List[Dict]]:
    app_id = log_path.parent.name
    text = log_path.read_text(errors='ignore')

    # 1) Attack Surface
    attack = parse_attack_surface(text)

    # 2) 클래스명 기반 totals 보완 (activity/service/receiver)
    totals_from_info = derive_totals_from_classnames(text)
    if (attack['total_activities'] in (None, 0)) and totals_from_info['total_activities_from_info'] > 0:
        attack['total_activities'] = totals_from_info['total_activities_from_info']
    if (attack['total_services'] in (None, 0)) and totals_from_info['total_services_from_info'] > 0:
        attack['total_services'] = totals_from_info['total_services_from_info']
    if (attack['total_receivers'] in (None, 0)) and totals_from_info['total_receivers_from_info'] > 0:
        attack['total_receivers'] = totals_from_info['total_receivers_from_info']

    # 3) provider 총개수 보완 (Authority 카운트)
    prov_total = derive_totals_from_provider_info(text, app_id)
    if (attack['total_providers'] in (None, 0)) and prov_total > 0:
        attack['total_providers'] = prov_total

    # 4) provider 스캐너
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
    """dz_batch/single_dz가 만든 summary.csv가 있으면 병합."""
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


# ---------- 메인 ----------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--root', required=True, help="dz_out_* 디렉토리 또는 글롭 (예: 'dz_out_*')")
    ap.add_argument('--outdir', default='outputs', help='저장 폴더 (기본: outputs)')
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

    # summary.csv 병합(있을 때만)
    unique_roots = list({str(p.parent) for p in logs})
    df = try_merge_batch_summary(df, unique_roots)

    # export rate 계산 (total이 비어있거나 0이면 0으로)
    for comp in ('activities', 'services', 'receivers', 'providers'):
        tot = f'total_{comp}'
        exp = f'exported_{comp}'
        rate = f'export_rate_{comp}'
        denom = df[tot].replace(0, pd.NA)
        df[rate] = (df[exp] / denom).fillna(0)

    # 간단 위험지표
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

    # 상위 20 표 (tabulate 필요)
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
