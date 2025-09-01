import os
import pandas as pd
import matplotlib.pyplot as plt
from sqlalchemy import create_engine, text

# -------------------------------------------------
# 0) 출력 디렉토리 보장
# -------------------------------------------------
os.makedirs("tables", exist_ok=True)
os.makedirs("figures", exist_ok=True)

# -------------------------------------------------
# 1) DB 연결
# -------------------------------------------------
engine = create_engine("postgresql://postgres:dud0926!@localhost:5432/iot_security")

# 작은 헬퍼: DataFrame을 LaTeX로 저장 (Jinja2 없으면 tabulate로 폴백)
def save_latex(df: pd.DataFrame, path: str, floatfmt="%.1f"):
    try:
        df.to_latex(path, index=False, float_format=floatfmt)
    except Exception:
        try:
            from tabulate import tabulate
        except ImportError:
            # tabulate도 없으면 간단한 latex tabular 최소본 생성
            cols = " & ".join(map(str, df.columns)) + r" \\"
            rows = "\n".join(" & ".join(map(str, r)) + r" \\" for r in df.values)
            content = (
                r"\begin{tabular}{" + " ".join(["l"] * df.shape[1]) + "}\n\\hline\n"
                + cols + "\n\\hline\n" + rows + "\n\\hline\n\\end{tabular}\n"
            )
            with open(path, "w", encoding="utf-8") as f:
                f.write(content)
            return
        with open(path, "w", encoding="utf-8") as f:
            f.write(tabulate(df.values, headers=df.columns,
                             tablefmt="latex_booktabs", floatfmt=floatfmt))

with engine.connect() as conn:
    # -------------------------------------------------
    # 2) Dangerous Permissions 테이블 (Top 10)
    # -------------------------------------------------
    sql_permissions = """
    select permission, 
           count(distinct app_id)::float / (select count(*) from app_analysis) * 100 as pct_apps
    from v_mobsf_permissions
    group by permission
    order by pct_apps desc
    limit 10;
    """
    df_perm = pd.read_sql(sql_permissions, conn)
    save_latex(df_perm, "tables/permissions.tex", floatfmt="%.1f")

    # -------------------------------------------------
    # 3) Insecure Flags 테이블 (한 줄 집계 → 2열 테이블로 변환)
    # -------------------------------------------------
    sql_flags = """
    select 
      sum((allow_backup)::int)::float / count(*) * 100 as pct_backup,
      sum((uses_cleartext_traffic)::int)::float / count(*) * 100 as pct_cleartext,
      sum((debuggable_hint)::int)::float / count(*) * 100 as pct_debuggable
    from v_mobsf_flags;
    """
    df_flags_row = pd.read_sql(sql_flags, conn)
    # 세로 형태로 바꿔 라텍스 테이블로 저장
    df_flags = df_flags_row.T.reset_index()
    df_flags.columns = ["Flag", "Percentage"]
    # 보기 좋은 라벨로 교체(선택)
    nice_map = {
        "pct_backup": "Allow Backup",
        "pct_cleartext": "Cleartext Traffic",
        "pct_debuggable": "Debuggable (manifest/hints)"
    }
    df_flags["Flag"] = df_flags["Flag"].map(lambda k: nice_map.get(k, k))
    save_latex(df_flags, "tables/flags.tex", floatfmt="%.1f")

    # -------------------------------------------------
    # 4) Top Domains 그래프 (Top 20)
    # -------------------------------------------------
    sql_domains = """
    select domain, count(distinct app_id) as apps
    from v_mobsf_domains
    group by domain
    order by apps desc
    limit 20;
    """
    df_dom = pd.read_sql(sql_domains, conn)

# 도메인 수직 막대 (가로 막대가 가독성 좋음)
plt.figure(figsize=(8, 5))
ax = plt.gca()
df_dom.plot(kind="barh", x="domain", y="apps", legend=False, ax=ax)
ax.invert_yaxis()
ax.set_xlabel("Number of Apps")
ax.set_ylabel("Domain")
ax.set_title("Top 20 Domains in IoT Apps")
plt.tight_layout()
plt.savefig("figures/top_domains.pdf")

with engine.connect() as conn:
    # -------------------------------------------------
    # 5) Risk Score Histogram (바인드 파라미터로 % 처리)
    # -------------------------------------------------
    sql_risk = text("""
    with dang as (
      select app_id, count(distinct permission) as c
      from v_mobsf_permissions
      group by app_id
    ),
    flags as (
      select app_id,
             (uses_cleartext_traffic)::int as clt,
             (allow_backup)::int          as bak,
             (debuggable_hint)::int       as dbg
      from v_mobsf_flags
    ),
    http_hint as (
      select app_id, count(*) as c
      from v_mobsf_findings
      where title ilike :pat
      group by app_id
    )
    select
      f.app_id,
      coalesce(dang.c,0)*2
      + coalesce(http_hint.c,0)*2
      + coalesce(flags.clt,0)*2
      + coalesce(flags.bak,0)*1
      + coalesce(flags.dbg,0)*1 as risk_score
    from (select app_id from app_analysis) f
    left join dang on f.app_id = dang.app_id
    left join flags on f.app_id = flags.app_id
    left join http_hint on f.app_id = http_hint.app_id;
    """)
    df_risk = pd.read_sql(sql_risk, conn, params={"pat": "%Clear text%"})

plt.figure(figsize=(6, 4))
ax2 = plt.gca()
ax2.hist(df_risk["risk_score"], bins=15, edgecolor="black")
ax2.set_xlabel("Risk Score")
ax2.set_ylabel("Number of Apps")
ax2.set_title("Distribution of Risk Scores")
plt.tight_layout()
plt.savefig("figures/risk_score_histogram.pdf")
