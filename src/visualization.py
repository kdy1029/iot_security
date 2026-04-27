import os
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from sqlalchemy import text
from tabulate import tabulate
from .database import get_engine

def ensure_output_dirs():
    os.makedirs("tables", exist_ok=True)
    os.makedirs("figures", exist_ok=True)

def save_latex(df: pd.DataFrame, path: str, floatfmt="%.1f"):
    """Saves DataFrame as a LaTeX table."""
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(tabulate(df.values, headers=df.columns, tablefmt="latex_booktabs", floatfmt=floatfmt))
    except Exception as e:
        print(f"[ERROR] Could not save LaTeX file {path}: {e}")
        # Minimal fallback
        cols = " & ".join(map(str, df.columns)) + r" \\"
        rows = "\n".join(" & ".join(map(str, r)) for r in df.values) + r" \\"
        content = (
            r"\begin{tabular}{" + " ".join(["l"] * df.shape[1]) + "}\n\\hline\n"
            + cols + "\n\\hline\n" + rows + "\n\\hline\n\\end{tabular}\n"
        )
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)

def generate_permissions_table():
    ensure_output_dirs()
    engine = get_engine()
    
    sql_permissions = text("""
    SELECT permission, 
           count(distinct app_id)::float / (SELECT count(*) FROM app_analysis) * 100 as pct_apps
    FROM v_mobsf_permissions
    GROUP BY permission
    ORDER BY pct_apps DESC
    LIMIT 10;
    """)
    
    with engine.connect() as conn:
        df_perm = pd.read_sql(sql_permissions, conn)
        save_latex(df_perm, "tables/permissions.tex", floatfmt="%.1f")
        print("[OK] Generated tables/permissions.tex")

def generate_flags_table():
    ensure_output_dirs()
    engine = get_engine()
    
    sql_flags = text("""
    SELECT 
      sum((allow_backup)::int)::float / count(*) * 100 as pct_backup,
      sum((uses_cleartext_traffic)::int)::float / count(*) * 100 as pct_cleartext,
      sum((debuggable_hint)::int)::float / count(*) * 100 as pct_debuggable
    FROM v_mobsf_flags;
    """)
    
    with engine.connect() as conn:
        df_flags_row = pd.read_sql(sql_flags, conn)
        
        # Transpose
        df_flags = df_flags_row.T.reset_index()
        df_flags.columns = ["Flag", "Percentage"]
        
        nice_map = {
            "pct_backup": "Allow Backup",
            "pct_cleartext": "Cleartext Traffic",
            "pct_debuggable": "Debuggable (manifest/hints)"
        }
        df_flags["Flag"] = df_flags["Flag"].map(lambda k: nice_map.get(k, k))
        
        save_latex(df_flags, "tables/flags.tex", floatfmt="%.1f")
        print("[OK] Generated tables/flags.tex")

def generate_credentials_table():
    ensure_output_dirs()
    engine = get_engine()
    
    sql = text("""
    WITH creds AS (
      SELECT app_id, COUNT(*) AS n_creds
      FROM v_mobsf_findings
      WHERE title ILIKE '%api key%'
         OR title ILIKE '%access token%'
         OR title ILIKE '%secret%'
         OR description ILIKE '%api key%'
         OR description ILIKE '%access token%'
         OR description ILIKE '%secret%'
      GROUP BY app_id
    )
    SELECT r.app_id, COALESCE(c.n_creds, 0) AS n_credential_findings, r.risk_score
    FROM v_risk_score r
    LEFT JOIN creds c USING (app_id)
    WHERE COALESCE(c.n_creds, 0) > 0
    ORDER BY n_credential_findings DESC, r.risk_score DESC
    LIMIT 20;
    """)
    
    with engine.connect() as conn:
        df_creds = pd.read_sql(sql, conn)
        save_latex(df_creds, "tables/credentials.tex")
        print("[OK] Generated tables/credentials.tex")

def plot_top_domains():
    ensure_output_dirs()
    engine = get_engine()
    
    sql_domains = text("""
    SELECT domain, count(distinct app_id) as apps
    FROM v_mobsf_domains
    GROUP BY domain
    ORDER BY apps DESC
    LIMIT 20;
    """)
    
    with engine.connect() as conn:
        df_dom = pd.read_sql(sql_domains, conn)
        
    plt.figure(figsize=(8, 5))
    ax = plt.gca()
    df_dom.plot(kind="barh", x="domain", y="apps", legend=False, ax=ax)
    ax.invert_yaxis()
    ax.set_xlabel("Number of Apps")
    ax.set_ylabel("Domain")
    ax.set_title("Top 20 Domains in IoT Apps")
    plt.tight_layout()
    plt.savefig("figures/top_domains.pdf")
    plt.close()
    print("[OK] Generated figures/top_domains.pdf")

def plot_risk_scores():
    ensure_output_dirs()
    engine = get_engine()
    
    sql_risk = text("""
    WITH dang AS (
      SELECT app_id, count(distinct permission) as c
      FROM v_mobsf_permissions
      GROUP BY app_id
    ),
    flags AS (
      SELECT app_id,
             (uses_cleartext_traffic)::int as clt,
             (allow_backup)::int          as bak,
             (debuggable_hint)::int       as dbg
      FROM v_mobsf_flags
    ),
    http_hint AS (
      SELECT app_id, count(*) as c
      FROM v_mobsf_findings
      WHERE title ilike :pat
      GROUP BY app_id
    )
    SELECT f.app_id,
      COALESCE(dang.c,0)*2 + COALESCE(http_hint.c,0)*2 + 
      COALESCE(flags.clt,0)*2 + COALESCE(flags.bak,0)*1 + 
      COALESCE(flags.dbg,0)*1 AS risk_score
    FROM (SELECT app_id FROM app_analysis) f
    LEFT JOIN dang ON f.app_id = dang.app_id
    LEFT JOIN flags ON f.app_id = flags.app_id
    LEFT JOIN http_hint ON f.app_id = http_hint.app_id;
    """)
    
    with engine.connect() as conn:
        df_risk = pd.read_sql(sql_risk, conn, params={"pat": "%Clear text%"})
        
    plt.figure(figsize=(6, 4))
    plt.hist(df_risk["risk_score"], bins=15, edgecolor="black")
    plt.xlabel("Risk Score")
    plt.ylabel("Number of Apps")
    plt.title("Distribution of Risk Scores")
    plt.tight_layout()
    plt.savefig("figures/risk_score_histogram.pdf")
    plt.close()
    print("[OK] Generated figures/risk_score_histogram.pdf")

def plot_masvs_violations():
    ensure_output_dirs()
    engine = get_engine()
    
    sql = text("""
    WITH per_app AS (
      SELECT masvs_area, app_id, count(*) as n_findings
      FROM v_masvs_mapping
      GROUP BY masvs_area, app_id
    )
    SELECT masvs_area, avg(n_findings)::numeric as avg_findings_per_app
    FROM per_app
    GROUP BY masvs_area
    ORDER BY avg_findings_per_app DESC;
    """)
    
    with engine.connect() as conn:
        df = pd.read_sql(sql, conn)
        
    plt.figure(figsize=(7, 4))
    plt.bar(df["masvs_area"], df["avg_findings_per_app"])
    plt.ylabel("Avg Findings per App")
    plt.title("Average MASVS Violations per App by Area")
    plt.xticks(rotation=30, ha="right")
    plt.tight_layout()
    plt.savefig("figures/masvs_avg_findings.pdf")
    plt.close()
    print("[OK] Generated figures/masvs_avg_findings.pdf")

def plot_presentation_charts():
    ensure_output_dirs()

    # 1) Grouped Bar Chart
    labels = ['Avg Findings', 'High Severity']
    iot = [109.39, 2.49]
    non_iot = [100.01, 3.04]
    x = np.arange(len(labels))
    width = 0.35

    fig1, ax1 = plt.subplots()
    ax1.bar(x - width/2, iot, width, label='IoT')
    ax1.bar(x + width/2, non_iot, width, label='Non-IoT')
    ax1.set_ylabel('Value')
    ax1.set_title('IoT vs Non-IoT: Findings & High Severity')
    ax1.set_xticks(x)
    ax1.set_xticklabels(labels)
    ax1.legend()
    plt.tight_layout()
    plt.savefig("figures/grouped_bar_iot_vs_non_iot.png")
    plt.close(fig1)

    # 2) Radar Chart: MASVS
    categories = ['MSTG-CODE', 'MSTG-CRYPTO', 'MSTG-NETWORK', 'MSTG-PLATFORM', 'MSTG-RESILIENCE', 'MSTG-STORAGE']
    N = len(categories)
    iot_values = [164, 209, 175, 115, 160, 223]
    non_iot_values = [150, 220, 177, 143, 183, 223]

    angles = np.linspace(0, 2 * np.pi, N, endpoint=False).tolist()
    angles += angles[:1]
    iot_plot = iot_values + iot_values[:1]
    non_iot_plot = non_iot_values + non_iot_values[:1]

    fig2, ax2 = plt.subplots(subplot_kw=dict(polar=True))
    ax2.plot(angles, iot_plot, linewidth=1, label='IoT')
    ax2.fill(angles, iot_plot, alpha=0.1)
    ax2.plot(angles, non_iot_plot, linewidth=1, label='Non-IoT')
    ax2.fill(angles, non_iot_plot, alpha=0.1)
    ax2.set_xticks(angles[:-1])
    ax2.set_xticklabels(categories)
    ax2.set_title('MASVS Area Violations (Count of Apps with ≥1 Issue)')
    ax2.legend(loc='upper right', bbox_to_anchor=(1.3, 1.1))
    plt.tight_layout()
    plt.savefig("figures/radar_masvs_iot_vs_non_iot.png")
    plt.close(fig2)

    # 3) Horizontal Bar Chart
    permissions = ["ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION", "POST_NOTIFICATIONS", "WRITE_EXTERNAL_STORAGE", "CAMERA", "DUMP", "READ_EXTERNAL_STORAGE", "BLUETOOTH_CONNECT", "BLUETOOTH_SCAN", "BIND_JOB_SERVICE"]
    prevalence = [84.9, 80.9, 77.3, 74.7, 72.9, 72.9, 72.9, 64.9, 63.1, 55.6]
    y_pos = np.arange(len(permissions))

    fig3, ax3 = plt.subplots()
    ax3.barh(y_pos, prevalence)
    ax3.set_yticks(y_pos)
    ax3.set_yticklabels(permissions)
    ax3.invert_yaxis()
    ax3.set_xlabel('Prevalence (%)')
    ax3.set_title('Dangerous Permissions in IoT Apps')
    plt.tight_layout()
    plt.savefig("figures/hbar_permissions_iot.png")
    plt.close(fig3)

    print("[OK] Generated presentation charts (figures/*.png)")


def generate_all_visualizations():
    print("Generating visualizations...")
    generate_permissions_table()
    generate_flags_table()
    generate_credentials_table()
    plot_top_domains()
    plot_risk_scores()
    plot_masvs_violations()
    plot_presentation_charts()
