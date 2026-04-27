import os
import pandas as pd
from sqlalchemy import create_engine, text
from tabulate import tabulate

# -------------------------------------------------
# 0) Ensure output directories exist
# -------------------------------------------------
os.makedirs("tables", exist_ok=True)
os.makedirs("figures", exist_ok=True)

# -------------------------------------------------
# 1) Database Connection
#    Tip: if you're on psycopg3, use "postgresql+psycopg://..."
# -------------------------------------------------
engine = create_engine("postgresql://postgres:dud0926!@localhost:5432/iot_security")

# -------------------------------------------------
# 2) SQL — wrap with sqlalchemy.text(...)
# -------------------------------------------------
sql = text("""
WITH creds AS (
  SELECT app_id,
         COUNT(*) AS n_creds
  FROM v_mobsf_findings
  WHERE title ILIKE '%api key%'
     OR title ILIKE '%access token%'
     OR title ILIKE '%secret%'
     OR description ILIKE '%api key%'
     OR description ILIKE '%access token%'
     OR description ILIKE '%secret%'
  GROUP BY app_id
)
SELECT r.app_id,
       COALESCE(c.n_creds, 0) AS n_credential_findings,
       r.risk_score
FROM v_risk_score r
LEFT JOIN creds c USING (app_id)
WHERE COALESCE(c.n_creds, 0) > 0
ORDER BY n_credential_findings DESC, r.risk_score DESC
LIMIT 20;
""")

# -------------------------------------------------
# 3) Execute the query (use a Connection and read_sql_query)
# -------------------------------------------------
with engine.connect() as conn:
    df_creds = pd.read_sql_query(sql, conn)

# -------------------------------------------------
# 4) Save as a LaTeX table
# -------------------------------------------------
with open("tables/credentials.tex", "w", encoding="utf-8") as f:
    f.write(
        tabulate(
            df_creds.values,
            headers=["App ID", "Credential Findings", "Risk Score"],
            tablefmt="latex_booktabs",
        )
    )
