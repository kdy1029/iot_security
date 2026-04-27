import pandas as pd
from .database import get_engine
from sqlalchemy import text

def calculate_risk_scores() -> pd.DataFrame:
    """Calculates risk scores based on permissions, cleartext flags, and backup flags."""
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
        return df_risk
