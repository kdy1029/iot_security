import pandas as pd
import matplotlib.pyplot as plt
from sqlalchemy import create_engine

engine = create_engine("postgresql://postgres:dud0926!@localhost:5432/iot_security")

sql = """
with per_app as (
  select masvs_area, app_id, count(*) as n_findings
  from v_masvs_mapping
  group by masvs_area, app_id
)
select masvs_area,
       avg(n_findings)::numeric as avg_findings_per_app
from per_app
group by masvs_area
order by avg_findings_per_app desc;
"""
df = pd.read_sql(sql, engine)

import matplotlib.pyplot as plt

plt.figure(figsize=(7,4))
plt.bar(df["masvs_area"], df["avg_findings_per_app"])
plt.ylabel("Avg Findings per App")
plt.title("Average MASVS Violations per App by Area")
plt.xticks(rotation=30, ha="right")
plt.tight_layout()
plt.savefig("figures/masvs_avg_findings.pdf")
