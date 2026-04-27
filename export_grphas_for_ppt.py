import matplotlib.pyplot as plt
import numpy as np

# 1) Grouped Bar Chart: IoT vs Non-IoT Findings & High Severity
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
plt.savefig("grouped_bar_iot_vs_non_iot.png")
plt.close(fig1)


# 2) Radar Chart: MASVS Violations (values from paper)
categories = [
    'MSTG-CODE',
    'MSTG-CRYPTO',
    'MSTG-NETWORK',
    'MSTG-PLATFORM',
    'MSTG-RESILIENCE',
    'MSTG-STORAGE'
]
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
plt.savefig("radar_masvs_iot_vs_non_iot.png")
plt.close(fig2)


# 3) Horizontal Bar Chart: Dangerous Permissions in IoT Apps
permissions = [
    "ACCESS_FINE_LOCATION",
    "ACCESS_COARSE_LOCATION",
    "POST_NOTIFICATIONS",
    "WRITE_EXTERNAL_STORAGE",
    "CAMERA",
    "DUMP",
    "READ_EXTERNAL_STORAGE",
    "BLUETOOTH_CONNECT",
    "BLUETOOTH_SCAN",
    "BIND_JOB_SERVICE",
]
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
plt.savefig("hbar_permissions_iot.png")
plt.close(fig3)


# 4) Histogram: Composite Risk Score Distribution (synthetic demo data)
np.random.seed(0)
risk_scores = np.concatenate([
    np.random.gamma(shape=2.0, scale=3.0, size=180),
    np.random.gamma(shape=4.0, scale=3.0, size=45)
])

fig4, ax4 = plt.subplots()
ax4.hist(risk_scores, bins=15)
ax4.set_xlabel('Risk Score')
ax4.set_ylabel('Number of Apps')
ax4.set_title('Distribution of Composite Risk Scores (IoT Apps)')

plt.tight_layout()
plt.savefig("hist_risk_scores_iot.png")
plt.close(fig4)
