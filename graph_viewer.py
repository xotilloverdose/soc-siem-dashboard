from collections import Counter
import matplotlib.pyplot as plt
import re

# -------------------------
# READ LOG FILE
# -------------------------

with open("sample_logs.txt", "r") as file:
    logs = file.readlines()

# -------------------------
# EXTRACT IPS
# -------------------------

ips = []

for line in logs:

    found = re.findall(r"\d+\.\d+\.\d+\.\d+", line)

    if found:
        ips.append(found[0])

# -------------------------
# COUNT IPS
# -------------------------

counts = Counter(ips)

labels = list(counts.keys())
values = list(counts.values())

# -------------------------
# CREATE GRAPH
# -------------------------

plt.figure(figsize=(12, 6))

bars = plt.bar(labels, values)

plt.title("LIVE SIEM ATTACK GRAPH")

plt.xlabel("Attacker IP")

plt.ylabel("Attack Attempts")

plt.xticks(rotation=15)

# -------------------------
# SHOW VALUES
# -------------------------

for bar in bars:

    height = bar.get_height()

    plt.text(
        bar.get_x() + bar.get_width()/2,
        height,
        str(height),
        ha='center',
        va='bottom'
    )

# -------------------------
# SAVE GRAPH
# -------------------------

plt.tight_layout()

plt.savefig("attack_graph.png")

print("📈 Attack graph generated successfully!")