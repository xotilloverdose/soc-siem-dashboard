from collections import Counter
import matplotlib.pyplot as plt
from matplotlib.animation import FuncAnimation
import re

fig, ax = plt.subplots()

def update(frame):

    ax.clear()

    try:

        with open(
            "sample_logs.txt",
            "r"
        ) as file:

            logs = file.readlines()

    except:

        logs = []

    ips = []

    for line in logs:

        found = re.findall(
            r"\d+\.\d+\.\d+\.\d+",
            line
        )

        if found:

            ips.append(found[0])

    counts = Counter(ips)

    labels = list(counts.keys())
    values = list(counts.values())

    ax.bar(
        labels,
        values
    )

    ax.set_title(
        "LIVE SIEM ATTACK GRAPH"
    )

    ax.set_xlabel(
        "Attacker IP"
    )

    ax.set_ylabel(
        "Attempts"
    )

    plt.xticks(
        rotation=20
    )

ani = FuncAnimation(
    fig,
    update,
    interval=2000,
    cache_frame_data=False
)

plt.tight_layout()

plt.show()