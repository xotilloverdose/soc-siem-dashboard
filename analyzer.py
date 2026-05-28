from collections import Counter
from datetime import datetime
import os
import re

BASE_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

LOG_FILE = os.path.join(
    BASE_DIR,
    "sample_logs.txt"
)

def detect_rule(ip, count):

    if count >= 150:

        return "CRITICAL", "Brute Force"

    elif count >= 80:

        return "HIGH", "Suspicious Activity"

    elif count >= 30:

        return "MEDIUM", "Repeated Failures"

    elif ip.startswith("192.168") and count > 50:

        return "HIGH", "Internal Threat"

    return "LOW", "Normal"


def analyze_logs(

    get_country,

    is_quarantined

):

    counts = Counter()

    timeline = []

    with open(

        LOG_FILE,

        "r",

        encoding="utf8",

        errors="ignore"

    ) as file:

        for line in file:

            ips = re.findall(

                r"\d+\.\d+\.\d+\.\d+",

                line

            )

            if ips:

                ip = ips[0]

                counts[ip] += 1

                timeline.append({

                    "time":

                    datetime.now().strftime(

                        "%H:%M:%S"

                    ),

                    "event":

                    line.strip()

                })

    data = []

    for ip, count in counts.items():

        severity, rule = detect_rule(

            ip,

            count

        )

        data.append({

            "ip": ip,

            "count": count,

            "country": get_country(ip),

            "severity": severity,

            "rule": rule,

            "auto_detected": count >= 120,

            "manual_blocked":

            is_quarantined(ip),

            "status": "NEW"

        })

    data.sort(

        key=lambda x: x["count"],

        reverse=True

    )

    return data, timeline[-30:]