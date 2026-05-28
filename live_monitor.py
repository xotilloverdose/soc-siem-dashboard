import random
import time

ips = [

    "8.8.8.8",
    "103.44.12.9",
    "45.12.33.10",
    "77.88.99.11",
    "88.21.77.3",
    "192.168.1.10"

]

while True:

    ip = random.choice(ips)

    with open(
        "sample_logs.txt",
        "a"
    ) as file:

        file.write(
            f"[FAILED LOGIN] {ip}\n"
        )

    print(
        f"Attack from {ip}"
    )

    time.sleep(
        0.5
    )