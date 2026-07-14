from __future__ import annotations

import random

from soc_dashboard.models import ProcessRecord


class ProcessMonitor:
    def snapshot(self, limit: int = 12) -> list[ProcessRecord]:
        records: list[ProcessRecord] = []
        for idx in range(limit):
            cpu = round(random.uniform(0.1, 80.0), 1)
            suspicious = cpu > 65 or random.random() < 0.08
            indicator = ""
            if suspicious:
                indicator = random.choice(
                    [
                        "High CPU spike",
                        "Unsigned binary",
                        "Reverse shell pattern",
                        "Unexpected parent process",
                    ]
                )
            records.append(
                ProcessRecord(
                    pid=1000 + idx,
                    user=random.choice(["root", "svc-api", "analyst", "system"]),
                    cpu_percent=cpu,
                    memory_mb=round(random.uniform(20, 1200), 1),
                    parent_pid=random.randint(1, 800),
                    executable=random.choice(["/usr/bin/python3", "/usr/sbin/sshd", "/opt/app/agent", "/bin/bash"]),
                    network_activity=random.choice(["idle", "dns", "http", "ssh", "tls"]),
                    suspicious=suspicious,
                    indicator=indicator,
                )
            )
        return records
