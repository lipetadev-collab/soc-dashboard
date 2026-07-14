from __future__ import annotations

from collections import deque
from datetime import datetime
import random


class LogParser:
    SOURCES = ["syslog", "windows", "zeek", "suricata", "wazuh", "falco", "auditd"]

    def __init__(self, max_lines: int = 400) -> None:
        self._lines: deque[str] = deque(maxlen=max_lines)

    def ingest_simulated(self, count: int = 4) -> None:
        severities = ["INFO", "WARN", "HIGH", "CRIT"]
        messages = [
            "User session token issued",
            "IDS signature: Potential C2 beacon",
            "Audit policy change detected",
            "Falco: shell opened in container",
            "Suricata: ET SCAN NMAP",
            "Kerberos pre-auth failed",
        ]
        for _ in range(count):
            ts = datetime.now().strftime("%H:%M:%S")
            line = f"{ts} [{random.choice(self.SOURCES).upper():8}] [{random.choice(severities):4}] {random.choice(messages)}"
            self._lines.append(line)

    def tail(self, keyword: str = "", limit: int = 100) -> list[str]:
        lines = list(self._lines)
        if keyword:
            needle = keyword.lower()
            lines = [line for line in lines if needle in line.lower()]
        return lines[-limit:]
