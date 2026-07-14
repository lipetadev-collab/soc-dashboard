from __future__ import annotations

from collections import deque
from datetime import datetime
import random

from soc_dashboard.models import SecurityEvent, Severity


EVENT_TYPES: list[tuple[str, Severity, str]] = [
    ("failed_login", Severity.MEDIUM, "Multiple failed SSH logins detected"),
    ("login_success", Severity.LOW, "User login accepted"),
    ("privilege_escalation", Severity.HIGH, "Possible sudo abuse behavior"),
    ("malware_detected", Severity.CRITICAL, "Malware signature matched endpoint"),
    ("suspicious_process", Severity.HIGH, "Suspicious process tree execution"),
    ("port_scan", Severity.HIGH, "Distributed port scan identified"),
    ("brute_force", Severity.CRITICAL, "Brute-force authentication pattern"),
    ("firewall_event", Severity.MEDIUM, "Firewall deny on sensitive destination"),
    ("vpn_connection", Severity.LOW, "Remote VPN session established"),
    ("auth_failure", Severity.MEDIUM, "Authentication provider denied token"),
]


class EventEngine:
    def __init__(self, max_events: int = 300) -> None:
        self._events: deque[SecurityEvent] = deque(maxlen=max_events)
        self._destinations = ["ssh://core-db", "vpn-gateway", "web-frontend", "idp", "siem"]

    def generate(self, burst: int = 2) -> list[SecurityEvent]:
        generated: list[SecurityEvent] = []
        for _ in range(random.randint(1, burst)):
            event_type, severity, description = random.choice(EVENT_TYPES)
            event = SecurityEvent(
                timestamp=datetime.now(),
                severity=severity,
                source_ip=f"185.24.{random.randint(1,254)}.{random.randint(1,254)}",
                destination=random.choice(self._destinations),
                event_type=event_type,
                description=description,
            )
            self._events.append(event)
            generated.append(event)
        return generated

    def all_events(self) -> list[SecurityEvent]:
        return list(self._events)
