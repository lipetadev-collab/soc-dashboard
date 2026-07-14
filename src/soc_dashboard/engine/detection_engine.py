from __future__ import annotations

from collections import Counter

from soc_dashboard.models import SecurityEvent, Severity


class DetectionEngine:
    """Very lightweight rule engine for demo workflows."""

    def __init__(self) -> None:
        self._ip_fail_counter: Counter[str] = Counter()

    def enrich(self, events: list[SecurityEvent]) -> list[SecurityEvent]:
        for event in events:
            if event.event_type in {"failed_login", "auth_failure"}:
                self._ip_fail_counter[event.source_ip] += 1
                if self._ip_fail_counter[event.source_ip] > 5 and event.severity != Severity.CRITICAL:
                    event.severity = Severity.HIGH
                    event.description = "Escalated repeated authentication failures"
            if "malware" in event.event_type:
                event.severity = Severity.CRITICAL
        return events
