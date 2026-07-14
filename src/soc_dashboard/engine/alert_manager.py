from __future__ import annotations

from collections import Counter

from soc_dashboard.models import SecurityEvent, Severity


class AlertManager:
    def summarize(self, events: list[SecurityEvent]) -> dict[str, int]:
        counter = Counter(event.severity.value for event in events)
        return {
            "critical": counter.get(Severity.CRITICAL.value, 0),
            "high": counter.get(Severity.HIGH.value, 0),
            "medium": counter.get(Severity.MEDIUM.value, 0),
            "low": counter.get(Severity.LOW.value, 0),
            "info": counter.get(Severity.INFO.value, 0),
        }
