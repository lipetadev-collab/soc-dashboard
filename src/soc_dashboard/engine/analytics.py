from __future__ import annotations

from collections import Counter

from soc_dashboard.models import SecurityEvent


def top_attacking_ips(events: list[SecurityEvent], limit: int = 5) -> list[tuple[str, int]]:
    return Counter(event.source_ip for event in events).most_common(limit)


def alerts_by_severity(events: list[SecurityEvent]) -> list[tuple[str, int]]:
    return Counter(event.severity.value for event in events).most_common()


def targeted_destinations(events: list[SecurityEvent], limit: int = 5) -> list[tuple[str, int]]:
    return Counter(event.destination for event in events).most_common(limit)
