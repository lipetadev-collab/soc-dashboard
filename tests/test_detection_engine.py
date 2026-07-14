from datetime import datetime

from soc_dashboard.engine.detection_engine import DetectionEngine
from soc_dashboard.models import SecurityEvent, Severity


def _event(source_ip: str) -> SecurityEvent:
    return SecurityEvent(
        timestamp=datetime.now(),
        severity=Severity.MEDIUM,
        source_ip=source_ip,
        destination="ssh://core-db",
        event_type="failed_login",
        description="failed auth",
    )


def test_detection_escalates_repeated_failures() -> None:
    engine = DetectionEngine()
    events = [_event("10.10.10.5") for _ in range(6)]
    result = engine.enrich(events)
    assert result[-1].severity == Severity.HIGH
