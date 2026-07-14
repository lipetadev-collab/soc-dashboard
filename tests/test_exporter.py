from datetime import datetime
from pathlib import Path

from soc_dashboard.exporter import Exporter
from soc_dashboard.models import IOCRecord, SecurityEvent, Severity


def test_export_json_creates_file(tmp_path: Path) -> None:
    exporter = Exporter(tmp_path)
    events = [
        SecurityEvent(
            timestamp=datetime.now(),
            severity=Severity.HIGH,
            source_ip="1.2.3.4",
            destination="hostA",
            event_type="port_scan",
            description="scan",
        )
    ]
    iocs = [
        IOCRecord(
            ioc_type="ip",
            value="1.2.3.4",
            reputation="malicious",
            country="RU",
            asn="AS123",
            score=90,
            last_seen=datetime.now(),
        )
    ]
    out = exporter.export_all(events, iocs, fmt="json")
    assert out.exists()
    assert out.suffix == ".json"
