from __future__ import annotations

import csv
import json
from pathlib import Path
from datetime import datetime

from soc_dashboard.models import IOCRecord, SecurityEvent


class Exporter:
    def __init__(self, export_dir: Path) -> None:
        self.export_dir = export_dir
        self.export_dir.mkdir(parents=True, exist_ok=True)

    def export_all(
        self,
        events: list[SecurityEvent],
        iocs: list[IOCRecord],
        fmt: str = "json",
    ) -> Path:
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        fmt_normalized = fmt.lower()
        path = self.export_dir / f"soc_snapshot_{stamp}.{fmt_normalized}"
        if fmt_normalized == "json":
            data = {
                "events": [self._event_dict(event) for event in events],
                "iocs": [self._ioc_dict(ioc) for ioc in iocs],
            }
            path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        elif fmt_normalized == "csv":
            self._write_csv(path, events)
        elif fmt_normalized == "txt":
            self._write_txt(path, events, iocs)
        elif fmt_normalized == "md":
            self._write_markdown(path, events, iocs)
        elif fmt_normalized == "html":
            self._write_html(path, events, iocs)
        else:
            raise ValueError(f"Unsupported export format: {fmt}")
        return path

    def _write_csv(self, path: Path, events: list[SecurityEvent]) -> None:
        with path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.writer(handle)
            writer.writerow(["timestamp", "severity", "source_ip", "destination", "event_type", "description"])
            for event in events:
                writer.writerow(
                    [
                        event.timestamp.isoformat(),
                        event.severity.value,
                        event.source_ip,
                        event.destination,
                        event.event_type,
                        event.description,
                    ]
                )

    def _write_txt(self, path: Path, events: list[SecurityEvent], iocs: list[IOCRecord]) -> None:
        lines = ["SOC Snapshot", "=" * 40, "Events"]
        lines.extend(
            f"{event.timestamp:%H:%M:%S} {event.severity.value.upper():8} {event.source_ip:15} {event.description}"
            for event in events[-100:]
        )
        lines.extend(["", "IOCs"])
        lines.extend(f"{ioc.ioc_type:8} {ioc.value:35} score={ioc.score}" for ioc in iocs[:50])
        path.write_text("\n".join(lines), encoding="utf-8")

    def _write_markdown(self, path: Path, events: list[SecurityEvent], iocs: list[IOCRecord]) -> None:
        lines = ["# SOC Snapshot", "", "## Events", "", "| Time | Sev | Source | Description |", "|---|---|---|---|"]
        lines.extend(
            f"| {event.timestamp:%H:%M:%S} | {event.severity.value} | {event.source_ip} | {event.description} |"
            for event in events[-100:]
        )
        lines.extend(["", "## Threat Intel", "", "| IOC | Rep | Score |", "|---|---|---|"])
        lines.extend(f"| {ioc.value} | {ioc.reputation} | {ioc.score} |" for ioc in iocs[:50])
        path.write_text("\n".join(lines), encoding="utf-8")

    def _write_html(self, path: Path, events: list[SecurityEvent], iocs: list[IOCRecord]) -> None:
        rows = "".join(
            f"<tr><td>{event.timestamp:%H:%M:%S}</td><td>{event.severity.value}</td><td>{event.source_ip}</td><td>{event.description}</td></tr>"
            for event in events[-100:]
        )
        ioc_rows = "".join(
            f"<tr><td>{ioc.value}</td><td>{ioc.reputation}</td><td>{ioc.score}</td></tr>"
            for ioc in iocs[:50]
        )
        html = (
            "<html><body><h1>SOC Snapshot</h1><h2>Events</h2><table border='1'>"
            "<tr><th>Time</th><th>Severity</th><th>Source</th><th>Description</th></tr>"
            f"{rows}</table><h2>IOCs</h2><table border='1'>"
            "<tr><th>IOC</th><th>Reputation</th><th>Score</th></tr>"
            f"{ioc_rows}</table></body></html>"
        )
        path.write_text(html, encoding="utf-8")

    @staticmethod
    def _event_dict(event: SecurityEvent) -> dict[str, str]:
        return {
            "timestamp": event.timestamp.isoformat(),
            "severity": event.severity.value,
            "source_ip": event.source_ip,
            "destination": event.destination,
            "event_type": event.event_type,
            "description": event.description,
        }

    @staticmethod
    def _ioc_dict(ioc: IOCRecord) -> dict[str, str | int]:
        return {
            "ioc_type": ioc.ioc_type,
            "value": ioc.value,
            "reputation": ioc.reputation,
            "country": ioc.country,
            "asn": ioc.asn,
            "score": ioc.score,
            "last_seen": ioc.last_seen.isoformat(),
        }
