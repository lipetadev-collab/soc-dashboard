from __future__ import annotations

from datetime import datetime, timedelta
import random

from soc_dashboard.models import IOCRecord


MITRE_TECHNIQUES = [
    "T1059 Command and Scripting Interpreter",
    "T1055 Process Injection",
    "T1078 Valid Accounts",
    "T1110 Brute Force",
    "T1021 Remote Services",
    "T1041 Exfiltration Over C2 Channel",
]


class ThreatIntelModule:
    def __init__(self) -> None:
        now = datetime.now()
        self._ioc_records: list[IOCRecord] = [
            IOCRecord("ip", "185.220.101.12", "malicious", "RU", "AS12345", 92, now - timedelta(minutes=2), ["botnet"]),
            IOCRecord("domain", "evil-domain.io", "suspicious", "Unknown", "Cloud", 74, now - timedelta(minutes=14), ["phishing"]),
            IOCRecord("hash", "8d7f7f83ad89f6f6d13f6e0f95af91c7", "malicious", "US", "AS15169", 88, now - timedelta(hours=1), ["ransomware"], "Lockbit", "SummerWave"),
        ]

    def get_recent_iocs(self, limit: int = 20) -> list[IOCRecord]:
        return sorted(self._ioc_records, key=lambda r: r.last_seen, reverse=True)[:limit]

    def refresh_feeds(self) -> None:
        if random.random() < 0.35:
            self._ioc_records.append(
                IOCRecord(
                    ioc_type="ip",
                    value=f"103.44.{random.randint(1,254)}.{random.randint(1,254)}",
                    reputation=random.choice(["suspicious", "malicious"]),
                    country=random.choice(["CN", "RU", "BR", "VN", "Unknown"]),
                    asn=f"AS{random.randint(1000,99999)}",
                    score=random.randint(65, 98),
                    last_seen=datetime.now(),
                    tags=["c2", "scanner"],
                )
            )

    def lookup(self, term: str) -> list[IOCRecord]:
        normalized = term.strip().lower()
        if not normalized:
            return []
        return [
            rec
            for rec in self._ioc_records
            if normalized in rec.value.lower() or any(normalized in tag for tag in rec.tags)
        ]
