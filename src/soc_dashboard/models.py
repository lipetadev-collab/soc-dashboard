from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass(slots=True)
class SystemHealth:
    cpu_percent: float
    memory_percent: float
    disk_percent: float
    network_mbps: float
    active_users: int
    sessions: int
    running_services: int
    uptime: str


@dataclass(slots=True)
class SecurityEvent:
    timestamp: datetime
    severity: Severity
    source_ip: str
    destination: str
    event_type: str
    description: str
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class IOCRecord:
    ioc_type: str
    value: str
    reputation: str
    country: str
    asn: str
    score: int
    last_seen: datetime
    tags: list[str] = field(default_factory=list)
    malware_family: str | None = None
    campaign: str | None = None


@dataclass(slots=True)
class ConnectionRecord:
    protocol: str
    source: str
    destination: str
    destination_port: int
    state: str
    encrypted: bool


@dataclass(slots=True)
class ProcessRecord:
    pid: int
    user: str
    cpu_percent: float
    memory_mb: float
    parent_pid: int
    executable: str
    network_activity: str
    suspicious: bool
    indicator: str = ""


@dataclass(slots=True)
class IncidentEntry:
    timestamp: datetime
    text: str
