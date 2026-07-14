from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path


@dataclass(slots=True)
class DashboardConfig:
    refresh_interval: float = 1.5
    max_events: int = 300
    max_timeline: int = 200
    theme: str = "cyber-green"
    export_dir: Path = Path("exports")

    @classmethod
    def load(cls) -> "DashboardConfig":
        refresh = float(os.getenv("SOC_REFRESH_INTERVAL", "1.5"))
        max_events = int(os.getenv("SOC_MAX_EVENTS", "300"))
        theme = os.getenv("SOC_THEME", "cyber-green")
        export_dir = Path(os.getenv("SOC_EXPORT_DIR", "exports"))
        return cls(
            refresh_interval=max(refresh, 0.5),
            max_events=max(max_events, 50),
            theme=theme,
            export_dir=export_dir,
        )
