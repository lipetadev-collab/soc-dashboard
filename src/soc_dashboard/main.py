from __future__ import annotations

from soc_dashboard.config import DashboardConfig
from soc_dashboard.ui.app import SOCDashboardApp


def run() -> None:
    config = DashboardConfig.load()
    app = SOCDashboardApp(config=config)
    app.run()


if __name__ == "__main__":
    run()
