from __future__ import annotations

import sqlite3
from pathlib import Path

from soc_dashboard.models import IOCRecord


class IOCDatabase:
    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.db_path)
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS iocs (
                ioc_type TEXT NOT NULL,
                value TEXT PRIMARY KEY,
                reputation TEXT NOT NULL,
                country TEXT NOT NULL,
                asn TEXT NOT NULL,
                score INTEGER NOT NULL,
                last_seen TEXT NOT NULL
            )
            """
        )
        self.conn.commit()

    def upsert(self, record: IOCRecord) -> None:
        self.conn.execute(
            """
            INSERT INTO iocs (ioc_type, value, reputation, country, asn, score, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(value) DO UPDATE SET
              reputation=excluded.reputation,
              country=excluded.country,
              asn=excluded.asn,
              score=excluded.score,
              last_seen=excluded.last_seen
            """,
            (
                record.ioc_type,
                record.value,
                record.reputation,
                record.country,
                record.asn,
                record.score,
                record.last_seen.isoformat(),
            ),
        )
        self.conn.commit()
