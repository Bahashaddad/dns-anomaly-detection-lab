"""Bounded SQLite event storage for one-host educational use."""

from pathlib import Path
import sqlite3
from collections import Counter
from contextlib import closing


class EventStore:
    def __init__(self, path, max_events=1000):
        if not 1 <= max_events <= 100000:
            raise ValueError("max_events must be 1-100000")
        self.path = Path(path)
        self.max_events = max_events
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with closing(self.connect()) as db, db:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute(
                "CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY, timestamp TEXT NOT NULL, source_ip TEXT NOT NULL, domain TEXT NOT NULL, qtype TEXT NOT NULL, entropy REAL NOT NULL, first_label_length INTEGER NOT NULL, label_count INTEGER NOT NULL, score INTEGER NOT NULL, verdict TEXT NOT NULL, popular INTEGER NOT NULL, action TEXT NOT NULL)"
            )

    def connect(self):
        db = sqlite3.connect(self.path, timeout=5)
        db.row_factory = sqlite3.Row
        return db

    def append(self, event):
        fields = [
            "timestamp",
            "source_ip",
            "domain",
            "qtype",
            "entropy",
            "first_label_length",
            "label_count",
            "score",
            "verdict",
            "popular",
            "action",
        ]
        db = self.connect()
        try:
            with db:
                db.execute(
                    "INSERT INTO events ("
                    + ",".join(fields)
                    + ") VALUES ("
                    + ",".join("?" for _ in fields)
                    + ")",
                    [event[k] for k in fields],
                )
                db.execute(
                    "DELETE FROM events WHERE id NOT IN (SELECT id FROM events ORDER BY id DESC LIMIT ?)",
                    (self.max_events,),
                )
        finally:
            db.close()

    def snapshot(self, limit=200):
        db = self.connect()
        try:
            with db:
                db.execute("BEGIN")
                summary = Counter(
                    {
                        r["verdict"]: r["n"]
                        for r in db.execute(
                            "SELECT verdict, COUNT(*) n FROM events GROUP BY verdict"
                        )
                    }
                )
                events = [
                    dict(r)
                    for r in db.execute(
                        "SELECT * FROM events ORDER BY id DESC LIMIT ?",
                        (max(1, min(limit, 1000)),),
                    )
                ]
            return events, {
                "total": sum(summary.values()),
                "low": summary["LOW SCORE"],
                "suspicious": summary["SUSPICIOUS"],
                "high": summary["HIGH RISK"],
            }
        finally:
            db.close()
