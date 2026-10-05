"""Lightweight rolling baselines for trend context (spec §19/§52).

Welford-style running stats per metric; used by the context builder ("known
baseline") and the daily summary. Not an anomaly engine — Netdata ML covers that.
"""

from __future__ import annotations

import math
import time

from ..state.db import Database


class Baselines:
    def __init__(self, db: Database) -> None:
        self.db = db

    def record(self, metric: str, value: float) -> None:
        row = self.db.one("SELECT samples, mean, stdev FROM baselines WHERE metric=?", (metric,))
        if row is None or not row["samples"]:
            self.db.execute(
                "INSERT INTO baselines(metric, mean, stdev, p95, samples, updated_at) VALUES(?,?,?,NULL,1,?)",
                (metric, value, 0.0, time.time()),
            )
            return
        n = int(row["samples"])
        mean = float(row["mean"])
        stdev = float(row["stdev"] or 0.0)
        n += 1
        delta = value - mean
        mean += delta / n
        stdev = math.sqrt(((n - 2) / (n - 1)) * stdev**2 + (delta * (value - mean)) ** 2 / n) if n > 2 else stdev
        self.db.execute(
            "UPDATE baselines SET mean=?, stdev=?, samples=?, updated_at=? WHERE metric=?",
            (mean, stdev, n, time.time(), metric),
        )

    def get(self, metric: str) -> dict | None:
        row = self.db.one("SELECT * FROM baselines WHERE metric=?", (metric,))
        if not row:
            return None
        return {"mean": row["mean"], "stdev": row["stdev"], "samples": row["samples"]}

    def compact(self) -> None:
        """Daily maintenance: keep the aggregate, drop stale rows (spec §20)."""
        self.db.execute(
            "DELETE FROM baselines WHERE updated_at < ?", (time.time() - 30 * 86400,)
        )
