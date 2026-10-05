"""Recurrent-transient detection (spec §12).

Transients are stored by the incident engine; this tracker turns repetition
into meaning: >= threshold transients of one fingerprint inside the window
raises a silent DEGRADED pattern incident.
"""

from __future__ import annotations

from ..clock import Clock
from ..log import info
from .incidents import IncidentEngine


class TransientTracker:
    def __init__(self, engine: IncidentEngine, config: dict, clock: Clock) -> None:
        self.engine = engine
        self.clock = clock
        self.window = float(config.get("transients", {}).get("window", 21600))
        self.threshold = int(config.get("transients", {}).get("threshold_default", 5))
        self.overrides: dict[str, int] = config.get("transients", {}).get("overrides", {})

    def check(self) -> None:
        now = self.clock.now()
        rows = self.engine.db.query(
            "SELECT fingerprint, category, entity, COUNT(*) AS n FROM transients "
            "WHERE ts > ? GROUP BY fingerprint HAVING n >= 2",
            (now - self.window,),
        )
        for row in rows:
            fp = row["fingerprint"]
            threshold = int(self.overrides.get(row["category"], self.threshold))
            if row["n"] < threshold:
                continue
            base_open = self.engine.get(fp)
            if base_open and base_open.open:
                continue  # real incident is already active
            if self.engine.pattern_incident_open(fp):
                continue
            pattern = self.engine.confirm_pattern(
                fp, row["category"], row["entity"], int(row["n"])
            )
            if pattern:
                info(
                    "transients", "pattern incident bevestigd",
                    fingerprint=fp, count=row["n"], window_hours=int(self.window / 3600),
                )
