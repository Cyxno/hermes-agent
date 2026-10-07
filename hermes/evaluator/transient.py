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
        counts = {row["fingerprint"]: row for row in rows}
        # Episode-einde: een open pattern-incident hoort bij het transient-
        # venster, niet bij het live-signaal. Zakt het aantal transients in het
        # venster onder de drempel, dan is de episode voorbij en lost het
        # incident af (met recovery-notificatie indien eerder gealert).
        for incident in self.engine.open_incidents():
            if incident.category != "transient_pattern":
                continue
            fp = incident.id.removeprefix("transient_pattern:")
            row = counts.get(fp)
            base = self.engine.get(fp)
            if base is not None and base.open:
                continue  # echt incident actief: patroon blijft zien
            n = int(row["n"]) if row else 0
            threshold = int(self.overrides.get(row["category"], self.threshold)) if row else self.threshold
            if n < threshold:
                self.engine.resolve_manual(
                    incident.id,
                    f"patroon gedempt: {n} transients in venster (< drempel {threshold})",
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
                    "transients", "pattern incident confirmed",
                    fingerprint=fp, count=row["n"], window_hours=int(self.window / 3600),
                )
