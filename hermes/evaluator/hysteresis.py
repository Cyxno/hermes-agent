"""Band evaluation with hysteresis (spec §9).

Two-sided debounce:
- OPENING a band requires the value to stay above `warn` for `sustain_seconds`
  (per metric; a single dip below warn resets the pending timer). CPU 84/86
  flapping therefore never opens a band and never becomes a notification.
- CLOSING requires the value to drop below `warn - clear_margin` for
  `good_samples` consecutive evaluations.

While a band is open, every evaluation re-confirms (sustain evidence) so the
incident engine sees continuous breach presence. Band state persists in
metric_state so restarts do not reset hysteresis.

Band-carrying categories have engine debounce 0: the sustain window here IS
the debounce (single source of truth for time-based confirmation).
"""

from __future__ import annotations

from dataclasses import dataclass

from ..state.db import Database
from .signals import Signal


@dataclass
class BandResult:
    metric: str
    band: str  # ok | pending | warning | critical | cleared
    severity: str | None


class MetricBands:
    def __init__(self, db: Database, config: dict) -> None:
        self.db = db
        self.thresholds: dict[str, dict] = config.get("thresholds", {})
        self.sustains: dict[str, float] = {
            "default": 120.0,
            **{k: float(v) for k, v in config.get("sustains", {}).items()},
        }
        self.hysteresis_default = {"clear_margin_pp": 5, "good_samples": 2}
        self.hysteresis_overrides: dict[str, dict] = config.get("hysteresis", {}).get(
            "overrides", {}
        )
        self._cache: dict[str, dict] = {}

    def _settings(self, metric: str) -> dict:
        merged = dict(self.hysteresis_default)
        merged.update(self.hysteresis_overrides.get(metric, {}))
        return merged

    def _sustain(self, metric: str) -> float:
        return self.sustains.get(metric, self.sustains["default"])

    def _load(self, metric: str) -> dict:
        if metric not in self._cache:
            row = self.db.one(
                "SELECT band, breached_since, pending_since, good_samples FROM metric_state WHERE metric=?",
                (metric,),
            )
            self._cache[metric] = {
                "band": row["band"] if row else "ok",
                "breached_since": row["breached_since"] if row else None,
                "pending_since": row["pending_since"] if row else None,
                "good_samples": row["good_samples"] if row else 0,
            }
        return self._cache[metric]

    def _save(self, full_metric: str, value: float | None, now: float) -> None:
        st = self._cache[full_metric]
        self.db.execute(
            "INSERT INTO metric_state(metric, value, band, breached_since, pending_since, good_samples, updated_at) "
            "VALUES(?,?,?,?,?,?,?) ON CONFLICT(metric) DO UPDATE SET value=excluded.value, "
            "band=excluded.band, breached_since=excluded.breached_since, "
            "pending_since=excluded.pending_since, good_samples=excluded.good_samples, "
            "updated_at=excluded.updated_at",
            (full_metric, value, st["band"], st["breached_since"], st["pending_since"],
             st["good_samples"], now),
        )

    def evaluate(
        self,
        metric: str,
        value: float,
        now: float,
        entity: str = "host",
        source: str = "beacon",
        unit: str = "",
        evidence_extra: dict | None = None,
    ) -> Signal | None:
        limits = self.thresholds.get(metric)
        if not limits or value is None:
            return None
        warn = float(limits["warn"])
        crit = float(limits["crit"])
        settings = self._settings(metric)
        margin = float(settings["clear_margin_pp"])
        good_needed = int(settings["good_samples"])
        full_metric = f"{metric}:{entity}" if entity != "host" else metric
        st = self._load(full_metric)
        band = st["band"]
        label = metric.replace("_", " ")

        # ---- band closed (ok | pending) --------------------------------
        if band in ("ok", "pending"):
            if value >= warn:
                if band == "ok" or st.get("pending_since") is None:
                    st.update(band="pending", pending_since=now, good_samples=0)
                    self._save(full_metric, value, now)
                    return None
                if now - st["pending_since"] >= self._sustain(metric):
                    new_band = "critical" if value >= crit else "warning"
                    st.update(band=new_band, breached_since=st["pending_since"],
                              pending_since=None, good_samples=0)
                    self._save(full_metric, value, now)
                    evidence = {"source": source, "confirm": True, "value": value, "band": new_band,
                                "sustained_s": round(now - st["breached_since"] or 0, 0)}
                    if evidence_extra:
                        evidence.update(evidence_extra)
                    return Signal(
                        category=metric, entity=entity,
                        severity="critical" if new_band == "critical" else "warning",
                        source=source, ts=now, value=value,
                        title=f"{label} {new_band} op {entity}: {value}{unit}",
                        evidence=[evidence],
                    )
                self._save(full_metric, value, now)
                return None
            # below warn while pending: single dip resets the pending timer
            st.update(band="ok", pending_since=None, good_samples=0)
            self._save(full_metric, value, now)
            return None

        # ---- band open (warning | critical) -----------------------------
        if value >= crit and band != "critical":
            st.update(band="critical", good_samples=0, pending_since=None)
            self._save(full_metric, value, now)
            return Signal(
                category=metric, entity=entity, severity="critical", source=source,
                ts=now, value=value, title=f"{label} critical op {entity}: {value}{unit}",
                evidence=[{"source": source, "confirm": True, "value": value, "band": "critical"}],
            )
        if value >= warn:
            st.update(good_samples=0, pending_since=None)
            self._save(full_metric, value, now)
            return Signal(
                category=metric, entity=entity,
                severity="critical" if band == "critical" else "warning",
                source=source, ts=now, value=value, title=None,
                evidence=[{"source": source, "confirm": True, "value": value, "sustained": True}],
            )
        # below warn: recovery accounting (clear margin + good samples)
        if value <= warn - margin:
            st["good_samples"] = int(st["good_samples"]) + 1
            st["pending_since"] = None
            if st["good_samples"] >= good_needed:
                st.update(band="ok", breached_since=None, good_samples=0)
                self._save(full_metric, value, now)
                return Signal(
                    category=metric, entity=entity, severity="recovery", source=source,
                    ts=now, value=value, cleared=True, kind="recovery",
                    title=f"{label} hersteld op {entity}: {value}{unit}",
                    evidence=[{"source": source, "confirm": False, "value": value}],
                )
            self._save(full_metric, value, now)
        else:
            # inside the margin (indeterminate zone): neither breach nor recovery
            st.update(pending_since=None)
            self._save(full_metric, value, now)
        return None

    def breached_since(self, metric: str) -> float | None:
        st = self._load(metric)
        return st.get("breached_since")

    def active_band(self, metric: str) -> str:
        return self._load(metric)["band"]

    def active_metrics(self) -> list[str]:
        rows = self.db.query("SELECT metric, band FROM metric_state WHERE band NOT IN ('ok','pending')")
        return [(row["metric"], row["band"]) for row in rows]
