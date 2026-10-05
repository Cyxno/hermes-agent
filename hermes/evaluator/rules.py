"""Deterministic rule evaluation: NormalizedState -> Signals.

Rules are the ONLY place thresholds are applied; the incident engine never sees
raw metrics. Data-fusion confidence (spec §4) is expressed through evidence
entries: each carries `source` and `confirm`.
"""

from __future__ import annotations

from ..state.desired import IGNORED, DesiredStateManager
from ..state.normalized import NormalizedState
from .hysteresis import MetricBands
from .signals import Signal

BEACON_SEVERITY_MAP = {"info": "notice", "warning": "warning", "critical": "urgent"}

# Beacon issue categories treated as infrastructure catastrophes (spec §8 immediate).
IMMEDIATE_BEACON_CATEGORIES = frozenset(
    {"filesystem", "array", "parity", "disk"}
)


class RuleEvaluator:
    def __init__(self, bands: MetricBands, desired: DesiredStateManager, config: dict) -> None:
        self.bands = bands
        self.desired = desired
        self.config = config
        self.thresholds = config.get("thresholds", {})

    # ------------------------------------------------------------------
    def evaluate(self, state: NormalizedState, now: float, events_window: float = 900.0) -> list[Signal]:
        signals: list[Signal] = []
        signals.extend(self._band_rules(state, now))
        signals.extend(self._container_rules(state, now, events_window))
        signals.extend(self._source_rules(state, now))
        signals.extend(self._beacon_issue_rules(state, now))
        return [s for s in signals if self._entity_monitored(s.entity)]

    def _entity_monitored(self, entity: str) -> bool:
        if entity == "host" or entity.startswith(("disk:", "mount:", "iface:", "dev:")):
            return True
        return self.desired.monitored(entity)

    # ------------------------------------------------------------------
    def _band_rules(self, state: NormalizedState, now: float) -> list[Signal]:
        out: list[Signal] = []
        host = state.host
        if host.beacon and host.beacon.fresh(now) or host.fallback and host.fallback.ok:
            if host.cpu_pct is not None:
                sig = self.bands.evaluate("host_cpu_pct", host.cpu_pct, now, source="beacon")
                if sig:
                    out.append(sig)
                if host.cores and host.load5 is not None:
                    load5_pc = host.load5 / host.cores
                    sig = self.bands.evaluate("host_load5_per_core", load5_pc, now, source="beacon")
                    if sig:
                        out.append(sig)
            if host.mem_pct is not None:
                sig = self.bands.evaluate("host_memory_pct", host.mem_pct, now, source="beacon")
                if sig:
                    out.append(sig)
            if host.package_temp_c is not None:
                sig = self.bands.evaluate(
                    "host_package_temp_c", host.package_temp_c, now, source="beacon"
                )
                if sig:
                    out.append(sig)
            if host.iowait_pct is not None:
                sig = self.bands.evaluate(
                    "host_iowait_pct",
                    host.iowait_pct,
                    now,
                    source="netdata",
                    unit="% iowait",
                )
                if sig:
                    out.append(sig)
        for dev, ms in host.disk_await_ms.items():
            sig = self.bands.evaluate("disk_await_ms", ms, now, entity=f"dev:{dev}", source="netdata", unit=" ms/op")
            if sig:
                out.append(sig)
        for mount, pct in host.storage_used_pct.items():
            sig = self.bands.evaluate(
                "storage_used_pct", pct, now, entity=f"mount:{mount}", source="beacon", unit="% used"
            )
            if sig:
                out.append(sig)
        for name, view in state.containers.items():
            if view.cpu_throttle_pct is not None:
                sig = self.bands.evaluate(
                    "container_cpu_throttle_pct",
                    view.cpu_throttle_pct,
                    now,
                    entity=name,
                    source="netdata",
                    unit="% throttled",
                )
                if sig:
                    out.append(sig)
            if view.mem_util_pct is not None:
                sig = self.bands.evaluate(
                    "container_mem_util_pct",
                    view.mem_util_pct,
                    now,
                    entity=name,
                    source="netdata",
                    unit="% of limit",
                )
                if sig:
                    out.append(sig)
        if state.anomaly_rate is not None:
            sig = self.bands.evaluate(
                "anomaly_rate", state.anomaly_rate, now, source="netdata", unit=" anomaly-rate"
            )
            if sig:
                out.append(sig)
        return out

    # ------------------------------------------------------------------
    def _container_rules(self, state: NormalizedState, now: float, events_window: float) -> list[Signal]:
        out: list[Signal] = []
        beacon_fresh = state.source("beacon").fresh(now)
        for name, view in state.containers.items():
            lifecycle = self.desired.get(name)
            if lifecycle == IGNORED:
                continue
            # --- absent managed container (desired state, spec §14) ---
            if beacon_fresh and not view.is_running and lifecycle is None:
                self.desired.ensure_discovered(name)
                lifecycle = self.desired.get(name)
            if (
                beacon_fresh
                and not view.is_running
                and self.desired.absent_is_incident(name)
            ):
                out.append(
                    Signal(
                        category="container_exit",
                        entity=name,
                        severity="warning",
                        source="beacon",
                        ts=now,
                        title=f"Container {name} draait niet (state={view.state})",
                        evidence=[{"source": "beacon", "confirm": True, "state": view.state}],
                    )
                )
                continue
            # --- unhealthy: fused beacon + netdata (spec §2/§4) ---
            beacon_unhealthy = beacon_fresh and view.is_running and view.health == "unhealthy"
            netdata_unhealthy = view.health_status_netdata == 0
            if beacon_unhealthy or netdata_unhealthy:
                evidence: list[dict] = []
                if beacon_unhealthy:
                    evidence.append({"source": "beacon", "confirm": True, "health": view.health})
                if netdata_unhealthy:
                    evidence.append({"source": "netdata", "confirm": True, "health_status": 0})
                if beacon_unhealthy and netdata_unhealthy:
                    severity, note = "warning", "beacon+netdata bevestigen"
                elif beacon_unhealthy:
                    severity, note = "warning", "alleen beacon; netdata normaal"
                else:
                    # Beacon healthy, Netdata sees unhealthy -> latent candidate (spec §4)
                    severity, note = "notice", "latent: alleen netdata"
                out.append(
                    Signal(
                        category="container_unhealthy",
                        entity=name,
                        severity=severity,
                        source="beacon" if beacon_unhealthy else "netdata",
                        ts=now,
                        title=f"Container {name} unhealthy ({note})",
                        evidence=evidence,
                    )
                )
        # --- MANAGED services absent from the inventory entirely (spec §14) ---
        if beacon_fresh:
            for entity in self.desired.absence_candidates():
                if entity not in state.containers:
                    out.append(
                        Signal(
                            category="container_exit",
                            entity=entity,
                            severity="warning",
                            source="beacon",
                            ts=now,
                            title=f"MANAGED container {entity} ontbreekt volledig in de Beacon-inventaris",
                            evidence=[{"source": "beacon", "confirm": True, "state": "absent"}],
                        )
                    )
        # --- restart loops from recent docker transitions ---
        counts: dict[str, int] = {}
        for event in state.recent_events:
            if event.type != "docker.transition":
                continue
            if event.data.get("to") == "started":
                counts[event.data.get("name", "")] = counts.get(event.data.get("name", ""), 0) + 1
        for name, count in counts.items():
            if count >= 3:
                out.append(
                    Signal(
                        category="container_restart_loop",
                        entity=name,
                        severity="urgent",
                        source="derived",
                        ts=now,
                        value=count,
                        title=f"Container {name} herstart {count}x binnen {int(events_window/60)} min",
                        evidence=[{"source": "beacon-stream", "confirm": True, "restarts": count}],
                    )
                )
        return out

    # ------------------------------------------------------------------
    def _source_rules(self, state: NormalizedState, now: float) -> list[Signal]:
        out: list[Signal] = []
        beacon = state.source("beacon")
        netdata = state.source("netdata")
        fallback = state.source("fallback")

        if beacon.disabled:
            pass  # Agent API not configured: Hermes degrades, no alarm spam
        elif not beacon.ok:
            if fallback.ok:
                out.append(
                    Signal(
                        category="beacon_unavailable",
                        entity="host",
                        severity="warning",
                        source="fallback",
                        ts=now,
                        title="Beacon onbereikbaar; Unraid-host reageert wel (fallback actief)",
                        evidence=[{"source": "fallback", "confirm": True}],
                    )
                )
            elif fallback.disabled:
                out.append(
                    Signal(
                        category="beacon_unavailable",
                        entity="host",
                        severity="warning",
                        source="derived",
                        ts=now,
                        title="Beacon onbereikbaar; fallback niet geconfigureerd",
                        evidence=[],
                    )
                )
            else:
                out.append(
                    Signal(
                        category="host_unreachable",
                        entity="host",
                        severity="critical",
                        source="fallback",
                        ts=now,
                        title="Beacon én fallback onbereikbaar — waarschijnlijk host-uitval",
                        evidence=[
                            {"source": "beacon", "confirm": True, "error": beacon.error},
                            {"source": "fallback", "confirm": True, "error": fallback.error},
                        ],
                    )
                )
        elif beacon.stale:
            out.append(
                Signal(
                    category="beacon_stale",
                    entity="host",
                    severity="notice",
                    source="beacon",
                    ts=now,
                    title="Beacon-data is verouderd",
                    evidence=[{"source": "beacon", "confirm": False, "stale": True}],
                )
            )

        if state.sources.get("netdata") and not netdata.ok:
            out.append(
                Signal(
                    category="netdata_unavailable",
                    entity="host",
                    severity="notice",
                    source="derived",
                    ts=now,
                    title="Netdata onbereikbaar; monitoring gaat door met Beacon",
                    evidence=[{"source": "netdata", "confirm": False, "error": netdata.error}],
                )
            )
        return out

    # ------------------------------------------------------------------
    # Beacon conditions Hermes detects natively with fusion + debounce; they
    # are evidence in our own signals, not mirrored separately (no duplicates).
    NATIVE_BEACON_CONDITIONS = frozenset(
        {"container_unhealthy", "container_exited", "container_stopped"}
    )

    def _beacon_issue_rules(self, state: NormalizedState, now: float) -> list[Signal]:
        """Mirror Beacon issues into signals; Beacon is the primary issue detector."""
        out: list[Signal] = []
        for issue in state.issues:
            if issue.status not in ("active",):
                continue
            if issue.condition in self.NATIVE_BEACON_CONDITIONS:
                continue
            category = issue.category or "beacon_issue"
            target = issue.target or {}
            entity = str(target.get("name") or target.get("id") or "host")
            severity = BEACON_SEVERITY_MAP.get(issue.severity, "notice")
            if category in IMMEDIATE_BEACON_CATEGORIES and issue.severity == "critical":
                severity = "critical"
            out.append(
                Signal(
                    category=f"beacon_{category}",
                    entity=entity,
                    severity=severity,
                    source="beacon",
                    ts=now,
                    title=f"Beacon: {issue.summary}",
                    evidence=[
                        {
                            "source": "beacon",
                            "confirm": True,
                            "issue_id": issue.id,
                            "observed_for_s": issue.metrics.get("observedForSeconds"),
                        }
                    ],
                )
            )
        # storage/array immediate conditions from the storage view
        host = state.host
        if host.array_state and str(host.array_state).upper() == "STOPPED":
            out.append(
                Signal(
                    category="array_parity_fault",
                    entity="array",
                    severity="critical",
                    source="beacon",
                    ts=now,
                    title="Unraid-array is STOPPED",
                    evidence=[{"source": "beacon", "confirm": True, "array_state": host.array_state}],
                )
            )
        for disk in host.disks:
            if disk.role in ("parity", "data") and disk.state and "missing" in str(disk.state).lower():
                out.append(
                    Signal(
                        category="disk_missing",
                        entity=f"disk:{disk.name}",
                        severity="critical",
                        source="beacon",
                        ts=now,
                        title=f"Schijf {disk.name} ontbreekt ({disk.state})",
                        evidence=[{"source": "beacon", "confirm": True, "state": disk.state}],
                    )
                )
        return out
