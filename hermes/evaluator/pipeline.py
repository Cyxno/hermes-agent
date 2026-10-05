"""Evaluation pipeline: one cycle = collect -> normalize -> rules -> engine ->
correlation -> transients -> intents -> FINAL RECHECK -> notify.

The final recheck before every notification is mandatory (spec §10); it fetches
FRESH state and cancels the notification when the condition no longer exists.
"""

from __future__ import annotations

from ..clock import Clock
from ..config import Config
from ..log import info, warning
from ..observer.base import poll_with_stamp
from ..observer.beacon import BeaconClient, BeaconStream, parse_beacon_issue
from ..observer.fallback import FallbackProbe
from ..observer.netdata import NetdataClient
from ..state.db import Database
from ..state.desired import DesiredStateManager
from ..state.normalized import ContainerView, NormalizedState, SourceStamp
from ..util import CircuitBreaker
from .correlation import ROOT_CATEGORIES, CorrelationEngine
from .hysteresis import MetricBands
from .incidents import Incident, IncidentEngine
from .rules import RuleEvaluator
from .signals import SEVERITY_RANK
from .transient import TransientTracker


class EvaluationPipeline:
    def __init__(
        self,
        cfg: Config,
        clock: Clock,
        db: Database,
        engine: IncidentEngine,
        bands: MetricBands,
        rules: RuleEvaluator,
        desired: DesiredStateManager,
        correlation: CorrelationEngine,
        tracker: TransientTracker,
        beacon: BeaconClient | None,
        netdata: NetdataClient | None,
        fallback: FallbackProbe | None,
        stream: BeaconStream | None = None,
        notifier=None,
        baseline_recorder=None,
    ) -> None:
        self.cfg = cfg
        self.clock = clock
        self.db = db
        self.engine = engine
        self.bands = bands
        self.rules = rules
        self.desired = desired
        self.correlation = correlation
        self.tracker = tracker
        self.beacon = beacon
        self.netdata = netdata
        self.fallback = fallback
        self.stream = stream
        self.notifier = notifier
        self.baseline_recorder = baseline_recorder
        self.breakers = {
            "beacon": CircuitBreaker(threshold=4, reset_after=120),
            "netdata": CircuitBreaker(threshold=4, reset_after=120),
            "fallback": CircuitBreaker(threshold=2, reset_after=60),
        }
        self.last_state: NormalizedState | None = None

    # ------------------------------------------------------------------
    # collection
    # ------------------------------------------------------------------
    async def collect(self, kind: str) -> NormalizedState:
        now = self.clock.now()
        state = NormalizedState(ts=now)
        beacon_stamp, netdata_stamp, fallback_stamp = await self._collect_sources(state, kind, now)
        state.sources = {"beacon": beacon_stamp, "netdata": netdata_stamp, "fallback": fallback_stamp}
        if self.stream is not None:
            state.recent_events = self.stream.drain()
        return state

    async def _collect_sources(self, state: NormalizedState, kind: str, now: float):
        beacon_stamp = SourceStamp(source="beacon", ok=False, disabled=True)
        netdata_stamp = SourceStamp(source="netdata", ok=False)
        fallback_stamp = SourceStamp(source="fallback", ok=False, disabled=True)

        if self.beacon is not None and self.cfg.section("sources.beacon")["enabled"]:
            async def fetch_beacon():
                summary, issues = await asyncio_gather(self.beacon.summary(), self.beacon.issues())
                # /docker every fast cycle: health flips are NOT SSE transitions,
                # and the incident engine needs continuous container truth.
                docker = await self.beacon.docker()
                storage = await self.beacon.storage() if kind == "reconcile" else {}
                system = await self.beacon.system() if kind == "reconcile" else {}
                return {"summary": summary, "issues": issues, "docker": docker,
                        "storage": storage, "system": system}

            result = await poll_with_stamp("beacon", fetch_beacon, self.clock, self.breakers["beacon"], now)
            beacon_stamp = result.stamp
            state.sources["beacon"] = beacon_stamp
            if result.data:
                self._apply_beacon(state, result.data, now)
        else:
            beacon_stamp.disabled = True
            state.sources["beacon"] = beacon_stamp

        if self.netdata is not None and self.cfg.section("sources.netdata")["enabled"]:
            async def fetch_netdata():
                alarms = await self.netdata.alarms()
                return {"alarms": alarms}

            result = await poll_with_stamp("netdata", fetch_netdata, self.clock, self.breakers["netdata"], now)
            netdata_stamp = result.stamp
            state.sources["netdata"] = netdata_stamp
            if result.data:
                state.netdata_alarms = result.data.get("alarms", [])
        else:
            netdata_stamp.disabled = True
            state.sources["netdata"] = netdata_stamp

        if beacon_stamp.ok is False and not beacon_stamp.disabled and self.fallback is not None:
            async def fetch_fallback():
                view = await self.fallback.probe()
                return {"view": view}

            result = await poll_with_stamp(
                "fallback", fetch_fallback, self.clock, self.breakers["fallback"], now
            )
            fallback_stamp = SourceStamp(
                source="fallback", ok=result.data["view"].host_ok if result.data else False,
                ts=now, error=result.stamp.error if result.stamp else None,
            )
            fallback_stamp.disabled = False
            state.sources["fallback"] = fallback_stamp
            if result.data:
                view = result.data["view"]
                state.host.fallback = fallback_stamp
                state.host.docker_daemon_ok = view.docker_hint if view.docker_hint is not None else None
                if not beacon_stamp.ok:
                    # fallback metrics feed the same band rules (clearly labeled)
                    if view.mem_used_pct is not None and state.host.mem_pct is None:
                        state.host.mem_pct = view.mem_used_pct
                    if view.load5 is not None and state.host.load5 is None:
                        state.host.load5 = view.load5
        else:
            fallback_stamp.disabled = True

        if self.netdata is not None and netdata_stamp.ok and kind in ("reconcile", "baseline"):
            await self._enrich_from_netdata(state)
        return beacon_stamp, netdata_stamp, fallback_stamp

    def _apply_beacon(self, state: NormalizedState, data: dict, now: float) -> None:
        summary = data.get("summary", {})
        host = state.host
        host.beacon = state.sources.get("beacon")
        cpu = summary.get("cpu") or {}
        memory = summary.get("memory") or {}
        load = summary.get("load") or {}
        thermal = summary.get("thermal") or {}
        if isinstance(cpu, dict):
            host.cpu_pct = cpu.get("percent")
        if isinstance(load, dict):
            host.load5 = load.get("five")
        if isinstance(memory, dict) and memory.get("percent") is not None:
            host.mem_pct = memory.get("percent")
        if isinstance(thermal, dict):
            host.package_temp_c = thermal.get("currentC")
        deps = summary.get("dependencies") or {}
        if isinstance(deps, dict) and deps.get("unraid") is not None:
            pass  # Beacon's own dependency view; Hermes keeps its own probe verdicts
        docker_summary = summary.get("docker") or {}
        if isinstance(docker_summary, dict) and docker_summary.get("running") is not None:
            pass
        storage = data.get("storage") or {}
        host.array_state = storage.get("arrayState")
        host.parity_status = storage.get("parityStatus")
        for disk in storage.get("disks") or []:
            from ..state.normalized import DiskView

            host.disks.append(
                DiskView(
                    name=str(disk.get("name", "")),
                    role=disk.get("role"),
                    state=disk.get("state"),
                    temp_c=disk.get("temperatureC"),
                )
            )
        system = data.get("system") or {}
        temps = system.get("temperatures") or {}
        if host.package_temp_c is None and isinstance(temps, dict):
            host.package_temp_c = temps.get("packageC")
        issues_raw = data.get("issues", [])
        if isinstance(issues_raw, list):
            state.issues = [parse_beacon_issue(raw) for raw in issues_raw if isinstance(raw, dict)]
        docker_raw = data.get("docker", [])
        if isinstance(docker_raw, list):
            for raw in docker_raw:
                if not isinstance(raw, dict):
                    continue
                name = str(raw.get("name", "")).strip()
                if not name:
                    continue
                view = state.containers.setdefault(
                    name,
                    ContainerView(name=name, beacon=state.sources.get("beacon")),
                )
                view.state = str(raw.get("state", "unknown"))
                view.health = raw.get("health")
                view.image = raw.get("image")
                view.update_available = bool(raw.get("updateAvailable"))
                view.compose_project = raw.get("composeProject")
                view.management_type = raw.get("managementType")
                view.beacon = SourceStamp(source="beacon", ok=True, ts=now,
                                          stale=bool((raw.get("freshness") or {}).get("stale")))
        # persist entity metadata for correlation / commands
        for name, view in state.containers.items():
            if view.compose_project or view.image:
                self.db.execute(
                    "INSERT INTO entity_meta(entity, compose_project, image, management_type, updated_at) "
                    "VALUES(?,?,?,?,?) ON CONFLICT(entity) DO UPDATE SET compose_project=excluded.compose_project, "
                    "image=excluded.image, management_type=excluded.management_type, updated_at=excluded.updated_at",
                    (name, view.compose_project, view.image, view.management_type, now),
                )
            self.desired.ensure_discovered(name)

    async def _enrich_from_netdata(self, state: NormalizedState) -> None:
        """Bounded per-container / per-device enrichment (reconcile only, spec §52)."""
        interesting: list[str] = []
        active_entities = {
            inc.entity for inc in self.engine.open_incidents()
            if inc.category.startswith("container_")
        }
        issue_entities = {
            str((i.target or {}).get("name") or (i.target or {}).get("id") or "")
            for i in state.issues if i.target
        }
        candidates = list(active_entities | issue_entities)
        # rotate through remaining monitored containers to stay bounded
        all_names = [n for n, v in state.containers.items() if v.is_running]
        candidates += [n for n in all_names if n not in candidates]
        for name in candidates[:8]:
            interesting.append(name)
        for name in interesting:
            view = state.containers.get(name)
            if view is None:
                continue
            try:
                view.health_status_netdata = await self.netdata.container_health(name)
                if name in active_entities or name in issue_entities:
                    view.cpu_throttle_pct = await self.netdata.container_throttle_pct(name)
                    view.mem_util_pct = await self.netdata.container_mem_util_pct(name)
            except Exception as exc:  # noqa: BLE001 - enrichment is best-effort
                warning("netdata", "enrichment failed", container=name, error=str(exc)[:120])
        try:
            state.host.iowait_pct = await self.netdata.iowait_pct()
            state.anomaly_rate = await self.netdata.anomaly_rate()
            devices = sorted({d.name for d in state.host.disks if d.name})[:6]
            if devices:
                state.host.disk_await_ms = await self.netdata.disk_await(devices)
        except Exception as exc:  # noqa: BLE001
            warning("netdata", "host enrichment failed", error=str(exc)[:120])

    # ------------------------------------------------------------------
    # cycle
    # ------------------------------------------------------------------
    async def run_cycle(self, kind: str) -> dict:
        started = self.clock.monotonic()
        now = self.clock.now()
        state = await self.collect(kind)
        self.last_state = state
        signals = self.rules.evaluate(state, now)
        self.engine.ingest(signals)
        self.correlation.apply(state)
        self.tracker.check()
        if kind == "baseline" and self.baseline_recorder is not None:
            self.baseline_recorder(state)
        intents = self.engine.tick()
        notified, cancelled = await self._process_intents(intents)
        duration = self.clock.monotonic() - started
        summary = {
            "kind": kind,
            "signals": len(signals),
            "open_incidents": len(self.engine.open_incidents()),
            "intents": len(intents),
            "notified": notified,
            "cancelled": cancelled,
            "sources": {k: {"ok": v.ok, "disabled": v.disabled, "stale": v.stale} for k, v in state.sources.items()},
            "duration_s": round(duration, 2),
        }
        info("pipeline", "cycle complete", **summary)
        return summary

    async def _process_intents(self, intents: list[dict]) -> tuple[int, int]:
        notified = cancelled = 0
        for intent in intents:
            incident: Incident = intent["incident"]
            if incident.suppressed and intent["kind"] in ("alert", "reminder"):
                continue  # correlated child: the root incident reports
            if intent["kind"] in ("alert", "reminder") and SEVERITY_RANK.get(incident.severity, 1) < 1:
                # notice severity: never a notification (spec §32); acknowledge locally
                # so the incident lifecycle completes and recovery stays silent (§11)
                self.engine.mark_acknowledged(incident.id)
                continue
            ok, reason = await self.final_recheck(incident)
            if not ok:
                self.engine.mark_cancelled(incident.id, reason)
                cancelled += 1
                info("pipeline", "notification geannuleerd door final recheck",
                     incident_id=incident.id, reason=reason)
                continue
            if self.notifier is None:
                continue
            delivered = await self.notifier.deliver(intent["kind"], self.engine.incident_snapshot(incident))
            if delivered:
                self.engine.mark_notified(incident.id, self.clock.now(), incident.severity)
                notified += 1
        return notified, cancelled

    # ------------------------------------------------------------------
    # final recheck (spec §10, §28)
    # ------------------------------------------------------------------
    async def final_recheck(self, incident: Incident) -> tuple[bool, str]:
        category = incident.category
        if category in ROOT_CATEGORIES:
            children = [
                i for i in self.engine.open_incidents()
                if i.root_incident == incident.id
            ]
            if children:
                return True, "affected incidents nog actief"
            return False, "geen affected incidents meer actief"
        if category == "transient_pattern":
            return True, "patroon-incident (geen enkele recheck)"
        entity = incident.entity
        fresh = await self._fresh_beacon()
        try:
            if category == "container_unhealthy":
                return await self._recheck_container_unhealthy(entity, fresh)
            if category == "container_exit":
                view = fresh.containers.get(entity)
                if view is None:
                    return False, f"{entity} verdwenen uit Beacon"
                if view.is_running:
                    return False, f"{entity} draait weer"
                return True, f"{entity} nog steeds {view.state}"
            if category in ("container_restart_loop", "container_high_cpu",
                            "container_memory_pressure", "container_memory_leak"):
                view = fresh.containers.get(entity)
                if view is None:
                    return False, f"{entity} verdwenen uit Beacon"
                unhealthy = view.health == "unhealthy"
                throttle = await self._safe_throttle(entity)
                if unhealthy or (throttle is not None and throttle >= 25):
                    return True, "conditie nog actief"
                return False, f"{entity} gezond in verse state"
            if category in ("host_memory_pct", "host_cpu_pct", "host_load5_per_core",
                            "host_package_temp_c", "storage_used_pct"):
                return self._recheck_host_band(incident, fresh)
            if category == "host_iowait_pct":
                if self.netdata is None:
                    return True, "netdata onbeschikbaar; conditie onverifieerbaar (behouden)"
                value = await self.netdata.iowait_pct()
                if value is None:
                    return True, "geen meetwaarde"
                warn = float(self.cfg.section("thresholds")["host_iowait_pct"]["warn"]) if "host_iowait_pct" in self.cfg.section("thresholds") else 30.0
                return (value >= warn, f"iowait {value}")
            if category == "disk_await_ms":
                dev = entity.split("dev:", 1)[-1]
                if self.netdata is None:
                    return True, "netdata onbeschikbaar"
                values = await self.netdata.disk_await([dev])
                warn = float(self.cfg.section("thresholds")["disk_await_ms"]["warn"])
                value = values.get(dev)
                if value is None:
                    return True, "geen meetwaarde"
                return (value >= warn, f"await {value} ms/op")
            if category == "anomaly_rate":
                if self.netdata is None:
                    return True, "netdata onbeschikbaar"
                value = await self.netdata.anomaly_rate()
                warn = float(self.cfg.section("thresholds")["anomaly_rate"]["warn"])
                return (value is not None and value >= warn, f"anomaly_rate {value}")
            if category == "beacon_unavailable":
                fresh_summary_ok = fresh.sources.get("beacon", SourceStamp("beacon", False)).ok
                if fresh_summary_ok:
                    return False, "Beacon weer bereikbaar"
                return True, "Beacon nog steeds onbereikbaar"
            if category == "host_unreachable":
                if self.fallback is not None:
                    view = await self.fallback.probe()
                    if view.host_ok:
                        return False, "host reageert weer via fallback"
                return True, "host nog steeds onbereikbaar"
            if category == "netdata_unavailable":
                if self.netdata is not None:
                    try:
                        await self.netdata.alarms()
                        return False, "Netdata weer bereikbaar"
                    except Exception:  # noqa: BLE001
                        pass
                return True, "Netdata nog steeds onbereikbaar"
            if category.startswith("beacon_"):
                fresh_issues = {i.id for i in fresh.issues}
                match = any(i.id in fresh_issues or i.category == incident.category.replace("beacon_", "", 1)
                            for i in fresh.issues)
                return (match, "beacon issue nog actief" if match else "beacon issue niet meer actief")
            if category in ("array_parity_fault", "disk_missing"):
                fresh2 = await self._fresh_beacon(storage=True)
                if category == "array_parity_fault":
                    return ((fresh2.host.array_state or "").upper() == "STOPPED",
                            f"array state {fresh2.host.array_state}")
                disk_name = entity.split(":", 1)[-1]
                for disk in fresh2.host.disks:
                    if disk.name == disk_name:
                        missing = disk.state and "missing" in str(disk.state).lower()
                        return (bool(missing), f"disk state {disk.state}")
                return False, "disk niet meer in storage-verzicht"
            if category == "filesystem_readonly":
                return True, "read-only filesystem vereist handmatig herstel"
            if category == "netdata_alarm" or category.startswith("netdata_"):
                if self.netdata is not None:
                    try:
                        alarms = await self.netdata.alarms()
                        for alarm in alarms:
                            if alarm.get("name") == incident.entity.split("@")[0]:
                                return True, "netdata alarm nog actief"
                        return False, "netdata alarm weg"
                    except Exception:  # noqa: BLE001
                        return True, "netdata onbereikbaar"
            # unknown category: keep the notification (conservative default)
            return True, "geen specifieke recheck; conditie verondersteld actief"
        except Exception as exc:  # noqa: BLE001 - recheck must never crash the cycle
            warning("pipeline", "final recheck faalde; notificatie behouden",
                    incident_id=incident.id, error=str(exc)[:160])
            return True, f"recheck error: {str(exc)[:80]}"

    async def _recheck_container_unhealthy(self, entity: str, fresh: NormalizedState):
        view = fresh.containers.get(entity)
        beacon_unhealthy = view is not None and view.is_running and view.health == "unhealthy"
        netdata_unhealthy = False
        if self.netdata is not None:
            try:
                netdata_unhealthy = await self.netdata.container_health(entity) == 0
            except Exception:  # noqa: BLE001
                pass
        if beacon_unhealthy or netdata_unhealthy:
            return True, "unhealthy bevestigd in verse state"
        return False, f"{entity} healthy in verse state"

    def _recheck_host_band(self, incident: Incident, fresh: NormalizedState):
        host = fresh.host
        metric = incident.category
        value = None
        warn = None
        try:
            warn = float(self.cfg.section("thresholds")[metric]["warn"])
        except KeyError:
            pass
        if metric == "host_memory_pct":
            value = host.mem_pct
        elif metric == "host_cpu_pct":
            value = host.cpu_pct
        elif metric == "host_load5_per_core":
            value = (host.load5 / host.cores) if host.load5 is not None and host.cores else None
        elif metric == "host_package_temp_c":
            value = host.package_temp_c
        elif metric == "storage_used_pct":
            value = max(host.storage_used_pct.values()) if host.storage_used_pct else None
        if value is None:
            return True, "geen verse meetwaarde; conditie verondersteld actief"
        if warn is None:
            return True, "geen drempel bekend"
        if value >= warn:
            return True, f"waarde {value} nog boven {warn}"
        return False, f"waarde {value} onder drempel {warn}"

    async def _safe_throttle(self, entity: str) -> float | None:
        if self.netdata is None:
            return None
        try:
            return await self.netdata.container_throttle_pct(entity)
        except Exception:  # noqa: BLE001
            return None

    async def _fresh_beacon(self, storage: bool = False) -> NormalizedState:
        state = NormalizedState(ts=self.clock.now())
        if self.beacon is None:
            state.sources = {"beacon": SourceStamp("beacon", False, error="not configured")}
            return state
        try:
            summary, issues = await asyncio_gather(self.beacon.summary(), self.beacon.issues())
            data = {"summary": summary, "issues": issues, "docker": await self.beacon.docker(),
                    "storage": await self.beacon.storage() if storage else {}, "system": {}}
            self._apply_beacon(state, data, self.clock.now())
            state.sources = {"beacon": SourceStamp("beacon", True, ts=self.clock.now())}
        except Exception as exc:  # noqa: BLE001
            state.sources = {"beacon": SourceStamp("beacon", False, error=str(exc)[:120])}
        return state


async def asyncio_gather(*aws):  # tiny indirection for testability
    import asyncio

    return await asyncio.gather(*aws)
