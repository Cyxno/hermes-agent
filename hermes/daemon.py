"""Hermes daemon: wires all components and runs the scheduler loops.

Loops (spec §20): fast (~60s), reconcile (~300s), baseline (~900s), daily.
Cycles never overlap (single pipeline lock). SIGTERM/SIGINT -> graceful stop.
Shadow mode: no real notifications, executor forced to dry-run (spec §48).
"""

from __future__ import annotations

import asyncio
import os
import signal
import time
from dataclasses import dataclass, field

import aiohttp

from . import version_info
from .clock import SystemClock
from .config import Config, load_config
from .evaluator.baselines import Baselines
from .evaluator.correlation import CorrelationEngine
from .evaluator.hysteresis import MetricBands
from .evaluator.incidents import IncidentEngine
from .evaluator.pipeline import EvaluationPipeline
from .evaluator.rules import RuleEvaluator
from .evaluator.transient import TransientTracker
from .executor.capabilities import CapabilityRegistry
from .executor.executor import Executor, SshOperator
from .executor.policy import ApprovalStore, PolicyEngine
from .intelligence.context import ContextBuilder
from .intelligence.provider import NullProvider, OpenRouterProvider
from .intelligence.router import AIRouter
from .interfaces.commands import CommandHandler
from .interfaces.notifier import Notifier
from .interfaces.telegram import TelegramClient, format_daily_summary
from .log import error, info, warning
from .observer.base import AiohttpPort
from .observer.beacon import BeaconClient, BeaconStream, StreamingHttpPort
from .observer.fallback import FallbackProbe, SshProbe
from .observer.netdata import NetdataClient
from .runbooks.engine import RunbookEngine
from .runbooks.verification import Diagnostics
from .state.db import Database
from .state.desired import DesiredStateManager
from .util import sanitize

DEFINITIONS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "hermes", "runbooks", "definitions")


@dataclass
class SelfMetrics:
    started_at: float = field(default_factory=time.time)
    last_fast: float = 0.0
    last_reconcile: float = 0.0
    last_baseline: float = 0.0
    last_daily: float = 0.0
    last_beacon_ok: float = 0.0
    last_netdata_ok: float = 0.0
    last_fallback: float = 0.0
    sse_status: str = "never"
    cycles: int = 0
    telegram_polls: int = 0


class HermesApp:
    def __init__(self, cfg: Config, data_dir: str | None = None) -> None:
        self.cfg = cfg
        self.clock = SystemClock()
        self.data_dir = data_dir or str(cfg.raw.get("data_dir", "/data"))
        os.makedirs(self.data_dir, exist_ok=True)
        self.db = Database(os.path.join(self.data_dir, "hermes.db"))
        self.db.migrate()
        self.metrics = SelfMetrics()
        self._pipeline_lock = asyncio.Lock()
        self._stop = asyncio.Event()
        self.desired = DesiredStateManager(self.db, cfg.section("desired_state"))
        self.desired.seed_from_config()
        self._build_observers()
        self._build_engine()
        self._build_intelligence()
        self._build_executor_and_runbooks()
        self._build_interfaces()

    # ------------------------------------------------------------------
    def _build_observers(self) -> None:
        self.session: aiohttp.ClientSession | None = None
        beacon_cfg = self.cfg.section("sources.beacon")
        net_cfg = self.cfg.section("sources.netdata")
        fb_cfg = self.cfg.section("sources.fallback")
        self.beacon: BeaconClient | None = None
        self.stream: BeaconStream | None = None
        self.netdata: NetdataClient | None = None
        self.fallback: FallbackProbe | None = None
        if beacon_cfg["enabled"]:
            self.beacon = BeaconClient(
                http=None, base_url=beacon_cfg["base_url"], token=str(beacon_cfg["token"] or "")
            )  # http port assigned in start()
        if net_cfg["enabled"]:
            self.netdata = NetdataClient(http=None, base_url=net_cfg["base_url"],
                                         ml_chart=str(net_cfg.get("ml_chart", "") or ""))
        ssh_probe = None
        if fb_cfg.get("ssh_enabled") and fb_cfg.get("ssh_host"):
            ssh_probe = SshProbe(fb_cfg["ssh_host"], fb_cfg["ssh_key_path"], fb_cfg["ssh_known_hosts"])
        if fb_cfg["enabled"]:
            self.fallback = FallbackProbe(http=None, prometheus_url=fb_cfg["prometheus_url"], ssh=ssh_probe)

    def _build_engine(self) -> None:
        raw = self.cfg.raw
        self.bands = MetricBands(self.db, raw)
        self.rules = RuleEvaluator(self.bands, self.desired, raw)
        self.engine = IncidentEngine(self.db, raw, self.clock,
                                     fast_interval=float(raw["scheduler"]["fast_interval"]))
        self.correlation = CorrelationEngine(self.engine, raw, self.clock)
        self.tracker = TransientTracker(self.engine, raw, self.clock)
        self.baselines = Baselines(self.db)

    def _build_intelligence(self) -> None:
        ai_cfg = self.cfg.section("ai")
        if ai_cfg["enabled"] and ai_cfg["api_key"]:
            self.ai_provider = OpenRouterProvider(api_key=str(ai_cfg["api_key"]),
                                                  base_url=ai_cfg["base_url"])
        else:
            self.ai_provider = NullProvider()
            info("ai", "AI uitgeschakeld of zonder key; deterministische modus")
        self.ai_router = AIRouter(dict(ai_cfg), self.ai_provider, self.db, self.clock)
        self.context_builder = ContextBuilder(
            dict(ai_cfg), self.db, baseline_lookup=self.baselines.get,
            events_path=os.path.join(self.data_dir, "docker-events.log"),
        )

    def _build_executor_and_runbooks(self) -> None:
        raw = self.cfg.raw
        exec_cfg = raw["executor"]
        mode = exec_cfg["mode"]
        if self.cfg.shadow and mode == "guarded":
            mode = "dry-run"
            warning("executor", "shadow mode forceert dry-run executor")
        exec_cfg["mode"] = mode
        self.registry = CapabilityRegistry()
        self.policy = PolicyEngine(exec_cfg)
        self.approvals = ApprovalStore(self.db, self.clock)
        operator = None
        if exec_cfg.get("ssh_host"):
            operator = SshOperator(exec_cfg["ssh_host"], exec_cfg["ssh_key_path"],
                                   exec_cfg["ssh_known_hosts"])
        self.executor = Executor(
            exec_cfg, self.registry, self.policy, self.approvals, operator, self.db, self.clock,
            lifecycle_lookup=self.desired.get,
            attempts_lookup=self._incident_attempts,
            root_incident_open=self._root_incident_open,
            fresh_recheck=self._fresh_action_recheck,
        )
        self.diagnostics = Diagnostics(
            beacon=self._BeaconShim(self.beacon), netdata=self.netdata,
            incident_engine=self.engine, bands=self.bands, config=raw,
        )
        self.runbooks = RunbookEngine(
            DEFINITIONS_DIR, self.executor, self.registry, self.diagnostics,
            self.clock, sleep=asyncio.sleep, db=self.db,
        )
        self.pipeline = EvaluationPipeline(
            self.cfg, self.clock, self.db, self.engine, self.bands, self.rules,
            self.desired, self.correlation, self.tracker,
            beacon=self.beacon, netdata=self.netdata, fallback=self.fallback,
            notifier=None,  # set in _build_interfaces
            baseline_recorder=self._record_baselines,
        )

    def _build_interfaces(self) -> None:
        tg_cfg = self.cfg.section("telegram")
        self.telegram: TelegramClient | None = None
        if tg_cfg["enabled"] and tg_cfg["bot_token"]:
            self.telegram = TelegramClient(token=str(tg_cfg["bot_token"]))
        self.notifier = Notifier(self.cfg, self.db, self.clock, self.telegram,
                                 affected_lookup=self._affected_of)
        self.pipeline.notifier = self.notifier
        self.commands = CommandHandler(self, self.telegram)

    # -- small adapters ----------------------------------------------------
    class _BeaconShim:
        """Diagnostics needs only .docker(); reuse the pipeline's client lazily."""

        def __init__(self, client) -> None:  # noqa: ANN001
            self._client = client

        async def docker(self):
            if self._client is None:
                return []
            return await self._client.docker()

    def _incident_attempts(self, incident_id: str | None) -> int:
        if not incident_id:
            return 0
        row = self.db.one(
            "SELECT COUNT(*) AS n FROM action_audit WHERE incident_id=? AND mode='real' AND result LIKE 'exit=%'",
            (incident_id,),
        )
        return int(row["n"]) if row else 0

    def _root_incident_open(self, incident_id: str | None) -> bool:
        """§C17: correlated root cause active -> suppress child self-healing."""
        if not incident_id:
            return False
        inc = self.engine.get(incident_id)
        if inc is None or not inc.root_incident:
            return False
        root = self.engine.get(inc.root_incident)
        return bool(root and root.open)

    async def _fresh_action_recheck(self, plan) -> tuple[bool, str]:  # noqa: ANN001
        """§C13: immediately before a real mutation, fresh Beacon inventory
        must still support the action. Separate from the notification
        final-recheck; a stale action plan is cancelled, not executed."""
        if self.beacon is None:
            return True, "no beacon client; transport gates apply"
        try:
            docker = await self.beacon.docker()
        except Exception as exc:  # noqa: BLE001 - cannot verify -> do not act
            return False, f"fresh state unavailable: {sanitize(exc, 80)}"
        view = next((d for d in docker if isinstance(d, dict) and d.get("name") == plan.target), None)
        if view is None:
            return False, f"{plan.target} no longer present in fresh inventory"
        state, health = view.get("state"), view.get("health")
        if plan.capability == "docker.restart":
            if state != "running":
                return False, f"{plan.target} is no longer running ({state!r})"
            if health in (None, "healthy"):
                return False, f"{plan.target} is healthy in fresh state (condition gone)"
        if plan.capability == "docker.start" and state == "running":
            return False, f"{plan.target} already runs in fresh state"
        return True, "fresh state still supports the action"

    def _affected_of(self, incident_id: str) -> list[str]:
        rows = self.db.query(
            "SELECT entity FROM incidents WHERE root_incident=? AND state != 'RESOLVED' LIMIT 12",
            (incident_id,),
        )
        return [r["entity"] for r in rows]

    def _record_baselines(self, state) -> None:  # noqa: ANN001
        host = state.host
        if host.cpu_pct is not None:
            self.baselines.record("host_cpu_pct", host.cpu_pct)
        if host.mem_pct is not None:
            self.baselines.record("host_memory_pct", host.mem_pct)
        if host.package_temp_c is not None:
            self.baselines.record("host_package_temp_c", host.package_temp_c)
        for name, view in state.containers.items():
            if view.mem_util_pct is not None:
                self.baselines.record(f"container_mem_util_pct:{name}", view.mem_util_pct)

    # ------------------------------------------------------------------
    # status & state helpers (commands/health)
    # ------------------------------------------------------------------
    def status_text(self) -> str:

        now = self.clock.now()
        host = self.pipeline.last_state.host if self.pipeline.last_state else None
        lines = [f"Hermes v2 — {version_info()['version']} ({version_info()['git_sha'][:10]})"]
        if host is not None:
            # langzaam verzamelde velden: alleen tonen als last-known vers is
            # (carry-forward houdt ze levend; na SLOW_STALE_AFTER valt het terug
            # naar "?" in plaats van een stille oude waarde)
            def slow_fresh(field: str) -> bool:
                ts = host.slow_ts.get(field)
                return ts is None or (now - ts) <= self.pipeline.SLOW_STALE_AFTER

            cpu = f"{host.cpu_pct:.0f}%" if host.cpu_pct is not None else "?"
            mem = f"{host.mem_pct:.0f}%" if host.mem_pct is not None else "?"
            temp = f"{host.package_temp_c:.0f}°C" if host.package_temp_c is not None else "?"
            array = host.array_state if (host.array_state and slow_fresh("array_state")) else "?"
            lines.append(f"Host: CPU {cpu}, RAM {mem}, {temp}, array={array}")
        beacon = self.pipeline.last_state.source("beacon") if self.pipeline.last_state else None
        if beacon is not None:
            age = int(now - beacon.ts) if beacon.ts else -1
            state = "ok" if beacon.ok else ("disabled" if beacon.disabled else f"storing ({beacon.error})")
            lines.append(f"Beacon: {state} (leeftijd {age}s)")
        net = self.pipeline.last_state.source("netdata") if self.pipeline.last_state else None
        if net is not None:
            lines.append(f"Netdata: {'ok' if net.ok else 'storing'}")
        open_inc = self.engine.open_incidents()
        lines.append(f"Open incidenten: {len(open_inc)}")
        for inc in open_inc[-8:]:
            flag = " [gecorreleerd]" if inc.suppressed else ""
            lines.append(f"- {inc.severity} {inc.id} ({inc.state}){flag}")
        # §C24/§27: compact executor status
        exec_cfg = self.cfg.section("executor")
        exec_mode = str(exec_cfg["mode"])
        real_enabled = bool(exec_cfg.get("real_actions_enabled", False))
        if exec_mode == "guarded" and not real_enabled:
            exec_mode = "guarded (real actions disabled)"
        day_start = now - (now % 86400)
        row = self.db.one(
            "SELECT COUNT(*) AS n FROM action_audit WHERE mode='real' AND ts >= ?", (day_start,)
        )
        ok_row = self.db.one(
            "SELECT COUNT(*) AS n FROM remediations WHERE outcome IN ('resolved','success') AND ts >= ?",
            (day_start,),
        )
        fail_row = self.db.one(
            "SELECT COUNT(*) AS n FROM remediations WHERE outcome IN ('failed','action_failed','verification_failed') AND ts >= ?",
            (day_start,),
        )
        lines.append(
            f"Executor: {exec_mode}, real actions enabled: {'yes' if real_enabled else 'no'}, "
            f"real actions today: {int(row['n']) if row else 0}"
        )
        lines.append(
            f"Remediations today: {int(ok_row['n']) if ok_row else 0} successful / "
            f"{int(fail_row['n']) if fail_row else 0} failed"
        )
        uptime = int(now - self.metrics.started_at)
        lines.append(f"Uptime: {uptime // 3600}h{(uptime % 3600) // 60}m, cycles: {self.metrics.cycles}")
        return "\n".join(lines)

    def current_state_lines(self, entity: str | None = None) -> list[str]:
        state = self.pipeline.last_state
        if state is None:
            return ["(geen state deze sessie)"]
        lines = []
        host = state.host
        lines.append(
            f"host: cpu={host.cpu_pct} mem={host.mem_pct} load5={host.load5} "
            f"temp={host.package_temp_c} iowait={host.iowait_pct} array={host.array_state}"
        )
        for name, view in state.containers.items():
            if entity and name != entity and view.is_running:
                continue
            lines.append(
                f"container {name}: state={view.state} health={view.health} "
                f"throttle={view.cpu_throttle_pct} mem_util={view.mem_util_pct} "
                f"update={view.update_available}"
            )
        return lines

    # ------------------------------------------------------------------
    # scheduler loops
    # ------------------------------------------------------------------
    async def cycle(self, kind: str) -> None:
        if self._pipeline_lock.locked():
            return  # never overlap; next interval will run
        async with self._pipeline_lock:
            try:
                summary = await self.pipeline.run_cycle(kind)
                self.metrics.cycles += 1
                if kind == "fast":
                    self.metrics.last_fast = time.time()
                    await self.notifier.retry_pending()
                elif kind == "reconcile":
                    self.metrics.last_reconcile = time.time()
                elif kind == "baseline":
                    self.metrics.last_baseline = time.time()
                stamps = summary.get("sources", {})
                if stamps.get("beacon", {}).get("ok"):
                    self.metrics.last_beacon_ok = time.time()
                if stamps.get("netdata", {}).get("ok"):
                    self.metrics.last_netdata_ok = time.time()
                if kind == "fast":
                    await self._auto_remediation()
            except Exception as exc:  # noqa: BLE001 - a broken cycle must not kill the daemon
                error("daemon", "cycle faalde", kind=kind, error=str(exc)[:200])

    async def _auto_remediation(self) -> None:
        """2.1 §E3: automatic guarded self-healing for confirmed incidents with
        a known action runbook. Safety is layered: the executor enforces the
        kill switch (`real_actions_enabled`), mode (dry-run default), MANAGED
        lifecycle, protection, budgets, idempotency, concurrency, root-cause
        suppression and a fresh pre-execution recheck. With dry-run or the
        switch off this records would_execute decisions for review (Stage 0).
        Notice-severity incidents are never auto-remediated; max one attempt
        per incident per hour and one candidate per cycle (§C16)."""
        exec_cfg = self.cfg.section("executor")
        if exec_cfg["mode"] == "disabled" or not exec_cfg.get("auto_remediate", True):
            return
        for inc in self.engine.open_incidents():
            # CONFIRMED pre-notification, or ACTIVE post-notification — both
            # are confirmed, open incidents eligible for one remediation attempt
            if inc.state not in ("CONFIRMED", "ACTIVE") or inc.suppressed:
                continue
            from .evaluator.pipeline import SEVERITY_RANK

            if SEVERITY_RANK.get(inc.severity, 1) < 1:  # notice: never automatic
                continue
            recent = self.db.one(
                "SELECT id FROM remediations WHERE incident_id=? AND ts > ?",
                (inc.id, self.clock.now() - 3600),
            )
            audit = self.db.one(
                "SELECT id FROM action_audit WHERE incident_id=? AND ts > ?",
                (inc.id, self.clock.now() - 3600),
            )
            if recent or audit:
                continue  # once per hour per incident
            runbook = self.runbooks.for_incident(inc)
            if runbook is None or not runbook.actions:
                continue
            info("remediation", "automatic runbook start",
                 incident_id=inc.id, runbook=runbook.name, initiator="automatic")
            result = await self.runbooks.run(inc, initiator="automatic")
            info("remediation", "automatic runbook done", incident_id=inc.id,
                 outcome=result.outcome, detail=result.detail[:140])
            return  # §C16: at most one candidate per cycle

    async def _loop(self, name: str, interval: float, coro_factory) -> None:  # noqa: ANN001
        await asyncio.sleep(min(5.0, interval))
        while not self._stop.is_set():
            await coro_factory()
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=interval)
            except TimeoutError:
                pass

    async def _telegram_loop(self) -> None:
        if self.telegram is None:
            return
        while not self._stop.is_set():
            try:
                await self.commands.poll_once()
                self.metrics.telegram_polls += 1
            except Exception as exc:  # noqa: BLE001
                warning("daemon", "telegram poll error", error=str(exc)[:160])
                await asyncio.sleep(5)

    async def _daily_maintenance(self) -> None:
        await self.cycle("baseline")
        self._retention_cleanup()
        await self._send_daily_summary()
        self.metrics.last_daily = time.time()

    def _retention_cleanup(self) -> None:
        now = self.clock.now()
        ret = self.cfg.section("retention")
        for table, days_key in (
            ("signals", "signals_days"),
            ("transients", "transients_days"),
            ("ai_calls", "audit_days"),
            ("notifications", "audit_days"),
        ):
            cutoff = now - float(ret[days_key]) * 86400
            self.db.execute(f"DELETE FROM {table} WHERE ts < ?", (cutoff,))
        self.db.execute(
            "DELETE FROM incidents WHERE state='RESOLVED' AND resolved_at < ?",
            (now - float(ret["incidents_days"]) * 86400,),
        )
        self.db.execute("DELETE FROM incident_events WHERE ts < ?", (now - float(ret["audit_days"]) * 86400,))
        self.baselines.compact()
        info("daemon", "retention cleanup uitgevoerd")

    async def _send_daily_summary(self) -> None:
        now = self.clock.now()
        day_ago = now - 86400
        stats: dict = {}
        row = self.db.one("SELECT COUNT(*) AS n FROM incidents WHERE state != 'RESOLVED'")
        stats["incidents_open"] = int(row["n"]) if row else 0
        row = self.db.one("SELECT COUNT(*) AS n FROM incidents WHERE first_seen >= ? AND category != 'transient_pattern'", (day_ago,))
        stats["incidents_new"] = int(row["n"]) if row else 0
        row = self.db.one("SELECT COUNT(*) AS n FROM transients WHERE ts >= ?", (day_ago,))
        stats["transients"] = int(row["n"]) if row else 0
        row = self.db.one("SELECT COUNT(*) AS n FROM remediations WHERE ts >= ? AND outcome='resolved'", (day_ago,))
        stats["self_healed"] = int(row["n"]) if row else 0
        row = self.db.one("SELECT COUNT(*) AS n FROM remediations WHERE ts >= ?", (day_ago,))
        stats["remediations"] = int(row["n"]) if row else 0
        row = self.db.one(
            "SELECT COUNT(*) AS n FROM remediations WHERE ts >= ? AND outcome IN ('failed','action_failed','verification_failed')",
            (day_ago,),
        )
        stats["failed_remediations"] = int(row["n"]) if row else 0
        row = self.db.one(
            "SELECT COUNT(*) AS n FROM action_audit WHERE ts >= ? AND result='denied'", (day_ago,)
        )
        stats["denied_actions"] = int(row["n"]) if row else 0
        row = self.db.one("SELECT COUNT(*) AS n FROM ai_calls WHERE ts >= ?", (day_ago,))
        stats["ai_calls"] = int(row["n"]) if row else 0
        row = self.db.one("SELECT COUNT(*) AS n FROM ai_calls WHERE ts >= ? AND result='escalated'", (day_ago,))
        stats["ai_escalations"] = int(row["n"]) if row else 0
        ns = self.notifier.stats_window(day_ago)
        stats["notifications_sent"] = ns["sent"]
        stats["notifications_suppressed"] = self.notifier.counters["suppressed"]
        unresolved = self.db.query(
            "SELECT severity, id, title FROM incidents WHERE state != 'RESOLVED' ORDER BY "
            "CASE severity WHEN 'critical' THEN 0 WHEN 'urgent' THEN 1 WHEN 'warning' THEN 2 ELSE 3 END LIMIT 8"
        )
        stats["unresolved"] = [f"{r['severity']} {r['id']}" for r in unresolved]
        patterns = self.db.query(
            "SELECT entity, COUNT(*) AS n FROM transients WHERE ts >= ? GROUP BY entity ORDER BY n DESC LIMIT 5",
            (day_ago,),
        )
        stats["patterns"] = [f"{r['entity']}: {r['n']}x transient" for r in patterns if int(r["n"]) > 1]
        stats["host_healthy"] = not self.engine.open_incidents()
        text = format_daily_summary(stats)
        if self.notifier.shadow:
            info("daemon", "daily summary (shadow, not sent)", stats=str(stats))
            return
        if self.telegram is not None:
            chat_id = str(self.cfg.section("telegram").get("home_chat_id") or "")
            if chat_id:
                try:
                    await self.telegram.send_message(chat_id, text)
                except Exception as exc:  # noqa: BLE001
                    warning("daemon", "daily summary send failed", error=str(exc)[:120])

    # ------------------------------------------------------------------
    # lifecycle
    # ------------------------------------------------------------------
    async def wire_http(self) -> None:
        """Create the shared session and attach it to every observer + the SSE
        stream object (without starting loops). Used by start() and by one-shot
        CLI paths that need live observers (runbook, once)."""
        self.session = aiohttp.ClientSession()
        port = AiohttpPort(self.session)
        if self.beacon is not None:
            self.beacon.http = port
            stream_port = StreamingHttpPort(self.session)
            if self.stream is None:
                self.stream = BeaconStream(
                    http=port, base_url=self.cfg.section("sources.beacon")["base_url"],
                    token=str(self.cfg.section("sources.beacon")["token"] or ""),
                    sse_reader=stream_port.sse_reader,
                )
                self.pipeline.stream = self.stream
        if self.netdata is not None:
            self.netdata.http = port
        if self.fallback is not None:
            self.fallback.http = port

    async def start(self) -> None:
        await self.wire_http()
        # §19: an action left in_progress by a previous crash has an unknown
        # outcome — label it at startup so it is never blindly repeated.
        self.executor.classify_stale_in_progress()
        if self.beacon is not None and self.stream is not None:
            self.stream.on_stamp = lambda kind: setattr(self.metrics, "sse_status", kind)
            asyncio.create_task(self.stream.run(self.clock))
        sched = self.cfg.section("scheduler")
        self._tasks = [
            asyncio.create_task(self._loop("fast", float(sched["fast_interval"]), lambda: self.cycle("fast"))),
            asyncio.create_task(self._loop("reconcile", float(sched["reconcile_interval"]), lambda: self.cycle("reconcile"))),
            asyncio.create_task(self._loop("baseline", float(sched["baseline_interval"]), lambda: self.cycle("baseline"))),
            asyncio.create_task(self._daily_loop()),
            asyncio.create_task(self._telegram_loop()),
            asyncio.create_task(self._health_server()),
        ]
        info("daemon", "Hermes started", mode=self.cfg.mode, executor=self.cfg.section("executor")["mode"],
             **version_info())

    async def _daily_loop(self) -> None:
        hour = int(self.cfg.section("scheduler").get("daily_hour", 4))
        while not self._stop.is_set():
            now = time.gmtime()
            seconds_today = now.tm_hour * 3600 + now.tm_min * 60
            target = hour * 3600
            wait = target - seconds_today if seconds_today < target else 86400 - seconds_today + target
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=max(60, wait))
                return
            except TimeoutError:
                pass
            await self._daily_maintenance()

    async def _health_server(self) -> None:
        from aiohttp import web

        async def health(_request):
            open_inc = len(self.engine.open_incidents())
            return web.json_response({
                "status": "ok" if not self._stop.is_set() else "stopping",
                "uptime_s": int(time.time() - self.metrics.started_at),
                "open_incidents": open_inc,
                "cycles": self.metrics.cycles,
            })

        async def diagnostics(_request):
            return web.json_response({
                "version": version_info(),
                "mode": self.cfg.mode,
                "executor": self.cfg.section("executor")["mode"],
                "metrics": {
                    "last_fast": self.metrics.last_fast,
                    "last_reconcile": self.metrics.last_reconcile,
                    "last_baseline": self.metrics.last_baseline,
                    "last_daily": self.metrics.last_daily,
                    "last_beacon_ok": self.metrics.last_beacon_ok,
                    "last_netdata_ok": self.metrics.last_netdata_ok,
                    "sse_status": self.metrics.sse_status,
                    "cycles": self.metrics.cycles,
                    "telegram_polls": self.metrics.telegram_polls,
                    "notifier": self.notifier.counters,
                },
                "sources": {name: {"enabled": bool(section.get("enabled"))}
                            for name, section in self.cfg.section("sources").items()},
            })

        app = web.Application()
        app.router.add_get("/health", health)
        app.router.add_get("/diagnostics", diagnostics)
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, self.cfg.raw.get("bind", "127.0.0.1"), int(self.cfg.raw.get("port", 8643)))
        await site.start()
        await self._stop.wait()
        await runner.cleanup()

    async def stop(self) -> None:
        info("daemon", "graceful shutdown started")
        self._stop.set()
        if self.stream is not None:
            self.stream.stop()
        for task in getattr(self, "_tasks", []):
            task.cancel()
        await asyncio.gather(*getattr(self, "_tasks", []), return_exceptions=True)
        if self.session is not None:
            await self.session.close()
        if self.telegram is not None:
            await self.telegram.close()
        self.db.close()
        info("daemon", "stopped")


async def run_daemon(config_path: str | None) -> None:
    cfg = load_config(config_path)
    for problem in cfg.validate():
        warning("config", "configletsel", problem=problem)
    if cfg.shadow:
        info("daemon", "SHADOW MODE: geen echte meldingen, executor=dry-run")
    app = HermesApp(cfg)
    loop = asyncio.get_running_loop()
    stop_signal = asyncio.Event()

    def _handle_signal() -> None:
        stop_signal.set()

    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(sig, _handle_signal)
        except NotImplementedError:  # pragma: no cover - platform-dependent
            pass
    await app.start()
    await stop_signal.wait()
    await app.stop()
