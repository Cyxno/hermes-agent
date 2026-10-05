"""Shared test fixtures: FakeClock, stub observers, and a full engine stack."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from hermes.clock import FakeClock  # noqa: E402
from hermes.config import Config  # noqa: E402
from hermes.evaluator.baselines import Baselines  # noqa: E402
from hermes.evaluator.correlation import CorrelationEngine  # noqa: E402
from hermes.evaluator.hysteresis import MetricBands  # noqa: E402
from hermes.evaluator.incidents import IncidentEngine  # noqa: E402
from hermes.evaluator.pipeline import EvaluationPipeline  # noqa: E402
from hermes.evaluator.rules import RuleEvaluator  # noqa: E402
from hermes.evaluator.transient import TransientTracker  # noqa: E402
from hermes.observer.fallback import FallbackView  # noqa: E402
from hermes.state.db import Database  # noqa: E402
from hermes.state.desired import DesiredStateManager  # noqa: E402


class FakeBeacon:
    def __init__(self) -> None:
        self.summary_data = {
            "cpu": {"percent": 12.0},
            "memory": {"percent": 40.0},
            "load": {"five": 0.5},
            "thermal": {"currentC": 55.0},
            "docker": {"running": 10, "total": 12, "unhealthy": 0},
            "health": {"level": None, "reasons": []},
        }
        self.docker_data = [
            {"name": "plex", "state": "running", "health": "healthy", "image": "plex",
             "updateAvailable": False, "composeProject": "media", "managementType": "compose"},
            {"name": "sonarr", "state": "running", "health": "healthy", "image": "sonarr",
             "updateAvailable": False, "composeProject": "media", "managementType": "compose"},
            {"name": "postgres", "state": "running", "health": "healthy", "image": "pg",
             "updateAvailable": False, "composeProject": "apps", "managementType": "compose"},
            {"name": "decypharr", "state": "running", "health": "healthy", "image": "decypharr",
             "updateAvailable": False, "composeProject": None, "managementType": "manual"},
            {"name": "radarr", "state": "running", "health": "healthy", "image": "radarr",
             "updateAvailable": False, "composeProject": "media", "managementType": "compose"},
        ]
        self.issues_data: list[dict] = []
        self.storage_data = {
            "arrayState": "STARTED", "parityStatus": "OK",
            "disks": [{"name": "sda", "role": "parity", "state": "DISK_OK", "temperatureC": 35},
                      {"name": "sdb", "role": "data", "state": "DISK_OK", "temperatureC": 36}],
            "capacity": {"usedBytes": 1, "totalBytes": 4},
        }
        self.system_data = {"temperatures": {"packageC": 55.0}, "uptime": {"seconds": 1000}}
        self.fail = False
        self.disabled = False
        self.call_count = 0

    async def _maybe_fail(self):
        self.call_count += 1
        if self.fail:
            raise TimeoutError("beacon stub down")

    async def summary(self):
        await self._maybe_fail()
        return self.summary_data

    async def docker(self):
        await self._maybe_fail()
        return self.docker_data

    async def storage(self):
        await self._maybe_fail()
        return self.storage_data

    async def system(self):
        await self._maybe_fail()
        return self.system_data

    async def issues(self):
        await self._maybe_fail()
        return self.issues_data

    async def projects(self):
        await self._maybe_fail()
        return {"apiVersion": "1", "data": {"projects": []}}

    async def operations(self):
        await self._maybe_fail()
        return {"apiVersion": "1", "data": {}}


class FakeNetdata:
    def __init__(self) -> None:
        self.alarms_data: list[dict] = []
        self.fail = False
        self.exists = {c: True for c in (
            "docker_local.container_plex_health_status",
            "cgroup_plex.throttled", "cgroup_plex.mem_utilization",
            "cgroup_plex.throttled_duration",
            "system.cpu", "disk_await.sda", "disk_await.sdb", "mem.oom_kill",
        )}
        self.health = {"plex": 1}
        self.throttle = {"plex": 2.0}
        self.mem_util = {"plex": 45.0}
        self.iowait = 0.5
        self.await_ms = {"sda": 3.0, "sdb": 4.0}
        self.anomaly = 0.0

    async def _maybe_fail(self):
        if self.fail:
            raise TimeoutError("netdata stub down")

    async def alarms(self):
        await self._maybe_fail()
        return self.alarms_data

    async def chart_exists(self, chart):
        return self.exists.get(chart, False)

    async def container_health(self, container):
        await self._maybe_fail()
        return self.health.get(container)

    async def container_throttle_pct(self, container):
        await self._maybe_fail()
        return self.throttle.get(container)

    async def container_mem_util_pct(self, container):
        await self._maybe_fail()
        return self.mem_util.get(container)

    async def iowait_pct(self):
        await self._maybe_fail()
        return self.iowait

    async def disk_await(self, devices):
        await self._maybe_fail()
        return {d: self.await_ms[d] for d in devices if d in self.await_ms}

    async def anomaly_rate(self):
        await self._maybe_fail()
        return self.anomaly

    async def oom_kills(self):
        return 0.0


class FakeFallback:
    def __init__(self) -> None:
        self.view = FallbackView(prometheus_ok=True, node_up=True)
        self.fail = False

    async def probe(self):
        if self.fail:
            self.view.errors.append("stub down")
            self.view.prometheus_ok = False
            self.view.node_up = False
        else:
            self.view.prometheus_ok = True
            self.view.node_up = True
        return self.view


class FakeNotifier:
    def __init__(self) -> None:
        self.delivered: list[tuple[str, dict]] = []

    async def deliver(self, kind, snapshot):
        self.delivered.append((kind, dict(snapshot)))
        return True


class FakeStream:
    def drain(self):
        return []


TEST_CONFIG = {
    "mode": "normal",
    "data_dir": "/tmp/hermes-test",
    "sources": {"beacon": {"enabled": True, "base_url": "http://x", "token": "t"},
                "netdata": {"enabled": True, "base_url": "http://y"},
                "fallback": {"enabled": True, "prometheus_url": "http://z", "ssh_enabled": False}},
    "debounce": {"container_unhealthy": 90, "container_exit": 45,
                 "beacon_unavailable": 90, "host_unreachable": 60},
    "sustains": {"host_cpu_pct": 300, "host_memory_pct": 300},
    "thresholds": {"host_memory_pct": {"warn": 90, "crit": 95},
                   "host_cpu_pct": {"warn": 85, "crit": 95},
                   "host_load5_per_core": {"warn": 2.0, "crit": 4.0},
                   "host_package_temp_c": {"warn": 95, "crit": 98},
                   "host_iowait_pct": {"warn": 30, "crit": 60},
                   "container_cpu_throttle_pct": {"warn": 25, "crit": 60},
                   "container_mem_util_pct": {"warn": 90, "crit": 97},
                   "disk_await_ms": {"warn": 50, "crit": 200},
                   "storage_used_pct": {"warn": 80, "crit": 88},
                   "net_errors_per_s": {"warn": 1, "crit": 10},
                   "anomaly_rate": {"warn": 0.05, "crit": 0.25}},
    "hysteresis": {"default": {"clear_margin_pp": 5, "good_samples": 2},
                   "overrides": {"host_cpu_pct": {"clear_margin_pp": 15, "good_samples": 3}}},
    "desired_state": {"managed": ["plex", "sonarr", "radarr", "postgres"], "optional": [],
                      "retired": ["decypharr", "DUMB"], "ignored": []},
    "transients": {"window": 21600, "threshold_default": 5},
    "correlation": {"storage_window": 600, "storage_min_entities": 3},
    "ai": {"enabled": True, "api_key": "k", "confidence_stop": 0.85},
    "executor": {"mode": "dry-run"},
    "telegram": {"enabled": True, "bot_token": "tok", "home_chat_id": "42",
                 "min_severity": "warning", "allowed_usernames": ["remco"]},
    "scheduler": {"fast_interval": 60, "reconcile_interval": 300, "baseline_interval": 900},
}


@pytest.fixture()
def clock():
    return FakeClock()


@pytest.fixture()
def db(tmp_path):
    database = Database(str(tmp_path / "hermes.db"))
    database.migrate()
    yield database
    database.close()


@pytest.fixture()
def cfg():
    return Config(raw=dict(TEST_CONFIG))


@pytest.fixture()
def stack(cfg, db, clock):
    """Full pipeline stack with stub observers and a recording notifier."""
    beacon, netdata, fallback = FakeBeacon(), FakeNetdata(), FakeFallback()
    bands = MetricBands(db, cfg.raw)
    desired = DesiredStateManager(db, cfg.section("desired_state"))
    desired.seed_from_config()
    rules = RuleEvaluator(bands, desired, cfg.raw)
    engine = IncidentEngine(db, cfg.raw, clock, fast_interval=60)
    correlation = CorrelationEngine(engine, cfg.raw, clock)
    tracker = TransientTracker(engine, cfg.raw, clock)
    baselines = Baselines(db)
    notifier = FakeNotifier()
    pipeline = EvaluationPipeline(
        cfg, clock, db, engine, bands, rules, desired, correlation, tracker,
        beacon=beacon, netdata=netdata, fallback=fallback, stream=FakeStream(),
        notifier=notifier,
        baseline_recorder=lambda state: baselines.record("host_cpu_pct", state.host.cpu_pct or 0),
    )
    return {
        "cfg": cfg, "db": db, "clock": clock, "beacon": beacon, "netdata": netdata,
        "fallback": fallback, "bands": bands, "desired": desired, "engine": engine,
        "pipeline": pipeline, "notifier": notifier, "correlation": correlation,
        "tracker": tracker, "baselines": baselines,
    }


def set_plex_unhealthy(beacon: FakeBeacon, netdata: FakeNetdata) -> None:
    for entry in beacon.docker_data:
        if entry["name"] == "plex":
            entry["health"] = "unhealthy"
    netdata.health["plex"] = 0


def set_plex_healthy(beacon: FakeBeacon, netdata: FakeNetdata) -> None:
    for entry in beacon.docker_data:
        if entry["name"] == "plex":
            entry["health"] = "healthy"
    netdata.health["plex"] = 1


async def run_cycles(stack, count: int = 1, kind: str = "fast", step: float = 60.0):
    for _ in range(count):
        stack["clock"].advance(step)
        await stack["pipeline"].run_cycle(kind)
