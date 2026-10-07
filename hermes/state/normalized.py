"""Normalized state: the single in-memory picture of observed infrastructure.

Every observation carries source freshness so downstream confidence logic can
distinguish "confirmed by two live sources" from "one stale source" (spec §4).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class SourceStamp:
    source: str
    ok: bool
    ts: float = 0.0
    stale: bool = False
    error: str | None = None
    disabled: bool = False  # e.g. Beacon Agent API returns 403 DISABLED

    def fresh(self, now: float, max_age: float = 120.0) -> bool:
        return self.ok and not self.stale and (now - self.ts) <= max_age


@dataclass
class ContainerView:
    name: str
    state: str = "unknown"  # running/exited/paused/...
    health: str | None = None  # healthy/unhealthy/starting/None
    image: str | None = None
    update_available: bool = False
    compose_project: str | None = None
    management_type: str | None = None
    beacon: SourceStamp | None = None
    # netdata evidence (None = not measured this cycle)
    cpu_throttle_pct: float | None = None
    mem_util_pct: float | None = None
    health_status_netdata: int | None = None

    @property
    def is_running(self) -> bool:
        return self.state == "running"

    @property
    def is_unhealthy(self) -> bool:
        return self.health == "unhealthy" or self.health_status_netdata == 0


@dataclass
class DiskView:
    name: str
    role: str | None = None
    state: str | None = None
    temp_c: float | None = None
    used_pct: float | None = None


@dataclass
class HostView:
    cpu_pct: float | None = None
    load5: float | None = None
    cores: int | None = None
    mem_pct: float | None = None
    package_temp_c: float | None = None
    docker_daemon_ok: bool | None = None
    array_state: str | None = None
    parity_status: str | None = None
    disks: list[DiskView] = field(default_factory=list)
    storage_used_pct: dict[str, float] = field(default_factory=dict)  # mount -> pct
    iowait_pct: float | None = None
    disk_await_ms: dict[str, float] = field(default_factory=dict)  # device -> ms/op
    beacon: SourceStamp | None = None
    netdata: SourceStamp | None = None
    fallback: SourceStamp | None = None
    slow_ts: dict = field(default_factory=dict)  # slow-field -> last observed ts (runtime)


@dataclass
class BeaconIssue:
    id: str
    severity: str
    category: str
    status: str
    summary: str
    condition: str = ""
    first_seen_at: str | None = None
    last_seen_at: str | None = None
    target: dict | None = None
    metrics: dict = field(default_factory=dict)
    suggested_checks: list = field(default_factory=list)


@dataclass
class StreamEvent:
    type: str  # docker.transition | system.health
    ts: float
    data: dict[str, Any]


@dataclass
class NormalizedState:
    ts: float
    containers: dict[str, ContainerView] = field(default_factory=dict)
    host: HostView = field(default_factory=HostView)
    issues: list[BeaconIssue] = field(default_factory=list)
    recent_events: list[StreamEvent] = field(default_factory=list)
    netdata_alarms: list[dict] = field(default_factory=list)
    anomaly_rate: float | None = None
    sources: dict[str, SourceStamp] = field(default_factory=dict)

    def source(self, name: str) -> SourceStamp:
        return self.sources.get(name, SourceStamp(source=name, ok=False, error="no data"))

    def active_container_names(self) -> list[str]:
        return sorted(self.containers)
