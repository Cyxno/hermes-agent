"""Deterministic diagnosis checks and post-action verification strategies.

All checks are read-only and evidence-based; they never invent conclusions.
`Diagnostics` bundles the observation clients so checks stay pure functions.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class CheckResult:
    name: str
    ok: bool | None  # None = inconclusive
    detail: str = ""


class Diagnostics:
    def __init__(self, beacon, netdata, incident_engine, bands, config) -> None:  # noqa: ANN001
        self.beacon = beacon
        self.netdata = netdata
        self.incidents = incident_engine
        self.bands = bands
        self.config = config

    async def _docker_map(self) -> dict[str, dict]:
        try:
            containers = await self.beacon.docker()
            return {c.get("name", ""): c for c in containers}
        except Exception:  # noqa: BLE001
            return {}

    # -- diagnosis checks ------------------------------------------------
    async def check(self, name: str, entity: str) -> CheckResult:
        method = getattr(self, f"check_{name}", None)
        if method is None:
            return CheckResult(name, None, f"onbekende check {name}")
        return await method(entity)

    async def check_container_exists(self, entity: str) -> CheckResult:
        cmap = await self._docker_map()
        if entity in cmap:
            return CheckResult("container_exists", True)
        return CheckResult("container_exists", False, f"{entity} niet gevonden in Beacon")

    async def check_not_restart_looping(self, entity: str) -> CheckResult:
        inc = self.incidents.get(f"container_restart_loop:{entity}")
        if inc and inc.open:
            return CheckResult("not_restart_looping", False, "restart-loop actief; herstarten voedt de loop")
        return CheckResult("not_restart_looping", True)

    async def check_no_active_update(self, entity: str) -> CheckResult:
        cmap = await self._docker_map()
        entry = cmap.get(entity)
        if entry is None:
            return CheckResult("no_active_update", None, "container onbekend")
        if entry.get("updateAvailable"):
            return CheckResult("no_active_update", False, "update beschikbaar; liever updaten dan herstarten")
        return CheckResult("no_active_update", True)

    async def check_dependencies_healthy(self, entity: str) -> CheckResult:
        cmap = await self._docker_map()
        entry = cmap.get(entity) or {}
        project = entry.get("composeProject")
        if not project:
            return CheckResult("dependencies_healthy", True, "geen compose-project bekend")
        siblings = [
            c for c in cmap.values()
            if c.get("composeProject") == project and c.get("name") != entity
        ]
        bad = [c["name"] for c in siblings if c.get("state") != "running"]
        if bad:
            return CheckResult("dependencies_healthy", False, f"projectgenoten niet gezond: {', '.join(bad)}")
        return CheckResult("dependencies_healthy", True, f"project {project}: alle genoten draaien")

    async def check_storage_healthy(self) -> CheckResult:
        breached = [
            (m, b) for m, b in self._active_bands()
            if m.startswith("disk_await_ms") or m.startswith("storage_used_pct")
        ]
        if breached:
            names = ", ".join(m for m, _ in breached)
            return CheckResult("storage_healthy", False, f"storage-band actief: {names}")
        return CheckResult("storage_healthy", True)

    async def check_network_healthy(self, entity: str) -> CheckResult:
        breached = [m for m, _ in self._active_bands() if m.startswith("net_errors")]
        if breached:
            return CheckResult("network_healthy", False, f"netwerk-fouten actief: {', '.join(breached)}")
        return CheckResult("network_healthy", True)

    async def check_memory_leak_trend(self, entity: str) -> CheckResult:
        if self.netdata is None:
            return CheckResult("memory_leak_trend", None, "netdata onbeschikbaar")
        util = await self.netdata.container_mem_util_pct(entity)
        if util is None:
            return CheckResult("memory_leak_trend", None, "geen mem-utilisatie meetbaar")
        baseline = self._baseline(f"container_mem_util_pct:{entity}")
        if baseline and baseline.get("samples", 0) > 50 and util > baseline["mean"] + 3 * (baseline["stdev"] or 1):
            return CheckResult("memory_leak_trend", False,
                               f"mem {util:.0f}% ver boven baseline {baseline['mean']:.0f}%")
        return CheckResult("memory_leak_trend", True)

    # -- helpers ---------------------------------------------------------
    def _active_bands(self) -> list[tuple[str, str]]:
        return list(self.bands.active_metrics())

    def _baseline(self, metric: str) -> dict | None:
        row = self.incidents.db.one("SELECT mean, stdev, samples FROM baselines WHERE metric=?", (metric,))
        return dict(row) if row else None

    # -- post-action verification strategies -----------------------------
    async def verify(self, strategy: str, entity: str) -> CheckResult:
        method = getattr(self, f"verify_{strategy}", None)
        if method is None:
            return CheckResult(strategy, None, f"onbekende verificatiestrategie {strategy}")
        return await method(entity)

    async def verify_container_running(self, entity: str) -> CheckResult:
        cmap = await self._docker_map()
        entry = cmap.get(entity)
        if entry is None:
            return CheckResult("container_running", None, "container onbekend in verse state")
        ok = entry.get("state") == "running"
        return CheckResult("container_running", ok, f"state={entry.get('state')}")

    async def verify_container_healthy(self, entity: str) -> CheckResult:
        cmap = await self._docker_map()
        entry = cmap.get(entity) or {}
        health = entry.get("health")
        if health == "healthy":
            return CheckResult("container_healthy", True)
        if self.netdata is not None:
            try:
                nd = await self.netdata.container_health(entity)
                if nd == 1:
                    return CheckResult("container_healthy", True, "netdata meldt healthy")
                if nd == 0:
                    return CheckResult("container_healthy", False, "netdata meldt unhealthy")
            except Exception:  # noqa: BLE001
                pass
        if health in (None, "starting"):
            return CheckResult("container_healthy", None, f"health={health}; nog niet conclusief")
        return CheckResult("container_healthy", False, f"health={health}")

    async def verify_container_stopped(self, entity: str) -> CheckResult:
        cmap = await self._docker_map()
        entry = cmap.get(entity) or {}
        ok = entry.get("state") != "running"
        return CheckResult("container_stopped", ok, f"state={entry.get('state')}")

    async def verify_no_throttle(self, entity: str) -> CheckResult:
        if self.netdata is None:
            return CheckResult("no_throttle", None, "netdata onbeschikbaar")
        value = await self.netdata.container_throttle_pct(entity)
        warn = float(self.config.get("thresholds", {}).get("container_cpu_throttle_pct", {}).get("warn", 25))
        if value is None:
            return CheckResult("no_throttle", None, "geen throttling meetwaarde")
        return CheckResult("no_throttle", value < warn, f"throttle {value:.1f}%")

    async def verify_service_running(self, entity: str) -> CheckResult:
        return CheckResult("service_running", None, "service-verificatie vereist SSH read-dispatch; overgeslagen")


async def run_verification(diagnostics: Diagnostics, strategies: list[str], entity: str) -> list[CheckResult]:
    results = []
    for strategy in strategies:
        results.append(await diagnostics.verify(strategy, entity))
    return results


def all_passed(results: list[CheckResult]) -> bool:
    return bool(results) and all(r.ok is True for r in results)


def any_failed(results: list[CheckResult]) -> bool:
    return any(r.ok is False for r in results)
