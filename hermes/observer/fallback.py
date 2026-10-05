"""Minimal Unraid/host fallback probe — ONLY used when Beacon is unreachable (spec §5).

Scope is deliberately tiny: distinguish (A) Beacon broken / host fine, (B) host
gone, (C) network problem. Prometheus (independent of Beacon) provides host
liveness + basic metrics; optional SSH read-dispatch provides a bounded
`host-summary` when configured. This is never a Beacon replacement.
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field

from ..util import sanitize
from .base import HttpError, HttpPort

PROM_API = "/api/v1"


@dataclass
class FallbackView:
    prometheus_ok: bool = False
    node_up: bool = False
    docker_hint: bool | None = None
    cpu_pct: float | None = None
    mem_used_pct: float | None = None
    load5: float | None = None
    uptime_s: float | None = None
    ssh_summary: dict | None = None
    errors: list[str] = field(default_factory=list)

    @property
    def host_ok(self) -> bool:
        return self.node_up or bool(self.ssh_summary)


class FallbackProbe:
    def __init__(
        self,
        http: HttpPort,
        prometheus_url: str,
        ssh: SshProbe | None = None,
        timeout: float = 8.0,
    ) -> None:
        self.http = http
        self.prometheus_url = prometheus_url.rstrip("/")
        self.ssh = ssh
        self.timeout = timeout

    async def _prom_instant(self, query: str) -> float | None:
        url = f"{self.prometheus_url}{PROM_API}/query"
        from urllib.parse import urlencode

        status, body = await self.http.get_json(
            f"{url}?{urlencode({'query': query})}", timeout=self.timeout
        )
        if status != 200 or not isinstance(body, dict):
            raise HttpError(f"prometheus query status={status}", status)
        result = body.get("data", {}).get("result", [])
        if not result:
            return None
        try:
            return float(result[0]["value"][1])
        except (KeyError, TypeError, ValueError):
            return None

    async def probe(self) -> FallbackView:
        view = FallbackView()
        try:
            up = await self._prom_instant('up{job="node"}')
            view.prometheus_ok = True
            view.node_up = up is not None and up == 1.0
            if view.node_up:
                view.load5 = await self._prom_instant('node_load5{job="node"}')
                mem_total = await self._prom_instant('node_memory_MemTotal_bytes{job="node"}')
                mem_avail = await self._prom_instant('node_memory_MemAvailable_bytes{job="node"}')
                if mem_total and mem_avail is not None and mem_total > 0:
                    view.mem_used_pct = round((mem_total - mem_avail) / mem_total * 100, 1)
                view.uptime_s = await self._prom_instant(
                    'node_boot_time_seconds{job="node"}'
                )
                # docker liveness hint via cadvisor target
                try:
                    cadvisor = await self._prom_instant('up{job="cadvisor"}')
                    view.docker_hint = cadvisor == 1.0
                except HttpError:
                    view.docker_hint = None
        except (TimeoutError, HttpError, OSError) as exc:
            view.errors.append(sanitize(exc, 120))
        if self.ssh is not None:
            try:
                view.ssh_summary = await self.ssh.host_summary()
            except Exception as exc:  # noqa: BLE001 - best effort probe
                view.errors.append(sanitize(exc, 120))
        return view


class SshProbe:
    """Bounded SSH read-dispatch client (same hardened dispatcher family as v1).

    Only ever runs allowlisted read-only actions with a fixed timeout; arguments
    are constants (never user/AI input), so there is no injection surface.
    """

    def __init__(self, host: str, key_path: str, known_hosts: str, timeout: float = 12.0) -> None:
        self.host = host
        self.key_path = key_path
        self.known_hosts = known_hosts
        self.timeout = timeout

    async def _run(self, action: str) -> dict:
        proc = await asyncio.create_subprocess_exec(
            "ssh",
            "-i", self.key_path,
            "-o", f"UserKnownHostsFile={self.known_hosts}",
            "-o", "StrictHostKeyChecking=yes",
            "-o", "BatchMode=yes",
            "-o", "ConnectTimeout=8",
            self.host,
            action,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=self.timeout)
        except TimeoutError:
            proc.kill()
            raise HttpError("ssh dispatch timeout", None) from None
        if proc.returncode != 0:
            raise HttpError(f"ssh dispatch rc={proc.returncode}: {sanitize(stderr, 120)}", None)
        try:
            data = json.loads(stdout.decode("utf-8", "replace"))
        except (ValueError, TypeError):
            raise HttpError("ssh dispatch returned non-JSON", None) from None
        if not isinstance(data, dict) or not data.get("ok"):
            raise HttpError("ssh dispatch failure envelope", None)
        return data.get("data", {})

    async def host_summary(self) -> dict:
        return await self._run("host-summary")
