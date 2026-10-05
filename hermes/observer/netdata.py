"""Netdata observer — second observability source (spec §3).

GET-only. Chart queries are targeted and bounded (no screen-scraping, no
full-dump polling). This host has NO PSI and NO swap — the client never
assumes those charts exist. Chart IDs follow the verified v2.11.1 layout:
cgroup_<name>.{throttled,throttled_duration,mem_usage_limit,mem_utilization},
docker_local.container_<name>_health_status, disk_await.<dev>, system.cpu,
mem.oom_kill, anomaly_detection.anomaly_rate_on_<guid>.
"""

from __future__ import annotations

from .base import HttpError, HttpPort

NETDATA_API = "/api/v1"


class NetdataClient:
    def __init__(self, http: HttpPort, base_url: str, ml_chart: str = "", timeout: float = 8.0) -> None:
        self.http = http
        self.base_url = base_url.rstrip("/")
        self.ml_chart = ml_chart
        self.timeout = timeout
        self._chart_exists: dict[str, bool] = {}

    async def _get(self, path: str, params: dict | None = None) -> dict:
        url = f"{self.base_url}{NETDATA_API}{path}"
        if params:
            from urllib.parse import urlencode

            url += "?" + urlencode(params)
        status, body = await self.http.get_json(url, timeout=self.timeout)
        if status != 200 or not isinstance(body, dict):
            raise HttpError(f"netdata {path} status={status}", status)
        return body

    # ------------------------------------------------------------------
    async def chart_exists(self, chart: str) -> bool:
        if chart in self._chart_exists:
            return self._chart_exists[chart]
        try:
            await self._get("/chart", {"chart": chart})
            self._chart_exists[chart] = True
        except HttpError:
            self._chart_exists[chart] = False
        return self._chart_exists[chart]

    async def chart_average(
        self, chart: str, dimension: str | None = None, after: int = -300, points: int = 25
    ) -> float | None:
        """Mean of the last `points` samples (oldest->newest mean over window)."""
        if not await self.chart_exists(chart):
            return None
        params: dict = {"chart": chart, "after": after, "points": points, "format": "json"}
        if dimension:
            params["dimensions"] = dimension
        body = await self._get("/data", params)
        data = body.get("data") or []
        values: list[float] = []
        dim_index = 1
        labels = body.get("labels") or []
        if dimension and dimension in labels:
            dim_index = labels.index(dimension)
        for row in data:
            try:
                values.append(float(row[dim_index]))
            except (TypeError, ValueError, IndexError):
                continue
        if not values:
            return None
        return sum(values) / len(values)

    async def chart_max(self, chart: str, dimension: str | None = None, after: int = -300) -> float | None:
        if not await self.chart_exists(chart):
            return None
        params: dict = {"chart": chart, "after": after, "points": 50, "format": "json", "group": "max"}
        if dimension:
            params["dimensions"] = dimension
        body = await self._get("/data", params)
        labels = body.get("labels") or []
        dim_index = labels.index(dimension) if dimension and dimension in labels else 1
        values = [float(row[dim_index]) for row in (body.get("data") or []) if len(row) > dim_index]
        return max(values) if values else None

    # -- typed convenience queries --------------------------------------
    async def container_health(self, container: str) -> int | None:
        """1 = healthy, 0 = unhealthy/not_running_unhealthy, None = unknown."""
        chart = f"docker_local.container_{container}_health_status"
        if not await self.chart_exists(chart):
            return None
        params = {"chart": chart, "after": -120, "points": 3, "format": "json"}
        body = await self._get("/data", params)
        labels = body.get("labels") or []
        rows = body.get("data") or []
        if not rows:
            return None
        latest = rows[0]  # newest first
        dims = ("healthy", "unhealthy", "not_running_unhealthy")
        idx = {d: labels.index(d) for d in dims if d in labels}
        if "unhealthy" in idx and float(latest[idx["unhealthy"]]) > 0:
            return 0
        if "not_running_unhealthy" in idx and float(latest[idx["not_running_unhealthy"]]) > 0:
            return 0
        if "healthy" in idx and float(latest[idx["healthy"]]) > 0:
            return 1
        return None

    async def container_throttle_pct(self, container: str) -> float | None:
        value = await self.chart_average(
            f"cgroup_{container}.throttled", "throttled", after=-600, points=30
        )
        return value

    async def container_mem_util_pct(self, container: str) -> float | None:
        return await self.chart_average(
            f"cgroup_{container}.mem_utilization", after=-600, points=30
        )

    async def iowait_pct(self) -> float | None:
        return await self.chart_average("system.cpu", "iowait", after=-600, points=30)

    async def disk_await(self, devices: list[str] | None = None) -> dict[str, float]:
        """Per-device average await (ms/op) for the requested (or discovered) devices."""
        out: dict[str, float] = {}
        for dev in devices or []:
            value = await self.chart_average(f"disk_await.{dev}", after=-600, points=30)
            if value is not None:
                out[dev] = round(value, 2)
        return out

    async def anomaly_rate(self) -> float | None:
        if not self.ml_chart:
            return None
        return await self.chart_average(self.ml_chart, "anomaly_rate", after=-600, points=30)

    async def alarms(self) -> list[dict]:
        body = await self._get("/alarms")
        alarms = body.get("alarms") or {}
        return list(alarms.values()) if isinstance(alarms, dict) else []

    async def oom_kills(self) -> float | None:
        return await self.chart_max("mem.oom_kill", "kills", after=-600)
