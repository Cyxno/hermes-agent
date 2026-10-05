"""Beacon Agent API observer — the PRIMARY operational source (spec §2).

GET-only client for the v1 agent namespace plus an SSE reader for /stream.
HTTP statuses are classified explicitly (DISABLED / UNAUTHORIZED / RATE_LIMITED /
unavailable) because Hermes must distinguish "Beacon broken" from "host gone".
"""

from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass
from datetime import UTC
from typing import Any

from ..log import info, warning
from ..state.normalized import BeaconIssue, StreamEvent
from ..util import backoff_delay, sanitize
from .base import AiohttpPort, HttpPort, aiohttp_timeout

AGENT_API = "/api/agent/v1"


def classify_status(status: int | None, body: Any) -> str:
    """Map an HTTP outcome to a stable error kind."""
    if status == 200:
        return "ok"
    if status == 403:
        code = ""
        if isinstance(body, dict):
            code = str(body.get("error", {}).get("code", ""))
        return "disabled" if code == "DISABLED" else "forbidden"
    if status == 401:
        return "unauthorized"
    if status == 429:
        return "rate_limited"
    if status is None:
        return "unreachable"
    if status >= 500:
        return "server_error"
    return "http_error"


@dataclass
class BeaconError(Exception):
    kind: str
    status: int | None = None
    detail: str = ""

    def __str__(self) -> str:  # pragma: no cover
        return f"beacon:{self.kind}{'@' + str(self.status) if self.status else ''} {self.detail}"


@dataclass
class BeaconClient:
    http: HttpPort
    base_url: str
    token: str
    timeout: float = 10.0

    def _headers(self) -> dict[str, str]:
        headers: dict[str, str] = {}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    async def _get(self, path: str, params: dict | None = None) -> Any:
        url = f"{self.base_url.rstrip('/')}{AGENT_API}{path}"
        if params:
            from urllib.parse import urlencode

            url += "?" + urlencode(params)
        status, body = await self.http.get_json(url, headers=self._headers(), timeout=self.timeout)
        kind = classify_status(status, body)
        if kind != "ok":
            raise BeaconError(kind, status, detail=body if isinstance(body, str) else "")
        if not isinstance(body, dict) or "data" not in body:
            raise BeaconError("invalid_response", status, detail="missing data envelope")
        return body

    async def capabilities(self) -> dict:
        body = await self._get("/capabilities")
        return body.get("data", {})

    async def summary(self) -> dict:
        body = await self._get("/summary")
        return body.get("data", {})

    async def docker(self) -> list[dict]:
        body = await self._get("/docker")
        return body.get("data", {}).get("containers", [])

    async def storage(self) -> dict:
        body = await self._get("/storage")
        return body.get("data", {})

    async def system(self) -> dict:
        body = await self._get("/system")
        return body.get("data", {})

    async def issues(self, limit: int = 200) -> list[dict]:
        body = await self._get("/issues", {"limit": limit})
        data = body.get("data", {})
        return data.get("issues", []) if isinstance(data, dict) else []

    async def projects(self) -> list[dict]:
        body = await self._get("/projects")
        data = body.get("data", {})
        return data.get("projects", []) if isinstance(data, dict) else []

    async def operations(self) -> dict:
        body = await self._get("/operations")
        return body.get("data", {})

    async def events(self, since: str | None = None, limit: int = 100) -> list[dict]:
        params: dict = {"limit": limit}
        if since:
            params["since"] = since
        body = await self._get("/events", params)
        data = body.get("data", {})
        return data.get("events", []) if isinstance(data, dict) else []


# ---------------------------------------------------------------------------
# SSE stream
# ---------------------------------------------------------------------------


@dataclass
class StreamOptions:
    reconnect_min: float = 6.0     # Beacon allows 10 stream connects/min (spec-verified)
    reconnect_max: float = 60.0
    heartbeat_timeout: float = 70.0  # ping every 20s; 70s without any frame = dead


class BeaconStream:
    """Reads GET /api/agent/v1/stream as an SSE consumer.

    The caller polls `drain()` for events; this task owns the connection with
    bounded exponential backoff and Last-Event-ID replay.
    """

    def __init__(
        self,
        http: HttpPort,
        base_url: str,
        token: str,
        sse_reader=None,  # async (url, headers, last_event_id, on_frame) -> None
        on_stamp=None,  # callable(kind: str) -> None, reports connection health
        options: StreamOptions | None = None,
    ) -> None:
        self.http = http
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.sse_reader = sse_reader
        self.on_stamp = on_stamp
        self.options = options or StreamOptions()
        self.events: asyncio.Queue[StreamEvent] = asyncio.Queue(maxsize=500)
        self.last_event_id: int = -1
        self.connected = False
        self._attempt = 0
        self._stop = asyncio.Event()

    def stop(self) -> None:
        self._stop.set()

    def drain(self) -> list[StreamEvent]:
        out: list[StreamEvent] = []
        while not self.events.empty():
            try:
                out.append(self.events.get_nowait())
            except asyncio.QueueEmpty:  # pragma: no cover
                break
        return out

    async def run(self, clock, sleep=asyncio.sleep) -> None:  # noqa: ANN001
        if self.sse_reader is None:
            info("beacon-stream", "stream disabled (geen SSE reader geconfigureerd)")
            return
        url = f"{self.base_url}{AGENT_API}/stream"
        headers = {"Accept": "text/event-stream"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        while not self._stop.is_set():
            if self._attempt:
                await sleep(backoff_delay(self._attempt - 1, base=self.options.reconnect_min,
                                          cap=self.options.reconnect_max))
            try:
                self._report("ok")
                await self.sse_reader(url, headers, self.last_event_id, self.handle_frame)
                self._attempt = 0
                self._report("closed")
            except BeaconError as exc:
                self._report(exc.kind)
                if exc.kind in ("disabled", "unauthorized"):
                    await sleep(300)  # configuration problem: back off long
                elif exc.kind == "rate_limited":
                    await sleep(self.options.reconnect_max)
                self._attempt = min(self._attempt + 1, 6)
            except (TimeoutError, OSError) as exc:
                self._report("unreachable")
                self._attempt = min(self._attempt + 1, 6)
                warning("beacon-stream", "stream disconnected", error=sanitize(exc, 120))
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001
                self._report("unreachable")
                self._attempt = min(self._attempt + 1, 6)
                warning("beacon-stream", "stream error", error=sanitize(exc, 120))

    def _report(self, kind: str) -> None:
        self.connected = kind == "ok"
        if self.on_stamp:
            self.on_stamp(kind)

    # -- SSE frame parsing (shared, unit-testable) -----------------------
    def handle_frame(self, raw: str) -> None:
        """Parse one SSE frame (event/data/id lines) and enqueue typed events."""
        event_type = "message"
        data_lines: list[str] = []
        for line in raw.splitlines():
            if line.startswith(":"):
                continue  # heartbeat comment
            if line.startswith("event:"):
                event_type = line.split(":", 1)[1].strip()
            elif line.startswith("data:"):
                data_lines.append(line.split(":", 1)[1].strip())
            elif line.startswith("id:"):
                try:
                    self.last_event_id = int(line.split(":", 1)[1].strip())
                except ValueError:
                    pass
        if not data_lines:
            return
        try:
            payload = json.loads("\n".join(data_lines))
        except (ValueError, TypeError):
            return
        self._enqueue(event_type, payload)

    def _enqueue(self, event_type: str, payload: dict) -> None:
        if event_type in ("hello", "message"):
            return
        if event_type in ("docker.transition", "system.health"):
            event = StreamEvent(
                type=event_type,
                ts=_parse_iso(payload.get("timestamp")) or time.time(),
                data=payload,
            )
            if self.events.full():
                try:
                    self.events.get_nowait()
                except asyncio.QueueEmpty:  # pragma: no cover
                    pass
            self.events.put_nowait(event)


def _parse_iso(value: str | None) -> float | None:
    if not value:
        return None
    try:
        from datetime import datetime

        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        return dt.timestamp()
    except (ValueError, TypeError):
        return None


class StreamingHttpPort(AiohttpPort):
    """AiohttpPort + streaming SSE reader for GET /stream."""

    def __init__(self, session) -> None:  # noqa: ANN001
        super().__init__(session)
        self._session = session

    async def sse_reader(self, url: str, headers: dict[str, str], last_event_id: int, on_frame) -> None:  # noqa: ANN001
        read_headers = dict(headers)
        if last_event_id >= 0:
            read_headers["Last-Event-ID"] = str(last_event_id)
        async with self._session.get(
            url, headers=read_headers, timeout=aiohttp_timeout(0)  # 0 = no total timeout;
        ) as resp:
            if resp.status != 200:
                text = await resp.text()
                raise BeaconError(classify_status(resp.status, None), resp.status, text[:200])
            buffer: list[str] = []
            async for raw in resp.content:
                line = raw.decode("utf-8", "replace").rstrip("\r\n")
                if line == "":
                    if buffer:
                        frame = "\n".join(buffer)
                        buffer.clear()
                        on_frame(frame)
                else:
                    buffer.append(line)


def parse_beacon_issue(raw: dict) -> BeaconIssue:
    return BeaconIssue(
        id=str(raw.get("id", "")),
        severity=str(raw.get("severity", "info")),
        category=str(raw.get("category", "issue")),
        status=str(raw.get("status", "active")),
        summary=str(raw.get("summary", "")),
        condition=str(raw.get("condition", "")),
        first_seen_at=raw.get("firstSeenAt"),
        last_seen_at=raw.get("lastSeenAt"),
        target=raw.get("target"),
        metrics=raw.get("metrics", {}) or {},
        suggested_checks=raw.get("suggestedChecks", []) or [],
    )
