"""Observer base: HTTP port abstraction + source stamps.

Observers depend on a tiny HttpPort so tests can stub transport without network.
All external calls are GET-only and time-bounded (spec §53).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from ..state.normalized import SourceStamp


class HttpError(Exception):
    def __init__(self, message: str, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


class HttpPort(Protocol):
    async def get_json(
        self, url: str, headers: dict[str, str] | None = None, timeout: float = 10.0
    ) -> tuple[int | None, Any]: ...

    async def get_text(
        self, url: str, headers: dict[str, str] | None = None, timeout: float = 10.0
    ) -> tuple[int | None, str]: ...


class AiohttpPort:
    """Default HttpPort backed by a shared aiohttp session (no redirects followed
    blindly; single hop only)."""

    def __init__(self, session) -> None:  # noqa: ANN001 - aiohttp session
        self._session = session

    async def get_json(self, url, headers=None, timeout=10.0):
        async with self._session.get(
            url, headers=headers, timeout=aiohttp_timeout(timeout), allow_redirects=False
        ) as resp:
            if resp.content_type and "json" not in (resp.content_type or ""):
                text = await resp.text()
                return resp.status, text[:2000]
            try:
                return resp.status, await resp.json(content_type=None)
            except Exception:
                return resp.status, None

    async def get_text(self, url, headers=None, timeout=10.0):
        async with self._session.get(
            url, headers=headers, timeout=aiohttp_timeout(timeout), allow_redirects=False
        ) as resp:
            return resp.status, await resp.text()


def aiohttp_timeout(seconds: float):
    import aiohttp

    return aiohttp.ClientTimeout(total=seconds)


@dataclass
class PollResult:
    stamp: SourceStamp
    data: Any = None


async def poll_with_stamp(
    name: str,
    fn,
    clock,  # noqa: ANN001
    breaker,  # noqa: ANN001
    now: float,
) -> PollResult:
    """Run a fetch, classify the outcome into a SourceStamp (spec §4/§30)."""
    if breaker.is_open and not breaker.allow(now):
        return PollResult(SourceStamp(source=name, ok=False, ts=now, error="circuit open"))
    try:
        data = await fn()
        breaker.record_success()
        return PollResult(SourceStamp(source=name, ok=True, ts=now), data)
    except HttpError as exc:
        breaker.record_failure(now)
        return PollResult(
            SourceStamp(
                source=name,
                ok=False,
                ts=now,
                error=str(exc)[:160],
                disabled=exc.status == 403,
            )
        )
    except (TimeoutError, OSError) as exc:
        breaker.record_failure(now)
        return PollResult(SourceStamp(source=name, ok=False, ts=now, error=str(exc)[:160]))
