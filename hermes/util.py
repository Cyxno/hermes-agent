"""Small shared utilities: backoff, circuit breaker, secret sanitizer, helpers."""

from __future__ import annotations

import random
import re
import time
from collections.abc import Awaitable, Callable
from typing import Any


def backoff_delay(attempt: int, base: float = 1.0, cap: float = 60.0, jitter: float = 0.2) -> float:
    """Exponential backoff with jitter. attempt starts at 0."""
    delay = min(cap, base * (2 ** max(0, attempt)))
    return delay * (1 + random.uniform(-jitter, jitter))


class CircuitBreaker:
    """Open after `threshold` consecutive failures; half-open after `reset_after` seconds."""

    def __init__(self, threshold: int = 5, reset_after: float = 120.0) -> None:
        self.threshold = threshold
        self.reset_after = reset_after
        self.failures = 0
        self.opened_at: float | None = None

    @property
    def is_open(self) -> bool:
        return self.opened_at is not None

    def allow(self, now: float) -> bool:
        if self.opened_at is None:
            return True
        if now - self.opened_at >= self.reset_after:
            return True  # half-open: allow one probe
        return False

    def record_success(self) -> None:
        self.failures = 0
        self.opened_at = None

    def record_failure(self, now: float) -> None:
        self.failures += 1
        if self.failures >= self.threshold and self.opened_at is None:
            self.opened_at = now


SECRET_PATTERNS = [
    re.compile(p, re.IGNORECASE)
    for p in (
        r"(bot\d+:[\w-]{20,})",           # telegram bot token
        r"(sk-[A-Za-z0-9-]{10,})",        # openai-style keys
        r"(Bearer\s+[\w.\-~=+/]{8,})",    # bearer tokens (keep scheme)
        r"((?:api[_-]?key|token|secret|password|authorization|credential)['\"]?\s*[:=]\s*['\"]?[^\s'\",}]{6,})",
    )
]


def sanitize(text: Any, limit: int = 400) -> str:
    """Best-effort secret scrubbing + length cap for anything that reaches logs/messages."""
    s = str(text)
    for pat in SECRET_PATTERNS:
        s = pat.sub("<masked>", s)
    return s[:limit]


def truncate(s: str, limit: int) -> str:
    return s if len(s) <= limit else s[: limit - 1] + "…"


def iso(ts: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


def safe_path(base: str, user: str) -> str | None:
    """Resolve `user` under `base`, refusing traversal outside base."""
    import os

    base_abs = os.path.realpath(base)
    joined = os.path.realpath(os.path.join(base_abs, user.lstrip("/")))
    if joined == base_abs or joined.startswith(base_abs + os.sep):
        return joined
    return None


async def retry_call(
    fn: Callable[[], Awaitable[Any]],
    attempts: int = 3,
    base_delay: float = 0.5,
    cap: float = 10.0,
    sleep: Callable[[float], Awaitable[None]] | None = None,
) -> Any:
    """Bounded retries with backoff; raises the last exception."""
    import asyncio

    if sleep is None:
        sleep = asyncio.sleep
    last: Exception | None = None
    for attempt in range(attempts):
        try:
            return await fn()
        except Exception as exc:  # noqa: BLE001 - deliberately broad at the boundary
            last = exc
            if attempt == attempts - 1:
                raise
            await sleep(backoff_delay(attempt, base=base_delay, cap=cap))
    raise last  # pragma: no cover
