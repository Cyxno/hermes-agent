"""Injectable clock so every timing decision (debounce, hysteresis, cooldown,
backoff) is deterministic and testable."""

from __future__ import annotations

import time
from dataclasses import dataclass, field


class Clock:
    def now(self) -> float:
        raise NotImplementedError

    def monotonic(self) -> float:
        raise NotImplementedError


class SystemClock(Clock):
    def now(self) -> float:
        return time.time()

    def monotonic(self) -> float:
        return time.monotonic()


@dataclass
class FakeClock(Clock):
    """Manual clock for tests. Seconds are epoch seconds; advance() moves time."""

    _now: float = 1_700_000_000.0
    _mono: float = 0.0
    _sleeps: list = field(default_factory=list)

    def now(self) -> float:
        return self._now

    def monotonic(self) -> float:
        return self._mono

    def advance(self, seconds: float) -> None:
        self._now += seconds
        self._mono += seconds

    async def sleep(self, seconds: float) -> None:
        self._sleeps.append(seconds)
        self.advance(seconds)
