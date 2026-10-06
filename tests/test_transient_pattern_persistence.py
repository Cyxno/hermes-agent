"""Regression: transient pattern incidents must persist to SQLite.

Shadow-soak 2026-10-06: confirm_pattern's INSERT OR REPLACE supplied 12 bind
parameters to an 11-placeholder statement (confirmed_at had a literal NULL in
VALUES), so every pattern confirmation raised sqlite3.ProgrammingError, aborted
its evaluation cycle (130 failed cycles in ~6h of shadow) and the pattern
incident was never written — silently lost on restart.
"""

from __future__ import annotations

import pytest
from conftest import run_cycles, set_plex_healthy, set_plex_unhealthy

from hermes.evaluator.incidents import IncidentEngine

pytestmark = pytest.mark.asyncio


async def test_transient_pattern_incident_is_persisted(stack):
    # five short unhealthy episodes -> five transients within the window
    for _ in range(5):
        set_plex_unhealthy(stack["beacon"], stack["netdata"])
        await run_cycles(stack, 1)  # OBSERVED (debounce not met)
        set_plex_healthy(stack["beacon"], stack["netdata"])
        await run_cycles(stack, 3, step=60)  # absence grace -> transient
    assert stack["engine"].transient_count("container_unhealthy:plex") >= 5

    # tracker confirms the pattern; the cycle must complete and the incident
    # must land in SQLite
    await run_cycles(stack, 1)
    pattern = stack["engine"].get("transient_pattern:container_unhealthy:plex")
    assert pattern is not None

    # restart semantics: a fresh engine on the same database still sees it
    engine2 = IncidentEngine(stack["db"], stack["cfg"].raw, stack["clock"], fast_interval=60)
    persisted = engine2.get("transient_pattern:container_unhealthy:plex")
    assert persisted is not None
    assert persisted.state in ("CONFIRMED", "ACTIVE")
