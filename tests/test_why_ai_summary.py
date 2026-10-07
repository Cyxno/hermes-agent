"""Regression: /why crashed on incidents without an in-process AI summary.

Cutover smoke test 2026-10-06: set_ai_summary stored the summary in SQLite and
set it dynamically on the in-memory Incident, but the dataclass had no such
field and load_open()/from_row() never hydrated it — so /why on any incident
loaded from the database (i.e. after a restart, or never investigated in this
process) raised AttributeError.
"""

from __future__ import annotations

from conftest import run_cycles, set_plex_unhealthy

from hermes.evaluator.incidents import IncidentEngine


async def test_why_survives_incident_without_ai_summary(stack):
    set_plex_unhealthy(stack["beacon"], stack["netdata"])
    await run_cycles(stack, 3)  # OBSERVED -> PENDING -> CONFIRMED
    incident = stack["engine"].get("container_unhealthy:plex")
    assert incident is not None
    assert incident.ai_summary is None  # never investigated

    from types import SimpleNamespace

    from hermes.interfaces.commands import CommandHandler

    app = SimpleNamespace(engine=stack["engine"], cfg=stack["cfg"])
    handler = CommandHandler(app, None)
    text = handler._why(incident.id)
    assert "AI:" not in text


async def test_ai_summary_survives_engine_restart(stack):
    set_plex_unhealthy(stack["beacon"], stack["netdata"])
    await run_cycles(stack, 3)
    incident_id = "container_unhealthy:plex"

    stack["engine"].set_ai_summary(incident_id, "root cause: test")
    assert stack["engine"].get(incident_id).ai_summary == "root cause: test"

    engine2 = IncidentEngine(stack["db"], stack["cfg"].raw, stack["clock"], fast_interval=60)
    assert engine2.get(incident_id).ai_summary == "root cause: test"
