"""Regressie: pattern-episode storm + recovery-notificaties (soak rc.3, 2026-10-07).

Drie soak-gevonden bugs:
1. confirm_pattern deed INSERT OR REPLACE bij heropening binnen het venster en
   resette notification_sent/last_notified_at — elke fling van plex-scraper-vfs
   werd opnieuw een "eerste" alert (28 duplicaten in ~2,5 uur).
2. Niemand produceerde ooit een resolved-intent: recovery-notificaties waren
   structureel dood ondanks notify_recovery.
3. Reminder-cooldown vermenigvuldigde config-seconden met 60.
"""

from __future__ import annotations

import pytest
from conftest import run_cycles, set_plex_healthy, set_plex_unhealthy

pytestmark = pytest.mark.asyncio


def _add_transients(stack, fingerprint, count, spread=60.0):
    now = stack["clock"].now()
    for i in range(count):
        stack["db"].execute(
            "INSERT INTO transients(fingerprint, category, entity, severity, ts) VALUES(?,?,?,?,?)",
            (fingerprint, "container_unhealthy", fingerprint.split(":", 1)[-1], "warning", now - i * spread),
        )


def _intents_for(intents, kind, pid):
    return [i for i in intents if i["kind"] == kind and i["incident"].id == pid]


async def test_pattern_reopen_preserves_notification_state(stack):
    pid = "transient_pattern:container_unhealthy:plex"
    _add_transients(stack, "container_unhealthy:plex", 5)
    stack["tracker"].check()
    assert stack["engine"].pattern_incident_open("container_unhealthy:plex")
    assert _intents_for(stack["engine"].tick(), "alert", pid)

    stack["engine"].mark_notified(pid, stack["clock"].now(), "warning")
    assert stack["engine"].get(pid).notification_sent
    original_first_seen = stack["engine"].get(pid).first_seen

    # episode gedempt: transients verlopen uit het venster -> tracker lost af,
    # recovery-intent verschijnt (er is eerder een alert verzonden)
    stack["db"].execute("UPDATE transients SET ts = ts - ?", (21600 * 2,))
    stack["clock"].advance(10)
    stack["tracker"].check()
    assert stack["engine"].get(pid).state == "RESOLVED"
    resolved = _intents_for(stack["engine"].tick(), "resolved", pid)
    assert len(resolved) == 1

    # nieuwe fling binnen het venster -> heropen als ACTIVE met behouden
    # boekhouding; GEEN nieuwe alert (de storm-regressie)
    _add_transients(stack, "container_unhealthy:plex", 5)
    stack["clock"].advance(10)
    stack["tracker"].check()
    reopened = stack["engine"].get(pid)
    assert reopened.state == "ACTIVE"
    assert reopened.notification_sent
    assert reopened.first_seen == original_first_seen  # episode loopt door
    assert not _intents_for(stack["engine"].tick(), "alert", pid)


async def test_momentary_clear_does_not_resolve_pattern(stack):
    pid = "transient_pattern:container_unhealthy:plex"
    _add_transients(stack, "container_unhealthy:plex", 5)
    stack["tracker"].check()
    stack["engine"].tick()
    stack["engine"].mark_notified(pid, stack["clock"].now(), "warning")

    # geen live-signalen voor het pattern-incident, maar transients nog in
    # venster: absence-grace mag het incident NIET resolven (oude storm-bron)
    stack["clock"].advance(600)
    stack["tracker"].check()  # houdt het patroon open (n nog >= drempel)
    stack["engine"].tick()
    assert stack["engine"].get(pid).state in ("ACTIVE", "CONFIRMED")


async def test_recovery_notification_sent_once_after_alert(stack):
    set_plex_unhealthy(stack["beacon"], stack["netdata"])
    await run_cycles(stack, 3)  # OBSERVED -> PENDING -> CONFIRMED -> alert verstuurd
    assert any(k == "alert" for k, _ in stack["notifier"].delivered)

    set_plex_healthy(stack["beacon"], stack["netdata"])
    await run_cycles(stack, 4)  # hysteresis-clear -> RECOVERING -> RESOLVED -> recovery
    recoveries = [k for k, _ in stack["notifier"].delivered if k == "resolved"]
    assert len(recoveries) == 1

    # geen tweede recovery als het incident daarna nogmaals een resolve-loop maakt
    await run_cycles(stack, 3)
    recoveries = [k for k, _ in stack["notifier"].delivered if k == "resolved"]
    assert len(recoveries) == 1


async def test_reminder_after_repeat_cooldown_minutes(stack):
    set_plex_unhealthy(stack["beacon"], stack["netdata"])
    await run_cycles(stack, 3)
    assert any(k == "alert" for k, _ in stack["notifier"].delivered)

    # cooldowns zijn gedocumenteerd in MINUTEN; default repeat = 1440 min.
    # De oude live-config schreef seconden-cijfers (86400) -> met de *60 werd
    # dat 60 dagen in plaats van 24 uur.
    await run_cycles(stack, 1, step=1440 * 60 + 60)
    assert any(k == "reminder" for k, _ in stack["notifier"].delivered)
