"""Regression: pattern-episode storm + recovery notifications (rc.3 soak, 2026-10-07).

Three soak-found bugs:
1. confirm_pattern did INSERT OR REPLACE on re-open within the window and
   reset notification_sent/last_notified_at — every flap of plex-scraper-vfs
   became a fresh "first" alert (28 duplicates in ~2.5h).
2. Nobody ever produced a resolved intent: recovery notifications were
   structurally dead despite notify_recovery.
3. Reminder cooldown multiplied config minutes by 60.
"""

from __future__ import annotations

from conftest import run_cycles, set_plex_healthy, set_plex_unhealthy


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

    # episode cleared: transients age out of the window -> tracker resolves,
    # recovery intent appears (an alert was sent before)
    stack["db"].execute("UPDATE transients SET ts = ts - ?", (21600 * 2,))
    stack["clock"].advance(10)
    stack["tracker"].check()
    assert stack["engine"].get(pid).state == "RESOLVED"
    resolved = _intents_for(stack["engine"].tick(), "resolved", pid)
    assert len(resolved) == 1

    # new flap within the window -> reopen as ACTIVE, keeping
    # bookkeeping; NO new alert (the storm regression)
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

    # no live signals for the pattern incident, but transients still in
    # window: absence grace must NOT resolve it (old storm source)
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

    # no second recovery when the incident resolves again later
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


async def test_pattern_multiple_reopenings_exactly_one_notification(stack):
    """Fase 15: herhaalde re-confirms van dezelfde episode -> exact 1 alert."""
    pid = "transient_pattern:container_unhealthy:plex"
    _add_transients(stack, "container_unhealthy:plex", 5)
    stack["tracker"].check()
    alerts = _intents_for(stack["engine"].tick(), "alert", pid)
    assert len(alerts) == 1
    stack["engine"].mark_notified(pid, stack["clock"].now(), "warning")

    # herhaalde flingen binnen het venster: pattern blijft open, 0 nieuwe alerts
    for _ in range(3):
        _add_transients(stack, "container_unhealthy:plex", 2)
        stack["clock"].advance(10)
        stack["tracker"].check()
        stack["engine"].tick()
    assert stack["engine"].get(pid).notification_sent
    assert len(_intents_for(stack["engine"].tick(), "alert", pid)) == 0


async def test_recovery_after_reopen_episode_not_duplicated(stack):
    """Reopen zonder nieuwe alert -> resolve geeft GEEN tweede recovery."""
    pid = "transient_pattern:container_unhealthy:plex"
    _add_transients(stack, "container_unhealthy:plex", 5)
    stack["tracker"].check()
    stack["engine"].tick()
    stack["engine"].mark_notified(pid, stack["clock"].now(), "warning")

    # episode 1 eindigt: recovery #1
    stack["db"].execute("UPDATE transients SET ts = ts - ?", (21600 * 2,))
    stack["clock"].advance(10)
    stack["tracker"].check()
    resolved1 = _intents_for(stack["engine"].tick(), "resolved", pid)
    assert len(resolved1) == 1

    # episode 2 binnen het venster: heropend zonder nieuwe alert; eindigt weer
    _add_transients(stack, "container_unhealthy:plex", 5)
    stack["clock"].advance(10)
    stack["tracker"].check()
    assert stack["engine"].get(pid).state == "ACTIVE"
    assert not _intents_for(stack["engine"].tick(), "alert", pid)
    stack["db"].execute("UPDATE transients SET ts = ts - ?", (21600 * 2,))
    stack["clock"].advance(10)
    stack["tracker"].check()
    stack["engine"].tick()
    # episode 2 zonder alert -> ook geen recovery (notified_active gate)
    assert len(_intents_for(stack["engine"].tick(), "resolved", pid)) == 0


async def test_never_notified_resolves_silently(stack):
    """Fase 15: nooit-genotificeerd incident -> resolve, 0 recovery."""
    set_plex_unhealthy(stack["beacon"], stack["netdata"])
    await run_cycles(stack, 1)  # OBSERVED/PENDING
    set_plex_healthy(stack["beacon"], stack["netdata"])
    await run_cycles(stack, 4)
    kinds = [k for k, _ in stack["notifier"].delivered if k == "resolved"]
    assert kinds == []
