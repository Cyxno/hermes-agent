"""2.0.1 quality fixes: /status host-velden, partial-cycle carry-forward en
'AI gebruikt'-metadata.

Root causes (live audit 2026-10-07):
- Beacon summary/system levert cpu/memory percent = null (alleen load);
  Netdata is de secundaire bron voor host CPU/RAM.
- array=? : Beacon storage wordt alleen op reconcile gepolld; elke cycle
  verving last_state door een lege state, waardoor een geldige reconcile-
  waarde bij de eerstvolgende fast cycle verdween.
"""

from __future__ import annotations

import pytest
from conftest import run_cycles, set_plex_unhealthy

from hermes.intelligence.provider import ai_usage_for_incident
from hermes.interfaces.telegram import format_alert

pytestmark = pytest.mark.asyncio


def beacon_payload(cpu_pct=None, mem_pct=None, temp=55, array="STARTED"):
    """Payload volgens het ECHTE live Beacon Agent API-contract (2026-10-07):
    summary.cpu.percent en summary.memory.percent kunnen null zijn; storage
    levert arrayState/parityStatus/capacity/disks."""
    return {
        "cpu": {"percent": cpu_pct, "load5": 7.8},
        "memory": {"percent": mem_pct, "usedBytes": None, "totalBytes": None},
        "load": None,
        "thermal": {"currentC": temp, "state": "ok"},
        "docker": {"running": 10, "total": 12, "unhealthy": 0},
        "health": {"level": None, "reasons": []},
    }


def storage_payload(array="STARTED", parity="IDLE"):
    return {"arrayState": array, "parityStatus": parity,
            "capacity": {"usedBytes": 100, "totalBytes": 200, "freeBytes": 100},
            "disks": [{"name": "sda", "role": "parity", "state": "ok", "temperatureC": 30,
                       "sizeBytes": 1000, "usedBytes": 500}]}


async def test_full_beacon_payload_shows_all_status_values(stack):
    stack["beacon"].summary_data.update(beacon_payload(cpu_pct=12, mem_pct=41))
    stack["beacon"].storage_data = storage_payload()
    await run_cycles(stack, 1, kind="reconcile")
    host = stack["pipeline"].last_state.host
    assert host.cpu_pct == 12 and host.mem_pct == 41
    assert host.package_temp_c == 55
    assert host.array_state == "STARTED"


async def test_fast_after_reconcile_keeps_array_state(stack):
    stack["beacon"].storage_data = storage_payload(array="STARTED")
    await run_cycles(stack, 1, kind="reconcile")
    assert stack["pipeline"].last_state.host.array_state == "STARTED"

    # fast cycle pollt storage niet — de waarde mag niet verdwijnen
    await run_cycles(stack, 2, kind="fast")
    assert stack["pipeline"].last_state.host.array_state == "STARTED"
    assert stack["pipeline"].last_state.host.disks  # disks ook carry-forward


async def test_new_storage_value_wins_immediately(stack):
    stack["beacon"].storage_data = storage_payload(array="STARTED")
    await run_cycles(stack, 1, kind="reconcile")
    await run_cycles(stack, 2, kind="fast")
    assert stack["pipeline"].last_state.host.array_state == "STARTED"

    stack["beacon"].storage_data = storage_payload(array="STOPPED")
    await run_cycles(stack, 1, kind="reconcile")
    assert stack["pipeline"].last_state.host.array_state == "STOPPED"


async def test_never_observed_stays_unknown():
    from hermes.state.normalized import HostView

    host = HostView()
    assert host.cpu_pct is None and host.array_state is None  # geen verzonnen waarden


async def test_beacon_null_percent_falls_back_to_netdata(stack):
    stack["beacon"].summary_data.update(beacon_payload(cpu_pct=None, mem_pct=None))

    class NetdataHostMetrics:
        async def host_cpu_pct(self):
            return 38.8

        async def host_mem_pct(self):
            return 79.9

        async def alarms(self):
            return []

    stack["pipeline"].netdata = NetdataHostMetrics()
    await run_cycles(stack, 1, kind="fast")
    host = stack["pipeline"].last_state.host
    assert host.cpu_pct == 38.8 and host.mem_pct == 79.9


# ---------------------------------------------------------------- AI gebruikt

def snapshot_with_ai(incident_id, ai_usage):
    return {"id": incident_id, "category": "container_unhealthy", "entity": "x",
            "title": "Cronjob faalt", "severity": "warning", "state": "ACTIVE",
            "first_seen": 0, "duration": "8m", "occurrences": 3, "evidence": [],
            "ai_usage": ai_usage}


async def test_ai_metadata_none_means_nee(stack):
    snap = snapshot_with_ai("inc:clean", None)
    text = format_alert("alert", snap)
    assert "AI gebruikt: nee" in text
    assert "AI gebruikt: ja" not in text


async def test_ai_metadata_gemini_success(stack):
    snap = snapshot_with_ai("inc:1", {"used": True, "model": "google/gemini-2.5-flash-lite",
                                      "tier": 1, "failed": False})
    text = format_alert("alert", snap)
    assert "AI gebruikt: ja — Gemini 2.5 Flash-Lite" in text


async def test_ai_metadata_deepseek_tier2_after_escalation(stack):
    snap = snapshot_with_ai("inc:1", {"used": True, "model": "deepseek/deepseek-v4-flash-0731",
                                      "tier": 2, "failed": False})
    text = format_alert("reminder", snap)
    assert "AI gebruikt: ja — DeepSeek V4 Flash (tier 2)" in text


async def test_ai_metadata_failed_calls_show_mislukt(stack):
    snap = snapshot_with_ai("inc:1", {"used": True, "model": None, "tier": None, "failed": True})
    text = format_alert("alert", snap)
    assert "AI gebruikt: ja — analyse mislukt" in text


async def test_ai_metadata_resolved_includes_line(stack):
    snap = snapshot_with_ai("inc:1", None)
    text = format_alert("resolved", snap)
    assert "AI gebruikt: nee" in text


async def test_ai_metadata_is_incident_scoped(stack):
    """AI-call voor een ANDER incident -> huidige melding blijft 'nee'."""
    stack["db"].execute(
        "INSERT INTO ai_calls(ts, incident_id, tier, model, purpose, result) "
        "VALUES(?,?,?,?,?,?)",
        (stack["clock"].now(), "inc:ander", 1, "google/gemini-2.5-flash-lite", "diagnose", "ok"),
    )
    assert ai_usage_for_incident(stack["db"], "inc:ander") is not None
    assert ai_usage_for_incident(stack["db"], "inc:mijn") is None
    text = format_alert("alert", snapshot_with_ai("inc:mijn", None))
    assert "AI gebruikt: nee" in text


async def test_ai_usage_helper_prefers_last_successful_call(stack):
    ins = "INSERT INTO ai_calls(ts, incident_id, tier, model, purpose, result) VALUES(?,?,?,?,?,?)"
    now = stack["clock"].now()
    stack["db"].execute(ins, (now, "inc:x", 1, "google/gemini-2.5-flash-lite", "diagnose", "invalid_output"))
    stack["db"].execute(ins, (now + 5, "inc:x", 2, "deepseek/deepseek-v4-flash-0731", "diagnose", "ok"))
    usage = ai_usage_for_incident(stack["db"], "inc:x")
    assert usage == {"used": True, "model": "deepseek/deepseek-v4-flash-0731", "tier": 2, "failed": False}


async def test_beacon_issue_notification_without_ai_says_nee(stack):
    """Cronjob/update-issue pad: volledig deterministisch -> 'AI gebruikt: nee'."""
    stack["beacon"].issues_data = [{
        "id": "updates:mysql:high_risk_update", "severity": "warning", "category": "updates",
        "status": "active", "condition": "high_risk_update", "summary": "HIGH-risk update beschikbaar",
    }]
    await run_cycles(stack, 3, step=60)
    assert stack["notifier"].delivered
    updates = [s for _, s in stack["notifier"].delivered if s.get("category") == "beacon_updates"]
    assert updates
    for snap in updates:
        assert snap.get("ai_usage") is None


async def test_investigate_then_next_notification_shows_gemini(stack):
    """Na een (gescripte) AI-analyse op het incident meldt de volgende
    notificatie correct 'AI gebruikt: ja'."""
    ins = "INSERT INTO ai_calls(ts, incident_id, tier, model, purpose, result) VALUES(?,?,?,?,?,?)"
    set_plex_unhealthy(stack["beacon"], stack["netdata"])
    stack["db"].execute(ins, (stack["clock"].now(), "container_unhealthy:plex", 1,
                              "google/gemini-2.5-flash-lite", "diagnose", "ok"))
    await run_cycles(stack, 3)  # OBSERVED -> PENDING -> CONFIRMED (AI-call was er al)
    snap = stack["engine"].incident_snapshot(stack["engine"].get("container_unhealthy:plex"))
    assert snap["ai_usage"]["used"] is True
    delivered = [(k, s) for k, s in stack["notifier"].delivered if s.get("id") == "container_unhealthy:plex"]
    assert delivered
    text = format_alert(delivered[0][0], delivered[0][1])
    assert "AI gebruikt: ja — Gemini 2.5 Flash-Lite" in text
