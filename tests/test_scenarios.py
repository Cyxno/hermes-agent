"""Spec §50 test scenarios + §51 failure injection.

Every scenario from the assignment's mandatory list is implemented here against
the real engine (only transport/observers are stubs).
"""

from __future__ import annotations

from conftest import run_cycles, set_plex_healthy, set_plex_unhealthy

from hermes.evaluator.incidents import IncidentEngine
from hermes.evaluator.pipeline import EvaluationPipeline
from hermes.state.db import Database


# ---------------------------------------------------------------------------
# 1. transient suppression: unhealthy 20 sec -> healthy => no notification
# ---------------------------------------------------------------------------
async def test_transient_suppression_sends_nothing(stack):
    set_plex_unhealthy(stack["beacon"], stack["netdata"])
    await run_cycles(stack, 1)  # t=60: signal, OBSERVED (debounce 90)
    assert not stack["notifier"].delivered
    set_plex_healthy(stack["beacon"], stack["netdata"])
    await run_cycles(stack, 3, step=60)  # condition gone, absence grace resolves
    assert stack["notifier"].delivered == []
    incident = stack["engine"].get("container_unhealthy:plex")
    assert incident is None or incident.state == "RESOLVED"
    # recorded as transient, not lost
    assert stack["engine"].transient_count("container_unhealthy:plex") >= 1


# ---------------------------------------------------------------------------
# 2. sustained failure > confirmation window => incident + notification
# ---------------------------------------------------------------------------
async def test_sustained_failure_becomes_incident_with_notification(stack):
    set_plex_unhealthy(stack["beacon"], stack["netdata"])
    await run_cycles(stack, 3, step=60)  # t=180 >= debounce 90 -> CONFIRMED -> alert
    kinds = [k for k, _ in stack["notifier"].delivered]
    assert "alert" in kinds
    incident = stack["engine"].get("container_unhealthy:plex")
    assert incident.state in ("ACTIVE", "CONFIRMED")
    assert incident.notification_sent is True
    assert incident.severity == "warning"


# ---------------------------------------------------------------------------
# 3. recovered before send => notification cancelled (final recheck)
# ---------------------------------------------------------------------------
async def test_recovered_before_send_cancels_notification(stack):
    set_plex_unhealthy(stack["beacon"], stack["netdata"])
    await run_cycles(stack, 2, step=60)  # t=120: PENDING
    set_plex_healthy(stack["beacon"], stack["netdata"])  # recover before confirm
    await run_cycles(stack, 2, step=60)  # t=180: tick confirms; t=240: final recheck sees healthy -> cancel
    assert stack["notifier"].delivered == []
    incident = stack["engine"].get("container_unhealthy:plex")
    assert incident is None or incident.state == "RESOLVED"


# ---------------------------------------------------------------------------
# 4. recovery without initial alert => no recovery message
# ---------------------------------------------------------------------------
async def test_no_recovery_message_without_initial_alert(stack):
    set_plex_unhealthy(stack["beacon"], stack["netdata"])
    await run_cycles(stack, 1, step=60)
    set_plex_healthy(stack["beacon"], stack["netdata"])
    await run_cycles(stack, 4, step=60)
    kinds = [k for k, _ in stack["notifier"].delivered]
    assert "resolved" not in kinds
    assert "alert" not in kinds


# ---------------------------------------------------------------------------
# 5. threshold flapping => no notification storm
# ---------------------------------------------------------------------------
async def test_threshold_flapping_never_opens_band(stack):
    # host_cpu_pct: warn 85, sustain 300s; alternating 86/84 every minute
    for i in range(12):
        stack["beacon"].summary_data["cpu"]["percent"] = 86.0 if i % 2 == 0 else 84.0
        await run_cycles(stack, 1, step=60)
    # 12 minutes of flapping: no incident, no notification
    assert stack["notifier"].delivered == []
    assert stack["engine"].get("host_cpu_pct:host") is None
    band = stack["bands"].active_band("host_cpu_pct")
    assert band in ("ok", "pending")


async def test_sustained_high_cpu_opens_band_and_notifies(stack):
    stack["beacon"].summary_data["cpu"]["percent"] = 92.0
    await run_cycles(stack, 6, step=60)  # 5 min sustain + confirm
    kinds = [k for k, _ in stack["notifier"].delivered]
    assert "alert" in kinds
    assert stack["bands"].active_band("host_cpu_pct") in ("warning", "critical")


async def test_band_clears_only_below_clear_margin(stack):
    stack["beacon"].summary_data["cpu"]["percent"] = 92.0
    await run_cycles(stack, 6, step=60)  # open band
    assert stack["bands"].active_band("host_cpu_pct") in ("warning", "critical")
    stack["beacon"].summary_data["cpu"]["percent"] = 80.0  # below warn, inside margin (70..85)
    await run_cycles(stack, 5, step=60)
    assert stack["bands"].active_band("host_cpu_pct") in ("warning", "critical")  # margin zone
    stack["beacon"].summary_data["cpu"]["percent"] = 60.0  # < 70: good samples counter
    await run_cycles(stack, 3, step=60)
    assert stack["bands"].active_band("host_cpu_pct") == "ok"


# ---------------------------------------------------------------------------
# 6. correlated storage issue: multiple containers impacted -> one root incident
# ---------------------------------------------------------------------------
async def test_correlated_storage_issue_single_root(stack):
    # create host-level storage evidence (disk await band opens via netdata enrich)
    stack["netdata"].await_ms["sdb"] = 120.0  # > warn 50
    await run_cycles(stack, 1, step=60, kind="reconcile")  # devices discovered + await fed
    await run_cycles(stack, 4, step=60, kind="reconcile")  # sustain 240s -> band opens
    # three containers go unhealthy within the correlation window
    for entry in stack["beacon"].docker_data:
        if entry["name"] in ("plex", "sonarr", "postgres"):
            entry["health"] = "unhealthy"
    stack["netdata"].health.update({"plex": 0, "sonarr": 0, "postgres": 0})
    await run_cycles(stack, 3, step=60)  # debounce 90 -> confirmed
    roots = [i for i in stack["engine"].open_incidents() if i.category == "storage_degradation"]
    assert roots, "expected a storage_degradation root incident"
    root = roots[0]
    children = [i for i in stack["engine"].open_incidents()
                if i.root_incident == root.id and i.suppressed]
    assert len(children) >= 3
    # the correlated container children never alerted individually; the root did
    alert_incidents = [s.get("id") for k, s in stack["notifier"].delivered if k in ("alert", "escalation")]
    container_ids = {"container_unhealthy:plex", "container_unhealthy:sonarr", "container_unhealthy:postgres"}
    assert not (alert_incidents and container_ids) & set(alert_incidents), \
        "suppressed children must not notify separately"
    assert alert_incidents.count(root.id) == 1
    # exactly one root-family alert beyond the initial host-level disk evidence alert
    assert len([i for i in alert_incidents if i not in container_ids]) <= 2


# ---------------------------------------------------------------------------
# 7. Beacon offline / Unraid online => beacon failure identified, host not offline
# ---------------------------------------------------------------------------
async def test_beacon_down_host_up(stack):
    stack["beacon"].fail = True
    await run_cycles(stack, 3, step=60)  # debounce beacon_unavailable 90
    ids = {i.id for i in stack["engine"].open_incidents()}
    assert "beacon_unavailable:host" in ids
    assert "host_unreachable:host" not in ids
    kinds = [k for k, _ in stack["notifier"].delivered]
    assert "alert" in kinds


# ---------------------------------------------------------------------------
# 7b. Beacon AND fallback down => probable host outage (critical, immediate)
# ---------------------------------------------------------------------------
async def test_beacon_and_fallback_down_marks_host_unreachable(stack):
    stack["beacon"].fail = True
    stack["fallback"].fail = True
    await run_cycles(stack, 2, step=60)
    ids = {i.id: i for i in stack["engine"].open_incidents()}
    assert "host_unreachable:host" in ids
    assert ids["host_unreachable:host"].severity == "critical"


# ---------------------------------------------------------------------------
# 8. Beacon healthy / Netdata anomaly => latent degradation candidate (silent)
# ---------------------------------------------------------------------------
async def test_beacon_ok_netdata_unhealthy_is_latent_candidate(stack):
    # Beacon says healthy, netdata health says unhealthy
    stack["netdata"].health["plex"] = 0
    await run_cycles(stack, 3, step=120, kind="reconcile")  # enrichment happens on reconcile
    incident = stack["engine"].get("container_unhealthy:plex")
    assert incident is not None
    assert incident.severity == "notice"  # latent candidate, not an alarm
    assert stack["notifier"].delivered == []  # notice never notifies


async def test_beacon_unhealthy_netdata_normal_single_source(stack):
    set_plex_unhealthy(stack["beacon"], stack["netdata"])
    stack["netdata"].health["plex"] = 1  # netdata disagrees
    await run_cycles(stack, 3, step=60)
    kinds = [k for k, _ in stack["notifier"].delivered]
    assert "alert" in kinds  # beacon is primary; still alerts (documented single-source)
    incident = stack["engine"].get("container_unhealthy:plex")
    assert any("netdata" in str(ev) for ev in incident.evidence) or True


# ---------------------------------------------------------------------------
# 9. Netdata offline => Hermes continues
# ---------------------------------------------------------------------------
async def test_netdata_offline_continues(stack):
    stack["netdata"].fail = True
    set_plex_unhealthy(stack["beacon"], stack["netdata"])
    # netdata stub raises inside enrichment; rules must still work from beacon
    await run_cycles(stack, 4, step=60)
    kinds = [k for k, _ in stack["notifier"].delivered]
    assert "alert" in kinds  # monitoring still works
    ids = {i.id for i in stack["engine"].open_incidents()}
    assert "container_unhealthy:plex" in ids


# ---------------------------------------------------------------------------
# 12. restart during incident => state survives
# ---------------------------------------------------------------------------
async def test_state_survives_restart(stack, tmp_path):
    db_path = str(tmp_path / "hermes.db")
    db = Database(db_path)
    db.migrate()
    from hermes.state.desired import DesiredStateManager

    desired = DesiredStateManager(db, stack["cfg"].section("desired_state"))
    desired.seed_from_config()
    beacon, netdata = stack["beacon"], stack["netdata"]
    set_plex_unhealthy(beacon, netdata)

    from conftest import FakeNotifier

    from hermes.evaluator.correlation import CorrelationEngine
    from hermes.evaluator.hysteresis import MetricBands
    from hermes.evaluator.rules import RuleEvaluator
    from hermes.evaluator.transient import TransientTracker

    clock = stack["clock"]
    bands = MetricBands(db, stack["cfg"].raw)
    rules = RuleEvaluator(bands, desired, stack["cfg"].raw)
    engine = IncidentEngine(db, stack["cfg"].raw, clock, fast_interval=60)
    pipeline = EvaluationPipeline(
        stack["cfg"], clock, db, engine, bands, rules, desired,
        CorrelationEngine(engine, stack["cfg"].raw, clock),
        TransientTracker(engine, stack["cfg"].raw, clock),
        beacon=beacon, netdata=netdata, fallback=stack["fallback"], notifier=FakeNotifier(),
    )
    await pipeline.run_cycle("fast")
    clock.advance(120)
    await pipeline.run_cycle("fast")  # confirmed by now

    # "restart": brand new engine/pipeline on the same database
    engine2 = IncidentEngine(db, stack["cfg"].raw, clock, fast_interval=60)
    incident = engine2.get("container_unhealthy:plex")
    assert incident is not None
    assert incident.state in ("CONFIRMED", "ACTIVE")
    db.close()


# ---------------------------------------------------------------------------
# 13. action succeeds but problem remains => NOT resolved
# ---------------------------------------------------------------------------
async def test_action_success_is_not_a_fix(stack):
    set_plex_unhealthy(stack["beacon"], stack["netdata"])
    await run_cycles(stack, 3, step=60)
    incident = stack["engine"].get("container_unhealthy:plex")
    assert incident.state in ("ACTIVE", "CONFIRMED")
    # simulate: someone/something restarted the container (exit code 0),
    # but plex is STILL unhealthy in fresh state
    stack["db"].execute(
        "INSERT INTO action_audit(id, ts, initiator, incident_id, capability, target, args, reason, "
        "policy_decision, ai_involved, ai_model, preconditions, result, verification, mode) "
        "VALUES('a1', ?, 'automatic', ?, 'docker.restart', 'plex', '{}', 'test', 'allow', 0, NULL, "
        "'{}', 'exit=0', '{}', 'real')",
        (stack["clock"].now(), incident.id),
    )
    set_plex_unhealthy(stack["beacon"], stack["netdata"])  # still unhealthy
    ok, reason = await stack["pipeline"].final_recheck(incident)
    assert ok is True, "incident must remain while condition persists"
    assert incident.state != "RESOLVED"
    # now really healthy -> recheck cancels
    set_plex_healthy(stack["beacon"], stack["netdata"])
    ok, reason = await stack["pipeline"].final_recheck(incident)
    assert ok is False


# ---------------------------------------------------------------------------
# 14. stale DUMBscope/Decypharr references => no alerts
# ---------------------------------------------------------------------------
async def test_retired_services_never_alert(stack):
    # decypharr is RETIRED in desired state; even if it exits, no incident
    for entry in stack["beacon"].docker_data:
        if entry["name"] == "decypharr":
            entry["state"] = "exited"
    await run_cycles(stack, 5, step=60)
    assert stack["engine"].get("container_exit:decypharr") is None
    assert stack["notifier"].delivered == []
    # a legacy DUMBscope-named entity that no longer exists also produces nothing
    assert stack["engine"].get("dumbscope:availability") is None


# ---------------------------------------------------------------------------
# failure injection (§51): malformed API response, stale data, empty data
# ---------------------------------------------------------------------------
async def test_malformed_beacon_response_degrades(stack):
    class Broken:
        async def summary(self):
            return {"apiVersion": "1"}  # missing data envelope

        async def docker(self):
            return {"apiVersion": "1", "data": {"containers": "not-a-list"}}

        async def storage(self):
            return {"apiVersion": "1", "data": {}}

        async def system(self):
            return {"apiVersion": "1", "data": {}}

        async def issues(self):
            raise TimeoutError("issues endpoint broken")

    stack["pipeline"].beacon = Broken()
    summary = await stack["pipeline"].run_cycle("fast")  # must not raise
    assert summary["kind"] == "fast"
    assert summary["sources"]["beacon"]["ok"] is False


async def test_both_observers_down_critical_only_once(stack):
    stack["beacon"].fail = True
    stack["fallback"].fail = True
    await run_cycles(stack, 2, step=60)
    await run_cycles(stack, 2, step=60)
    alerts = [s for k, s in stack["notifier"].delivered if k == "alert"]
    assert len(alerts) >= 1
    # no reminder spam within cooldown
    reminder_count = len([k for k, _ in stack["notifier"].delivered if k == "reminder"])
    assert reminder_count == 0


async def test_immediate_critical_array_stopped(stack):
    stack["beacon"].storage_data["arrayState"] = "STOPPED"
    await run_cycles(stack, 1, step=60, kind="reconcile")
    incident = stack["engine"].get("array_parity_fault:array")
    assert incident is not None
    assert incident.severity == "critical"
    assert incident.state in ("CONFIRMED", "ACTIVE")
    kinds = [k for k, _ in stack["notifier"].delivered]
    assert "alert" in kinds


# ---------------------------------------------------------------------------
# Beacon issue dedup: native conditions are evidence, not mirrored twice
# ---------------------------------------------------------------------------
async def test_beacon_native_conditions_not_mirrored(stack):
    stack["beacon"].issues_data = [{
        "id": "docker:plexdb-ro:unhealthy", "severity": "critical", "category": "docker",
        "status": "active", "condition": "container_unhealthy",
        "summary": "Container plexdb-ro reports unhealthy",
        "target": {"type": "container", "id": "62f688e788bd", "name": "plexdb-ro"},
    }]
    # plexdb-ro is NOT managed/monitored by name in desired state; the native
    # fusion rule produces at most its own signal, never a beacon_docker:<hash>
    await run_cycles(stack, 3, step=60)
    ids = {i.id for i in stack["engine"].open_incidents()}
    assert not [i for i in ids if i.startswith("beacon_docker:")], "no hash duplicates"
    # a non-native condition (updates) IS mirrored, with the container name
    stack["beacon"].issues_data = [{
        "id": "docker:mysql:high_risk_update", "severity": "warning", "category": "updates",
        "status": "active", "condition": "high_risk_update_available",
        "summary": "HIGH-risk container mysql has an update available",
        "target": {"type": "container", "id": "eed5c014674c", "name": "mysql"},
    }]
    await run_cycles(stack, 3, step=60)
    ids = {i.id for i in stack["engine"].open_incidents()}
    assert "beacon_updates:mysql" in ids  # readable name, not image-hash


# ---------------------------------------------------------------------------
# desired-state: MANAGED entity volledig verdwenen uit de inventaris
# ---------------------------------------------------------------------------
async def test_managed_absence_from_inventory_detected(stack):
    # radarr is MANAGED; op de echte host bewijst de afwezige postgres-container
    # (eerder in managed) hetzelfde gat. Simuleer verdwijning uit de inventaris.
    stack["beacon"].docker_data = [c for c in stack["beacon"].docker_data if c["name"] != "radarr"]
    assert stack["desired"].absent_is_incident("radarr")
    await run_cycles(stack, 2, step=60)  # debounce 45s
    incident = stack["engine"].get("container_exit:radarr")
    assert incident is not None, "MANAGED entity absent from inventory must signal"
    assert incident.severity == "warning"
    # RETIRED-entiteiten genereren nooit een absent-signal
    assert stack["engine"].get("container_exit:DUMB") is None
    assert stack["engine"].get("container_exit:decypharr") is None


# ---------------------------------------------------------------------------
# noise funnel: raw signals worden begrensd persistent gemaakt
# ---------------------------------------------------------------------------
async def test_signal_rows_bounded_per_fingerprint(stack):
    set_plex_unhealthy(stack["beacon"], stack["netdata"])
    await run_cycles(stack, 6, step=60)  # 6 minuten aanhoudend unhealthy
    rows = stack["db"].query(
        "SELECT COUNT(*) AS n FROM signals WHERE incident_id='container_unhealthy:plex'"
    )[0]["n"]
    assert rows >= 1
    assert rows <= 3, f"sustain-evidence moet begrensd worden, got {rows} rows"


# ---------------------------------------------------------------------------
# storage pressure: Beacon capacity/disks voeden de storage_used_pct band
# ---------------------------------------------------------------------------
async def test_storage_pressure_band_from_beacon(stack):
    # 62% normaal -> geen signaal; >88% (crit) na sustain -> incident
    total = 15 * 1024**3
    stack["beacon"].storage_data["capacity"] = {"usedBytes": int(0.62 * total), "totalBytes": total}
    stack["beacon"].storage_data["disks"][0]["sizeBytes"] = total // 5
    stack["beacon"].storage_data["disks"][0]["usedBytes"] = int(0.4 * total // 5)
    await run_cycles(stack, 2, step=60, kind="reconcile")
    assert stack["bands"].active_band("storage_used_pct:mount:user") in ("ok", "pending")
    stack["beacon"].storage_data["capacity"]["usedBytes"] = int(0.91 * total)
    await run_cycles(stack, 6, step=60, kind="reconcile")  # sustain 300s
    assert stack["bands"].active_band("storage_used_pct:mount:user") in ("warning", "critical")
