"""2.1 guarded-executor safety matrix (Part D).

Every adversarial gate from the 2.1 spec: kill switch, idempotency, cooldowns,
budgets, concurrency, protected targets, fresh pre-execution recheck,
malicious targets, approval scoping. Real transport is always stubbed.
"""

from __future__ import annotations

import pytest
from conftest import FakeClock

from hermes.executor.capabilities import CapabilityRegistry
from hermes.executor.executor import ActionPlan, Executor, SshOperator
from hermes.executor.policy import ApprovalStore, PolicyEngine
from hermes.state.db import Database

pytestmark = pytest.mark.asyncio


class ScriptedOperator(SshOperator):
    """Records dispatches; returns configurable exit codes."""

    def __init__(self):
        self.dispatches: list[list[str]] = []
        self.rc = 0
        self.enabled = True

    async def run_action(self, argv, timeout=None):
        self.dispatches.append(argv)
        return self.rc, "ok"


def make_executor(tmp_path, guarded=True, real_enabled=True, lifecycle=None,
                  root_open=False, fresh=None, policy_overrides=None):
    db = Database(str(tmp_path / "guard.db"))
    db.migrate()
    clock = FakeClock()
    policy = PolicyEngine({"mode": "guarded" if guarded else "dry-run"} | (policy_overrides or {}))
    operator = ScriptedOperator()
    approvals = ApprovalStore(db, clock)
    executor = Executor(
        {"mode": "guarded" if guarded else "dry-run", "real_actions_enabled": real_enabled,
         "target_cooldown_seconds": 900, "max_attempts_per_target_hour": 3,
         "max_attempts_per_target_day": 6, "max_concurrent_real_actions": 1},
        CapabilityRegistry(), policy, approvals, operator, db, clock,
        lifecycle_lookup=(lifecycle or {"plex": "MANAGED", "random": "DISCOVERED",
                                        "retired": "RETIRED", "optional": "OPTIONAL"}).get,
        attempts_lookup=lambda _i: 0,
        root_incident_open=lambda _i: root_open,
        fresh_recheck=fresh,
    )
    return {"db": db, "clock": clock, "policy": policy, "executor": executor,
            "operator": operator, "approvals": approvals}


def restart_plan(target="plex", incident="inc:1", args=None):
    return ActionPlan(capability="docker.restart", target=target, reason="test",
                      incident_id=incident, args=args or {}, verification=("container_running",))


async def test_d1_guarded_restart_success_verified(tmp_path):
    st = make_executor(tmp_path)
    result = await st["executor"].execute(restart_plan())
    assert result.status == "executed" and result.audit_id
    assert st["operator"].dispatches and st["operator"].dispatches[0][0] == "docker-restart"
    row = st["db"].one(
        "SELECT result, policy_decision FROM action_audit WHERE mode='real' AND result LIKE 'exit%'"
    )
    assert row["result"] == "exit=0" and row["policy_decision"] == "allow"


async def test_d2_condition_gone_before_action_cancels(tmp_path):
    async def fresh(plan):
        return False, "plex is healthy in fresh state (condition gone)"
    st = make_executor(tmp_path, fresh=fresh)
    result = await st["executor"].execute(restart_plan())
    assert result.status == "cancelled"
    assert st["operator"].dispatches == []
    row = st["db"].one("SELECT result FROM action_audit ORDER BY ts DESC LIMIT 1")
    assert row["result"] == "cancelled"


async def test_d3_protected_target_denied_no_mutation(tmp_path):
    st = make_executor(tmp_path, policy_overrides={"protected_targets": ["plex"]})
    result = await st["executor"].execute(restart_plan())
    assert result.status == "denied" and "protected" in result.detail
    assert st["operator"].dispatches == []


async def test_d4_discovered_target_denied(tmp_path):
    st = make_executor(tmp_path)
    result = await st["executor"].execute(restart_plan(target="random"))
    assert result.status == "denied" and "MANAGED" in result.detail


async def test_d5_retired_target_denied(tmp_path):
    st = make_executor(tmp_path)
    result = await st["executor"].execute(restart_plan(target="retired"))
    assert result.status == "denied"


async def test_d6_attempt_budget_defers(tmp_path):
    st = make_executor(tmp_path)
    await st["executor"].execute(restart_plan())
    st["clock"].advance(1800)  # buiten cooldown, binnen het uur-venster
    budgets = st["executor"]._target_budgets("plex")
    assert budgets["attempts_hour"] == 1 and budgets["attempts_day"] == 1
    for _ in range(6):
        await st["executor"].execute(restart_plan(args={"allow_repeat": True}))
        st["clock"].advance(3600)
    result = await st["executor"].execute(restart_plan(args={"allow_repeat": True}))
    assert result.status == "deferred" and "budget" in result.detail


async def test_d7_cooldown_defers_second_restart(tmp_path):
    st = make_executor(tmp_path)
    await st["executor"].execute(restart_plan(args={"allow_repeat": True}))
    st["clock"].advance(60)  # binnen 900s cooldown
    result = await st["executor"].execute(restart_plan(args={"allow_repeat": True}))
    assert result.status == "deferred" and "cooldown" in result.detail


async def test_d8_root_incident_active_defers_child(tmp_path):
    st = make_executor(tmp_path, root_open=True)
    result = await st["executor"].execute(restart_plan())
    assert result.status == "deferred" and "root incident" in result.detail
    assert st["operator"].dispatches == []


async def test_d9_exit_zero_is_not_success(tmp_path):
    """Exit code 0 is executed, but NOT verified success — verification is the
    caller's explicit next step; a failing health check must surface as failed."""
    st = make_executor(tmp_path)
    st["operator"].rc = 0
    result = await st["executor"].execute(restart_plan())
    assert result.status == "executed"  # dispatch ok
    # verification semantics live in runbooks; executor must never claim "fixed"
    assert "fixed" not in result.detail.lower()


async def test_d9b_transport_failure_is_failed_and_audited(tmp_path):
    class BrokenOp(ScriptedOperator):
        async def run_action(self, argv, timeout=None):
            raise OSError("ssh down")
    st = make_executor(tmp_path)
    st["executor"].operator = BrokenOp()
    result = await st["executor"].execute(restart_plan())
    assert result.status == "failed"
    row = st["db"].one(
        "SELECT result FROM action_audit WHERE mode='real' AND result LIKE 'dispatch%'"
    )
    assert row["result"] == "dispatch_error"


async def test_d11_idempotency_blocks_repeat_after_restart(tmp_path):
    st = make_executor(tmp_path)
    await st["executor"].execute(restart_plan())
    st["clock"].advance(3600)  # cooldown verstreken
    result = await st["executor"].execute(restart_plan())  # zelfde episode, geen allow_repeat
    assert result.status == "denied" and "idempotency" in result.detail
    assert len(st["operator"].dispatches) == 1


async def test_d12_malicious_target_rejected_before_executor(tmp_path):
    st = make_executor(tmp_path)
    for bad in ("plex; rm -rf /", "$(x)", "plex && reboot", "../../x"):
        result = await st["executor"].execute(restart_plan(target=bad))
        assert result.status == "denied"
    assert st["operator"].dispatches == []


async def test_d13_dry_run_kill_switch(tmp_path):
    st = make_executor(tmp_path, real_enabled=False)
    result = await st["executor"].execute(restart_plan())
    assert result.status == "dry_run"
    assert st["operator"].dispatches == []


async def test_d14_approval_single_use(tmp_path):
    st = make_executor(tmp_path)
    approval = st["approvals"].create("inc:1", "docker", "plex", ttl=600)
    plan = ActionPlan(capability="docker.stop", target="plex", reason="t", incident_id="inc:1")
    first = await st["executor"].execute(plan, approval_id=approval["id"])
    assert first.status == "executed"
    second = await st["executor"].execute(
        ActionPlan(capability="docker.stop", target="plex", reason="t", incident_id="inc:2"),
        approval_id=approval["id"],
    )
    assert second.status == "denied"  # reuse must fail


async def test_d15_approval_wrong_target_fails(tmp_path):
    st = make_executor(tmp_path)
    approval = st["approvals"].create("inc:1", "docker", "plex", ttl=600)
    plan = ActionPlan(capability="docker.stop", target="radarr", reason="t", incident_id="inc:1")
    result = await st["executor"].execute(plan, approval_id=approval["id"])
    assert result.status == "denied"


async def test_d16_approval_expired_fails(tmp_path):
    st = make_executor(tmp_path)
    approval = st["approvals"].create("inc:1", "docker", "plex", ttl=600)
    st["clock"].advance(700)
    st["policy"] = st["policy"]  # noqa: keep reference
    plan = ActionPlan(capability="docker.stop", target="plex", reason="t", incident_id="inc:1")
    result = await st["executor"].execute(plan, approval_id=approval["id"])
    assert result.status == "denied"


async def test_d17_concurrency_defers_second_action(tmp_path):
    st = make_executor(tmp_path)
    # simulate an in-flight remediation (audit row in_progress, recent)
    st["db"].execute(
        "INSERT INTO action_audit(id, ts, initiator, incident_id, capability, target, args, "
        "reason, policy_decision, result, mode) VALUES('x', ?, 'automatic', 'inc:0', "
        "'docker.restart', 'sonarr', '{}', 't', 'allow', 'in_progress', 'real')",
        (st["clock"].now() - 10,),
    )
    result = await st["executor"].execute(restart_plan())
    assert result.status == "deferred" and "in progress" in result.detail


async def test_kill_switch_config_defaults_safe():
    from hermes.config import DEFAULTS

    exec_cfg = DEFAULTS["executor"]
    assert exec_cfg["mode"] == "dry-run"
    assert exec_cfg["real_actions_enabled"] is False  # clean installs stay dry-run
