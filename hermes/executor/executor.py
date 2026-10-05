"""Executor: the ONLY component that performs mutating actions (spec §23/§27).

Flow: ActionPlan -> preconditions -> PolicyEngine -> (scoped approval) ->
SSH operator dispatch -> audit. A successful command is NEVER treated as a
fix: verification is the caller's explicit next step (spec §28).

In dry-run mode nothing executes; the exact intended action, reason,
preconditions, policy verdict and expected verification are logged + audited
(spec §49).
"""

from __future__ import annotations

import asyncio
import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from ..clock import Clock
from ..log import info, warning
from ..util import sanitize
from .capabilities import Capability, CapabilityRegistry
from .policy import REQUIRE_APPROVAL, ApprovalStore, PolicyDecision, PolicyEngine


@dataclass
class ActionPlan:
    capability: str
    target: str
    reason: str
    incident_id: str | None = None
    args: dict[str, Any] = field(default_factory=dict)
    expected: list[str] = field(default_factory=list)
    verification: list[str] = field(default_factory=list)
    initiator: str = "automatic"  # automatic | telegram/<user> | cli
    ai_involved: bool = False
    ai_model: str | None = None


@dataclass
class ExecutionResult:
    status: str  # executed | dry_run | denied | needs_approval | failed | timeout
    detail: str = ""
    policy: PolicyDecision | None = None
    audit_id: str | None = None


class SshOperator:
    """Client for the hardened SSH operator dispatcher (plantokens + host audit).

    Only fixed action verbs with validated names are sent; no shell, no
    interpolation — arguments are passed as discrete argv entries to ssh, and
    the dispatcher re-validates everything server-side.
    """

    def __init__(self, host: str, key_path: str, known_hosts: str, timeout: float = 150.0) -> None:
        self.host = host
        self.key_path = key_path
        self.known_hosts = known_hosts
        self.timeout = timeout
        self.enabled = bool(host and key_path and known_hosts)

    async def run_action(self, argv: list[str], timeout: float | None = None) -> tuple[int, str]:
        proc = await asyncio.create_subprocess_exec(
            "ssh",
            "-i", self.key_path,
            "-o", f"UserKnownHostsFile={self.known_hosts}",
            "-o", "StrictHostKeyChecking=yes",
            "-o", "BatchMode=yes",
            "-o", "ConnectTimeout=10",
            self.host,
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=timeout or self.timeout
            )
        except TimeoutError:
            proc.kill()
            return 124, "timeout"
        out = stdout.decode("utf-8", "replace").strip()
        err = stderr.decode("utf-8", "replace").strip()
        return (proc.returncode or 0), err or out[:400]

    def docker_argv(self, verb: str, container: str, incident_id: str, approved: str) -> list[str]:
        return [f"docker-{verb}", container, incident_id[:128], approved[:40]]

    def service_argv(self, verb: str, service: str, incident_id: str, approved: str) -> list[str]:
        return [f"service-{verb}", service, incident_id[:128], approved[:40]]


class Executor:
    def __init__(
        self,
        config: dict,
        registry: CapabilityRegistry,
        policy: PolicyEngine,
        approvals: ApprovalStore,
        operator: SshOperator | None,
        db,  # Database
        clock: Clock,
        lifecycle_lookup=None,  # callable(target) -> lifecycle state
        attempts_lookup=None,   # callable(incident_id) -> int
    ) -> None:
        self.config = config
        self.registry = registry
        self.policy = policy
        self.approvals = approvals
        self.operator = operator
        self.db = db
        self.clock = clock
        self.lifecycle_lookup = lifecycle_lookup or (lambda _t: None)
        self.attempts_lookup = attempts_lookup or (lambda _i: 0)

    # ------------------------------------------------------------------
    async def execute(self, plan: ActionPlan, approval_id: str | None = None) -> ExecutionResult:
        cap = self.registry.get(plan.capability)
        if cap is None:
            return self._deny(plan, "onbekende capability")
        lifecycle = self.lifecycle_lookup(plan.target)
        attempts = self.attempts_lookup(plan.incident_id) if plan.incident_id else 0
        decision = self.policy.decide(cap, plan.target, lifecycle, attempts)
        if decision.decision == "deny":
            return self._finish(plan, cap, "denied", decision.reason, decision, {})
        if decision.decision == REQUIRE_APPROVAL:
            if approval_id is None:
                return self._finish(plan, cap, "needs_approval", decision.reason, decision, {})
            ok = self.approvals.consume(approval_id, cap.name.split(".")[0], plan.target)
            if not ok:
                ok = self.approvals.consume(approval_id, plan.capability, plan.target)
            if not ok:
                return self._finish(
                    plan, cap, "denied", "goedkeuring ongeldig/verlopen/verkeerd gescoped",
                    decision, {},
                )
        if self.policy.mode == "dry-run":
            audit_id = self._audit(plan, cap, decision, result="would_execute", mode="dry_run",
                                   preconditions={"lifecycle": lifecycle, "attempts": attempts})
            info(
                "executor", "DRY-RUN: actie zou worden uitgevoerd",
                capability=plan.capability, target=plan.target, reason=plan.reason,
                policy=decision.decision, preconditions="PASS",
                verification_expected=",".join(plan.verification or cap.verification),
                incident_id=plan.incident_id, audit_id=audit_id,
            )
            return ExecutionResult("dry_run", "dry-run: niets uitgevoerd", decision, audit_id)
        if self.operator is None or not self.operator.enabled:
            return self._finish(plan, cap, "denied", "geen operator-transport geconfigureerd", decision, {})
        argv = self._build_argv(cap, plan)
        started = time.time()
        try:
            rc, output = await self.operator.run_action(argv, timeout=cap.timeout)
        except (TimeoutError, OSError) as exc:
            warning("executor", "dispatch faalde", capability=plan.capability, error=sanitize(exc, 120))
            audit_id = self._audit(plan, cap, decision, result="dispatch_error", mode="real",
                                   preconditions={"lifecycle": lifecycle}, verification={"error": sanitize(exc, 120)})
            return ExecutionResult("failed", sanitize(exc, 200), decision, audit_id)
        duration = round(time.time() - started, 2)
        status = "executed" if rc == 0 else "failed"
        audit_id = self._audit(
            plan, cap, decision, result=f"exit={rc}", mode="real",
            preconditions={"lifecycle": lifecycle},
            verification={"rc": rc, "duration_s": duration, "output": sanitize(output, 300)},
        )
        info("executor", "actie uitgevoerd", capability=plan.capability, target=plan.target,
             rc=rc, duration_s=duration, incident_id=plan.incident_id, audit_id=audit_id)
        result = ExecutionResult(status, f"exit={rc} {sanitize(output, 160)}", decision, audit_id)
        return result

    def _build_argv(self, cap: Capability, plan: ActionPlan) -> list[str]:
        incident = (plan.incident_id or "unknown").replace(" ", "-")[:128]
        approved = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        if cap.dispatch_action.startswith("docker-"):
            verb = cap.dispatch_action.split("-", 1)[1]
            return self.operator.docker_argv(verb, plan.target, incident, approved)  # type: ignore[union-attr]
        if cap.dispatch_action.startswith("service-"):
            verb = cap.dispatch_action.split("-", 1)[1]
            service = str(plan.args.get("service", plan.target))
            return self.operator.service_argv(verb, service, incident, approved)  # type: ignore[union-attr]
        raise ValueError(f"capability {cap.name} heeft geen geldig transport")

    # ------------------------------------------------------------------
    def _deny(self, plan: ActionPlan, reason: str) -> ExecutionResult:
        audit_id = self._audit(plan, None, None, result="denied", mode="none", preconditions={})
        warning("executor", "actie geweigerd", capability=plan.capability, target=plan.target, reason=reason)
        return ExecutionResult("denied", reason, None, audit_id)

    def _finish(
        self, plan: ActionPlan, cap: Capability | None, status: str, detail: str,
        decision: PolicyDecision, preconditions: dict,
    ) -> ExecutionResult:
        audit_id = self._audit(plan, cap, decision, result=status, mode="none" if status == "denied" else "pending",
                               preconditions=preconditions)
        info("executor", f"actie {status}", capability=plan.capability, target=plan.target,
             reason=detail, incident_id=plan.incident_id, audit_id=audit_id)
        return ExecutionResult(status, detail, decision, audit_id)

    def _audit(
        self, plan: ActionPlan, cap: Capability | None, decision: PolicyDecision | None,
        result: str, mode: str, preconditions: dict, verification: dict | None = None,
    ) -> str:
        audit_id = str(uuid.uuid4())
        self.db.execute(
            "INSERT OR REPLACE INTO action_audit(id, ts, initiator, incident_id, capability, target, args, "
            "reason, policy_decision, ai_involved, ai_model, preconditions, result, verification, mode) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                audit_id, self.clock.now(), plan.initiator, plan.incident_id, plan.capability,
                plan.target, json.dumps(plan.args, default=str), plan.reason[:500],
                decision.decision if decision else "unknown",
                int(plan.ai_involved), plan.ai_model,
                json.dumps(preconditions, default=str), result,
                json.dumps(verification or {}, default=str), mode,
            ),
        )
        return audit_id
