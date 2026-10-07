"""Runbook engine (spec §21/§22).

Definitions are data (YAML); execution is deterministic Python. Outcome is one
of: resolved (verified), would_execute (dry-run), needs_approval, failed
(escalation criterion met), ambiguous (diagnosis inconclusive -> AI layer),
diagnosed (checks only, no action available).
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

import yaml

from ..clock import Clock
from ..executor.capabilities import CapabilityRegistry
from ..executor.executor import ActionPlan, Executor
from ..log import info, warning
from .verification import Diagnostics, all_passed, any_failed, run_verification

OUTCOME_RESOLVED = "resolved"
OUTCOME_WOULD_EXECUTE = "would_execute"
OUTCOME_NEEDS_APPROVAL = "needs_approval"
OUTCOME_FAILED = "failed"
OUTCOME_AMBIGUOUS = "ambiguous"
OUTCOME_DIAGNOSED = "diagnosed"


@dataclass
class RunbookDef:
    name: str
    detect: list[str]
    description: str = ""
    preconditions: list[str] = field(default_factory=list)
    diagnose: list[str] = field(default_factory=list)
    actions: list[dict] = field(default_factory=list)
    verification: list[str] = field(default_factory=list)
    settle_seconds: float = 90.0
    escalation_criteria: list[str] = field(default_factory=lambda: ["action_failed", "verification_failed"])


@dataclass
class RunbookResult:
    outcome: str
    detail: str = ""
    runbook: str | None = None
    checks: list = field(default_factory=list)
    audit_ids: list[str] = field(default_factory=list)


class RunbookEngine:
    def __init__(
        self,
        definitions_dir: str,
        executor: Executor,
        registry: CapabilityRegistry,
        diagnostics: Diagnostics,
        clock: Clock,
        sleep,  # async sleep callable (injected for tests)
        db=None,  # noqa: ANN001
    ) -> None:
        self.definitions_dir = definitions_dir
        self.executor = executor
        self.registry = registry
        self.diagnostics = diagnostics
        self.clock = clock
        self.sleep = sleep
        self.db = db
        self.definitions: dict[str, RunbookDef] = {}
        self.load_definitions()

    def load_definitions(self) -> None:
        self.definitions.clear()
        directory = self.definitions_dir
        if not os.path.isdir(directory):
            warning("runbooks", "definitions directory missing", directory=directory)
            return
        for filename in sorted(os.listdir(directory)):
            if not filename.endswith((".yaml", ".yml")):
                continue
            with open(os.path.join(directory, filename), encoding="utf-8") as fh:
                data = yaml.safe_load(fh) or {}
            for name, spec in data.items():
                self.definitions[name] = RunbookDef(
                    name=name,
                    description=str(spec.get("description", "")),
                    detect=list(spec.get("detect", [])),
                    preconditions=list(spec.get("preconditions", [])),
                    diagnose=list(spec.get("diagnose", [])),
                    actions=list(spec.get("actions", [])),
                    verification=list(spec.get("verification", [])),
                    settle_seconds=float(spec.get("settle_seconds", 90)),
                    escalation_criteria=list(spec.get("escalation_criteria", ["action_failed", "verification_failed"])),
                )
        info("runbooks", "definitions loaded", count=len(self.definitions))

    def for_incident(self, incident) -> RunbookDef | None:  # noqa: ANN001
        return self.definitions.get(incident.category)

    # ------------------------------------------------------------------
    async def run(self, incident, approval_id: str | None = None, initiator: str = "automatic") -> RunbookResult:  # noqa: ANN001
        runbook = self.for_incident(incident)
        if runbook is None:
            return RunbookResult(OUTCOME_AMBIGUOUS, f"geen runbook voor {incident.category}")
        checks = []

        for check_name in runbook.preconditions:
            result = await self.diagnostics.check(check_name, incident.entity)
            checks.append(result)
            if result.ok is False:
                return RunbookResult(
                    OUTCOME_AMBIGUOUS, f"precondition {check_name} failed: {result.detail}",
                    runbook.name, checks,
                )
        for check_name in runbook.diagnose:
            result = await self.diagnostics.check(check_name, incident.entity)
            checks.append(result)
            if result.ok is False:
                return RunbookResult(
                    OUTCOME_AMBIGUOUS, f"diagnose {check_name}: {result.detail}", runbook.name, checks,
                )
        if not runbook.actions:
            return RunbookResult(
                OUTCOME_DIAGNOSED,
                "diagnosis complete; no safe automatic action defined",
                runbook.name, checks,
            )

        for action in runbook.actions:
            capability = str(action.get("capability", ""))
            if self.registry.get(capability) is None:
                return RunbookResult(OUTCOME_AMBIGUOUS, f"onbekende capability {capability}", runbook.name, checks)
            plan = ActionPlan(
                capability=capability,
                target=action.get("target", incident.entity),
                reason=f"runbook {runbook.name} voor {incident.id}",
                incident_id=incident.id,
                verification=runbook.verification,
                initiator=initiator,
            )
            result = await self.executor.execute(plan, approval_id=approval_id)
            if result.audit_id:
                checks.append(result)
            if result.status == "dry_run":
                return RunbookResult(OUTCOME_WOULD_EXECUTE, result.detail, runbook.name, checks,
                                     [result.audit_id or ""])
            if result.status == "needs_approval":
                return RunbookResult(OUTCOME_NEEDS_APPROVAL, result.detail, runbook.name, checks,
                                     [result.audit_id or ""])
            if result.status != "executed":
                # a successful command is not a fix; a failed one certainly isn't
                if "action_failed" in runbook.escalation_criteria:
                    return RunbookResult(OUTCOME_FAILED, f"action failed: {result.detail}", runbook.name, checks,
                                         [result.audit_id or ""])
                continue
            # settle then verify against FRESH state (spec §28)
            await self.sleep(runbook.settle_seconds)
            results = await run_verification(self.diagnostics, runbook.verification, incident.entity)
            checks.extend(results)
            if all_passed(results):
                self._record(incident, runbook.name, OUTCOME_RESOLVED, checks)
                info("runbooks", "runbook resolved", incident_id=incident.id, runbook=runbook.name)
                return RunbookResult(OUTCOME_RESOLVED, "verificatie geslaagd", runbook.name, checks,
                                     [result.audit_id or ""])
            if "verification_failed" in runbook.escalation_criteria and any_failed(results):
                detail = "; ".join(f"{r.name}: {r.detail}" for r in results if r.ok is not True)
                self._record(incident, runbook.name, OUTCOME_FAILED, checks)
                return RunbookResult(OUTCOME_FAILED, f"verification failed: {detail}", runbook.name, checks,
                                     [result.audit_id or ""])
        return RunbookResult(OUTCOME_AMBIGUOUS, "actions completed without conclusion", runbook.name, checks)

    async def run_diagnose_only(self, incident) -> RunbookResult:  # noqa: ANN001
        """Preconditions + diagnose checks without any action (for /investigate)."""
        runbook = self.for_incident(incident)
        if runbook is None:
            return RunbookResult(OUTCOME_AMBIGUOUS, f"geen runbook voor {incident.category}")
        checks = []
        for check_name in runbook.preconditions + runbook.diagnose:
            result = await self.diagnostics.check(check_name, incident.entity)
            checks.append(result)
        failed = [f"{r.name}: {r.detail}" for r in checks if r.ok is False]
        if failed:
            return RunbookResult(OUTCOME_AMBIGUOUS, "afwijkende checks: " + "; ".join(failed),
                                 runbook.name, checks)
        return RunbookResult(OUTCOME_DIAGNOSED, "alle diagnose-checks gezond", runbook.name, checks)

    def _record(self, incident, runbook_name: str, outcome: str, checks: list) -> None:  # noqa: ANN001
        if self.db is None:
            return
        import json as _json

        self.db.execute(
            "INSERT INTO remediations(ts, incident_id, runbook, outcome, detail) VALUES(?,?,?,?,?)",
            (
                self.clock.now(), incident.id, runbook_name, outcome,
                _json.dumps([{"name": getattr(c, "name", "action"), "ok": getattr(c, "ok", None),
                              "detail": getattr(c, "detail", "")[:200]} for c in checks], default=str),
            ),
        )
