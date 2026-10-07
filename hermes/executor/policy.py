"""Policy engine + scoped approvals (spec §25/§26).

Policy decisions are deterministic and fully audited. A Telegram "los het op"
approval is scoped to (incident, action-class, target), expires, and is
single-use; it can never unlock FORBIDDEN capabilities.

2.1 additions (§C5/§C6/§C11/§C17):
- protected targets are always denied;
- target strings must be strict identifiers (no shell metacharacters/path
  tricks — rejected before the executor sees them);
- automatically initiated actions require lifecycle MANAGED (OPTIONAL targets
  remain reachable via explicit Telegram approval flows);
- target-level cooldown and hourly/daily attempt budgets (from the persistent
  action audit) gate real execution to prevent restart loops.
"""

from __future__ import annotations

import re
import secrets
import time
from dataclasses import dataclass
from typing import Any

from ..log import info
from ..state.db import Database
from .capabilities import APPROVAL_REQUIRED, FORBIDDEN, Capability

ALLOW = "allow"
DENY = "deny"
REQUIRE_APPROVAL = "require_approval"
DEFER = "defer"

TARGET_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")


@dataclass
class PolicyDecision:
    decision: str
    reason: str
    capability: str
    target: str
    incident_id: str | None = None


def valid_target(target: str) -> bool:
    """Strict identifier check: no shell metacharacters, whitespace, paths."""
    return bool(target) and TARGET_RE.match(target) is not None


class PolicyEngine:
    def __init__(self, config: dict) -> None:
        self.mode = config.get("mode", "dry-run")
        self.max_attempts = int(config.get("max_attempts_per_incident", 2))
        self.protected_targets = {str(t) for t in config.get("protected_targets", [])}
        self.cooldown_seconds = float(config.get("target_cooldown_seconds", 900))
        self.max_per_hour = int(config.get("max_attempts_per_target_hour", 3))
        self.max_per_day = int(config.get("max_attempts_per_target_day", 6))

    def decide(
        self,
        capability: Capability,
        target: str,
        lifecycle: str | None,
        attempts: int = 0,
        initiator: str = "automatic",
        budgets: dict | None = None,
        root_incident_open: bool = False,
    ) -> PolicyDecision:
        base = dict(capability=capability.name, target=target)
        budgets = budgets or {}

        if capability.risk_level == FORBIDDEN:
            return PolicyDecision(DENY, "risk level FORBIDDEN is never executable", **base)
        if not valid_target(target):
            return PolicyDecision(DENY, "target fails strict identifier validation", **base)
        if target in self.protected_targets:
            return PolicyDecision(DENY, "target is protected (protected_targets)", **base)
        if self.mode == "disabled":
            return PolicyDecision(DENY, "executor mode=disabled", **base)
        if initiator == "automatic" and lifecycle != "MANAGED":
            return PolicyDecision(
                DENY,
                f"automatic actions require MANAGED lifecycle (got {lifecycle!r})",
                **base,
            )
        if lifecycle not in capability.allowed_lifecycle:
            return PolicyDecision(
                DENY,
                f"target lifecycle {lifecycle!r} not in allowed lifecycles "
                f"{capability.allowed_lifecycle}",
                **base,
            )
        if attempts >= self.max_attempts:
            return PolicyDecision(
                DENY, f"max {self.max_attempts} attempts per incident reached", **base
            )
        if root_incident_open:
            return PolicyDecision(
                DEFER, "correlated root incident active; child remediation suppressed", **base
            )
        if not budgets.get("cooldown_ok", True):
            return PolicyDecision(
                DEFER, f"target cooldown active ({self.cooldown_seconds:.0f}s)", **base
            )
        if budgets.get("attempts_hour", 0) >= self.max_per_hour:
            return PolicyDecision(DEFER, "target hourly attempt budget reached", **base)
        if budgets.get("attempts_day", 0) >= self.max_per_day:
            return PolicyDecision(DEFER, "target daily attempt budget reached", **base)
        if capability.risk_level == APPROVAL_REQUIRED or capability.requires_approval:
            return PolicyDecision(
                REQUIRE_APPROVAL,
                f"risk {capability.risk_level} requires scoped approval",
                **base,
            )
        return PolicyDecision(ALLOW, f"risk {capability.risk_level} allowed", **base)


class ApprovalStore:
    def __init__(self, db: Database, clock=None) -> None:
        self.db = db
        self.clock = clock  # injectable clock; real time as fallback

    def _now(self) -> float:
        return self.clock.now() if self.clock is not None else time.time()

    def create(
        self, incident_id: str, action_class: str, target: str, ttl: float = 600.0,
        chat_id: str | None = None,
    ) -> dict:
        approval_id = secrets.token_hex(8)
        now = self._now()
        self.db.execute(
            "INSERT INTO approvals(id, incident_id, action_class, target, created_at, expires_at, used, chat_id) "
            "VALUES(?,?,?,?,?,?,0,?)",
            (approval_id, incident_id, action_class, target, now, now + ttl, chat_id),
        )
        info("approvals", "scoped approval created", incident_id=incident_id,
             action_class=action_class, target=target, ttl=ttl)
        return {"id": approval_id, "expires_at": now + ttl, "action_class": action_class, "target": target}

    def consume(self, approval_id: str, action_class: str, target: str, now: float | None = None) -> bool:
        """Single-use, time-limited, class+target scoped."""
        now = now if now is not None else self._now()
        row = self.db.one("SELECT * FROM approvals WHERE id=?", (approval_id,))
        if row is None:
            return False
        if row["used"]:
            return False
        if now > float(row["expires_at"]):
            return False
        if row["action_class"] != action_class or row["target"] != target:
            return False
        self.db.execute("UPDATE approvals SET used=1 WHERE id=?", (approval_id,))
        return True

    def pending_for_incident(self, incident_id: str) -> list[dict[str, Any]]:
        rows = self.db.query(
            "SELECT * FROM approvals WHERE incident_id=? AND used=0 AND expires_at > ?",
            (incident_id, self._now()),
        )
        return [dict(r) for r in rows]
