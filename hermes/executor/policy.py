"""Policy engine + scoped approvals (spec §25/§26).

Policy decisions are deterministic and fully audited. A Telegram "los het op"
approval is scoped to (incident, action-class, target), expires, and is
single-use; it can never unlock FORBIDDEN capabilities.
"""

from __future__ import annotations

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


@dataclass
class PolicyDecision:
    decision: str
    reason: str
    capability: str
    target: str
    incident_id: str | None = None


class PolicyEngine:
    def __init__(self, config: dict) -> None:
        self.mode = config.get("mode", "dry-run")
        self.max_attempts = int(config.get("max_attempts_per_incident", 2))

    def decide(
        self,
        capability: Capability,
        target: str,
        lifecycle: str | None,
        attempts: int = 0,
    ) -> PolicyDecision:
        base = dict(capability=capability.name, target=target)

        if capability.risk_level == FORBIDDEN:
            return PolicyDecision(DENY, "risk level FORBIDDEN is nooit uitvoerbaar", **base)
        if self.mode == "disabled":
            return PolicyDecision(DENY, "executor mode=disabled", **base)
        if lifecycle not in capability.allowed_lifecycle:
            return PolicyDecision(
                DENY,
                f"target lifecycle {lifecycle!r} niet in toegestane levenscycli "
                f"{capability.allowed_lifecycle}",
                **base,
            )
        if attempts >= self.max_attempts:
            return PolicyDecision(
                DENY, f"maximaal {self.max_attempts} pogingen per incident bereikt", **base
            )
        if capability.risk_level == APPROVAL_REQUIRED or capability.requires_approval:
            return PolicyDecision(
                REQUIRE_APPROVAL,
                f"risk {capability.risk_level} vereist scoped goedkeuring",
                **base,
            )
        return PolicyDecision(ALLOW, f"risk {capability.risk_level} toegestaan", **base)


class ApprovalStore:
    def __init__(self, db: Database) -> None:
        self.db = db

    def create(
        self, incident_id: str, action_class: str, target: str, ttl: float = 600.0,
        chat_id: str | None = None,
    ) -> dict:
        approval_id = secrets.token_hex(8)
        now = time.time()
        self.db.execute(
            "INSERT INTO approvals(id, incident_id, action_class, target, created_at, expires_at, used, chat_id) "
            "VALUES(?,?,?,?,?,?,0,?)",
            (approval_id, incident_id, action_class, target, now, now + ttl, chat_id),
        )
        info("approvals", "scoped approval aangemaakt", incident_id=incident_id,
             action_class=action_class, target=target, ttl=ttl)
        return {"id": approval_id, "expires_at": now + ttl, "action_class": action_class, "target": target}

    def consume(self, approval_id: str, action_class: str, target: str, now: float | None = None) -> bool:
        """Single-use, time-limited, class+target scoped."""
        now = now if now is not None else time.time()
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
            (incident_id, time.time()),
        )
        return [dict(r) for r in rows]
