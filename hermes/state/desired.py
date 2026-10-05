"""Desired state / service lifecycle (spec §14).

No hardcoded "container absent = error". Every observed entity gets a lifecycle
state, persisted in SQLite and seeded from config. Absence of a RETIRED service
is normal; absence of a MANAGED service is an incident candidate.
"""

from __future__ import annotations

import time

from ..log import info
from .db import Database

MANAGED = "MANAGED"
OPTIONAL = "OPTIONAL"
RETIRED = "RETIRED"
IGNORED = "IGNORED"
DISCOVERED = "DISCOVERED"

LIFECYCLE_STATES = (MANAGED, OPTIONAL, RETIRED, IGNORED, DISCOVERED)


class DesiredStateManager:
    def __init__(self, db: Database, config_section: dict) -> None:
        self.db = db
        self._config = config_section

    def seed_from_config(self) -> None:
        """Apply config-provided desired states; DB row (if any) wins over config."""
        for state, key in (
            (MANAGED, "managed"),
            (OPTIONAL, "optional"),
            (RETIRED, "retired"),
            (IGNORED, "ignored"),
        ):
            for entity in self._config.get(key, []):
                existing = self.get(entity)
                if existing is None:
                    self.set(entity, state, origin="config")

    def get(self, entity: str) -> str | None:
        row = self.db.one("SELECT state FROM desired_state WHERE entity=?", (entity,))
        return row["state"] if row else None

    def set(self, entity: str, state: str, origin: str = "user") -> None:
        if state not in LIFECYCLE_STATES:
            raise ValueError(f"invalid lifecycle state {state!r}")
        self.db.execute(
            "INSERT INTO desired_state(entity, state, origin, updated_at) VALUES(?,?,?,?) "
            "ON CONFLICT(entity) DO UPDATE SET state=excluded.state, origin=excluded.origin, "
            "updated_at=excluded.updated_at",
            (entity, state, origin, time.time()),
        )
        info("desired", "desired state set", entity=entity, state=state, origin=origin)

    def ensure_discovered(self, entity: str) -> str:
        state = self.get(entity)
        if state is None:
            self.set(entity, DISCOVERED, origin="discover")
            return DISCOVERED
        return state

    def absent_is_incident(self, entity: str) -> bool:
        """Absent container is an incident candidate only for MANAGED services."""
        state = self.get(entity) or self.ensure_discovered(entity)
        return state == MANAGED

    def absence_candidates(self) -> list[str]:
        """Entities whose complete absence from the inventory is an incident
        candidate (MANAGED). Used by the rules to catch services that vanish
        from the Beacon docker list entirely."""
        rows = self.db.query("SELECT entity FROM desired_state WHERE state=?", (MANAGED,))
        return [r["entity"] for r in rows]

    def monitored(self, entity: str) -> bool:
        """IGNORED entities produce no signals at all."""
        state = self.get(entity)
        return state != IGNORED

    def retired(self, entity: str) -> bool:
        return self.get(entity) == RETIRED
