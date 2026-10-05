"""Correlation / root-cause grouping (spec §13).

Deterministic rules that reduce groups of related incidents into one root
incident with affected children. Children are suppressed (no separate
notifications); the root carries the affected list and gets one notification.
"""

from __future__ import annotations

from ..clock import Clock
from ..log import info
from ..state.normalized import NormalizedState
from .incidents import IncidentEngine
from .signals import SEVERITY_RANK, Signal

ROOT_CATEGORIES = frozenset(
    {"storage_degradation", "docker_daemon_down", "project_degradation"}
)

STORAGE_EVIDENCE_CATEGORIES = frozenset(
    {"disk_await_ms", "host_iowait_pct", "storage_used_pct", "anomaly_rate"}
)

CONTAINER_INCIDENT_CATEGORIES = frozenset(
    {"container_unhealthy", "container_exit", "container_restart_loop", "container_high_cpu",
     "container_memory_pressure"}
)


class CorrelationEngine:
    def __init__(self, engine: IncidentEngine, config: dict, clock: Clock) -> None:
        self.engine = engine
        self.clock = clock
        self.storage_window = float(config.get("correlation", {}).get("storage_window", 600))
        self.storage_min_entities = int(
            config.get("correlation", {}).get("storage_min_entities", 3)
        )

    # ------------------------------------------------------------------
    def apply(self, state: NormalizedState) -> None:
        now = self.clock.now()
        open_incidents = self.engine.open_incidents()
        self._release_orphans(open_incidents)
        self._docker_daemon_rule(state, open_incidents, now)
        self._storage_family_rule(state, open_incidents, now)
        self._project_rule(open_incidents, now)

    def _release_orphans(self, open_incidents) -> None:
        roots = {i.id for i in open_incidents if i.category in ROOT_CATEGORIES}
        for inc in open_incidents:
            if inc.root_incident and inc.root_incident not in roots:
                inc.suppressed = False
                inc.root_incident = None
                self.engine._persist(inc, self.clock.now())

    # ------------------------------------------------------------------
    def _ingest_root(self, category: str, entity: str, severity: str, title: str, evidence: list[dict]) -> str:
        sig = Signal(
            category=category, entity=entity, severity=severity, source="derived",
            ts=self.clock.now(), title=title, evidence=evidence,
        )
        self.engine._ingest_signal(sig, self.clock.now())
        return sig.fingerprint

    def _docker_daemon_rule(self, state: NormalizedState, open_incidents, now: float) -> None:
        daemon_ok = state.host.docker_daemon_ok
        if daemon_ok is not False:
            return
        affected = [
            i for i in open_incidents
            if i.entity in state.containers and i.category in CONTAINER_INCIDENT_CATEGORIES
        ]
        root_id = self._ingest_root(
            "docker_daemon_down", "host", "critical",
            "Docker-daemon reageert niet; alle container-signalen worden gecorreleerd",
            [{"source": "beacon", "confirm": True}],
        )
        for inc in affected:
            if inc.id != root_id:
                inc.suppressed = True
                inc.root_incident = root_id
                self.engine._persist(inc, now)
        info("correlation", "docker daemon down: containers gecorreleerd", affected=len(affected))

    def _storage_family_rule(self, state: NormalizedState, open_incidents, now: float) -> None:
        storage_evidence = [
            i for i in open_incidents
            if i.category in STORAGE_EVIDENCE_CATEGORIES
            and now - (i.last_seen or i.first_seen) <= self.storage_window
        ]
        if not storage_evidence:
            return
        container_incidents = [
            i for i in open_incidents
            if i.category in CONTAINER_INCIDENT_CATEGORIES
            and not i.root_incident  # don't re-group already correlated children
            and now - (i.last_seen or i.first_seen) <= self.storage_window
        ]
        if len(container_incidents) < self.storage_min_entities:
            return
        root_id = self._ingest_root(
            "storage_degradation", "storage", "urgent",
            f"Storage-degradatie: {len(storage_evidence)} host-signalen + "
            f"{len(container_incidents)} containers getroffen",
            [e for i in storage_evidence for e in i.evidence][:10],
        )
        for inc in storage_evidence + container_incidents:
            if inc.id != root_id:
                inc.suppressed = True
                inc.root_incident = root_id
                self.engine._persist(inc, now)
        info(
            "correlation", "storage family correlated",
            root=root_id, affected=[i.id for i in container_incidents],
        )

    def _project_rule(self, open_incidents, now: float) -> None:
        by_project: dict[str, list] = {}
        for inc in open_incidents:
            if inc.category not in CONTAINER_INCIDENT_CATEGORIES or inc.root_incident:
                continue
            row = self.engine.db.one(
                "SELECT compose_project FROM entity_meta WHERE entity=?", (inc.entity,)
            )
            project = row["compose_project"] if row else None
            if project:
                by_project.setdefault(project, []).append(inc)
        for project, incidents in by_project.items():
            if len(incidents) < 2:
                continue
            severity = max((i.severity for i in incidents), key=lambda s: SEVERITY_RANK.get(s, 0))
            root_id = self._ingest_root(
                "project_degradation", f"project:{project}", severity,
                f"Compose-project {project}: {len(incidents)} services tegelijk afwijkend",
                [{"source": "derived", "confirm": True, "services": [i.entity for i in incidents]}],
            )
            for inc in incidents:
                if inc.id != root_id:
                    inc.suppressed = True
                    inc.root_incident = root_id
                    self.engine._persist(inc, now)
