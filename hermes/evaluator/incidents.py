"""Incident state machine (spec §7-§12).

OBSERVED -> PENDING -> CONFIRMED -> ACTIVE -> RECOVERING -> RESOLVED
plus flags: suppressed (correlation), FLAPPING (reopen churn).

Guarantees:
- a signal only becomes an incident candidate after the per-category debounce
  window (config, spec §8);
- a transient (condition gone before confirmation) is recorded silently;
- recovery notifications only exist if an alert was actually sent;
- all transitions are persisted and survive restarts.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..clock import Clock
from ..log import info
from ..state.db import Database, json_dumps, json_loads
from .signals import IMMEDIATE_CATEGORIES, SEVERITY_RANK, Signal

STATES = ("OBSERVED", "PENDING", "CONFIRMED", "ACTIVE", "RECOVERING", "RESOLVED")
OPEN_STATES = ("OBSERVED", "PENDING", "CONFIRMED", "ACTIVE", "RECOVERING")


@dataclass
class Incident:
    id: str
    category: str
    entity: str
    title: str
    severity: str
    state: str
    first_seen: float
    last_seen: float | None = None
    confirmed_at: float | None = None
    resolved_at: float | None = None
    notification_sent: bool = False
    occurrences: int = 1
    flap_count: int = 0
    last_notified_at: float | None = None
    last_notified_severity: str | None = None
    suppressed: bool = False
    root_incident: str | None = None
    ai_summary: str | None = None
    evidence: list[dict] = field(default_factory=list)
    recovering_since: float | None = None  # runtime (persisted via evidence meta)

    @property
    def open(self) -> bool:
        return self.state in OPEN_STATES

    def to_row(self, now: float) -> tuple:
        return (
            self.id, self.category, self.entity, self.title, self.severity, self.state,
            self.first_seen, self.last_seen, self.confirmed_at, self.resolved_at,
            int(self.notification_sent), self.occurrences, self.flap_count,
            self.last_notified_at, self.last_notified_severity, int(self.suppressed),
            self.root_incident, json_dumps(self.evidence), now,
        )

    @classmethod
    def from_row(cls, row: Any) -> Incident:
        return cls(
            id=row["id"], category=row["category"], entity=row["entity"], title=row["title"],
            severity=row["severity"], state=row["state"], first_seen=row["first_seen"],
            last_seen=row["last_seen"], confirmed_at=row["confirmed_at"],
            resolved_at=row["resolved_at"], notification_sent=bool(row["notification_sent"]),
            occurrences=row["occurrences"], flap_count=row["flap_count"],
            last_notified_at=row["last_notified_at"],
            last_notified_severity=row["last_notified_severity"],
            suppressed=bool(row["suppressed"]), root_incident=row["root_incident"],
            ai_summary=row["ai_summary"] if "ai_summary" in row.keys() else None,
            evidence=json_loads(row["evidence"], []) or [],
        )

    def describe_duration(self, now: float) -> str:
        end = self.resolved_at or now
        seconds = int(max(0, end - self.first_seen))
        if seconds < 120:
            return f"{seconds}s"
        if seconds < 7200:
            return f"{seconds // 60}m"
        return f"{seconds // 3600}h{seconds % 3600 // 60}m"


class IncidentEngine:
    def __init__(
        self,
        db: Database,
        config: dict,
        clock: Clock,
        fast_interval: float = 60.0,
    ) -> None:
        self.db = db
        self.config = config
        self.clock = clock
        self.fast_interval = fast_interval
        self.transient_threshold = config.get("transients", {}).get("threshold_default", 5)
        self.transient_window = config.get("transients", {}).get("window", 21600)
        self.absence_grace = max(2 * fast_interval, 120.0)
        self.absence_confirm = max(3 * fast_interval, 300.0)
        self.reopen_window = 3600.0
        self.flap_threshold = 3
        self._incidents: dict[str, Incident] = {}
        self._pending_resolved: list[dict] = []
        self.load_open()

    # ------------------------------------------------------------------
    def load_open(self) -> None:
        self._incidents.clear()
        for row in self.db.query(
            f"SELECT * FROM incidents WHERE state IN ({','.join('?' * len(OPEN_STATES))})",
            OPEN_STATES,
        ):
            self._incidents[row["id"]] = Incident.from_row(row)

    def get(self, incident_id: str) -> Incident | None:
        return self._incidents.get(incident_id)

    def all_incidents(self) -> list[Incident]:
        return sorted(self._incidents.values(), key=lambda i: i.first_seen)

    def open_incidents(self) -> list[Incident]:
        return [i for i in self.all_incidents() if i.open]

    # ------------------------------------------------------------------
    def ingest(self, signals: list[Signal]) -> None:
        """Process one batch of rule signals. Deduplicates by fingerprint;
        muted fingerprints (/mute) are dropped until their mute expires."""
        now = self.clock.now()
        by_fp: dict[str, Signal] = {}
        for sig in signals:
            if self.is_muted(sig.fingerprint, now):
                continue
            existing = by_fp.get(sig.fingerprint)
            if existing is None or sig.rank > existing.rank:
                by_fp[sig.fingerprint] = sig
        for sig in sorted(by_fp.values(), key=lambda s: -s.rank):
            self._ingest_signal(sig, now)
        self.db.conn.commit()

    def is_muted(self, fingerprint: str, now: float) -> bool:
        value = self.db.get_cursor(f"mute:{fingerprint}")
        if not value:
            return False
        try:
            return float(value) > now
        except (TypeError, ValueError):
            return False

    def _persist_signal_row(self, sig: Signal, now: float) -> None:
        """Bounded raw-signal persistence for the noise funnel: one row per
        fingerprint per `sample_window` seconds, plus every severity escalation."""
        window = max(self.fast_interval, 300.0)
        row = self.db.one(
            "SELECT ts, severity FROM signals WHERE incident_id=? ORDER BY ts DESC LIMIT 1",
            (sig.fingerprint,),
        )
        escalated = row is not None and SEVERITY_RANK.get(sig.severity, 0) > SEVERITY_RANK.get(
            row["severity"], 0
        )
        if row is not None and not escalated and now - row["ts"] < window:
            return
        self.db.execute(
            "INSERT INTO signals(ts, category, entity, severity, value, source, evidence, incident_id) "
            "VALUES(?,?,?,?,?,?,?,?)",
            (now, sig.category, sig.entity, sig.severity, sig.value, sig.source,
             json_dumps(sig.evidence[:3]), sig.fingerprint),
        )

    def set_ai_summary(self, incident_id: str, summary: str) -> None:
        incident = self._incidents.get(incident_id)
        self.db.execute(
            "UPDATE incidents SET ai_summary=? WHERE id=?", (summary[:1000], incident_id)
        )
        if incident is not None:
            incident.ai_summary = summary

    def _ingest_signal(self, sig: Signal, now: float) -> None:
        if sig.kind == "recovery" and sig.cleared:
            self._explicit_recovery(sig, now)
            return
        self._persist_signal_row(sig, now)
        incident = self._incidents.get(sig.fingerprint)
        debounce = float(self.config.get("debounce", {}).get(sig.category, 0))
        if incident is None or not incident.open:
            incident = self._create(sig, now)
        else:
            self._update(incident, sig, now)
        # debounce progression
        if incident.state in ("OBSERVED", "PENDING"):
            if now - incident.first_seen >= debounce or sig.category in IMMEDIATE_CATEGORIES:
                if incident.state != "CONFIRMED":
                    self._transition(incident, "CONFIRMED", f"debounce ({debounce:.0f}s) gehaald", sig.severity, now)
            elif incident.state != "PENDING":
                self._transition(incident, "PENDING", "in debounce-venster", sig.severity, now, quiet=True)

    def _create(self, sig: Signal, now: float) -> Incident:
        # reopen a recently resolved incident instead of creating a new row
        prior = self.db.one(
            "SELECT * FROM incidents WHERE id=? AND state='RESOLVED' ORDER BY resolved_at DESC LIMIT 1",
            (sig.fingerprint,),
        )
        occurrences, flap_count = 1, 0
        reopen = False
        if prior and prior["resolved_at"] and now - prior["resolved_at"] <= self.reopen_window:
            reopen = True
            occurrences = int(prior["occurrences"]) + 1
            flap_count = int(prior["flap_count"]) + 1
        incident = Incident(
            id=sig.fingerprint,
            category=sig.category,
            entity=sig.entity,
            title=sig.describe(),
            severity=sig.severity,
            state="OBSERVED",
            first_seen=now,
            last_seen=now,
            occurrences=occurrences,
            flap_count=flap_count,
            evidence=list(sig.evidence),
        )
        self._incidents[incident.id] = incident
        sql = (
            "INSERT INTO incidents(id, category, entity, title, severity, state, first_seen, last_seen, "
            "confirmed_at, resolved_at, notification_sent, occurrences, flap_count, last_notified_at, "
            "last_notified_severity, suppressed, root_incident, evidence, updated_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(id) DO UPDATE SET title=excluded.title, severity=excluded.severity, "
            "state=excluded.state, first_seen=excluded.first_seen, last_seen=excluded.last_seen, "
            "occurrences=excluded.occurrences, flap_count=excluded.flap_count, "
            "resolved_at=NULL, confirmed_at=NULL, notification_sent=0, suppressed=0, "
            "root_incident=NULL, evidence=excluded.evidence, updated_at=excluded.updated_at"
        )
        self.db.execute(sql, incident.to_row(now))
        if reopen:
            self._event(incident.id, now, "RESOLVED", "OBSERVED", "reopen binnen venster", sig.severity)
            if flap_count >= self.flap_threshold:
                info("incidents", "incident flapping", incident_id=incident.id, flap_count=flap_count)
        else:
            self._event(incident.id, now, None, "OBSERVED", "nieuw signaal", sig.severity)
        return incident

    def _update(self, incident: Incident, sig: Signal, now: float) -> None:
        incident.last_seen = now
        incident.recovering_since = None
        if sig.rank > SEVERITY_RANK.get(incident.severity, 0):
            incident.severity = sig.severity
            incident.title = sig.describe()
        for ev in sig.evidence:
            if ev not in incident.evidence:
                incident.evidence.append(ev)
        incident.evidence = incident.evidence[-20:]
        self._persist(incident, now)

    def _explicit_recovery(self, sig: Signal, now: float) -> None:
        incident = self._incidents.get(sig.fingerprint)
        if incident is None or not incident.open:
            return
        if incident.state in ("OBSERVED", "PENDING"):
            self._resolve(incident, now, "conditie verdwenen vóór bevestiging (transient)")
            return
        self._transition(incident, "RECOVERING", "band cleared, wacht op bevestiging", sig.severity, now)
        # explicit band recovery is already sample-confirmed by hysteresis: resolve now
        self._resolve(incident, now, "conditie bevestigd weg (hysteresis clear)")

    # ------------------------------------------------------------------
    def tick(self) -> list[dict]:
        """Time-based transitions + pending notification intents. Returns intent dicts:
        {kind: alert|escalation|resolved|reminder, incident: Incident}."""
        now = self.clock.now()
        intents: list[dict] = []
        for incident in self.open_incidents():
            if incident.state in ("OBSERVED", "PENDING"):
                stale = not incident.last_seen or now - incident.last_seen > self.absence_grace
                if stale:
                    self._resolve(incident, now, "conditie verdwenen vóór bevestiging (transient)")
                else:
                    debounce = float(self.config.get("debounce", {}).get(incident.category, 0))
                    recent = incident.last_seen and now - incident.last_seen <= self.fast_interval * 1.5
                    if recent and (now - incident.first_seen >= debounce or incident.category in IMMEDIATE_CATEGORIES):
                        self._transition(incident, "CONFIRMED", "debounce gehaald (tick)", incident.severity, now)
            elif incident.state == "CONFIRMED":
                intents.append({"kind": "alert", "incident": incident})
            elif incident.state == "ACTIVE":
                if (incident.category != "transient_pattern"
                        and incident.last_seen
                        and now - incident.last_seen > self.absence_grace):
                    # pattern-incidenten volgen het transient-venster, niet het
                    # live-signaal; de tracker lost ze af wanneer het venster
                    # leeg raakt (een momentane clear is geen episode-einde)
                    self._transition(incident, "RECOVERING", "geen signalen meer", incident.severity, now)
                elif incident.notification_sent and incident.last_notified_at and (
                    now - incident.last_notified_at
                    >= self._repeat_cooldown(incident.severity) * 60  # cooldowns in minuten
                ):
                    intents.append({"kind": "reminder", "incident": incident})
            elif incident.state == "RECOVERING":
                if incident.category == "transient_pattern":
                    self._transition(incident, "ACTIVE", "patroon-incident: geen live-clear", incident.severity, now)
                elif incident.last_seen and now - incident.last_seen > self.absence_grace:
                    self._resolve(incident, now, "hersteld (afwezigheid bevestigd)")
                elif incident.last_seen and now - incident.last_seen <= self.fast_interval:
                    # condition came back during recovering
                    self._transition(incident, "ACTIVE", "conditie terug tijdens herstel", incident.severity, now)
        if self._pending_resolved:
            intents.extend(self._pending_resolved)
            self._pending_resolved.clear()
        self.db.conn.commit()
        return intents

    def _repeat_cooldown(self, severity: str) -> float:
        cd = self.config.get("cooldowns", {}).get(severity, {})
        return float(cd.get("repeat", 480))

    # ------------------------------------------------------------------
    def mark_notified(self, incident_id: str, ts: float, severity: str) -> None:
        incident = self._incidents.get(incident_id)
        if incident is None:
            return
        incident.notification_sent = True
        incident.last_notified_at = ts
        incident.last_notified_severity = severity
        if incident.state == "CONFIRMED":
            self._transition(incident, "ACTIVE", "notificatie verzonden", severity, ts)
        else:
            self._persist(incident, ts)

    def mark_acknowledged(self, incident_id: str) -> None:
        """CONFIRMED -> ACTIVE without any notification (notice severity path)."""
        incident = self._incidents.get(incident_id)
        if incident is None or incident.state != "CONFIRMED":
            return
        self._transition(incident, "ACTIVE", "acknowledged (notice, geen notificatie)",
                         incident.severity, self.clock.now())

    def mark_cancelled(self, incident_id: str, reason: str) -> None:
        """Final recheck found the condition gone: transient + resolve, no messages."""
        incident = self._incidents.get(incident_id)
        if incident is None:
            return
        now = self.clock.now()
        self._resolve(incident, now, f"final recheck: {reason}")
        if not incident.notification_sent:
            self.record_transient(incident, f"final recheck: {reason}")

    def resolve_manual(self, incident_id: str, reason: str) -> None:
        incident = self._incidents.get(incident_id)
        if incident and incident.open:
            self._resolve(incident, self.clock.now(), reason)

    # ------------------------------------------------------------------
    def record_transient(self, incident: Incident, reason: str) -> None:
        now = self.clock.now()
        self.db.execute(
            "INSERT INTO transients(ts, fingerprint, category, entity, severity, meta) VALUES(?,?,?,?,?,?)",
            (now, incident.id, incident.category, incident.entity, incident.severity, reason),
        )
        info("incidents", "transient geregistreerd", incident_id=incident.id, reason=reason)

    def transient_count(self, fingerprint: str, window: float | None = None) -> int:
        w = window or self.transient_window
        row = self.db.one(
            "SELECT COUNT(*) AS n FROM transients WHERE fingerprint=? AND ts > ?",
            (fingerprint, self.clock.now() - w),
        )
        return int(row["n"]) if row else 0

    def pattern_incident_open(self, fingerprint: str) -> bool:
        pid = f"transient_pattern:{fingerprint}"
        inc = self._incidents.get(pid)
        return bool(inc and inc.open)

    def confirm_pattern(self, fingerprint: str, category: str, entity: str, count: int) -> Incident | None:
        """Recurrent transients become a DEGRADED pattern incident (spec §12)."""
        pid = f"transient_pattern:{fingerprint}"
        if self.pattern_incident_open(fingerprint):
            return None
        now = self.clock.now()
        prior = self.db.one(
            "SELECT * FROM incidents WHERE id=? AND state='RESOLVED' ORDER BY resolved_at DESC LIMIT 1",
            (pid,),
        )
        if prior and (now - prior["resolved_at"]) <= self.transient_window:
            # Heropen dezelfde episode binnen het transient-venster, mét de
            # oorspronkelijke notificatieboekhouding: een verse INSERT OR REPLACE
            # resette notification_sent/last_notified_at, waardoor elke fling
            # opnieuw als eerste alert verstuurd werd (soak 2026-10-07: 28
            # duplicaten in ~2,5 uur op plex-scraper-vfs).
            incident = Incident.from_row(prior)
            incident.state = "ACTIVE" if incident.notification_sent else "CONFIRMED"
            incident.resolved_at = None
            incident.confirmed_at = now
            incident.last_seen = now
            incident.occurrences = count
            incident.title = (
                f"{entity} is momenteel gezond, maar had {count}x kortstondig "
                f"{category} in de afgelopen {int(self.transient_window / 3600)} uur"
            )
            incident.evidence = [{"source": "derived", "confirm": True,
                                  "transient_count": count, "base": fingerprint}]
            self._incidents[pid] = incident
            self._persist(incident, now)
            self._event(pid, now, "RESOLVED", incident.state,
                        "patroon heropend binnen venster (notificatie behouden, geen nieuwe alert)",
                        "warning")
            return incident
        incident = Incident(
            id=pid,
            category="transient_pattern",
            entity=entity,
            title=(
                f"{entity} is momenteel gezond, maar had {count}x kortstondig "
                f"{category} in de afgelopen {int(self.transient_window / 3600)} uur"
            ),
            severity="warning",
            state="CONFIRMED",
            first_seen=now,
            last_seen=now,
            confirmed_at=now,
            occurrences=count,
            evidence=[{"source": "derived", "confirm": True, "transient_count": count, "base": fingerprint}],
        )
        self._incidents[pid] = incident
        self.db.execute(
            "INSERT OR REPLACE INTO incidents(id, category, entity, title, severity, state, first_seen, "
            "last_seen, confirmed_at, resolved_at, notification_sent, occurrences, flap_count, "
            "last_notified_at, last_notified_severity, suppressed, root_incident, evidence, updated_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,0,0,?,0,NULL,NULL,0,NULL,?,?)",
            (pid, incident.category, incident.entity, incident.title, incident.severity,
             incident.state, incident.first_seen, incident.last_seen, incident.confirmed_at,
             incident.occurrences, json_dumps(incident.evidence), now),
        )
        self._event(pid, now, None, "CONFIRMED", "patroon: herhaalde transients", "warning")
        return incident

    # ------------------------------------------------------------------
    def _transition(
        self, incident: Incident, to_state: str, reason: str, severity: str, now: float, quiet: bool = False
    ) -> None:
        from_state = incident.state
        incident.state = to_state
        if to_state == "CONFIRMED":
            incident.confirmed_at = now
        self._persist(incident, now)
        self._event(incident.id, now, from_state, to_state, reason, severity)
        if not quiet:
            info(
                "incidents", "state transition",
                incident_id=incident.id, state=to_state, from_state=from_state,
                severity=incident.severity, reason=reason,
            )

    def _resolve(self, incident: Incident, now: float, reason: str) -> None:
        was_pending = incident.state in ("OBSERVED", "PENDING")
        from_state = incident.state
        incident.state = "RESOLVED"
        incident.resolved_at = now
        self._persist(incident, now)
        self._event(incident.id, now, from_state, "RESOLVED", reason, incident.severity)
        if was_pending:
            self.record_transient(incident, reason)
        elif (from_state in OPEN_STATES and incident.notification_sent
                and self.config.get("telegram", {}).get("notify_recovery", True)):
            # Recovery-notificatie: alleen na eerder verzonden alert (spec §11).
            # De pipeline doet de verplichte final recheck; kwam de conditie
            # toch terug, dan wordt de recovery geannuleerd.
            self._pending_resolved.append({"kind": "resolved", "incident": incident})
        info("incidents", "incident resolved", incident_id=incident.id, reason=reason,
             notified=incident.notification_sent, duration=incident.describe_duration(now))

    def _persist(self, incident: Incident, now: float) -> None:
        self.db.execute(
            "INSERT INTO incidents(id, category, entity, title, severity, state, first_seen, last_seen, "
            "confirmed_at, resolved_at, notification_sent, occurrences, flap_count, last_notified_at, "
            "last_notified_severity, suppressed, root_incident, evidence, updated_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(id) DO UPDATE SET title=excluded.title, severity=excluded.severity, "
            "state=excluded.state, last_seen=excluded.last_seen, confirmed_at=excluded.confirmed_at, "
            "resolved_at=excluded.resolved_at, notification_sent=excluded.notification_sent, "
            "occurrences=excluded.occurrences, flap_count=excluded.flap_count, "
            "last_notified_at=excluded.last_notified_at, "
            "last_notified_severity=excluded.last_notified_severity, suppressed=excluded.suppressed, "
            "root_incident=excluded.root_incident, evidence=excluded.evidence, "
            "updated_at=excluded.updated_at",
            incident.to_row(now),
        )

    def _event(
        self, incident_id: str, ts: float, from_state: str | None, to_state: str, reason: str, severity: str
    ) -> None:
        self.db.execute(
            "INSERT INTO incident_events(incident_id, ts, from_state, to_state, reason, severity) "
            "VALUES(?,?,?,?,?,?)",
            (incident_id, ts, from_state, to_state, reason, severity),
        )

    # ------------------------------------------------------------------
    def incident_snapshot(self, incident: Incident) -> dict[str, Any]:
        return {
            "id": incident.id,
            "category": incident.category,
            "entity": incident.entity,
            "title": incident.title,
            "severity": incident.severity,
            "state": incident.state,
            "first_seen": incident.first_seen,
            "duration": incident.describe_duration(self.clock.now()),
            "occurrences": incident.occurrences,
            "suppressed": incident.suppressed,
            "root_incident": incident.root_incident,
            "evidence": incident.evidence,
        }
