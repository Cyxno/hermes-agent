"""Telegram command interface (spec §34/§57).

Simple commands are answered deterministically (no LLM). `/investigate` and
`/fix` are the AI-assisted and remediation paths — always scoped, audited and
gated by the policy engine. Only explicitly authorized users/chats get access;
mutation commands create scoped, single-use, time-limited approvals.
"""

from __future__ import annotations

import time

from ..intelligence.router import RouteOutcome
from ..log import info, warning
from ..util import sanitize
from .telegram import TelegramClient


class CommandHandler:
    def __init__(self, app, telegram: TelegramClient | None) -> None:  # noqa: ANN001
        self.app = app
        self.telegram = telegram
        section = app.cfg.section("telegram")
        self.allowed_usernames = {u.lower().lstrip("@") for u in section.get("allowed_usernames", [])}
        self.allowed_chat_ids = {str(c) for c in section.get("allowed_chat_ids", [])}
        self.last_update_id = 0

    # -- auth -------------------------------------------------------------
    def _authorize(self, message: dict) -> tuple[bool, str]:
        chat = str(message.get("chat", {}).get("id", ""))
        username = str(message.get("from", {}).get("username", "")).lower()
        if self.allowed_chat_ids and chat in self.allowed_chat_ids:
            return True, username
        if username and username in self.allowed_usernames:
            return True, username
        return False, username

    # -- updates ----------------------------------------------------------
    async def poll_once(self) -> None:
        if self.telegram is None:
            return
        updates = await self.telegram.get_updates(self.last_update_id + 1,
                                                  poll_timeout=int(self.app.cfg.section("telegram").get("poll_timeout", 50)))
        for update in updates:
            uid = int(update.get("update_id", 0))
            if uid <= self.last_update_id:
                continue  # replay protection
            self.last_update_id = uid
            message = update.get("message") or {}
            text = str(message.get("text", "")).strip()
            if not text:
                continue
            ok, username = self._authorize(message)
            chat_id = str(message.get("chat", {}).get("id", ""))
            if not ok:
                warning("telegram", "niet-geautoriseerd commando geweigerd", username=sanitize(username, 40))
                await self._reply(chat_id, "Niet geautoriseerd.")
                continue
            try:
                reply = await self.handle(text, username)
            except Exception as exc:  # noqa: BLE001 - commands must never kill the poller
                warning("telegram", "commandofout", error=sanitize(exc, 160))
                reply = f"Interne fout: {sanitize(exc, 160)}"
            await self._reply(chat_id, reply)

    async def _reply(self, chat_id: str, text: str) -> None:
        if self.telegram is None or not chat_id:
            return
        try:
            await self.telegram.send_message(chat_id, text)
        except Exception as exc:  # noqa: BLE001
            warning("telegram", "reply gefaald", error=sanitize(exc, 120))

    # -- dispatch ---------------------------------------------------------
    async def handle(self, text: str, username: str) -> str:
        app = self.app
        lower = text.lower().strip()
        parts = text.split()
        cmd = parts[0].lower()

        # Dutch free-text intents (spec §26/§34)
        if lower in ("los het op", "fix het", "fix"):
            return await self._fix_target(self._last_incident(), username)
        if lower in ("onderzoek dit", "onderzoek", "investigate"):
            return await self._investigate(self._last_incident())
        if cmd in ("/start", "/help"):
            return self._help()
        if cmd == "/status":
            return app.status_text()
        if cmd == "/incidents":
            return self._incidents()
        if cmd in ("/why", "/details"):
            return self._why(parts[1] if len(parts) > 1 else self._last_incident_id())
        if cmd == "/investigate":
            return await self._investigate(parts[1] if len(parts) > 1 else self._last_incident_id())
        if cmd == "/fix":
            return await self._fix_target(parts[1] if len(parts) > 1 else self._last_incident_id(), username)
        if cmd == "/approve":
            return await self._approve(parts[1] if len(parts) > 1 else "", username)
        if cmd == "/whatdidyoudo":
            return self._audit_tail()
        if cmd == "/mute":
            return self._mute(parts[1] if len(parts) > 1 else "", parts[2] if len(parts) > 2 else "6")
        if cmd == "/desired":
            return self._desired(parts[1:])
        return f"Onbekend commando. {self._help()}"

    def _help(self) -> str:
        return (
            "Hermes v2 commando's:\n"
            "/status — gezondheidsoverzicht\n"
            "/incidents — openstaande incidenten\n"
            "/why <id> — uitleg + evidence\n"
            "/investigate <id> — diagnose (runbook + AI)\n"
            "/fix <id> — veilige remediëring (policy-gate)\n"
            "/approve <code> — scoped goedkeuring bevestigen\n"
            "los het op — fix laatste actieve incident\n"
            "/whatdidyoudo — actie-audit laatste 24u\n"
            "/mute <fingerprint> <uren> — dempen\n"
            "/desired [list|set <entity> <state>]"
        )

    # -- implementations ---------------------------------------------------
    def _last_incident_id(self) -> str:
        open_inc = self.app.engine.open_incidents()
        if open_inc:
            return open_inc[-1].id
        return ""

    def _last_incident(self) -> str:
        return self._last_incident_id()

    def _incidents(self) -> str:
        open_inc = self.app.engine.open_incidents()
        if not open_inc:
            return "Geen openstaande incidenten."
        lines = []
        for inc in open_inc[-15:]:
            flag = " [gecorreleerd]" if inc.suppressed else ""
            lines.append(f"- `{inc.id}` {inc.severity}/{inc.state}{flag} — {inc.title[:90]}")
        return "\n".join(lines)

    def _why(self, incident_id: str) -> str:
        incident = self.app.engine.get(incident_id)
        if incident is None:
            return f"Onbekend incident: {incident_id}"
        snapshot = self.app.engine.incident_snapshot(incident)
        import datetime

        first = datetime.datetime.fromtimestamp(incident.first_seen, datetime.UTC).strftime("%Y-%m-%d %H:%M UTC")
        lines = [
            f"{incident.title}",
            f"state={incident.state} severity={incident.severity} duur={snapshot['duration']} "
            f"eerst gezien={first}",
            "",
            "Evidence:",
        ]
        for ev in incident.evidence[:8]:
            lines.append(f"- [{ev.get('source')}] {sanitize(str({k: v for k, v in ev.items() if k != 'source'}), 140)}")
        if incident.root_incident:
            lines.append(f"Gecorreleerd onder: {incident.root_incident}")
        if incident.ai_summary:
            lines.append("")
            lines.append(f"AI: {sanitize(incident.ai_summary, 400)}")
        return "\n".join(lines)

    async def _investigate(self, incident_id: str) -> str:
        incident = self.app.engine.get(incident_id)
        if incident is None:
            return f"Onbekend incident: {incident_id}"
        app = self.app
        runbook = app.runbooks.for_incident(incident)
        diagnosis_text = ""
        if runbook is not None:
            result = await app.runbooks.run_diagnose_only(incident)
            diagnosis_text = f"Runbook {runbook.name}: {result.detail}\n\n"
        snapshot = app.engine.incident_snapshot(incident)
        context = app.context_builder.build(
            snapshot, current_state_lines=app.current_state_lines(incident.entity)
        )
        outcome: RouteOutcome = await app.ai_router.analyze(incident.id, context)
        if not outcome.ok:
            return (f"{diagnosis_text}AI-analyse niet beschikbaar ({outcome.error or 'geen resultaat'}). "
                    f"Deterministische diagnose blijft actief.")
        d = outcome.diagnosis
        app.engine.set_ai_summary(incident.id, d.explanation or d.rootCause)  # type: ignore[union-attr]
        lines = [
            diagnosis_text.strip(),
            f"Model: {outcome.model_used} (tier {outcome.tier_used})",
            f"Root cause: {d.rootCause}",  # type: ignore[union-attr]
            f"Confidence: {d.confidence:.2f}",  # type: ignore[union-attr]
        ]
        if d.recommendedRunbook:  # type: ignore[union-attr]
            lines.append(f"Aanbevolen runbook: {d.recommendedRunbook}")  # type: ignore[union-attr]
        for action in d.proposedActions:  # type: ignore[union-attr]
            lines.append(f"Voorgesteld: {action.capability} op {action.target} — {action.reason[:80]}")
        if d.requiresHumanApproval:  # type: ignore[union-attr]
            lines.append("Menselijke goedkeuring vereist voor uitvoering.")
        return "\n".join(line for line in lines if line)

    async def _fix_target(self, incident_id: str, username: str) -> str:
        if not incident_id:
            return "Geen actief incident om te fixen."
        incident = self.app.engine.get(incident_id)
        if incident is None:
            return f"Onbekend incident: {incident_id}"
        result = await self.app.runbooks.run(
            incident, initiator=f"telegram/{username}"
        )
        if result.outcome == "would_execute":
            return f"DRY-RUN: ik zou '{result.runbook}' uitvoeren ({result.detail}). Executor staat op dry-run."
        if result.outcome == "needs_approval":
            approval = self.app.approvals.create(
                incident_id, "docker", incident.entity,
                ttl=float(self.app.cfg.section("executor").get("approval_ttl", 600)),
            )
            return (
                f"Goedkeuring nodig ({result.detail}).\n"
                f"Bevestig met: /approve {approval['id']} (geldig {int((approval['expires_at'] - time.time()) / 60)} min)"
            )
        if result.outcome == "resolved":
            self.app.engine.resolve_manual(incident_id, "hersteld na runbook + verificatie")
            return f"Uitgevoerd en geverifieerd gezond ({result.runbook})."
        return f"{result.outcome}: {result.detail}"

    async def _approve(self, approval_id: str, username: str) -> str:
        if not approval_id:
            return "Gebruik: /approve <code>"
        # probe-consume with mismatched classes is a no-op; validate from the row below
        row = self.app.db.one("SELECT * FROM approvals WHERE id=?", (approval_id,))
        if row is None:
            return "Onbekende goedkeuringscode."
        if row["used"]:
            return "Deze goedkeuring is al gebruikt."
        if float(row["expires_at"]) < time.time():
            return "Deze goedkeuring is verlopen."
        incident_id = row["incident_id"]
        incident = self.app.engine.get(incident_id)
        if incident is None:
            return "Incident niet meer actief."
        info("telegram", "scoped approval gebruikt", incident_id=incident_id, username=username)
        # the runbook re-run will consume the approval via executor
        self.app.db.execute("UPDATE approvals SET used=0 WHERE id=?", (approval_id,))
        result = await self.app.runbooks.run(incident, approval_id=approval_id, initiator=f"telegram/{username}")
        if result.outcome == "resolved":
            self.app.engine.resolve_manual(incident_id, "hersteld na goedgekeurde runbook")
        return f"{result.outcome}: {result.detail}"

    def _audit_tail(self) -> str:
        since = time.time() - 86400
        rows = self.app.db.query(
            "SELECT ts, initiator, capability, target, result, mode FROM action_audit "
            "WHERE ts >= ? ORDER BY ts DESC LIMIT 20",
            (since,),
        )
        if not rows:
            return "Laatste 24u: geen acties uitgevoerd."
        lines = ["Acties laatste 24u (nieuwste eerst):"]
        import datetime

        for row in rows:
            ts = datetime.datetime.fromtimestamp(row["ts"], datetime.UTC).strftime("%H:%M")
            lines.append(f"- {ts} [{row['mode']}] {row['capability']} {row['target']} → {row['result']} ({row['initiator']})")
        return "\n".join(lines)

    def _mute(self, fingerprint: str, hours: str) -> str:
        if not fingerprint:
            return "Gebruik: /mute <fingerprint> <uren>"
        try:
            duration = max(1, int(hours)) * 3600
        except ValueError:
            return "Ongeldig aantal uren."
        self.app.db.set_cursor(f"mute:{fingerprint}", str(time.time() + duration))
        return f"Gedempt tot over {hours} uur: {fingerprint}"

    def _desired(self, args: list[str]) -> str:
        if not args or args[0] == "list":
            rows = self.app.db.query("SELECT entity, state FROM desired_state ORDER BY entity LIMIT 60")
            return "Desired state:\n" + "\n".join(f"- {r['entity']}: {r['state']}" for r in rows)
        if args[0] == "set" and len(args) == 3:
            entity, state = args[1], args[2].upper()
            try:
                self.app.desired.set(entity, state)
            except ValueError as exc:
                return str(exc)
            return f"{entity} → {state}"
        return "Gebruik: /desired [list|set <entity> <MANAGED|OPTIONAL|RETIRED|IGNORED>]"
