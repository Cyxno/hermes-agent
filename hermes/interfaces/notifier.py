"""Notifier: turns notification intents into Telegram messages under strict rules.

- shadow mode: nothing leaves the machine (optional debug channel only);
- min_severity gate: notice is never sent;
- final recheck already happened in the pipeline — this layer never re-decides
  truth, it only records + transports;
- every send/attempt/suppression is persisted (notifications table) so retries
  survive restarts (spec §30: Telegram down => no event loss).
"""

from __future__ import annotations

from ..clock import Clock
from ..config import Config
from ..log import info, warning
from ..util import backoff_delay
from .telegram import TelegramClient, format_alert


class Notifier:
    def __init__(
        self,
        cfg: Config,
        db,  # Database
        clock: Clock,
        telegram: TelegramClient | None,
        affected_lookup=None,  # callable(incident_id) -> list[str]
    ) -> None:
        self.cfg = cfg
        self.section = cfg.section("telegram")
        self.db = db
        self.clock = clock
        self.telegram = telegram
        self.affected_lookup = affected_lookup or (lambda _i: [])
        self.shadow = cfg.shadow
        self.min_severity = self.section.get("min_severity", "warning")
        self.debug_chat_id = str(self.section.get("debug_chat_id") or "")
        self._severity_rank = {"notice": 0, "warning": 1, "urgent": 2, "critical": 3}
        self.counters = {"sent": 0, "suppressed": 0, "failed": 0, "shadow": 0}

    # ------------------------------------------------------------------
    async def deliver(self, kind: str, snapshot: dict) -> bool:
        """Returns True when the intent was fully handled (send, shadow-record or
        deliberate suppression). Only False on hard failure worth retrying."""
        now = self.clock.now()
        severity = snapshot.get("severity", "warning")
        if kind in ("alert", "reminder", "escalation"):
            if self._severity_rank.get(severity, 1) < self._severity_rank[self.min_severity]:
                self._record(now, snapshot, kind, "suppressed:min_severity", 0)
                self.counters["suppressed"] += 1
                return True
        affected = self.affected_lookup(snapshot.get("id", ""))
        text = format_alert(
            "resolved" if kind == "resolved" else "alert",
            snapshot, affected,
            ai_explanation=snapshot.get("ai_summary"),
        )
        if kind == "reminder":
            text = text.replace("—", "— (herinnering)", 1)
        chat_id = self._home_chat()
        if self.shadow:
            self.counters["shadow"] += 1
            if self.debug_chat_id:
                return await self._send(chat_id=self.debug_chat_id, text=f"[SHADOW] {text}",
                                        snapshot=snapshot, kind=kind)
            self._record(now, snapshot, kind, "shadow:not sent", 0)
            info("notifier", "shadow: melding niet verzonden", incident_id=snapshot.get("id"), kind=kind)
            return True
        if not self.telegram or not chat_id:
            self._record(now, snapshot, kind, "suppressed:no transport", 0)
            self.counters["suppressed"] += 1
            return True
        return await self._send(chat_id, text, snapshot, kind)

    async def _send(self, chat_id: str, text: str, snapshot: dict, kind: str) -> bool:
        now = self.clock.now()
        try:
            message_id = await self.telegram.send_message(chat_id, text)  # type: ignore[union-attr]
        except Exception as exc:  # noqa: BLE001 - delivery failures are retried, not fatal
            warning("notifier", "telegram verzending gefaald", incident_id=snapshot.get("id"),
                    error=str(exc)[:160])
            self.db.execute(
                "INSERT INTO notifications(ts, incident_id, severity, kind, message, delivered, attempts, next_retry, meta) "
                "VALUES(?,?,?,?,?,0,1,?,?)",
                (now, snapshot.get("id"), snapshot.get("severity"), kind, text[:3800],
                 now + backoff_delay(0, base=60, cap=900), "retry pending"),
            )
            self.counters["failed"] += 1
            return False
        self._record(now, snapshot, kind, f"delivered:{message_id}", 1, message_id=message_id, message=text)
        self.counters["sent"] += 1
        info("notifier", "melding verzonden", incident_id=snapshot.get("id"), kind=kind,
             severity=snapshot.get("severity"), message_id=message_id)
        return True

    async def retry_pending(self) -> int:
        """Controlled retry of failed deliveries (bounded backoff, no runaway loops)."""
        now = self.clock.now()
        rows = self.db.query(
            "SELECT * FROM notifications WHERE delivered=0 AND next_retry <= ? AND attempts < 6 LIMIT 5",
            (now,),
        )
        sent = 0
        chat_id = self._home_chat() if not self.shadow else (self.debug_chat_id or "")
        for row in rows:
            if not self.telegram or not chat_id:
                break
            try:
                message_id = await self.telegram.send_message(chat_id, row["message"])  # type: ignore[union-attr]
            except Exception:  # noqa: BLE001
                attempts = int(row["attempts"]) + 1
                self.db.execute(
                    "UPDATE notifications SET attempts=?, next_retry=? WHERE id=?",
                    (attempts, now + backoff_delay(attempts, base=60, cap=900), row["id"]),
                )
                continue
            self.db.execute(
                "UPDATE notifications SET delivered=1, message_id=? WHERE id=?",
                (message_id, row["id"]),
            )
            sent += 1
        return sent

    # ------------------------------------------------------------------
    def _home_chat(self) -> str:
        return str(self.section.get("home_chat_id") or "")

    def _record(self, ts: float, snapshot: dict, kind: str, result: str, delivered: int,
                message_id: str | None = None, message: str | None = None) -> None:
        self.db.execute(
            "INSERT INTO notifications(ts, incident_id, severity, kind, message, message_id, delivered, attempts, next_retry, meta) "
            "VALUES(?,?,?,?,?,?,?,1,NULL,?)",
            (ts, snapshot.get("id"), snapshot.get("severity"), kind,
             (message or "")[:3800], message_id, delivered, result),
        )

    def stats_window(self, since: float) -> dict:
        rows = self.db.query(
            "SELECT delivered, COUNT(*) AS n FROM notifications WHERE ts >= ? GROUP BY delivered",
            (since,),
        )
        out = {"sent": 0, "failed": 0}
        for row in rows:
            if row["delivered"]:
                out["sent"] = int(row["n"])
            else:
                out["failed"] = int(row["n"])
        return out
