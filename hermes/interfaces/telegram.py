"""Telegram client: outgoing alerts + incoming commands.

Lightweight long-poll client (no bot framework). Authorization is handled by
the caller; update_id deduplication protects against command replay (spec §57).
"""

from __future__ import annotations

import asyncio
from urllib.parse import urlencode

from ..log import warning
from ..util import backoff_delay, sanitize


class TelegramError(Exception):
    pass


class TelegramClient:
    def __init__(self, token: str, api_base: str = "https://api.telegram.org", timeout: float = 15.0) -> None:
        self.token = token
        self.api_base = api_base.rstrip("/")
        self.timeout = timeout
        self._session = None

    async def _get_session(self):
        if self._session is None:
            import aiohttp

            self._session = aiohttp.ClientSession()
        return self._session

    def _url(self, method: str) -> str:
        return f"{self.api_base}/bot{self.token}/{method}"

    async def send_message(self, chat_id: str, text: str, retries: int = 3) -> str | None:
        import aiohttp

        session = await self._get_session()
        payload = {"chat_id": chat_id, "text": text[:4000], "disable_web_page_preview": True}
        last_error = ""
        for attempt in range(retries):
            try:
                async with session.post(
                    self._url("sendMessage"), json=payload,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                ) as resp:
                    body = await resp.json(content_type=None)
                    if resp.status == 200 and isinstance(body, dict) and body.get("ok"):
                        result = body.get("result", {})
                        return str(result.get("message_id", ""))
                    last_error = f"http {resp.status}: {sanitize(body, 160)}"
            except (aiohttp.ClientError, TimeoutError, OSError) as exc:
                last_error = sanitize(exc, 160)
            if attempt < retries - 1:
                await asyncio.sleep(backoff_delay(attempt, base=2.0, cap=30.0))
        raise TelegramError(last_error)

    async def get_updates(self, offset: int, poll_timeout: int = 50) -> list[dict]:
        import aiohttp

        session = await self._get_session()
        params = urlencode({"offset": offset, "timeout": poll_timeout, "allowed_updates": '["message"]'})
        try:
            async with session.get(
                f"{self._url('getUpdates')}?{params}",
                timeout=aiohttp.ClientTimeout(total=poll_timeout + self.timeout),
            ) as resp:
                body = await resp.json(content_type=None)
                if resp.status == 200 and isinstance(body, dict) and body.get("ok"):
                    return body.get("result", [])
                warning("telegram", "getUpdates failed", detail=sanitize(body, 120))
                return []
        except (aiohttp.ClientError, TimeoutError, OSError) as exc:
            warning("telegram", "getUpdates netwerkfout", error=sanitize(exc, 120))
            return []

    async def close(self) -> None:
        if self._session is not None:
            await self._session.close()
            self._session = None


def _self_healing_line(snapshot: dict) -> str | None:
    """§C21: compact remediation status — only when there is something to say."""
    rem = snapshot.get("remediation")
    if rem:
        outcome = str(rem.get("outcome", ""))
        rb = rem.get("runbook") or "runbook"
        if outcome in ("resolved", "success"):
            return f"Zelfherstel: gelukt — {rb}"
        if outcome == "needs_approval":
            return f"Zelfherstel: wacht op goedkeuring ({rb})"
        if outcome in ("failed", "action_failed", "verification_failed"):
            return f"Zelfherstel: gefaald — {rb} ({str(rem.get('detail', ''))[:60]})"
        return f"Zelfherstel: {outcome} — {rb}"
    return None


def _ai_usage_line(snapshot: dict) -> str:
    """'AI gebruikt'-regel uit de incident-scoped audit-metadata (geen AI-calls)."""
    from ..intelligence.router import model_display_name

    usage = snapshot.get("ai_usage")
    if not usage or not usage.get("used"):
        return "AI gebruikt: nee"
    if usage.get("failed"):
        return "AI gebruikt: ja — analyse mislukt"
    name = model_display_name(usage.get("model"))
    tier = f" (tier {usage['tier']})" if int(usage.get("tier") or 0) >= 2 else ""
    return f"AI gebruikt: ja — {name}{tier}"


def format_alert(kind: str, snapshot: dict, affected: list[str] | None = None,
                 ai_explanation: str | None = None) -> str:
    """Deterministic alert text — no LLM involved (spec §15)."""
    icons = {"notice": "ℹ️", "warning": "⚠️", "urgent": "🟠", "critical": "🔴"}
    severity = snapshot.get("severity", "warning")
    icon = icons.get(severity, "⚠️")
    ai_line = _ai_usage_line(snapshot)
    if kind == "resolved":
        return (
            f"✅ OPGELOST — {snapshot.get('title')}\n"
            f"Incident: `{snapshot.get('id')}`\n"
            f"Duur: {snapshot.get('duration')}\n"
            f"{ai_line}"
        )
    if kind == "reminder":
        header = f"{icon} NOG ACTIEF — {snapshot.get('title')}"
    else:
        header = f"{icon} {severity.upper()} — {snapshot.get('title')}"
    lines = [
        header,
        f"Incident: `{snapshot.get('id')}`",
        f"Duur: {snapshot.get('duration')} | Occurrences: {snapshot.get('occurrences', 1)}",
    ]
    evidence = snapshot.get("evidence") or []
    if evidence:
        lines.append("Evidence: " + "; ".join(
            sanitize(str(e.get("source", "?")), 20) for e in evidence[:4]
        ))
    if affected:
        lines.append("Getroffen: " + ", ".join(affected[:10]))
    healing = _self_healing_line(snapshot)
    if healing:
        lines.append(healing)
    lines.append(ai_line)
    if ai_explanation:
        lines.append("")
        lines.append(f"AI-analyse: {sanitize(ai_explanation, 600)}")
    return "\n".join(lines)


def format_daily_summary(stats: dict) -> str:
    lines = ["📋 Hermes dagoverzicht", ""]
    lines.append(f"Host: {'gezond' if stats.get('host_healthy') else 'met aandachtspunten'}")
    lines.append(
        f"Incidenten: {stats.get('incidents_open', 0)} open / {stats.get('incidents_new', 0)} nieuw"
    )
    lines.append(f"Transients (stil onderdrukt): {stats.get('transients', 0)}")
    lines.append(f"Zelf hersteld (geen melding): {stats.get('self_healed', 0)}")
    lines.append(f"Meldingen verzonden: {stats.get('notifications_sent', 0)} (onderdrukt: {stats.get('notifications_suppressed', 0)})")
    if stats.get("remediations"):
        lines.append(
            f"Autonome remediëringen: {stats.get('remediations')} "
            f"(gefaald: {stats.get('failed_remediations', 0)}, geweigerd: {stats.get('denied_actions', 0)})"
        )
    if stats.get("ai_calls"):
        lines.append(f"AI-calls: {stats.get('ai_calls')} (escalaties: {stats.get('ai_escalations', 0)})")
    if stats.get("unresolved"):
        lines.append("")
        lines.append("Openstaand:")
        for item in stats.get("unresolved", [])[:8]:
            lines.append(f"- {item}")
    if stats.get("patterns"):
        lines.append("")
        lines.append("Patronen: " + "; ".join(stats["patterns"][:5]))
    return "\n".join(lines)
