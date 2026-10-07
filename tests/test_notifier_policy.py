"""Notifier policy: min severity, cooldowns, shadow mode, retry queue, Telegram auth."""

from __future__ import annotations

from conftest import FakeClock

from hermes.config import Config
from hermes.interfaces.notifier import Notifier
from hermes.interfaces.telegram import format_alert, format_daily_summary
from hermes.state.db import Database


class FakeTelegram:
    def __init__(self, fail_times: int = 0) -> None:
        self.sent: list[tuple[str, str]] = []
        self.fail_times = fail_times

    async def send_message(self, chat_id, text, retries=3):
        if self.fail_times > 0:
            self.fail_times -= 1
            raise RuntimeError("telegram down")
        self.sent.append((chat_id, text))
        return f"msg-{len(self.sent)}"


def snapshot(severity="warning", incident_id="container_unhealthy:plex"):
    return {"id": incident_id, "category": "container_unhealthy", "entity": "plex",
            "title": "Container plex unhealthy", "severity": severity, "state": "CONFIRMED",
            "first_seen": 0, "duration": "2m", "occurrences": 1, "evidence": []}


def make_notifier(tmp_path, cfg_overrides=None, clock=None):
    db = Database(str(tmp_path / "t.db"))
    db.migrate()
    cfg = Config(raw={"telegram": {"enabled": True, "bot_token": "tok", "home_chat_id": "42",
                                   "min_severity": "warning", "notify_recovery": True},
                      "mode": "normal"} | (cfg_overrides or {}))
    clock = clock or FakeClock()
    tg = FakeTelegram()
    notifier = Notifier(cfg, db, clock, tg)
    return notifier, db, tg, clock


async def test_min_severity_gate_suppresses_notice(tmp_path):
    notifier, db, tg, _ = make_notifier(tmp_path)
    handled = await notifier.deliver("alert", snapshot(severity="notice"))
    assert handled is True
    assert tg.sent == []
    row = db.one("SELECT meta FROM notifications ORDER BY id DESC LIMIT 1")
    assert "min_severity" in row["meta"]


async def test_shadow_mode_sends_nothing(tmp_path):
    notifier, db, tg, _ = make_notifier(tmp_path, {"mode": "shadow"})
    handled = await notifier.deliver("alert", snapshot())
    assert handled is True  # state machine completes...
    assert tg.sent == []    # ...but nothing is delivered
    row = db.one("SELECT meta FROM notifications ORDER BY id DESC LIMIT 1")
    assert row["meta"] == "shadow:not sent"


async def test_shadow_mode_uses_debug_channel(tmp_path):
    notifier, db, tg, _ = make_notifier(
        tmp_path, {"mode": "shadow", "telegram": {"debug_chat_id": "999"}})
    handled = await notifier.deliver("alert", snapshot())
    assert handled and tg.sent and tg.sent[0][0] == "999"
    assert tg.sent[0][1].startswith("[SHADOW]")


async def test_telegram_down_persists_pending_and_retries(tmp_path):
    db = Database(str(tmp_path / "t.db"))
    db.migrate()
    cfg = Config(raw={"telegram": {"enabled": True, "bot_token": "tok", "home_chat_id": "42",
                                   "min_severity": "warning"}})
    clock = FakeClock()
    tg = FakeTelegram(fail_times=1)
    notifier = Notifier(cfg, db, clock, tg)
    delivered = await notifier.deliver("alert", snapshot())
    assert delivered is False  # will retry
    assert tg.sent == []
    pending = db.one("SELECT * FROM notifications WHERE delivered=0")
    assert pending is not None
    # telegram recovers -> controlled retry succeeds (after backoff window)
    clock.advance(120)
    sent = await notifier.retry_pending()
    assert sent == 1
    assert len(tg.sent) == 1
    assert db.one("SELECT COUNT(*) AS n FROM notifications WHERE delivered=0")["n"] == 0


async def test_recovery_only_after_alert(tmp_path):
    notifier, db, tg, _ = make_notifier(tmp_path)
    # alert first
    assert await notifier.deliver("alert", snapshot()) is True
    assert len(tg.sent) == 1
    # recovery after a real alert is allowed
    snap = snapshot()
    snap["state"] = "RESOLVED"
    assert await notifier.deliver("resolved", snap) is True
    texts = [t for _, t in tg.sent]
    assert any("OPGELOST" in t for t in texts)


async def test_message_format_is_deterministic():
    text = format_alert("alert", snapshot(severity="critical"))
    assert "🔴" in text and "CRITICAL" in text
    assert "container_unhealthy:plex" in text
    text2 = format_alert("alert", snapshot())
    assert text2 == format_alert("alert", snapshot())  # identical inputs -> identical message


def test_daily_summary_format():
    stats = {"host_healthy": True, "incidents_open": 1, "incidents_new": 2, "transients": 7,
             "self_healed": 3, "notifications_sent": 4, "notifications_suppressed": 5,
             "remediations": 3, "ai_calls": 2, "ai_escalations": 1,
             "unresolved": ["warning x"], "patterns": ["plex: 6x transient"]}
    text = format_daily_summary(stats)
    for needle in ("dagoverzicht", "Transients", "Zelf hersteld", "plex: 6x transient"):
        assert needle in text


def test_format_alert_never_leaks_evidence_dicts_verbatim():
    snap = snapshot()
    snap["evidence"] = [{"source": "beacon", "token": "123456:ABCDEFghijk"}]
    text = format_alert("alert", snap)
    assert "123456" not in text


# ---------------------------------------------------------------------------
# Telegram authorization is tested through the CommandHandler auth path
# ---------------------------------------------------------------------------


class StubApp:
    def __init__(self, cfg):
        self.cfg = cfg


async def test_unauthorized_user_is_rejected(tmp_path):
    from hermes.interfaces.commands import CommandHandler

    db = Database(str(tmp_path / "t.db"))
    db.migrate()
    cfg = Config(raw={"telegram": {"enabled": True, "bot_token": "t",
                                   "allowed_usernames": ["remco"], "allowed_chat_ids": []},
                      "executor": {"mode": "dry-run"}})
    handler = CommandHandler(StubApp(cfg), None)
    ok, _ = handler._authorize({"chat": {"id": "123"}, "from": {"username": "attacker"}})
    assert ok is False
    ok, _ = handler._authorize({"chat": {"id": "123"}, "from": {"username": "remco"}})
    assert ok is True


async def test_command_replay_is_ignored(tmp_path):
    from hermes.interfaces.commands import CommandHandler

    class TG:
        def __init__(self):
            self.updates = []

        async def get_updates(self, offset, poll_timeout=0):
            return self.updates

        async def send_message(self, chat_id, text):
            return "1"

    db = Database(str(tmp_path / "t.db"))
    db.migrate()
    cfg = Config(raw={"telegram": {"enabled": True, "bot_token": "t",
                                   "allowed_usernames": ["remco"], "allowed_chat_ids": ["42"]},
                      "executor": {"mode": "dry-run"}})
    tg = TG()
    handler = CommandHandler(StubApp(cfg), tg)
    tg.updates = [{"update_id": 5, "message": {"text": "/status", "chat": {"id": "42"},
                                               "from": {"username": "remco"}}}]
    await handler.poll_once()
    assert handler.last_update_id == 5
    # same update again (replay) -> ignored
    await handler.poll_once()
    assert handler.last_update_id == 5
