"""Telegram interaction-authorization matrix (soak/finalisatie 2026-10-07).

Root cause van "Niet geautoriseerd." vanuit de eigenaar: _authorize keek
uitsluitend naar allowed_chat_ids/allowed_usernames (beide leeg in de
live-config) en betrok home_chat_id nooit — Hermes stuurde alerts naar de
home chat, maar de eigenaar mocht daar niet praten.

Semantics nu: home_chat_id is de trusted interaction chat (private = voldoende;
group/supergroup vereist daarnaast een expliciet geautoriseerde user),
aangevuld met exact allowed_user_id / allowed_chat_id / allowed_username.
"""

from __future__ import annotations

from conftest import TEST_CONFIG

from hermes.config import Config
from hermes.interfaces.commands import CommandHandler

HOME = "123456789"          # private home chat
GROUP = "-1009988776655"    # supergroup (negatief)


def make_handler(**tg_overrides):
    raw = dict(TEST_CONFIG)
    raw["telegram"] = {
        "enabled": True, "bot_token": "tok",
        "home_chat_id": tg_overrides.pop("home_chat_id", HOME),
        "allowed_usernames": tg_overrides.pop("allowed_usernames", []),
        "allowed_chat_ids": tg_overrides.pop("allowed_chat_ids", []),
        "allowed_user_ids": tg_overrides.pop("allowed_user_ids", []),
        "min_severity": "warning",
    } | tg_overrides
    cfg = Config(raw=raw)
    from types import SimpleNamespace
    return CommandHandler(SimpleNamespace(cfg=cfg), None)


def msg(chat_id, user_id=0, username="", chat_type="private"):
    frm = {"id": user_id}
    if username:
        frm["username"] = username
    return {"chat": {"id": chat_id, "type": chat_type}, "from": frm}


async def test_private_home_chat_exact_match_allows():
    h = make_handler()
    ok, _ = h._authorize(msg(HOME, user_id=42))  # geen enkele allowlist
    assert ok


async def test_allowed_chat_id_exact_match_allows():
    h = make_handler(allowed_chat_ids=[555])
    assert h._authorize(msg(555, user_id=7))[0]


async def test_allowed_user_id_exact_match_allows():
    h = make_handler(allowed_user_ids=[4242])
    assert h._authorize(msg("999888777", user_id=4242))[0]


async def test_allowed_username_exact_match_allows():
    h = make_handler(allowed_usernames=["Remco"])
    assert h._authorize(msg("999888777", username=" @remco "))[0]


async def test_username_missing_but_private_home_chat_matches():
    h = make_handler()
    assert h._authorize(msg(HOME, user_id=1))[0]  # from zonder username


async def test_wrong_private_chat_and_unknown_user_denied():
    h = make_handler()
    ok, _ = h._authorize(msg("555000111", user_id=13, username="stranger"))
    assert not ok


async def test_group_home_chat_unknown_user_denied():
    h = make_handler(home_chat_id=GROUP)
    ok, _ = h._authorize(msg(GROUP, user_id=13, username="stranger", chat_type="supergroup"))
    assert not ok


async def test_group_home_chat_allowed_user_id_allows():
    h = make_handler(home_chat_id=GROUP, allowed_user_ids=[42])
    assert h._authorize(msg(GROUP, user_id=42, chat_type="supergroup"))[0]


async def test_negative_group_ids_handled_exactly():
    h = make_handler(allowed_chat_ids=[-1009988776655])
    # int id in config -> str genormaliseerd; incoming int -> str
    assert h._authorize(msg(GROUP, user_id=1))[0]
    assert not h._authorize(msg("-1009988776654", user_id=1))[0]  # 1 char verschil


async def test_int_string_normalization_exact():
    h = make_handler(allowed_user_ids=[42])
    assert h._authorize(msg("999", user_id="42"))[0]      # from int, config str
    assert not h._authorize(msg("999", user_id="420"))[0] # geen substring/prefix match


async def test_unknown_command_does_not_bypass_auth():
    h = make_handler()
    ok, _ = h._authorize(msg("555000111", user_id=13, username="stranger"))
    assert not ok  # auth gebeurt vóór dispatch; /unknown verandert daar niets aan
    # en de dispatch zelf geeft alleen help-tekst:
    reply = await h.handle("/unknown", "smoke")
    assert "Onbekend commando" in reply
