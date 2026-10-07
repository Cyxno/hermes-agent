"""AI router: deterministic escalation, budgets, structured-output validation."""

from __future__ import annotations

import pytest
from conftest import FakeClock
from pydantic import ValidationError

from hermes.intelligence.provider import AIRequest, AIResponse, extract_json
from hermes.intelligence.router import AIRouter
from hermes.state.db import Database

pytestmark = pytest.mark.asyncio


class ScriptedProvider:
    """Returns canned responses per model; records requested models in order."""

    def __init__(self, responses: dict[str, list[str]]) -> None:
        self.responses = responses
        self.requested: list[str] = []

    async def complete(self, request: AIRequest, model: str) -> AIResponse:
        self.requested.append(model)
        queue = self.responses.get(model, [])
        if not queue:
            return AIResponse(model, "", False, "provider down", provider_error=True)
        content = queue.pop(0)
        if content == "__raise__":
            return AIResponse(model, "", False, "http 502", provider_error=True)
        return AIResponse(model, content, True)

    @staticmethod
    def diagnosis_json(confidence: float, **overrides) -> str:
        data = {
            "rootCause": "OOM kill in container",
            "confidence": confidence,
            "knownCause": True,
            "multipleRootCauses": False,
            "insufficientEvidence": False,
            "evidence": ["oom_kill counter incremented"],
            "recommendedRunbook": "container_memory_pressure",
            "proposedActions": [],
            "requiresEscalation": False,
            "requiresHumanApproval": False,
            "explanation": "Container werd door de kernel gedood.",
        }
        data.update(overrides)
        import json

        return json.dumps(data)


@pytest.fixture()
def db(tmp_path):
    database = Database(str(tmp_path / "t.db"))
    database.migrate()
    yield database
    database.close()


AI_CONFIG = {"enabled": True, "api_key": "k", "confidence_stop": 0.85,
             "tier1_model": "gemini", "tier2_model": "deepseek",
             "max_calls_per_incident": 3, "max_calls_per_day": 8}


def make_router(db) -> AIRouter:
    return AIRouter(dict(AI_CONFIG), None, db, FakeClock())


async def test_high_confidence_stops_at_tier1(db):
    provider = ScriptedProvider({"gemini": [ScriptedProvider.diagnosis_json(0.95)]})
    router = AIRouter(dict(AI_CONFIG), provider, db, FakeClock())
    outcome = await router.analyze("inc:1", "context")
    assert outcome.ok and outcome.tier_used == 1
    assert provider.requested == ["gemini"]


async def test_low_confidence_escalates_to_deepseek(db):
    provider = ScriptedProvider({
        "gemini": [ScriptedProvider.diagnosis_json(0.4)],
        "deepseek": [ScriptedProvider.diagnosis_json(0.9)],
    })
    router = AIRouter(dict(AI_CONFIG), provider, db, FakeClock())
    outcome = await router.analyze("inc:1", "context")
    assert outcome.ok and outcome.tier_used == 2
    assert provider.requested == ["gemini", "deepseek"]
    assert outcome.escalation_reason == "low_confidence"


async def test_invalid_output_retries_then_escalates(db):
    provider = ScriptedProvider({
        "gemini": ["no valid json at all", ScriptedProvider.diagnosis_json(0.4)],
        "deepseek": [ScriptedProvider.diagnosis_json(0.92)],
    })
    router = AIRouter(dict(AI_CONFIG), provider, db, FakeClock())
    outcome = await router.analyze("inc:1", "context")
    assert provider.requested == ["gemini", "gemini", "deepseek"]
    assert outcome.ok and outcome.tier_used == 2


async def test_insufficient_evidence_escalates(db):
    provider = ScriptedProvider({
        "gemini": [ScriptedProvider.diagnosis_json(0.95, insufficientEvidence=True)],
        "deepseek": [ScriptedProvider.diagnosis_json(0.9)],
    })
    router = AIRouter(dict(AI_CONFIG), provider, db, FakeClock())
    outcome = await router.analyze("inc:1", "context")
    assert outcome.ok and outcome.tier_used == 2
    assert outcome.escalation_reason == "insufficient_evidence"


async def test_provider_error_budgets_preserved(db):
    provider = ScriptedProvider({"gemini": ["__raise__", "__raise__"]})
    router = AIRouter(dict(AI_CONFIG), provider, db, FakeClock())
    outcome = await router.analyze("inc:1", "context")
    assert not outcome.ok
    # elke poging wordt geauditeerd én telt mee: gemini x2 + deepseek escalatie
    # (budget stop! max_per_incident=3)
    row = db.one("SELECT COUNT(*) AS n FROM ai_calls WHERE incident_id='inc:1'")
    assert int(row["n"]) == 3
    assert outcome.error == "incidentbudget AI bereikt"


async def test_incident_budget_stops_calls(db):
    provider = ScriptedProvider({"gemini": ["__raise__"] * 5})
    config = dict(AI_CONFIG) | {"max_calls_per_incident": 2}
    router = AIRouter(config, provider, db, FakeClock())
    await router.analyze("inc:1", "context")
    await router.analyze("inc:1", "context")
    outcome = await router.analyze("inc:1", "context")
    assert outcome.error == "incidentbudget AI bereikt"
    assert len(provider.requested) == 2


async def test_daily_budget_stops_calls(db):
    provider = ScriptedProvider({"gemini": ["__raise__"] * 10})
    config = dict(AI_CONFIG) | {"max_calls_per_day": 3}
    router = AIRouter(config, provider, db, FakeClock())
    for i in range(3):
        await router.analyze(f"inc:{i}", "context")
    outcome = await router.analyze("inc:99", "context")
    assert outcome.error == "dagbudget AI bereikt"


async def test_ai_disabled_monitoring_unaffected(db):
    config = dict(AI_CONFIG) | {"enabled": False}
    router = AIRouter(config, None, db, FakeClock())
    outcome = await router.analyze("inc:1", "context")
    assert not outcome.ok and outcome.error == "ai disabled"


def test_extract_json_variants():
    assert extract_json('{"a": 1}') == {"a": 1}
    assert extract_json('```json\n{"a": 1}\n```') == {"a": 1}
    assert extract_json('bla {"a": 1} bla') == {"a": 1}
    assert extract_json("total nonsense") is None


def test_proposed_action_rejects_shell_metacharacters():
    from hermes.intelligence.schemas import ProposedAction

    with pytest.raises(ValidationError):
        ProposedAction(capability="docker.restart; rm -rf /", target="plex")
    with pytest.raises(ValidationError):
        ProposedAction(capability="docker.restart", target="plex\nINJECTED")


def test_diagnosis_bounds_confidence():
    from hermes.intelligence.schemas import Diagnosis

    with pytest.raises(ValidationError):
        Diagnosis.model_validate({"rootCause": "x", "confidence": 1.5})


def test_defaults_have_gemini_tier1_and_no_ling():
    from hermes.config import DEFAULTS

    ai = DEFAULTS["ai"]
    assert ai["tier1_model"] == "google/gemini-2.5-flash-lite"
    assert ai["tier2_model"] == "deepseek/deepseek-v4-flash-0731"
    from pathlib import Path

    import hermes.intelligence.router as router_mod

    src = Path(router_mod.__file__).read_text().lower()
    assert "inclusionai" not in src and "ling-3.0" not in src and "ling 3.0" not in src


async def test_gemini_provider_failure_escalates_to_deepseek(db):
    """Fase 8/13: provider error/timeout na retry = escalatie-grond."""
    provider = ScriptedProvider({
        "gemini": ["__raise__", "__raise__"],
        "deepseek": [ScriptedProvider.diagnosis_json(0.9)],
    })
    router = AIRouter(dict(AI_CONFIG), provider, db, FakeClock())
    outcome = await router.analyze("inc:1", "context")
    assert provider.requested == ["gemini", "gemini", "deepseek"]
    assert outcome.ok and outcome.tier_used == 2
    assert outcome.escalation_reason == "provider_error"


async def test_deepseek_failure_falls_back_deterministic(db):
    """Fase 10/13: beide tiers falen -> deterministic fallback, geen crash."""
    config = dict(AI_CONFIG) | {"max_calls_per_incident": 4}
    provider = ScriptedProvider({
        "gemini": ["__raise__", "__raise__"],
        "deepseek": ["__raise__", "__raise__"],
    })
    router = AIRouter(config, provider, db, FakeClock())
    outcome = await router.analyze("inc:1", "context")
    assert not outcome.ok
    assert outcome.error  # foutmelding aanwezig
    assert provider.requested == ["gemini", "gemini", "deepseek", "deepseek"]


async def test_gemini_success_never_calls_deepseek(db):
    """Fase 13: valide high-confidence tier1-output -> 0 deepseek calls."""
    provider = ScriptedProvider({"gemini": [ScriptedProvider.diagnosis_json(0.99)]})
    router = AIRouter(dict(AI_CONFIG), provider, db, FakeClock())
    outcome = await router.analyze("inc:1", "context")
    assert outcome.ok and outcome.tier_used == 1
    assert provider.requested == ["gemini"]
    assert outcome.escalated_from is None


async def test_schema_and_reasoning_passed_for_tier1(db):
    """Fase 5/6: native json_schema response_format + reasoning uit op tier1."""
    captured: list[AIRequest] = []

    class CaptureProvider(ScriptedProvider):
        async def complete(self, request, model):
            captured.append(request)
            return await super().complete(request, model)

    provider = CaptureProvider({"gemini": [ScriptedProvider.diagnosis_json(0.95)]})
    router = AIRouter(dict(AI_CONFIG), provider, db, FakeClock())
    await router.analyze("inc:1", "context")
    assert captured[0].reasoning_disabled is True
    assert captured[0].json_schema is not None
    assert "rootCause" in captured[0].json_schema["properties"]
