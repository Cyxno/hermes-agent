"""AI provider abstraction (spec §16).

One narrow interface; provider specifics (OpenRouter today) live here and
nowhere else. Single-model requests — no provider-side fallback arrays, the
router owns escalation (v1's hard-won lesson).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Protocol

from ..log import info, warning
from ..util import sanitize


@dataclass
class AIRequest:
    system: str
    user: str
    json_mode: bool = True
    json_schema: dict | None = None  # native structured-output contract (als model het ondersteunt)
    reasoning_disabled: bool = False  # tier1: goedkoop/voorspelbaar, geen chain-of-thought
    max_tokens: int = 900
    temperature: float = 0.1


@dataclass
class AIResponse:
    model: str
    content: str
    ok: bool
    error: str | None = None
    tokens_in: int = 0
    tokens_out: int = 0
    provider_error: bool = False  # transport/provider failure vs bad content
    timeout: bool = False  # expliciete timeout-klasse (Fase 7 result-classificatie)


class AIProvider(Protocol):
    async def complete(self, request: AIRequest, model: str) -> AIResponse: ...


class OpenRouterProvider:
    """OpenRouter chat-completions client (same provider family as legacy Hermes)."""

    def __init__(
        self,
        api_key: str,
        base_url: str = "https://openrouter.ai/api/v1",
        timeout: float = 45.0,
        session=None,  # aiohttp session or None (lazy)
    ) -> None:
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._session = session

    async def _get_session(self):
        if self._session is None:
            import aiohttp

            self._session = aiohttp.ClientSession()
        return self._session

    async def complete(self, request: AIRequest, model: str) -> AIResponse:
        import aiohttp

        session = await self._get_session()
        payload: dict[str, Any] = {
            "model": model,
            "messages": [
                {"role": "system", "content": request.system},
                {"role": "user", "content": request.user},
            ],
            "max_tokens": request.max_tokens,
            "temperature": request.temperature,
            "allow_fallbacks": False,  # router owns escalation; never silent model swaps
        }
        if request.json_mode:
            if request.json_schema:
                payload["response_format"] = {
                    "type": "json_schema",
                    "json_schema": {"name": "diagnosis", "strict": False, "schema": request.json_schema},
                }
            else:
                payload["response_format"] = {"type": "json_object"}
        if request.reasoning_disabled:
            payload["reasoning"] = {"enabled": False}
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        try:
            async with session.post(
                f"{self.base_url}/chat/completions",
                json=payload,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=self.timeout),
            ) as resp:
                body = await resp.json(content_type=None)
                if resp.status != 200:
                    detail = ""
                    if isinstance(body, dict):
                        detail = str(body.get("error", ""))[:200]
                    # schema niet ondersteund op dit endpoint: één gestripte
                    # retry met plain json_object; pydantic blijft het harde contract
                    if resp.status == 400 and request.json_schema and (
                        "schema" in detail.lower() or "response_format" in detail.lower()
                    ):
                        stripped = dict(payload)
                        stripped["response_format"] = {"type": "json_object"}
                        async with session.post(
                            f"{self.base_url}/chat/completions", json=stripped, headers=headers,
                            timeout=aiohttp.ClientTimeout(total=self.timeout),
                        ) as resp2:
                            body = await resp2.json(content_type=None)
                            if resp2.status != 200:
                                return AIResponse(model, "", False, f"http {resp2.status}: {detail}",
                                                  provider_error=True)
                        resp = resp2
                    else:
                        return AIResponse(model, "", False, f"http {resp.status}: {detail}",
                                          provider_error=True)
        except TimeoutError:
            return AIResponse(model, "", False, "timeout", provider_error=True, timeout=True)
        except (aiohttp.ClientError, OSError) as exc:
            return AIResponse(model, "", False, sanitize(exc, 160), provider_error=True)
        usage = body.get("usage") or {}
        try:
            content = body["choices"][0]["message"]["content"] or ""
        except (KeyError, IndexError, TypeError):
            return AIResponse(model, "", False, "antwoord mist choices/message",
                              tokens_in=int(usage.get("prompt_tokens", 0)),
                              tokens_out=int(usage.get("completion_tokens", 0)))
        return AIResponse(
            model, content, True, None,
            tokens_in=int(usage.get("prompt_tokens", 0)),
            tokens_out=int(usage.get("completion_tokens", 0)),
        )


class NullProvider:
    """Used when AI is disabled or no key is configured: monitoring works, AI doesn't."""

    async def complete(self, request: AIRequest, model: str) -> AIResponse:
        return AIResponse(model, "", False, "ai disabled", provider_error=True)


def extract_json(content: str) -> dict | None:
    """Tolerant JSON extraction: whole-string parse, then fenced, then brace scan."""
    text = content.strip()
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        pass
    if "```" in text:
        for block in text.split("```"):
            block = block.strip()
            if block.startswith("json"):
                block = block[4:].strip()
            try:
                return json.loads(block)
            except (ValueError, TypeError):
                continue
    start = text.find("{")
    end = text.rfind("}")
    if start >= 0 and end > start:
        try:
            return json.loads(text[start : end + 1])
        except (ValueError, TypeError):
            return None
    return None


def audit_ai_call(db, clock, incident_id: str | None, tier: int, model: str, purpose: str,  # noqa: ANN001
                  request: AIRequest, response: AIResponse, result: str, confidence: float | None) -> None:
    try:
        db.execute(
            "INSERT INTO ai_calls(ts, incident_id, tier, model, purpose, prompt_chars, response_chars, "
            "confidence, result, meta) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (
                clock.now(), incident_id, tier, model, purpose,
                len(request.user), len(response.content), confidence, result,
                json.dumps({"tokens_in": response.tokens_in, "tokens_out": response.tokens_out,
                            "error": response.error}),
            ),
        )
    except Exception as exc:  # noqa: BLE001 - audit must never break the pipeline
        warning("ai", "audit write failed", error=sanitize(exc, 120))
    info("ai", "call", tier=tier, model=model, purpose=purpose, result=result,
         incident_id=incident_id, confidence=confidence)
