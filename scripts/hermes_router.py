#!/usr/bin/env python3
"""hermes_router.py — expliciete, auditbare LLM-router (fase 5).

Regels:
- één model per request; GEEN models-array; GEEN cross-model fallback door
  OpenRouter (allow_fallbacks=false). requested_model == actual_model wordt
  gecontroleerd; mismatch = routing_violation en telt als mislukte analyse.
- Ling (tier 1): géén response_format (bewezen endpoint-killer); compacte JSON
  via prompt; lokaal parsen met maximaal één extractie-repair.
- DeepSeek/Luna: response_format json_object (hun endpoints ondersteunen dat).
- Escalatie is deterministic code: providerfout DeepSeek → GLM (tier 3);
  content-escalatie (onzekerheid) → DeepSeek (tier 2); Luna (tier 4) alleen bij
  URGENT/CRITICAL + multi-system + DeepSeek-conf < 0.5.
- Limits: max calls per incident-lifecycle en per kalenderdag (caller telt).
- Audit: iedere call (en elke geweigerde call) naar homelab/router_calls.jsonl.
- Sanitizer redigeert secretpatronen vóór de call.

Geen monitoringlogica in deze module: thresholds/trends/severity blijven in de
evaluator (tier 0). Geen Telegram, geen remediation.
"""
import datetime as dt
import json, os, re, time
from pathlib import Path

HOME = Path(os.environ.get("HERMES_HOME", "/opt/data"))
ROUTER_CALLS = HOME / "homelab" / "router_calls.jsonl"

MODELS = {
    "tier1": "inclusionai/ling-3.0-flash",
    "tier2": "deepseek/deepseek-v4-flash-0731",
    "tier3": "z-ai/glm-5.3-flash",
    "tier4": "openai/gpt-5.6-luna",
}
# USD per miljoen tokens (input, output) — alleen voor kostenschatting in audit
PRICES = {
    MODELS["tier1"]: (0.021, 0.063),
    MODELS["tier2"]: (0.065, 0.18),
    MODELS["tier3"]: (0.075, 0.25),
    MODELS["tier4"]: (0.20, 1.20),
}
# read-only diagnostics die recommended_checks mogen noemen (§8)
ALLOWED_CHECKS = {
    "memory-status", "docker-status", "docker-restarts", "docker-vdisk-status",
    "docker-space-detail", "logfs-status", "pool-status", "disk-health",
    "temperature-status", "array-status", "oom-events", "kernel-errors",
    "fs-errors", "host-summary", "memory", "processes", "network", "syslog",
    "block-devices", "mounts", "smart-health", "nvme-health", "service-status",
    "audit-tail",
}

SECRET_PATTERNS = [
    (re.compile(r"sk-[A-Za-z0-9_-]{12,}"), "[REDACTED-KEY]"),
    (re.compile(r"(?i)openrouter_api_key\s*[=:]\s*\S+"), "OPENROUTER_API_KEY=[REDACTED]"),
    (re.compile(r"bot\d{5,}:[A-Za-z0-9_-]{25,}"), "[REDACTED-TOKEN]"),
    (re.compile(r"(?i)(authorization|cookie|set-cookie)\s*[=:]\s*\S+"), "[REDACTED-AUTH]"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "[REDACTED-PRIVATE-KEY]"),
    (re.compile(r"(?i)(password|passwd|secret|token|api[_-]?key)\s*[=:]\s*['\"]?[A-Za-z0-9+/_-]{12,}"), "[REDACTED-SECRET]"),
    (re.compile(r"\b[0-9a-f]{32,64}\b"), "[REDACTED-HASH]"),
]


def load_env_key(env_path=None):
    """OPENROUTER_API_KEY uit $HERMES_HOME/.env (wordt nooit gelogd)."""
    p = Path(env_path or (HOME / ".env"))
    if not p.exists():
        return None
    for line in p.read_text(errors="replace").splitlines():
        if line.startswith("OPENROUTER_API_KEY="):
            v = line.split("=", 1)[1].strip()
            return v or None
    return None


def sanitize(obj):
    """Deterministic sanitizer over geserialiseerde context (§30)."""
    raw = json.dumps(obj, ensure_ascii=False, default=str)
    count = 0
    for pat, repl in SECRET_PATTERNS:
        raw, n = pat.subn(repl, raw)
        count += n
    return raw, count


def extract_json(text):
    """1) directe loads; 2) eerste valide JSON-object eruit knippen. Eén
    repair-poging, daarna None (§9)."""
    if not text:
        return None
    try:
        return json.loads(text)
    except (json.JSONDecodeError, ValueError):
        pass
    m = re.search(r"\{.*\}", text, re.S)
    if m:
        try:
            return json.loads(m.group(0))
        except (json.JSONDecodeError, ValueError):
            return None
    return None


def filter_checks(checks):
    """recommended_checks: uitsluitend bekende read-only diagnostics (§8/§30)."""
    out, dropped = [], []
    for c in checks or []:
        if isinstance(c, str) and c.strip().lower() in ALLOWED_CHECKS:
            out.append(c.strip().lower())
        else:
            dropped.append(str(c)[:80])
    return out, dropped


def http_post_openrouter(body, api_key, timeout=75):
    """Transport (testbaar: tests monkeypatchen deze functie)."""
    req = urllib_post(body, api_key, timeout)
    return req


def urllib_post(body, api_key, timeout):
    import urllib.error, urllib.request
    req = urllib.request.Request(
        "https://openrouter.ai/api/v1/chat/completions",
        data=json.dumps(body).encode(),
        headers={"Authorization": "Bearer " + api_key, "Content-Type": "application/json",
                 "HTTP-Referer": "http://192.168.1.2", "X-Title": "Hermes Homelab"})
    t0 = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.load(r), None, time.monotonic() - t0
    except urllib.error.HTTPError as e:
        try:
            detail = json.loads(e.read().decode()).get("error", {}).get("message", "")[:120]
        except Exception:
            detail = ""
        return e.code, None, detail or f"http {e.code}", time.monotonic() - t0
    except Exception as e:
        return 0, None, str(e)[:120], time.monotonic() - t0


def audit(row):
    ROUTER_CALLS.parent.mkdir(parents=True, exist_ok=True)
    with ROUTER_CALLS.open("a") as f:
        f.write(json.dumps(row, ensure_ascii=False) + "\n")


def _audit_base(fp, source, severity, task):
    return {"ts": datetime_iso(), "fingerprint": fp, "source": source,
            "incident_severity": severity, "task": task}


def datetime_iso():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


TIER_PROMPTS = {
    "tier1": ("Je bent een compacte homelab-incident-classifier. Antwoord UITSLUITEND"
              " met minified JSON (geen markdown, geen extra tekst). Velden: summary"
              " (max 200 tekens, Nederlands), classification (known_cause|unclear|"
              "multi_system), likely_cause (max 200 tekens), confidence (0.0-1.0),"
              " needs_more_analysis (bool), recommended_checks (array; uitsluitend"
              " namen uit de toegestane lijst in de context)."),
    "tier2": ("Je bent een homelab-diagnostiek-expert. Antwoord UITSLUITEND met"
              " minified JSON. Velden: diagnosis (max 400 tekens, Nederlands),"
              " likely_root_cause (max 200 tekens), confidence (0.0-1.0),"
              " discriminating_checks (array van max 3 korte controles),"
              " recommended_checks (array; uitsluitend namen uit de toegestane"
              " lijst in de context)."),
    "tier3": "Zie tier2-stijl: minified JSON met diagnosis, likely_root_cause, confidence, recommended_checks.",
    "tier4": ("Je lost een uitzonderlijk complex multi-systeem homelab-incident op."
              " Antwoord UITSLUITEND met minified JSON: diagnosis (max 500 tekens),"
              " likely_root_cause, confidence, discriminating_checks (max 3),"
              " recommended_checks (uitsluitend toegestane namen)."),
}


def call_model(tier, *, fp, source, severity, task, context, llm_cfg, api_key,
               audit_extra=None):
    """Één expliciete modelcall. Geeft resultaat-dict; schrijft auditregel."""
    th = llm_cfg
    model = MODELS[tier]
    max_tokens = int(th.get("output_max_tokens", {}).get(tier, 600))
    cap_chars = int(th.get("ling_input_chars_cap", 4800) if tier == "tier1"
                    else th.get("deepseek_input_chars_cap", 24000))
    clean_ctx, redactions = sanitize(context)
    if len(clean_ctx) > cap_chars:
        clean_ctx = clean_ctx[:cap_chars] + ' …[afgekapt]'
    user = ("Toegestane recommended_checks: " + ",".join(sorted(ALLOWED_CHECKS)) +
            ".\nCompacte incident-context (JSON):\n" + clean_ctx)
    body = {"model": model,
            "messages": [{"role": "system", "content": TIER_PROMPTS[tier]},
                         {"role": "user", "content": user}],
            "temperature": 0, "max_tokens": max_tokens,
            "provider": {"allow_fallbacks": False}}
    if tier == "tier1":
        body["reasoning"] = {"enabled": False}   # §10: Ling goedkoop houden
        body["provider"]["order"] = ["deepinfra", "novita"]  # beide Ling-endpoints
    elif tier == "tier3":
        body["reasoning"] = {"effort": "low"}    # GLM verbrandt anders reasoning-budget
    elif tier == "tier2":
        body["reasoning"] = {"enabled": False}   # DeepSeek v4 reasoning telt in output-budget
        body["response_format"] = {"type": "json_object"}
    elif tier == "tier4":
        body["response_format"] = {"type": "json_object"}

    base = _audit_base(fp, source, severity, task)
    t0 = time.monotonic()
    status, resp, err, elapsed = http_post_openrouter(body, api_key, timeout=75)
    latency_ms = int(elapsed * 1000)
    row = dict(base, requested_model=model, actual_model=None, provider=None,
               reason_selected=f"expliciete {tier}-call",
               escalation_reason=(audit_extra or {}).get("escalation_reason", ""),
               input_tokens=0, cached_tokens=0, reasoning_tokens=0, output_tokens=0,
               latency_ms=latency_ms, cost=0.0, confidence=None, success=False,
               response_valid=False, routing_violation=False, error=err)
    if redactions:
        row["context_redactions"] = redactions
    if status != 200 or not isinstance(resp, dict):
        row["error"] = err or f"http {status}"
        audit(row)
        return {"ok": False, "provider_error": True, "error": row["error"],
                "http_status": status, "audit": row}
    choice = (resp.get("choices") or [{}])[0].get("message", {})
    content = choice.get("content")
    usage = resp.get("usage", {})
    actual = resp.get("model")
    cdetails = usage.get("completion_tokens_details", {}) or {}
    row.update(actual_model=actual, provider=resp.get("provider"),
               input_tokens=int(usage.get("prompt_tokens", 0)),
               cached_tokens=int((usage.get("prompt_tokens_details") or {}).get("cached_tokens", 0)),
               reasoning_tokens=int(cdetails.get("reasoning_tokens", 0)),
               output_tokens=int(usage.get("completion_tokens", 0)),
               success=True)
    price = PRICES.get(actual, PRICES[model])
    row["cost"] = round((row["input_tokens"] * price[0] + row["output_tokens"] * price[1]) / 1e6, 8)
    row["routing_violation"] = (actual or "").split(":")[0] != model
    parsed = extract_json(content)
    if parsed is None:
        row["error"] = "invalid_json"
        audit(row)
        return {"ok": False, "provider_error": False, "error": "invalid_json",
                "routing_violation": row["routing_violation"], "audit": row}
    conf = parsed.get("confidence")
    conf = float(conf) if isinstance(conf, (int, float)) else None
    checks, dropped = filter_checks(parsed.get("recommended_checks"))
    parsed["recommended_checks"] = checks
    if dropped:
        row["error"] = "filtered_checks:" + ";".join(dropped)[:100]
    row["response_valid"] = True
    row["confidence"] = conf
    audit(row)
    return {"ok": True, "parsed": parsed, "confidence": conf, "actual": actual,
            "provider": resp.get("provider"), "usage": row, "content": content,
            "routing_violation": row["routing_violation"], "audit": row}


def analyze(fp, *, source, severity, task, context, llm_cfg, api_key,
            per_incident_calls, daily_calls, multi_system=None):
    """Deterministische ladder (§11-§15). Geeft (final, calls_meta)."""
    audit_budget = lambda reason: audit({**_audit_base(fp, source, severity, task),
                                         "requested_model": None, "success": False,
                                         "error": reason, "routing_violation": False,
                                         "response_valid": False})
    max_inc = int(llm_cfg.get("max_calls_per_incident", 3))
    max_day = int(llm_cfg.get("max_calls_per_day", 8))
    conf_stop = float(llm_cfg.get("confidence_stop", 0.85))
    calls = []
    if daily_calls >= max_day:
        audit_budget("llm_budget_exhausted:daily")
        return {"status": "skipped", "reason": "llm_budget_exhausted:daily"}, calls
    if per_incident_calls >= max_inc:
        audit_budget("llm_budget_exhausted:incident")
        return {"status": "skipped", "reason": "llm_budget_exhausted:incident"}, calls

    ms = multi_system
    if ms is None:
        ms = (len(context.get("affected_services") or []) > 1
              or len(context.get("host_correlations") or []) > 0)

    # Tier 1 — Ling (expliciet, geen response_format, reasoning uit)
    r1 = call_model("tier1", fp=fp, source=source, severity=severity, task=task,
                    context=context, llm_cfg=llm_cfg, api_key=api_key)
    calls.append(r1["audit"])
    if daily_calls + len(calls) >= max_day:
        audit_budget("llm_budget_exhausted:daily")
        return {"status": "budget_stop", "final": r1.get("parsed"), "calls": calls}, calls
    if not r1["ok"]:
        reason = "ling_provider_error" if r1.get("provider_error") else "ling_invalid_response"
    elif r1["routing_violation"]:
        # requested != actual: response niet vertrouwen (§15)
        reason = "routing_violation_ling"
    else:
        p = r1["parsed"] or {}
        conf = r1["confidence"]
        if conf is not None and conf >= conf_stop and not p.get("needs_more_analysis") \
                and (p.get("classification") in ("known_cause", None)) and not ms:
            return {"status": "done", "tier": "tier1", "analysis": p,
                    "confidence": conf, "calls": calls}, calls
        reason = (f"ling_confidence_{conf}" if conf is not None else "ling_geen_confidence")
        if ms:
            reason += ";multi_system"
        if p.get("needs_more_analysis"):
            reason += ";needs_more_analysis"

    # Tier 2 — DeepSeek (alleen bij expliciete escalatie)
    if daily_calls + len(calls) >= max_day:
        audit_budget("llm_budget_exhausted:daily")
        return {"status": "budget_stop", "calls": calls}, calls
    r2 = call_model("tier2", fp=fp, source=source, severity=severity, task="diagnose",
                    context=context, llm_cfg=llm_cfg, api_key=api_key,
                    audit_extra={"escalation_reason": reason})
    calls.append(r2["audit"])
    if not r2["ok"] or r2["routing_violation"]:
        if r2.get("provider_error") or r2.get("routing_violation"):
            # Tier 3 — GLM: uitsluitend provider-fallback/routing-violatie van
            # DeepSeek (§13) — niet bij lage content-confidence
            reason3 = ("deepseek_provider_error" if r2.get("provider_error")
                       else "routing_violation_deepseek")
            r3 = call_model("tier3", fp=fp, source=source, severity=severity, task="diagnose",
                            context=context, llm_cfg=llm_cfg, api_key=api_key,
                            audit_extra={"escalation_reason": reason3})
            calls.append(r3["audit"])
            if r3["ok"]:
                p = r3["parsed"] or {}
                conf = r3["confidence"]
                if _luna_allowed(severity, ms, conf):
                    return _luna_step(fp, source, severity, context, llm_cfg, api_key,
                                      calls, daily_calls, p, conf)
                return {"status": "done", "tier": "tier3", "analysis": p,
                        "confidence": conf, "calls": calls}, calls
            return {"status": "failed", "tier": "tier3", "calls": calls}, calls
        p = r2.get("parsed") or {}
        conf = r2["confidence"]
        if _luna_allowed(severity, ms, conf):
            return _luna_step(fp, source, severity, context, llm_cfg, api_key,
                              calls, daily_calls, p, conf)
        return {"status": "done", "tier": "tier2", "analysis": p, "confidence": conf,
                "calls": calls}, calls
    p = r2["parsed"] or {}
    conf = r2["confidence"]
    if _luna_allowed(severity, ms, conf):
        return _luna_step(fp, source, severity, context, llm_cfg, api_key,
                          calls, daily_calls, p, conf)
    return {"status": "done", "tier": "tier2", "analysis": p, "confidence": conf,
            "calls": calls}, calls


def _luna_allowed(severity, multi_system, conf):
    """§14: alle voorwaarden moeten gelden; geen Luna 'omdat het interessant is'."""
    return (severity in ("urgent", "critical") and multi_system
            and conf is not None and conf < 0.5)


def _luna_step(fp, source, severity, context, llm_cfg, api_key, calls, daily_calls,
               prev_parsed, prev_conf):
    if daily_calls + len(calls) >= int(llm_cfg.get("max_calls_per_day", 8)):
        return {"status": "budget_stop", "tier": "tier2", "analysis": prev_parsed,
                "confidence": prev_conf, "calls": calls}, calls
    r4 = call_model("tier4", fp=fp, source=source, severity=severity, task="complex_diagnose",
                    context=context, llm_cfg=llm_cfg, api_key=api_key,
                    audit_extra={"escalation_reason":
                                 f"deepseek_conf_{prev_conf}_multi_system_{severity}"})
    calls.append(r4["audit"])
    if r4["ok"]:
        return {"status": "done", "tier": "tier4", "analysis": r4["parsed"] or {},
                "confidence": r4["confidence"], "calls": calls}, calls
    return {"status": "done", "tier": "tier2", "analysis": prev_parsed,
            "confidence": prev_conf, "calls": calls}, calls


def smoke(tier, count=1):
    """Live micro-smoketest (§21-§23): miniprompt, per call alle auditvelden."""
    key = load_env_key()
    if not key:
        print("geen OPENROUTER_API_KEY in .env"); return 1
    ok = 0
    for i in range(count):
        r = call_model(tier, fp=f"smoke:{tier}:{i+1}", source="smoketest", severity="normal",
                       task="smoketest",
                       context={"prompt": 'Reply with exactly {"ok":true} and nothing else.',
                                "i": i + 1},
                       llm_cfg={"output_max_tokens": {"tier1": 300, "tier2": 600, "tier4": 700}},
                       api_key=key)
        a = r["audit"]
        print(json.dumps({k: a.get(k) for k in ("requested_model", "actual_model", "provider",
                                                "input_tokens", "reasoning_tokens", "output_tokens",
                                                "latency_ms", "cost", "routing_violation",
                                                "response_valid", "error")}))
        if a.get("actual_model") == MODELS[tier] and a.get("routing_violation") is False:
            ok += 1
    print(f"{ok}/{count} {MODELS[tier]}")
    return 0 if ok == count else 1


if __name__ == "__main__":
    import sys
    if len(sys.argv) >= 3 and sys.argv[1] == "smoke" and sys.argv[2] in MODELS:
        sys.exit(smoke(sys.argv[2], int(sys.argv[3]) if len(sys.argv) > 3 else 1))
    print("gebruik: hermes_router.py smoke <tier1|tier2|tier3|tier4> [aantal]"); sys.exit(64)
