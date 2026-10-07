# Hermes v2 — Architecture

Status: 2.1 implementation architecture. Historical design background:
`docs/audit/2026-10-05-phase-a.md` (v1 audit) and the git history of this
document (original phase-B design notes are in earlier revisions).

> Deterministic first. AI second. Signals are cheap. Incidents are expensive.
> Notifications are exceptional.

## 1. What Hermes v2 is

One Python daemon (container) that:

1. **observes** via Beacon (primary), Netdata (depth/anomaly), and a minimal
   fallback probe (only when Beacon is unreachable);
2. normalizes observations into **evidence** with source + freshness
   (slow fields are carry-forwarded across partial cycles and go stale
   after `SLOW_STALE_AFTER`);
3. shapes evidence into **signals** (deterministic rules, per-category
   debounce and hysteresis);
4. turns signals into **incidents** via an explicit state machine
   (`OBSERVED→PENDING→CONFIRMED→ACTIVE→RECOVERING→RESOLVED`);
5. **correlates** incidents into root causes and detects recurring transients
   (pattern incidents open/close by window, preserving notification
   bookkeeping across re-opens);
6. **diagnoses** known problems deterministically via runbooks;
7. **remediates** where safe through the guarded executor (capability
   registry, policy engine, fresh pre-execution recheck, always verify);
8. consults **AI** (Gemini 2.5 Flash-Lite → DeepSeek V4 Flash via OpenRouter)
   only when deterministic logic is insufficient, with structured output;
9. sends only relevant, verified **notifications** (final recheck before every
   send; recovery only after a previous alert) and answers Telegram commands.

No LLM loop, no second dashboard, no duplication of Beacon.

## 2. Components and data flow

```text
Beacon (REST+SES) ─┐
Netdata ───────────┼─→ observers ─→ NormalizedState (carry-forward slow fields)
fallback probe ────┘                      │
                        rules → signals → IncidentEngine (SQLite state machine)
                                          │ correlation · transients · patterns
                        runbooks (deterministic) ← diagnostics (fresh Beacon shim)
                                          │
                        policy → capability registry → guarded executor → audit
                                          │ (AI advisory only, never executing)
                        notifier (debounce→confirm→final recheck→send) → Telegram
```

Key modules:

- `observer/` — Beacon client + SSE, Netdata charts, Prometheus/SSH fallback
- `evaluator/` — rules, incidents, hysteresis, correlation, transients,
  baselines, pipeline
- `runbooks/` — YAML definitions, engine, verification checks
- `executor/` — capability registry (risk classes), policy engine + scoped
  approvals, SSH-operator executor (see docs/REMEDIATION.md)
- `intelligence/` — AI router (tier1 Gemini → tier2 DeepSeek escalation),
  OpenRouter provider with native JSON-schema structured output, pydantic
  schemas, budgets, call audit
- `interfaces/` — notifier (cooldowns, dedup, retry queue), Telegram bot +
  command handler, command authorization
- `state/` — SQLite (WAL) persistence: incidents, events, signals,
  notifications, ai_calls, action_audit, approvals, remediations, desired_state

## 3. State semantics

- Every cycle replaces `NormalizedState`; slow fields (storage/array, netdata
  enrichment) are **carry-forwarded** from the previous state when not polled
  this cycle — "not collected" ≠ "known absent" — with per-field freshness
  (`slow_ts`) and a stale fallback (`SLOW_STALE_AFTER`).
- Incident lifecycle completion is decoupled from delivery: in shadow mode
  notifications are recorded, not sent, so promotion to production causes no
  storm.
- Budgets/idempotency for real actions are derived from the persistent
  `action_audit` and therefore survive restarts.

## 4. AI layer

- Deterministic engine first; AI only on escalation criteria (low confidence,
  invalid output, insufficient evidence, multi-subsystem, policy denial, ...).
- Tier 1: `google/gemini-2.5-flash-lite` (reasoning off, temperature 0.1,
  native JSON-schema response format). Tier 2:
  `deepseek/deepseek-v4-flash-0731`. Output is pydantic-validated
  (`Diagnosis`); budgets are hard caps audited per call.
- AI output is advisory: `proposedActions` never execute directly.

## 5. Executor

See docs/REMEDIATION.md for the full gate list. Summary: capability risk
classes (SAFE/GUARDED/APPROVAL_REQUIRED/FORBIDDEN), protected targets, strict
target validation, MANAGED-only automatic actions, cooldowns + hourly/daily
budgets, episode idempotency, single-action concurrency, fresh pre-execution
recheck, post-action verification on fresh state, kill switch
(`real_actions_enabled`, default false), full audit per attempt.

## 6. Interfaces

- Telegram: alerts (exceptional), commands, scoped approvals; interaction
  authorization via trusted home chat / allowlists; mutation authorization is
  a separate, stricter question (executor mode + kill switch).
- HTTP: `/health`, `/diagnostics` on 127.0.0.1 (container-local).

## 7. Persistence

Single SQLite database (WAL) in `/data`; schema migrations with automatic
`.pre-migrate` backup; retention/cleanup on the daily cycle. All state
(incidents, notifications, audits, approvals, desired state) survives
container recreation.
