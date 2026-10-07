# Hermes v2 — security model

Threat-model summary (spec §56, updated for 2.1). This document describes what
AI and outsiders explicitly **cannot** do, and where the boundaries live in code.

## 1. AI has no shell authority (§23/§65.7)

- The AI (Gemini/DeepSeek) at most produces a validated `Diagnosis` object with
  `proposedActions` — **pydantic-validated** (`intelligence/schemas.py`):
  capability and target must not contain shell metacharacters.
- Actions always go through: PolicyEngine → CapabilityRegistry → Executor
  (`executor/executor.py`). The executor is the only component that builds
  SSH-operator invocations, and builds argv **without a shell**: every
  parameter is a discrete argv element (`SshOperator.docker_argv`), re-validated
  server-side by the dispatcher.
- AI output is never executed without a policy verdict; FORBIDDEN capabilities
  have **no transport** (`dispatch_action=None`) and can never execute, even
  with approval.
- AI `proposedActions` are advisory: they are surfaced in `/investigate` output
  and audits, but only deterministic runbooks can produce an `ActionPlan`.

## 2. Log data is untrusted input

- `ContextBuilder._log_section` wraps log lines in explicit
  `<<<BEGIN_LOGDATA / END_LOGDATA>>>` markers with a system-prompt instruction
  that the content is data, never instructions (tested:
  `test_context_builder_fences_log_content`).
- Everything that reaches logs/Telegram passes through `util.sanitize`
  (token/key patterns masked, length bounded).

## 3. Executor and transport

- **Default `dry-run`**: nothing executes; audit rows document what would
  happen (§49, `mode=dry_run` in `action_audit`).
- Transport is the existing hardened **SSH operator dispatcher**: plantokens
  (10 min TTL, single use), CONFIRM-DANGEROUS for dangerous classes, host-side
  audit, allowlisted write roots. No `/var/run/docker.sock` in the container
  (docker.sock = root-equivalent; §38).
- 2.1 guardrails (all tested in `tests/test_guarded_executor.py`):
  - `executor.real_actions_enabled` master kill switch (default **false**);
    with `mode=guarded` and the switch off, execution behaves as dry-run;
  - `protected_targets` deny list (e.g. Beacon, Netdata, Hermes itself,
    databases, reverse proxies);
  - automatic actions require desired-state **MANAGED** (DISCOVERED/RETIRED/
    IGNORED denied; OPTIONAL reachable only via explicit Telegram approval);
  - target strings must pass strict identifier validation (no shell
    metacharacters/paths — rejected before dispatch);
  - per-target cooldown + hourly/daily attempt budgets, persisted in
    `action_audit` so they survive restarts;
  - idempotency: one real attempt per (incident, capability, target) episode;
  - one real remediation at a time (bounded concurrency);
  - correlated root incident active → child remediation deferred;
  - fresh pre-execution recheck on live Beacon inventory: condition gone →
    CANCEL, never execute;
  - scoped approvals are single-use, expire, and are scoped to
    (incident, action-class, target).

## 4. Telegram (§57)

- Only `home_chat_id` (private, trusted interaction chat),
  `allowed_user_ids`, `allowed_chat_ids` / `allowed_usernames` get through
  (`CommandHandler._authorize`, tested: unauthorized users rejected; group
  home chats require an explicitly authorized user).
- `update_id` dedup: replayed commands are ignored (tested).
- "los het op" creates a **scoped** approval: (incident, action-class,
  target), TTL 10 min, single use; wrong target/class/expired/reused is
  rejected (tested).
- Mutation commands (/fix, /approve) log initiator `telegram/<user>` in the
  audit.
- **Telegram authorization ≠ execution authorization**: talking does not
  permit mutating; the executor mode and kill switch decide that.

## 5. Network & SSRF

- Observer clients follow no redirects (`allow_redirects=False`); all calls
  are GET with timeouts, bounded-backoff retries + circuit breakers.
- Config URLs come from the own config volume; no user input in URLs.
- The health/diagnostics endpoint binds to 127.0.0.1 inside the container and
  exposes no secrets (counters/version only).

## 6. Secrets

- Secrets live exclusively in env (`env:NAME` references in config) or
  `/data/secrets.env` (0600). They are never logged (`sanitize` as last
  resort), never placed into audit/message fields; CI fails on token patterns
  in the tree (grep gate in `ci.yml`).
- The migration tool writes v1 secrets to `secrets.env` with chmod 600 and
  keeps them out of `config.yaml` (tested).

## 7. Fail-safe

- Every external call is failure-isolated; one source can never kill a cycle.
- AI off/both providers down → monitoring + runbooks continue (tested).
- Beacon down → fallback probe distinguishes Beacon outage from host outage
  (tested). Telegram down → pending queue with backoff, no event loss (tested).

## Residual risks (documented deliberately)

- The SSH operator identity can restart allowlisted containers by design; the
  dispatcher-side allowlist is the blast-radius boundary.
- A wrong-but-policy-legal restart (e.g. of a container that would have
  recovered by itself) is a bounded, audited, self-limiting action: cooldowns
  and budgets prevent loops, and verification prevents false success.
