# Changelog

## 2.1.3 (2026-10-07)

- Auto-remediation now also picks up ACTIVE incidents (post-notification);
  the CONFIRMED-only window missed the normal alert flow.

## 2.1.2 (2026-10-07)

- Automatic guarded self-healing trigger: confirmed incidents (warning+) with
  a known action runbook now enter the executor automatically (once per
  incident per hour, one candidate per cycle). With dry-run or the kill
  switch off this records would_execute decisions (Stage 0 review); with
  guarded + real_actions_enabled the executor guards decide.
- Completes the 2.1.0 guarded feature (the trigger was missing).

## 2.1.1 (2026-10-07)

- Image: add openssh-client — the guarded executor dispatches through the
  hardened SSH operator (fixed argv verbs); required for real remediation.
  No code changes.

## 2.1.0 (2026-10-07)

- Guarded self-healing: `container_restart`/`container_start` may execute for
  real under strict policy — kill switch (`executor.real_actions_enabled`,
  default false), protected targets, MANAGED-only automatic actions, strict
  target validation, per-target cooldown + hourly/daily budgets (persisted),
  episode idempotency, single-action concurrency, correlated-root suppression,
  fresh pre-execution recheck, post-action verification on fresh state.
- `/whatdidyoudo` reports remediation outcomes; `/status` shows executor mode
  + real actions today; `/incidents` marks remediation state; alerts may carry
  a compact self-healing line (Dutch runtime strings kept intentionally).
- Repository fully English (current tree; runtime Telegram strings remain
  Dutch by design; historical docs keep their original language).
- Release automation: rc tags never move `latest`; workflow_dispatch test
  route; reliable build timestamp; immutable-tag rule documented.

## 2.0.1 (2026-10-07)

- `/status` host line: Netdata fallback for host CPU/RAM percentages (Beacon
  summary does not provide them on this host); carry-forward for slow fields
  with freshness (`array=?` bug).
- `AI used: yes/no` metadata on every incident notification, incident-scoped,
  derived from the existing `ai_calls` audit (zero extra AI calls).
- VERSION now derived from package metadata (single source of truth).

## 2.0.0 (2026-10-07)

- First stable monitoring release: Beacon-primary observability, incident
  state machine, correlation, deterministic runbooks, AI diagnosis
  (Gemini → DeepSeek), Telegram interface, executor in dry-run.
