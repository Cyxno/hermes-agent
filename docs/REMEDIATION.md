# Guarded self-healing (remediation)

> Core principle: **AI has no execution authority.**
> AI may suggest; only deterministic policy may authorize.

## Flow

```text
Observation
→ Incident Engine
→ Deterministic diagnosis (runbook preconditions + diagnose checks)
→ optional AI recommendation (advisory only)
→ Runbook action
→ Policy Engine (risk, lifecycle, protection, budgets)
→ Capability Registry
→ Fresh pre-execution recheck (live Beacon inventory)
→ Executor (SSH operator, argv, no shell)
→ Verification (fresh state; exit code 0 is never "fixed")
→ Audit (single row per attempt: in_progress → exit=N / dispatch_error)
```

## Capability risk classes

| class | meaning |
|-------|---------|
| `SAFE` | may execute automatically when all preconditions hold (read-only probes) |
| `GUARDED` | may execute automatically under stricter policy + verification (`docker.restart`, `docker.start`, `service.restart`) |
| `APPROVAL_REQUIRED` | explicit scoped human approval required (`docker.stop`, `compose.restart`) |
| `FORBIDDEN` | never executable by Hermes (no transport): filesystem deletion, disk format, array stop, self-modification, compose recreate |

## Gates for a real action (all must hold)

1. `executor.mode = guarded` **and** `executor.real_actions_enabled = true`
   (kill switch; default **false** — flip back to full dry-run without
   rebuilding at any time);
2. target desired-state == MANAGED (automatic actions; OPTIONAL only via
   explicit Telegram approval);
3. target not in `executor.protected_targets`;
4. target passes strict identifier validation;
5. incident confirmed, severity threshold met, runbook known;
6. fresh pre-execution recheck still confirms the fault (live Beacon
   inventory — condition gone → CANCEL);
7. attempt budget below limit (max per incident) and cooldown satisfied
   (per-target, persisted across restarts);
8. no correlated root incident active (child restarts are deferred);
9. idempotency: (incident, capability, target) not already attempted;
10. concurrency slot free (initially one real remediation at a time).

## Verification (§C14/§C15)

After dispatch: bounded recovery schedule (settle seconds from the runbook,
then fresh checks 5s/15s/30s/60s within the max window). Expected outcome
(e.g. `container_running`, `container_healthy`) must be observed on fresh
state; otherwise the remediation is **failed** — retry/approval policy applies.
Verification runs in the background of the scheduler; it never blocks cycles.

## Notifications (§C20/§C21)

- successful routine SAFE remediation → silently audited, surfaced in the
  daily summary (`Self-healed: ...`);
- failed remediation / repeated remediation / dangerous situation → notified;
- approval required → approval request with single-use code;
- alerts may include compact `Zelfherstel:` (self-healing) lines and always
  keep the `AI gebruikt:` (AI used) line.

## Telegram

- `/fix <id>` / `los het op`: safest permitted remediation for the scoped
  incident — SAFE/GUARDED executes when allowed, APPROVAL_REQUIRED returns a
  single-use code, FORBIDDEN refuses clearly;
- `/approve <code>`: consumes the scoped approval (single-use, TTL,
  incident+capability+target bound);
- `/whatdidyoudo`: last 24h of actions + remediation outcomes;
- `/status`: compact executor line (`Executor: guarded ..., real actions today: N`).

## Rollback (guarded → dry-run, immediately)

Any of these, no rebuild required:

1. `docker exec hermes-v2 ...` not needed — flip config:
   `executor.real_actions_enabled: false` → recreate/restart the container;
2. or set `executor.mode: dry-run` entirely;
3. or (planned admin command) `/executor dry-run` from the home chat — audited,
   authorization-gated, never enables FORBIDDEN capabilities.

The audit trail (`action_audit`, one row per attempt incl. risk level,
budgets, policy verdict, fresh-recheck result, exit and verification) is the
permanent record for every proposed/attempted action.
