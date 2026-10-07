# Runbooks

Runbooks are **data** (YAML in `hermes/runbooks/definitions/`); execution is
deterministic Python (`hermes/runbooks/engine.py`). AI never writes or picks
actions outside this format.

## Structure

```yaml
<category>:                     # matches the incident category
  description: >               # English, shown to humans
    ...
  detect: [<rule names>]       # signals that map to this runbook
  possible_causes: [...]       # documentation for humans/AI context
  preconditions: [<check>]     # all must pass (else ambiguous)
  diagnose: [<check>]          # all must pass before any action
  actions:                     # ordered; each becomes an ActionPlan
    - capability: docker.restart
  verification: [<check>]      # fresh-state checks after settle
  settle_seconds: 90           # recovery grace before verifying
  escalation_criteria: [action_failed, verification_failed]
```

## Outcomes

| outcome | meaning |
|---------|---------|
| `resolved` | executed + verified healthy on fresh state |
| `would_execute` | policy allowed, executor dry-run (audited) |
| `needs_approval` | APPROVAL_REQUIRED capability — scoped code issued |
| `failed` | action/verification failed → escalation criteria met |
| `ambiguous` | preconditions/diagnose inconclusive → AI layer or human |
| `diagnosed` | checks only; no safe automatic action defined |

## Built-in runbooks

- containers: `container_unhealthy` (restart), `container_exit` (start),
  `container_restart_loop` (diagnose-only — never feeds the loop),
  `container_high_cpu` / `container_memory_pressure` (diagnose-only),
  `container_memory_leak` (restart when trend proven + managed)
- infrastructure (all diagnose-only): `storage_latency`, `filesystem_readonly`
  (never automatic), `network_packet_loss`, `beacon_unavailable`,
  `netdata_unavailable`

## Adding a runbook

1. Add YAML matching an existing incident category.
2. Reuse existing diagnose/verification checks from
   `hermes/runbooks/verification.py` (Diagnostics).
3. Choose the least-privileged registered capability.
4. Add tests: success, precondition-fail, verification-fail paths.

Checks run against fresh state via the Beacon shim; an action only dispatches
if policy, budgets, protection, idempotency, concurrency and the fresh
pre-execution recheck all allow it (see docs/REMEDIATION.md).
