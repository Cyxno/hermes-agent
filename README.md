# Hermes v2 — Autonomous operations agent for Unraid

> Beacon observes. Netdata adds depth. Hermes understands and acts.
> Deterministic first. AI second. Notifications are exceptional.

Hermes v2 is a stateful, low-noise, AI-assisted operations agent that replaces
the legacy v1 monitoring/evaluator agent:

- **Beacon** (unraid-dashboard Agent API) as the primary observability source
  (REST reconciliation + SSE stream);
- **Netdata** as the depth source (throttling, iowait, disk-await, ML anomaly);
- **fallback probe** (Prometheus/optional SSH) to distinguish "Beacon broken"
  from "host gone";
- **incident state machine** (`OBSERVED→PENDING→CONFIRMED→ACTIVE→RECOVERING→RESOLVED`)
  with per-category debounce, two-sided hysteresis (sustain-open + margin-clear),
  flapping protection and a **mandatory final recheck before every notification**;
- **transients** are recorded silently; repetition → pattern incident;
- **correlation** into root incidents (storage family, docker daemon, compose project);
- **desired-state lifecycle** (MANAGED/OPTIONAL/RETIRED/IGNORED) instead of
  hardcoded container expectations;
- **deterministic runbooks** for diagnosis and safe remediation;
- **AI only when needed**: Gemini 2.5 Flash-Lite → (deterministic escalation
  criteria) → DeepSeek V4 Flash, structured output (pydantic + native JSON
  schema), hard budget, fully audited;
- **executor** with a capability registry (FORBIDDEN classes are impossible),
  policy engine, scoped approvals ("los het op"), **dry-run by default**,
  always verify (exit code 0 is never "fixed");
- **guarded self-healing (2.1)**: `container_restart` may execute for real
  under strict policy — MANAGED targets only, protected-target deny list,
  fresh pre-execution recheck, restart cooldowns/budgets, idempotency,
  single-action concurrency and a config kill switch
  (`executor.real_actions_enabled`, default **false**);
- **Telegram**: alerts (exceptional) + commands (`/status /incidents /why
  /investigate /fix /approve /whatdidyoudo /mute /desired`, "los het op");
- **self-observability**: `/health`, `/diagnostics`, structured JSON logging,
  retention, daily summary.

> **Language note:** the repository and all current source/docs are English.
> The Telegram user-facing texts are intentionally Dutch (the operator's
> language) and are excluded from translation on purpose.

## Quickstart (Unraid)

See [docs/MIGRATION.md](docs/MIGRATION.md): place template → migrate from v1
→ shadow mode → validate → cutover. Config example:
[config/config.yaml.example](config/config.yaml.example).

## Development

```bash
pip install aiohttp PyYAML pydantic pytest pytest-asyncio ruff
ruff check hermes tests
python -m pytest tests/ -q          # 130+ tests incl. the guarded-executor safety matrix
hermes once fast                    # one-off cycle
hermes validate-config
```

## Documentation

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — design and decisions
- [docs/SECURITY.md](docs/SECURITY.md) — threat model: what AI cannot do
- [docs/REMEDIATION.md](docs/REMEDIATION.md) — guarded self-healing, risk
  classes, budgets, kill switch, rollback
- [docs/RUNBOOKS.md](docs/RUNBOOKS.md) — runbook format and built-ins
- [docs/RELEASE.md](docs/RELEASE.md) — release process, immutable tags, CI
- [docs/MIGRATION.md](docs/MIGRATION.md) — Beacon token, shadow, cutover, rollback
- [docs/BEACON.md](docs/BEACON.md) — verified Agent API contract
- [docs/audit/2026-10-05-phase-a.md](docs/audit/2026-10-05-phase-a.md) — full
  v1 audit (historical)

## Release

`git tag vX.Y.Z` (immutable once pushed — see
[docs/RELEASE.md](docs/RELEASE.md)) → GitHub Actions: lint → tests → build →
push `ghcr.io/cyxno/hermes-agent:{version,major.minor,latest}` + release notes
with git SHA/build time. The tag must match `pyproject.toml` (enforced).

## Telegram authorization (interaction)

- `home_chat_id` is the **trusted interaction chat**: a private chat with that
  id may send commands. If the home chat is a group/supergroup, users must
  additionally be listed in `allowed_user_ids` or `allowed_usernames`.
- `allowed_user_ids` (Telegram user id, more robust than usernames),
  `allowed_chat_ids` and `allowed_usernames` grant additional access via
  exact match only.
- **Telegram authorization ≠ execution authorization**: being allowed to talk
  does not allow mutations. The executor defaults to `dry-run`; AI advice is
  always advisory and passes through policy + capability registry.
