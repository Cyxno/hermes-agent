# Hermes v2 — Autonomous operations agent voor Unraid

> Beacon observes. Netdata adds depth. Hermes understands and acts.
> Deterministic first. AI second. Notifications are exceptional.

Hermes v2 vervangt de v1 monitoring/evaluator-agent door een stateful,
low-noise, AI-assisted operations agent:

- **Beacon** (unraid-dashboard Agent API) als primaire observability-bron
  (REST-reconciliatie + SSE-stream);
- **Netdata** als dieptebron (throttling, iowait, disk-await, ML-anomaly);
- **fallback-probe** (Prometheus/optionele SSH) om "Beacon stuk" vs
  "host weg" te onderscheiden;
- **incident state machine** (`OBSERVED→PENDING→CONFIRMED→ACTIVE→RECOVERING→RESOLVED`)
  met per-categorie debounce, twee-zijdige hysteresis (sustain-open + margin-clear),
  flapping-bescherming en **verplichte final recheck vóór elke notificatie**;
- **transiënten** worden stil geregistreerd; herhaling → pattern-incident;
- **correlatie** tot root-incidenten (storage-familie, docker-daemon, compose-project);
- **desired-state lifecycle** (MANAGED/OPTIONAL/RETIRED/IGNORED) i.p.v. hardcoded
  containerverwachtingen — DUMBscope/Decypharr-legacy is verwijderd;
- **deterministische runbooks** voor diagnose + veilige remediëring;
- **AI alleen indien nodig**: Ling 3.0 Flash → (deterministische escalatiecriteria)
  → DeepSeek V4 Flash, structured output (pydantic), hard budget, volledig geauditeerd;
- **executor** met capability-registry (FORBIDDEN-klassen onmogelijk), policy-engine,
  scoped goedkeuringen ("los het op"), standaard **dry-run**, altijd verifiëren
  (exit-code 0 is nooit "fixed");
- **Telegram**: alerts (exceptioneel) + commando's (`/status /incidents /why
  /investigate /fix /approve /whatdidyoudo /mute /desired`, "los het op");
- **self-observability**: `/health`, `/diagnostics`, structured JSON-logging,
  retentie, daily summary.

## Quickstart (Unraid)

Zie [docs/MIGRATION.md](docs/MIGRATION.md): template plaatsen → migreren vanuit v1
→ shadow mode → valideren → cutover. Config-voorbeeld:
[config/config.yaml.example](config/config.yaml.example).

## Ontwikkeling

```bash
pip install aiohttp PyYAML pydantic pytest pytest-asyncio ruff
ruff check hermes tests
python -m pytest tests/ -q          # 65+ tests, inclusief alle verplichte scenario's
hermes once fast                    # eenmalige cyclus
hermes validate-config
```

## Documentatie

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — ontwerp en besluiten
- [docs/SECURITY.md](docs/SECURITY.md) — threat model: wat AI níet kan
- [docs/MIGRATION.md](docs/MIGRATION.md) — Beacon-token activeren, shadow, cutover, rollback
- [docs/audit/2026-10-05-phase-a.md](docs/audit/2026-10-05-phase-a.md) — volledige v1-audit
- [docs/BEACON.md](docs/BEACON.md) — geverifieerde Agent API-contract

## Release

`git tag vX.Y.Z` → GitHub Actions: lint → tests → build → push
`ghcr.io/cyxno/hermes-agent:{version,major.minor,latest}` + release notes met
git SHA/build-tijd. Tag moet overeenkomen met `pyproject.toml` (afgedwongen).
