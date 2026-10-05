# Hermes v2 — Architectuur

Status: implementatieontwerp (Phase B), gebaseerd op `docs/audit/2026-10-05-phase-a.md`.

> Deterministic first. AI second. Signals are cheap. Incidents are expensive.
> Notifications are exceptional.

## 1. Wat Hermes v2 is

Eén Python-daemon (container) die:

1. **observeert** via Beacon (primair), Netdata (diepte/anomalie), en een minimale
   fallback-probe (alleen als Beacon onbereikbaar is);
2. signalen normaliseert tot **evidence** met bron + confidence + freshness;
3. evidence en masseert tot **signalen** (deterministische rules, per-categorie
   debounce en hysteresis);
4. signalen tot **incidenten** maakt via een expliciete state machine
   (`OBSERVED→PENDING→CONFIRMED→ACTIVE→RECOVERING→RESOLVED`, + SUPPRESSED/FLAPPING/ESCALATED);
5. incidenten **corrigeert tot root-cause** (correlatie) en transiënt-herhaling herkent;
6. bekende problemen deterministisch diagnosticeert via **runbooks**;
7. waar veilig mogelijk **herstelt** via een executor met capability-registry,
   policy-engine, dry-run en always-verify;
8. alleen dan **AI** (Ling 3.0 Flash → DeepSeek V4 Flash via OpenRouter) raadpleegt
   wanneer deterministische logica onvoldoende is, met structured output;
9. alleen relevante, gecontroleerde **meldingen** stuurt (final recheck vóór elke
   verzending; recovery alleen na eerdere alert) en Telegram-commando's beantwoordt.

Geen LLM-loop, geen tweede dashboard, geen duplicatie van Beacon.

## 2. Componenten en dataflow

```text
Beacon Agent API (SSE + REST) ─┐
Netdata REST (charts/alarms)  ─┼─▶ Observer ─▶ NormalizedState ─▶ RuleEvaluator ─▶ Signal
Unraid/Prom fallback probe    ─┘                                                          │
                                                                                          ▼
                                            IncidentEngine (debounce/hysteresis/recovery)
                                                                                          │
                                                                       CorrelationEngine ◀┘
                                                                                          │
                                              ┌───────────────────────────────────────────┤
                                              ▼                                           ▼
                                        RunbookEngine  ── solved ──▶ Verify ◀──┐     TransientTracker
                                              │ ambiguous                     │           │
                                              ▼                               │           ▼
                                        AIRouter (Ling→DeepSeek, structured)  │    PatternIncidents
                                              │ ActionPlan                    │
                                              ▼                               │
                                        PolicyEngine → CapabilityGuard        │
                                              ▼                               │
                                        Executor (dry-run|guarded|approval) ──┘
                                                                                          │
                                                     Notifier (final recheck) ◀───────────┘
                                                              │
                                                        Telegram (alerts + commando's)
```

### 2.1 Observer-laag

- **Beacon** (`observer/beacon.py`): primaire bron. Snelle events via
  `GET /api/agent/v1/stream` (SSE; `hello`, `docker.transition`, `system.health`;
  ping 20s; ring 200; Last-Event-ID). Reconnect met exponentiële backoff
  (≥6 s + jitter, cap 60 s) i.v.m. connect-limiet 10/min. Periodieke reconciliatie:
  `summary` elke fast-cycle, `docker`/`storage`/`system`/`issues` elke reconcile-cycle,
  `operations` elke deep-cycle. Freshness-velden (`sampledAt/stale/ageSeconds`) worden
  overgenomen in evidence; stale data telt niet als "confirm". Rate-limits gerespecteerd
  (summary 120/min, data 60/min).
  - HTTP-statussen worden expliciet onderscheiden: 403 `DISABLED` (API uit),
    401 (token fout), 429 (rate limit), 5xx, timeout → aparte `beacon:source`-signalen.
- **Netdata** (`observer/netdata.py`): tweede bron, GET-only:
  - `/api/v1/alarms` (allowlist zoals v1);
  - gerichte chart-queries alleen tijdens diagnose/bevestiging en in de reconcile-cycle
    voor evidence: `cgroup_<n>.throttled_duration`, `cgroup_<n>.mem_usage_limit`,
    `system.cpu:iowait`, `disk_await.<dev>`, `net_drops/errors.<iface>`,
    `docker_local.container_<n>_health_status`, `mem.oom_kill`,
    `anomaly_detection.anomaly_rate_on_<guid>`;
  - **geen PSI/swap-verwachtingen** (bestaat niet op deze host).
- **Fallback-probe** (`observer/fallback.py`): alleen als Beacon onbereikbaar.
  Keten: (1) Prometheus `up{}` + node-exporter instant-queries (onafhankelijk van
  Beacon); (2) optionele SSH read-dispatch `host-summary` (zelfde geharde dispatcher
  als v1, alleen als key geconfigureerd). Doel: onderscheid tussen "Beacon stuk",
  "Unraid weg", "netwerkstoring". Geen volledige Beacon-duplicatie.

### 2.2 State

- **NormalizedState**: laatste observaties per bron per entiteit (host, container,
  disk, interface), inclusief timestamp/age/stale per bron.
- **DesiredState / ServiceRegistry** (`state/desired.py`): persistent per entiteit:
  `MANAGED` (incident-kandidaat bij afwezigheid), `OPTIONAL` (alleen bij health-
  problemen), `RETIRED` (afwezigheid is normaal, bijv. decypharr-achtige legacy),
  `IGNORED`, `DISCOVERED` (default voor nieuw gezien). Persistent in SQLite;
  seed vanuit legacy-migratie (`known_stopped` → RETIRED, bekende lijst → MANAGED).
- **Persistence**: SQLite (WAL, busy_timeout) in `/data/hermes.db` — tabellen:
  `incidents`, `incident_events`, `signals`, `metric_state`, `cursors`, `counters`,
  `transients`, `desired_state`, `remediations`, `action_audit`, `baselines`,
  `notifications`, `ai_calls`, `schema_migrations`. Versioned migrations bij startup
  (backup van db vóór migratie; bij falen veilig stoppen). Eén db-bestand, eenvoudig
  te backuppen; geen database-server.

### 2.3 Incident engine (`engine/`)

- **Signals**: `{category, entity, severity_hint, value, evidence[], ts, source}`.
- **Debounce** per categorie (config, defaults):
  `container_unhealthy 90s`, `container_exit 45s`, `high_cpu 7min`, `high_ram 5min`,
  `io_latency 4min`, `temperature 3min`, `beacon_unavailable 90s`,
  `filesystem_readonly 0s (immediate)`, `disk_missing 0s (high)`,
  `array_parity_fault 0s (high)`.
- **Hysteresis**: open/clear-banden met clear-margin (default 5pp) + n good samples
  (default 2) vóór clear; cooldown per fingerprint (default 30 min) tegen flapping;
  bij herhaald flappen (≥3 clear/reopen binnen venster) → status FLAPPING, melding
  slechts één keer.
- **Final recheck (verplicht)**: vóórdat een melding wordt gebouwd, haalt de notifier
  verse state op (Beacon + relevante Netdata-chart). Bestaat het incident niet meer →
  cancel + markeer transient/resolved. Geen stale alerts.
- **Recovery-melding alleen als `notification_sent=true`** op het incident.
- **Transients**: elk binnen-debounce hersteld signaal wordt opgeslagen
  (`transients`) maar niet gemeld. Herhaling telt: ≥N transients van hetzelfde
  fingerprint in venster W (default 5 in 6u, per categorie config) → `DEGRADED`
  pattern-incident ("X is gezond, maar N keer kortstondig afwijkend vandaag").
- **Correlation**: deterministische regels —
  - resource-familie: ≥3 containers met io-latency/pressure-signalen binnen 10 min
    + host `disk_await`/storage-evidence → één root-incident `storage_degradation`
    met affected-lijst;
  - dependency: compose-project uit Beacon (`/projects`): alle services van een
    project unhealthy → root-incident op project;
  - infra: docker daemon down → alle container-signalen worden `affected`, geen
    losse incidenten;
  - temporal overlap van incidenten met dezelfde categorie binnen venster.
  Confidence-score = functie van aantal bevestigende bronnen en freshness.

### 2.4 Runbooks (`runbooks/`)

Data-driven definities (YAML in `runbooks/definitions/`) + Python-actie-handlers.
Per runbook: `detect` (categories), `confirm` (extra checks), `diagnose` (volgorde),
`possible_causes`, `preconditions`, `safe_actions` (capability + args-sjabloon),
`verification` (welke bronnen/waarden), `rollback`, `escalation_criteria`.
Startset: `container_unhealthy`, `container_exited`, `container_restart_loop`,
`container_high_cpu`, `container_memory_pressure`, `container_memory_leak`,
`storage_latency`, `filesystem_readonly`, `network_packet_loss`, `beacon_unavailable`,
`netdata_unavailable`. Runbook-resultaat is óf `resolved` (na verificatie) óf een
gestructureerd `ambiguous`-antwoord voor de AI-laag.

### 2.5 AI (`intelligence/`)

- Interface: `AIProvider.complete(AIRequest) -> AIResponse` (modulair; OpenRouter-
  implementatie met model-naam config; géén provider-logica elders).
- Router: tier1 `ling-3.0-flash` → stop bij `confidence ≥ 0.85` én `known_cause` én
  niet multi-system; anders tier2 `deepseek-v4-flash` bij een van de deterministische
  escalatiecriteria (lage confidence, invalid/missing structured result, geen passende
  remediation, conflicterende root causes, eerste remediation faalt, multi-subsystem,
  expliciet "insufficient evidence", policy-weigering op ambiguïteit). Geen
  "gevoel"-escalaatie. Alle calls geauditeerd (`ai_calls`) incl. budget
  (≤3/incident, ≤8/dag, token caps) —lamaar overgenomen uit bewezen v1-limieten.
- **Structured output** (pydantic-schema): `Diagnosis{rootCause, confidence, evidence[],
  recommendedRunbook, proposedActions[], requiresEscalation, requiresHumanApproval}`.
  Invalid → 1 retry → escalate. Vrije prose alleen voor menselijke uitleg-velden.
- **Context builder** (deterministisch): compacte evidence-bundel per incident
  (state, transitions, gerelateerde signalen, Beacon/Netdata-findings, begrensde
  log-snippets, eerdere pogingen, baseline). Geen volledige logs, geen containerdumps.
- **Logdata is untrusted**: log-inhoud wordt uitsluitend als data-string in evidence
  opgenomen (ge-escape in prompts, met markeringsconventie), nooit als instructie.

### 2.6 Executor (`executor/`)

- **Capability-registry**: `docker.restart/start/stop`, `service.<x>.restart`,
  `network.probe`, `dns.probe`, `filesystem.inspect`, `unraid.inspect` — elk met
  `riskLevel (SAFE|GUARDED|APPROVAL_REQUIRED|FORBIDDEN)`, `allowedTargets`
  (desiredState MANAGED/OPTIONAL), preconditions, timeout, verification-strategy.
  Defaults: restart managed container GUARDED; recreate/edit/delete/FORBIDDEN-klasse
  standaard dicht; stop array/format = FORBIDDEN (niet configureerbaar naar open).
- **Policy engine**: beslist allow/deny/require-approval o.b.v. riskLevel, desired
  state, maintenance-window, incident-scope, eerdere mislukte pogingen (max 2 per
  incident).
- **Approval** ("los het op"): Telegram-goedkeuring is **scoped** (incident + action-
  class + target), TTL 10 min, eenmalig; verleent nooit wildcard. FORBIDDEN kan nooit
  worden goedgekeurd.
- **Action contract**: preconditions → action → expected → wait → verify (Beacon
  fresh + relevante Netdata-chart) → RESOLVED alleen als conditie weg is. Exit-code
  0 is nooit "fixed". Bij falen: rollback indien aanwezig, anders escalate.
- **Transport**: execution is standaard **UIT** (`executor.mode=dry-run`). Echte
  acties lopen via de bestaande geharde **SSH agent-operator dispatcher** (plantokens,
  audit, allowlist) — rationale in `docs/SECURITY.md`; docker.sock wordt bewust níet
  gemount (root-equivalent; aparte executor-sidecar = toekomstig onderzoek).
- Dry-run logt exact: zou uitvoeren / reden / preconditions / policy / verwachte
  verificatie (`action_audit` met `mode=dry_run`).

### 2.7 Notifier + Telegram (`notify/`, `interfaces/telegram.py`)

- Alerts: min_severity default `warning`; notice wordt nooit direct verzonden;
  verzending pas bij PENDING→CONFIRMED na final recheck; cooldown first/repeat
  (warning 12u/24u, urgent 4u/8u, critical 4u/12u — bewezen v1-waarden); recovery
  één keer, alleen na alert; geen dubbele meldingen tijdens correlation (root-incident
  ontvangt de melding, affected worden genoemd).
- Self-healed zonder melding: telt op in de **daily summary** (deterministisch).
- Daily summary: host health, incident/transient counts, self-healed, AI escalations,
  unresolved, interessante patronen. AI alleen indien expliciet aangezet en waarde
  toevoegend (default uit).
- Telegram-interface: eigen lichte long-poll client (geen gateway-framework meer).
  Authorisatie: allowlist chat_id/user_id (read en mutations aparte policy);
  vrije tekst alleen gemapt op bekende intents; geen LLM voor commando's.
  Commando's: `/status`, `/incidents`, `/why <id>`, `/investigate <id>`,
  `/fix <id>` (policy+approval), `los het op` (fix laatste actieve incident, scoped),
  `/details <id>`, `/whatdidyoudo`, `/mute <fp> <duur>`, `/help`.

### 2.8 Scheduler (event-first, cron-achtig)

- **fast** (60 s): Beacon summary/issues + SSE-events verwerken + netdata critical
  alarms + executor job-status.
- **reconcile** (300 s): Beacon docker/storage/system/issues volledig, desired state
  reconciliatie, netdata evidence-charts, fallback-probe indien Beacon down.
- **baseline** (900 s): trend/baseline-onderhoud, transiënt-aggregatie, anomaly-rate.
- **daily**: retentie-cleanup, baseline-compaction, summary, staleness-sweep.
- SSE is een aanvulling op fast; reconcile blijft de waarheidsbron (spec §20).

### 2.9 Zelf-observatie & fail-safe (`health.py`)

- Lokale HTTP endpoint (127.0.0.1:8643): `/health`, `/diagnostics` (uptime, last
  successful polls per bron, SSE-status, incident-counts, AI-calls/escalaties,
  executor-acties, telegram-sends/suppressed, version/git SHA/digest-file).
- Docker healthcheck op `/health`.
- Uitval: Beacon down → fallback-probe + `beacon:unavailable` incident (met
  onderscheid Beacon-stuk vs host-weg); Netdata down → verder met Beacon, mark
  observability degraded; AI down → deterministisch door; Telegram down → incidenten
  blijven bestaan, retry met backoff (persistent pending), geen event-verlies;
  Hermes-restart → alles persists en wordt hervat (cursors).

## 3. Beveiligingsmodel (samenvatting; details docs/SECURITY.md)

- AI heeft **geen** shell/docker/SSH-authoriteit; produceert hooguit ActionPlans die
  door policy+guard+executor gaan. AI-output is untrusted data tot gevalideerd.
- Log-inhoud/container-namen = untrusted; geen interpolatie in shell; capability-args
  zijn getypeerd en tegen allowlist gevalideerd; paden ge-normaliseerd tegen
  traversal; URLs tegen SSRF-allowlist (privé-ranges toegestaan, redirects geweigerd).
- Secrets uitsluitend via env/config-volume (`/data/secrets/`, 0600), nooit in logs,
  nooit in image, nooit in repo. Log-sanitizer als laatste lijn.
- Telegram: mutaties alleen van geautoriseerde chat/user; command-replay bescherming
  (update_id dedup); "los het op" verleent nooit gestructureerde wildcard-rechten.

## 4. Packaging & release

- Image: `ghcr.io/cyxno/hermes-agent:<semver>` + `latest` (bestaande owner/repo-naam;
  v1-remote is `Cyxno/hermes-agent`). Multi-arch alleen amd64 (host is x86_64) —
  arm64 later alleen als betrouwbaar testbaar.
- Dockerfile: python:3.13-slim, non-root (uid 10000), eigen deps (aiohttp, PyYAML,
  pydantic), s6 niet nodig (python is PID 1 met signal handling), healthcheck,
  read-only rootfs waar kan, state in `/data` volume.
- CI (GitHub Actions): lint (ruff), typecheck (mypy basis), pytest, docker build,
  trivy-scan, publish op tag; git tag == image tag; traceability (VERSION, GIT_SHA,
  BUILD_TIME gebakken in image; digest in release notes).
- Unraid CA-template `unraid/hermes-agent.xml`: exposes Beacon URL/token, Netdata
  URL, Telegram token/chat, AI keys, /data pad, TZ, loglevel, executor-mode;
  secrets masked; veilige defaults (execution uit).
- Updates via normale Unraid Docker-workflow; state/config in /data overleeft updates;
  schema-migrations bij startup; update verliest nooit incident/history.

## 5. Migratie & shadow mode (samenvatting; details docs/MIGRATION.md)

- `hermes migrate-legacy` leest v1 `data/`: `.env` (telegram/openrouter), thresholds
  (mapping naar v2-categorieën), notifications.yaml (cooldowns), agent_state.db
  (gewenste desired-state seed; incident-historie optioneel als read-only import),
  `known_stopped` → RETIRED. Rapport: must/optional/obsolete/do-not-migrate.
- **Shadow mode** (`mode=shadow`): alles draait (observers, engine, AI indien aan),
  maar: géén echte alerts (optioneel apart debug-chat-id), géén mutaties (executor
  geforceerd dry-run), beslissingen + wat-gezouwd-zijn gelogd voor vergelijking met
  v1 (false positives/negatives, suppressie, correlatie, AI-aantal, footprint).
- Dry-run executor standaard; echte acties pas na bewezen correctheid (§49).
- Cutover: freeze v1 notifications → v2 notificaties aan (normale mode) → v1 container
  stop → observatie → safe executor aan → legacy cleanup (alleen na bewijs, met
  backups). Rollback: v2 stop, v1 start; state/config onaangetast.

## 6. Oude-generatie-beslissingen (bewust)

| beslissing | rationale |
|---|---|
| Eén Python-daemon i.p.v. cron+one-shot | SSE,event-first, één state-owner, healthcheck; cron-model blijft beschikbaar via `hermes once` |
| SQLite i.p.v. Postgres | workload is klein; backup = file copy; geen extra infra (spec §31) |
| aiohttp+PyYAML+pydantic i.p.v. stdlib-only | async SSE/HTTP robuust; structured output; bewust klein gehouden |
| SSH operator-dispatch i.p.v. docker.sock | least privilege, bestaande geharde audit-laag; docker.sock = root-equivalent (§38) |
| Eigen Telegram-client i.p.v. NousResearch gateway | v2 hoeft geen conversationeel agent-framework; minder resource + attack surface; interactie blijft bewaard |
| Geen Prometheus-schrijfpad in v2 | Beacon+Netdata dekken observatie; v2 is decision layer (§59) |
