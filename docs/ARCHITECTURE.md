# Hermes Homelab — architectuur (herzien ontwerp, sept 2026)

Status: fase 0 (source of truth) en fase 1 (host-sampler) geïmplementeerd; fase 2+ volgt
met expliciete goedkeuring per fase.

## Principe

DETERMINISTISCH EERST → cron/scripts/rules/state → alleen indien nodig LLM →
alleen indien nodig escaleren naar duurder model. Een gezonde omgeving kost ~0 tokens.

## Observatiebronnen

1. **DUMBscope (:8091)** — incident-engine voor alles binnen DUMB (Plex, *arr,
   InfiniDysk, media-flow). Hermes implementeert die logica niet opnieuw; polling met
   lokale cursor (fase 4; eerste variant tegen deployed 0.6.1).
2. **Unraid SSH (primary current truth)** — bestaande forced-command read-dispatcher,
   gecontroleerd uitgebreid met host-summary-/memory-/docker-/disk-acties.
3. **Prometheus** — uitsluitend historie/trendcontext; nooit een harde dependency.
   Lokale `samples.db` (48 u) is de fallback-historie.

## Lagen

| Laag | Frequentie | Waar | LLM |
|---|---|---|---|
| host-sampler | elke 5 min | Unraid host (user.scripts) → `samples.db` | nee |
| evaluator-fast (fase 3) | elke 15 min | Hermes cron (no-agent): trends, severity-state | alleen bij nieuw incident (Tier 1) |
| evaluator-deep (fase 3) | uur | Hermes cron: SSH-deepchecks + DUMBscope-poll | alleen bij afwijking |
| daily (fase 7) | dag 07:00 | trends lang, backup-health, docker system df-rapport | alleen bij afwijking |

## Modelrouting (fase 5)

Expliciete single-model calls, nooit een models-array als taakroutering:
Tier 1 `inclusionai/ling-3.0-flash` (direct; géén `response_format` — Novita ondersteunt
dat niet en het is bewezen de oorzaak dat Ling werd overgeslagen; JSON via prompt +
lokale validatie) → Tier 2 `deepseek/deepseek-v4-flash-0731` → Tier 3 `z-ai/glm-5.3-flash`
(alleen providerfout) → Tier 4 `openai/gpt-5.6-luna` (alleen complex). Escalatie beslist
onze code op confidence/known-root-cause/multi-service; elke call volledig geaudit in
`router_calls.jsonl` (requested_model, actual_model, reason, tokens, latency, cost).

## Docker vDisk-meting

Primair en GUI-authoritatief: `df -kP /var/lib/docker` (loop2, xfs).
Secundair (alleen cache-pool-impact): `du` op `/mnt/cache/system/docker/docker-xfs.img`.
`docker system df` alleen in de daily-laag. Niet-gemounte vDisk = CRITICAL.

## Remediation

Ongewijzigd: read-SSH automatisch; operator-SSH uitsluitend na expliciet akkoord;
plantokens/CONFIRM-DANGEROUS/audit blijven staan; cron/single-query/unattended approvals
blijven `deny`.

## Fase 2 — read-only SSH-deepchecks (agent-read)

Alle nieuwe acties antwoorden met een JSON-envelope
`{"ok":true,"action":"…","ts":…,"data":{…}}` of `{"ok":false,…,"error":"…"}`,
zijn opbouw-gebonden begrensd (< 16 KB) en hebben server-side timeouts
(docker 10–12 s, smartctl 8 s, overige subseconde). Zware commands zijn
best-effort; een abort halverwege levert een fail-envelope, nooit halve JSON.

| Actie | Inhoud | Waarom geen duplicaat van de 5-min-sampler |
|---|---|---|
| host-summary | uptime, kernel, load, RAM, docker-ok, array-state, 6 mounts | één keer bij diagnose; sampler blijft de history-leverancier |
| memory-status | totals, buffers/cache, swap, OOM-teller, top-10 RSS | top-processen en cper-container RSS zijn te duur voor elke 5 min |
| oom-events [since] | OOM-regels uit dmesg + cumulatieve teller | gebeurtenissen, geen meting; alleen bij verdenking |
| docker-status | per container: state/health/restarts/started/exit/memlimit | één inspect-batch on-demand; sampler houdt alleen states-teller |
| docker-restarts | subset: restarts>0 of niet-running | trendsignaal voor de evaluator, niet per 5 min nodig |
| docker-vdisk-status | df op loop-mount (GUI-authoritatief) + du-allocatie | bevestiging/detail; primaire serie komt van de sampler |
| docker-space-detail | docker system df + 10 grootste images | zwaar (≈0,5 s, alle lagen); alleen on-demand bij groei |
| logfs-status | df + top-10 du van /var/log | detailachtervolging bij groei; sampler houdt alleen % |
| pool-status | cache/vm_storage/user: fstype, rw, pct | ro-remount/fstype-detail hoort niet in het 5-min-pad |
| disk-health [dev] | SMART: health, temp, realloc(5/196), pending(197), uncorrectable(198), media-errors, ssd-life(231/NVMe-%used) | standby-aware (`-n standby` wekt nooit); volledige poll per 5 min zou disks wakker houden |
| temperature-status | package/core-max + SSD-temps | momentopname ter bevestiging; sampler heeft de trend |
| array-status | mdState, sbSynced (epoch!), resync-actie/% | mdcmd-status is diagnose, geen timeserie |
| kernel-errors [since] | gefilterd: I/O, XFS/BTRFS/EXT4, ro-remount, NVMe, MCE, hangs | event-detectie met venster, geen meting |
| fs-errors [since] | filesystem-specifieke regels | idem |

Semantiek-opmerkingen: `wear_pct` is bij NVMe "Percentage Used" (slijtage) en bij
ATA attr 231 "SSD_Life_Left" (restleven) — evaluator interpreteert per bron.
`parity_synced` in array-status is een epoch-tijdstip van de laatste sync.
PSI bestaat niet op deze host (kernel zonder PSI) en wordt nergens verwacht.

## Fase 3 — deterministische evaluator (dry-run)

`scripts/hermes_evaluator.py` (container-side, uid 10000, one-shot via host-cron):
- **fast** (7,22,37,52 * * * *): replayt nieuwe samples uit `samples.db` (cursor
  `fast:last_ts`), berekent trends (d15m/d1h/d6h, OLS-slope, min/max, sustain),
  past banden + hysteresis (enter/exit −5pp, 2 samples) + recovery
  (RECOVERING → RESOLVED na 2 goede samples) toe. Geen SSH.
- **deep** (23 * * * *): read-only SSH — disk-health (standby-aware),
  array-status (actieve resync alleen op pos/size), pool ro/ro, docker-status
  (restart-delta ≥3 = loop-kandidaat; exits alleen classificatie),
  kernel/fs-errors (fingerprint-dedup), vdisk-confirm; docker-space-detail
  alléén bij actief groei-incident; oom-events alleen bij OOM-teller-delta.
- **baseline-report**: min/p50/p95/p99/max + typische slope + suggested warn.
- **test**: 20 synthetische cases via zelfde codepad.

State: `homelab/agent_state.db` (WAL, busy_timeout 5000) met incidents,
metric_state, counters (monotone SMART/OOM-tellers: alleen delta = event,
eerste waarneming = baseline) en cursors. Events: `homelab/evaluator-events.jsonl`
(audit: waarom WARNING, zonder LLM). Alles `baseline_pending: true` → elke
severity is provisional tot de baseline is goedgekeurd.

Modelrouting/prometheus zijn bewust afwezig: later als optionele provider
in te haken zonder deze code aan te passen.

## Fase 4 — DUMBscope-integratie (bron A, polling)

`scripts/hermes_dumbscope.py` + `run_dumbscope()` in de fast evaluator (elke
15 min, failure-isolated). DUMBscope blijft de incident-engine voor alles binnen
DUMB: Hermes berekent geen service-health, fingerprints, hysteresis of
root-cause opnieuw.

- **Deployment (waarheid):** DUMBscope 0.7.0 op :8091 (`/api/health` publiek;
  `/api/incidents` sessie-auth; `/api/agent/events` bestaat niet; `/api/actions`
  bestaat wél sinds 0.7.0 maar wordt bewust NIET aangeroepen).
- **Auth:** POST `/api/auth/login` (username+password, Origin-header verplicht,
  rate-limit 10/15 min) → cookie `dumbscope_session` (TTL 7 d). Wachtwoord uit
  `secrets/dumbscope-admin-password.txt` (fallback: arrsight-bestand); sessie-
  token in `secrets/dumbscope-session` (0600). Bij 401 → één re-login per poll.
  Geen credentials in logs/state/events.
- **Poll-strategie:** polling, géén SSE. `status=active&limit=200` +
  `status=resolved&limit=20` dekt new/changed/resolved/reopen; lokaal diffen.
- **Mapping:** severity info→notice, warning→warning, critical→critical
  (onbekend→notice, gemarkeerd); lifecycle 1-op-1 overgenomen (DUMBscope kent
  active/resolved; Hermes verzint geen extra recovery).
- **State:** `dumbscope_incidents`-tabel (fingerprint=`dumbscope:<source-fp>`,
  incident-id, status, severity, occurrences, resolved_at, host_correlations)
  + cursors (`dumbscope:last_poll`, `:failures`, `:seeded`). Eerste poll =
  baseline-seeding zonder per-incident events.
- **Availability:** 1–2 mislukte polls = alleen teller; ≥3 → WARNING
  `dumbscope:availability`; ≥12 → URGENT; herstel → RESOLVED. Host-monitoring
  draait onafhankelijk door (failure isolation).
- **Host-correlatie (§13):** actieve host-incidenten (≥warning) worden als
  `host_correlations` aan DUMBscope-events toegevoegd — gelijktijdigheid, geen
  oorzaak-claim.

## Fase 5 — LLM-router (expliciet, auditbaar)

`scripts/hermes_router.py`: één model per request, `allow_fallbacks=false`,
`requested_model == actual_model` wordt gecontroleerd (mismatch = routing_violation,
response onvertrouwd). Ling (tier 1) zonder `response_format` en met
`reasoning: {enabled: false}` (live gemeten: 0 reasoning-tokens); DeepSeek (tier 2)
idem reasoning uit + JSON-modus; GLM (tier 3) uitsluitend bij DeepSeek-providerfout
( `reasoning effort: low`); Luna (tier 4) alleen bij urgent/critical + multi-system +
DeepSeek-conf < 0,5.

- **Tier 0 skip-regels** (`needs_llm_analysis`): bekende deterministische oorzaken
  (threshold/growth/restart-delta/CRC-delta/availability) worden nooit naar een model
  gestuurd; DUMBscope-incidenten met duidelijke rootCauseService + evidence evenmin.
- **Escalatie** (deterministic code): conf < 0,85 / onbekende oorzaak / multi-system /
  invalid JSON / providerfout / routing-violatie — elke reden in de audit.
- **Limits**: 3 calls per incident-lifecycle, 8 per kalenderdag (config), audit
  `llm_budget_exhausted:*`.
- **Audit**: `homelab/router_calls.jsonl` — requested/actual/provider/tokens
  (incl. reasoning)/latency/cost/confidence/routing_violation/error.
- **State**: llm_*-kolommen op incidents + `llm_context_hash` — ongewijzigde
  incidenten worden niet her-analyseerd.
- **Sanitizer** redigeert secretpatronen vóór iedere call (getest).
- In testmodus (`hermes_evaluator.py test`) staat de llm-laag uit: tests maken
  nooit echte modelcalls; de routertests mocken het transport.
