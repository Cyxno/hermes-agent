# Hermes v2 — security model

Threat-model pass (spec §56), samengevat. Dit document beschrijft wat AI en
externen expliciet **niet** kunnen, en waar de Grenzen in code zitten.

## 1. AI heeft geen shell-authoriteit (§23/§65.7)

- De AI (Gemini/DeepSeek) produceert hooguit een gevalideerd `Diagnosis`-object met
  `proposedActions` — **pydantic-gevalideerd** (`intelligence/schemas.py`):
  capability en target mogen geen shell-metatekens bevatten (`\n\r;|&$\``).
- Acties gaan altijd via: PolicyEngine → CapabilityGuard → Executor
  (`executor/executor.py`). De executor is de enige component die SSH-operator-
  acties aanmaakt, en bouwt argv **zonder shell**: elke parameter is een
  los argv-element (`SshOperator.docker_argv`), door de dispatcher server-side
  opnieuw gevalideerd.
- AI-output wordt nooit uitgevoerd zonder policy-verdict; FORBIDDEN-capabilities
  hebben **geen transport** (`dispatch_action=None`) en zijn onmogelijk uit te
  voeren, ook niet met goedkeuring.

## 2. Logdata is untrusted input

- `ContextBuilder._log_section` plaatst logregels expliciet tussen
  `<<<BEGIN_LOGDATA / END_LOGDATA>>>` markers met een systeemprompt-instructie
  dat inhoud data is, nooit instructies (getest:
  `test_context_builder_fences_log_content`).
- Alles dat naar logs/Telegram gaat, gaat door `util.sanitize` (token/key-
  patterns worden gemaskeerd, lengte begrensd).

## 3. Executor en transport

- **Standaard `dry-run`**: niets wordt uitgevoerd; audit-regels documenteren
  wat er zou gebeuren (§49, `mode=dry_run` in `action_audit`).
- Transport is de bestaande geharde **SSH agent-operator dispatcher**: plantokens
  (10 min TTL, eenmalig), CONFIRM-DANGEROUS voor gevaarlijke klassen, audit op de
  host, allowlist van schrijfwortels. Geen `/var/run/docker.sock` in de container
  (docker.sock = root-equivalent; §38). AI-processen draaien in dezelfde container
  maar hebben géén SSH-sleutel tot de operator-identiteit zodra die via file-
  permissies (0600, eigen uid) uit hun bereik gehouden wordt; executor-modus
  `guarded` vereist bovendien expliciete configuratie.
- Pogingen per incident: max 2 (`max_attempts_per_incident`); targets moeten
  desired-state MANAGED/OPTIONAL hebben — DISCOVERED/RETIRED/IGNORED worden
  geweigerd (getest).

## 4. Telegram (§57)

- Alleen `allowed_usernames` / `allowed_chat_ids` komen door
  (`CommandHandler._authorize`, getest: niet-geautoriseerde user wordt geweigerd).
- `update_id`-dedup: replay van commands wordt genegeerd (getest).
- "los het op" creëert een **scoped** goedkeuring: (incident, action-class,
  target), TTL 10 min, eenmalig; verkeerde target/klasse/verlopen/hergebruik
  wordt geweigerd (getest).
- Mutatie-commando's (/fix, /approve) loggen initiator `telegram/<user>` in de
  audit.

## 5. Netwerk & SSRF

- Observer-clients volgen géén redirects (`allow_redirects=False`), alle calls
  zijn GET met timeouts, retries met bounded backoff + circuit breakers.
- Config-URLs komen uit het eigen config-volume; geen gebruikersinput in URLs.
- Het health/diagnostics endpoint bindt op 127.0.0.1 in de container en stelt
  geen secrets bloot (alleen counters/versie).

## 6. Secrets

- Secrets staan uitsluitend in env (`env:NAAM`-referenties in config) of
  `/data/secrets.env` (0600). Ze worden nooit gelogd (`sanitize` als laatste
  verdediging), nooit in de audit/message-velden gezet, en de CI faalt op
  token-patronen in de tree (grep-gate in `ci.yml`).
- De migratietool schrijft v1-secrets naar `secrets.env` met chmod 600 en houdt
  ze buiten `config.yaml` (getest).

## 7. Fail-safe

- Elke externe aanroep is failure-isolated; een cycle faalt nooit door één bron.
- AI uit/beide providers down → monitoring + runbooks draaien door (getest).
- Beacon uit → fallback-probe maakt onderscheid tussen Beacon-storing en
  host-uitval (getest). Telegram uit → pending-wachtrij met backoff, geen
  event-verlies (getest).

## Restrisico's (bewust gedocumenteerd)

1. SSH-operator sleutel in het /data-volume: file-permissies zijn de grens.
   Mitigatie later: aparte executor-sidecar (onderzoeksitem, spec §38).
2. De Agent API van Beacon vertrouwt (bij `AGENT_API_TRUST_LOCAL`) op
   X-Forwarded-For — daarom gebruikt Hermes altijd een **token**, niet
   trust-local.
3. Prompt-injection via container-namen/labels blijft een model-risico; mitigatie
   is de schema-validatie + capability-allowlist + policy-engine, niet het model.
