# Beacon Agent API — geverifieerd contract (voor Hermes v2)

Geverifieerd op 2026-10-05 tegen repo-HEAD `2d56f22` == running container
`unraid-dashboard:1.3.18` (GIT_SHA match). Alle bevindingen zijn uit code +
live-probe; de live API was tijdens de audit 403 `DISABLED` (geen token).

## Auth

- `Authorization: Bearer $AGENT_API_TOKEN` (server-env, min. 32 tekens),
  constant-time vergeleken (`src/server/agent/auth.ts`).
- Geen token + `AGENT_API_TRUST_LOCAL` niet gezet → **403 `{"error":{"code":"DISABLED"}}`**.
- Geen token + trust-local → alleen loopback/192.168.1.* (header-based; Hermes
  gebruikt daarom altijd een token).
- **Rate limits** (60s venster): summary 120/min; docker/issues/projects/storage/
  system/operations/events 60/min; capabilities 30/min; **stream 10/min**.

## Envelope & freshness

Elke response: `{apiVersion:"1", beaconVersion, generatedAt, data}`.
Freshness: `{sampledAt, stale, ageSeconds, source}`.

## Endpoints (GET-only; mutaties bestaan niet in v1 namespace)

| endpoint | gebruik door Hermes |
|---|---|
| `/capabilities` | startup-check |
| `/summary` | fast-cycle: health/cpu/memory/load/thermal/docker-counts |
| `/docker` | elke fast-cycle: state/health/image/updateAvailable/composeProject/freshness |
| `/issues` | fast-cycle: primaire issue-invoer (id, severity, status, firstSeen, suggestedChecks info-only) |
| `/storage` | reconcile: arrayState/parity/disks+temperatuur |
| `/system` | reconcile: cpu/load/temps/uptime |
| `/operations` | deep/daily: automation/update-helper state |
| `/events?since=&limit=` | reconnect backfill (in-memory, max 100, weg bij restart) |
| `/stream` | SSE: `hello`, `docker.transition`, `system.health`; ping-comment elke 20s; ring 200; `Last-Event-ID` replay |

## Consument-regels voor Hermes

1. HTTP-status expliciet classificeren (`DISABLED` ≠ 401 ≠ 429 ≠ 5xx ≠ timeout);
   `DISABLED` = configuratieprobleem → geen alarm-storm, bron gemarkeerd.
2. `?since=` is een lexicografische ISO-string compare → altijd UTC `toISOString()`.
3. Stream-reconnect met backoff ≥6s+jitter (10/min-limiet); reconnect → eerst
   `/events` sinds Last-Event-ID, dan `/docker`-resync (ring is vluchtig).
4. `stale:true` of oude `ageSeconds` telt niet als "confirm" in evidence.
5. `/issues` negeert `?status=` (niet geïmplementeerd); filteren aan onze kant.
6. `/openapi.json` bestaat niet (404) ondanks docs.
7. Rate-limit bucket = door client gezonden `X-Forwarded-For` — Hermes stuurt
   die header niet.
