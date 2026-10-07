# Beacon Agent API — verified contract (used by Hermes v2)

Verified on 2026-10-05 against repo-HEAD `2d56f22` == running container
`unraid-dashboard:1.3.18` (GIT_SHA match). All findings derive from code +
live probes; during the audit the live API was 403 `DISABLED` (no token).
Field-level notes updated 2026-10-07 (2.0.1 audit): `summary.cpu.percent` and
`summary.memory.percent` may be `null` on this host — Hermes falls back to
Netdata for host CPU/RAM percentages.

## Endpoints used by Hermes

- `GET /api/agent/v1/summary` — cpu{percent,load5}, memory{percent,bytes},
  load, thermal{currentC,avg24hC,state}, docker{running,total,unhealthy},
  dependencies, health
- `GET /api/agent/v1/docker` — per-container: name, state, health, image,
  updateAvailable, composeProject, managementType
- `GET /api/agent/v1/issues` — active Beacon issues (id, severity, category,
  status, condition, summary, first/last_seen)
- `GET /api/agent/v1/storage` — arrayState, parityStatus, capacity{bytes},
  disks[{name,role,state,temperatureC,sizeBytes,usedBytes}] (reconcile only)
- `GET /api/agent/v1/system` — cpu, memory, load{five,fifteen},
  temperatures{packageC}, uptime, network, dependencies, freshness
- `GET /api/agent/v1/events` / SSE stream — container lifecycle events

## Authentication

- `Authorization: Bearer <token>`; empty/wrong token → 403 with
  `{"error":"DISABLED"}` → Hermes marks Beacon disabled (not an outage).

## Semantics Hermes relies on

- `docker[].health` may be null (no healthcheck) — never treated as unhealthy.
- `issues` dedup: Hermes keys on issue `condition` to avoid double-counting
  native conditions.
- `arrayState`/`parityStatus` are authoritative strings (e.g. STARTED, IDLE,
  CANCELLED) shown verbatim in `/status`.
