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
