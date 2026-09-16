# Hermes Homelab Operator

## Actuele installatie

- Hermes Agent `v0.21.0` (`2026.8.31`, upstream `58472d80`) draait als Docker-container `hermes` op Unraid.
- Persistente data: `/mnt/user/appdata/hermes/data`.
- Compose: `/mnt/user/appdata/hermes/compose/docker-compose.yml`.
- Telegram gebruikt dezelfde bestaande bot met een expliciete user-allowlist; allow-all staat uit.
- De standaard interactieve agent gebruikt OpenRouter met `deepseek/deepseek-v4-flash-0731`.

## Router

```text
Tier 0  scripts/API/Prometheus/SQLite
   ├─ gezond → stop, 0 LLM
   └─ compact afwijkingssetje → Ling 3.0 Flash
         ├─ normal/harmless → stop
         └─ incident → DeepSeek V4 Flash 0731
               ├─ providerfout → GLM 5.3 Flash
               └─ inhoudelijk complex/onzeker → GPT-5.6 Luna
```

Model-IDs zijn op 1 september 2026 tegen de live OpenRouter-catalogus gecontroleerd:

| Rol | Model-ID | Input/output per miljoen tokens |
|---|---|---:|
| Gatekeeper | `inclusionai/ling-3.0-flash` | $0.021 / $0.063 |
| Troubleshooting | `deepseek/deepseek-v4-flash-0731` | $0.065 / $0.18 |
| Technische fallback | `z-ai/glm-5.3-flash` | $0.075 / $0.25 |
| Complex | `openai/gpt-5.6-luna` | $0.20 / $1.20 |

De automatische router staat in `/opt/data/scripts/homelab_monitor.py`. Providerfouten van DeepSeek gaan naar GLM; inhoudelijke onzekerheid gaat naar Luna. De router begrenst events, context, outputtokens en het aantal escalaties.

## Monitoring

- `homelab-hourly`: ieder uur, Hermes no-agent/script-only.
- `homelab-daily`: dagelijks 09:00, Hermes no-agent/script-only.
- Snapshot/API en Prometheus vormen de eerste laag.
- SQLite-state: `/opt/data/homelab/monitor.db`.
- LLM-kostentelemetrie: `/opt/data/homelab/cost-calls.jsonl`.
- Daglogs worden met `--since` en maximaal 500 regels per kritieke container gelezen, lokaal gefilterd en als fingerprints met maximaal drie voorbeelden gededupliceerd.
- Adaptieve monitors hebben een maximum van vijf beoogde actieve monitors en een standaardlevensduur van zeven dagen. De patroon- en expirylogica is in SQLite vastgelegd; de testcase maakt uitsluitend gesimuleerde metingen aan.

## SSH

Hermes toont één homelab-operator, maar gebruikt twee Ed25519-identiteiten:

- `agent-read`: forced-command allowlist voor status, Docker-inspect/logs/stats, disk, RAM, netwerk en kernel-errors. Uitvoer is hard begrensd.
- `agent-operator`: forced-command allowlist voor `docker-restart`, `docker-start` en `docker-stop`.

Beide sleutels controleren `known_hosts`; host-key-bypass is verboden. De operatorroute mag volgens `SOUL.md` alleen na expliciet akkoord worden gebruikt. Brede root-shell, willekeurige configwijzigingen en onbeperkte sudo zijn niet beschikbaar.

