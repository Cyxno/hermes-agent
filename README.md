# hermes-setup

Source of truth en deployment voor de Hermes homelab-agent op Unraid
(`homeserver`, 192.168.1.2).

## Wat staat hier

| Pad | Functie |
|---|---|
| `compose/docker-compose.yml` | Containerdefinitie (image, mount, poort, limits) |
| `config/config.yaml` | Hermes-agentconfiguratie (model, approvals, gateway) |
| `config/SOUL.md` | Persona/system prompt van de operator-agent |
| `config/thresholds.yaml` | Drempels voor de evaluator (baseline_pending) |
| `host/hermes-read-dispatch.sh` | SSH forced-command dispatcher, read-only allowlist |
| `host/hermes-operator-dispatch.sh` | SSH forced-command dispatcher, write-acties met tokens+audit |
| `host/hermes-host-sampler.sh` | Deterministische host-sampler (cron, schrijft samples.db) |
| `scripts/` | Container-side evaluatie/routering (fase 3+) |
| `deploy/install.sh` | Idempotente installatie: repo → live (`--check` voor dry-run) |
| `deploy/install-ssh-identities.sh` | SSH-key/authorized_keys-regie (expliciet uitvoeren) |
| `legacy/` | Vervangen code, alleen referentie |
| `docs/` | Architectuur, security, runbook; `docs/history` = originele docs |

## Regels

- **Secrets committen we nooit.** Waarden staan uitsluitend live in
  `/mnt/user/appdata/hermes/data/.env` (600, uid 10000) en `data/secrets/`.
  Vóór elke commit: `tools/check-secrets.sh`.
- **Live-wijzigingen gaan via de repo**: aanpassen hier → `deploy/install.sh`.
- Implementatie gebeurt in kleine fases met expliciete goedkeuring per fase
  (zie `docs/ARCHITECTURE.md`).

## Snelstart

```bash
tools/check-secrets.sh          # secretscan
deploy/install.sh --check       # dry-run: wat zou er veranderen?
deploy/install.sh               # daadwerkelijk installeren
```
