# Beveiliging

## Telegram en secrets

- Telegram allow-all staat uit; alleen de gemigreerde numerieke user-ID is toegestaan.
- `.env`, SSH-private keys en de OpenClaw-backup hebben mode `0600`/`0700` en staan buiten Git.
- Secrets zijn nergens in deze documentatie of testuitvoer opgenomen.
- Telegram draait in polling-modus; er is geen publiek webhook-endpoint nodig.

## Command approval

Hermes gebruikt `approvals.mode: manual`, timeout 600 seconden en `cron_mode`, `single_query_mode` en `unattended_mode` op `deny`. De persona vereist voor iedere write-actie eerst doel, globale stappen, impact en rollback plus expliciet akkoord.

Destructieve acties zoals mass delete, filesystem/arraywijzigingen, database-drop, security/firewalluitschakeling en reboot/shutdown vereisen altijd een aparte bevestiging en zijn niet opgenomen in de operator-allowlist.

## SSH-verdediging

- Ed25519-sleutels, restrictieve permissies en een gepinde `known_hosts`.
- Geen passwords, `StrictHostKeyChecking=no` of onbeperkte passwordless sudo.
- `agent-read` en `agent-operator` komen binnen als root, maar iedere key heeft een server-side forced-command dispatcher.
- Read heeft alleen een beperkte set observatieacties; operator heeft alleen start/stop/restart van één gevalideerde containernaam.
- Port-forwarding, agent-forwarding, PTY en user rc zijn door `restrict` uitgeschakeld.

Resterend risico: een kwaadaardige prompt kan proberen Hermes tot een operatorcommando te bewegen. De combinatie van de expliciete goedkeuringsregel, Hermes manual approvals en de kleine forced-command allowlist beperkt de impact, maar Telegram-accountbeveiliging en de OpenRouter/providerketen blijven onderdeel van het vertrouwensmodel.

