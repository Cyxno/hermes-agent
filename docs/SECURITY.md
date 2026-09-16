# Beveiliging — Hermes homelab (status sept 2026)

## Toegangsmodel

- Container `hermes`: niet privileged, `no-new-privileges:true`, geen Docker-socket,
  enige mount = `/mnt/user/appdata/hermes/data` → `/opt/data` (RW), limiet 4 GB / 2 CPU.
- Container→host uitsluitend via SSH met twee Ed25519-identiteiten naar
  `root@192.168.1.2`; elke key heeft in `authorized_keys` `restrict` + forced command
  naar één van de twee dispatchers (`host/*.sh`, live op `/boot/config/plugins/`).
  PTY, port/agent-forwarding en user-rc zijn uitgeschakeld; `known_hosts` is gepind;
  host-key-bypass is verboden.
- `agent-read`: read-only allowlist met harde uitvoercaps; weigert `.env`, keys,
  `secrets/`, `operator-state/`. `agent-operator`: allowlist met wrappers, plantokens
  (10 min TTL, single-use), `CONFIRM-DANGEROUS` tweede bevestiging en audit naar
  `operator-audit.jsonl` (600). Schrijf-roots alleen `/mnt/user/appdata/*` en
  `/mnt/vm_storage/config/*`.

## Approval-keten (schrijfacties)

1. Hermes `approvals.mode: manual`; `cron_mode`, `single_query_mode`, `unattended_mode`
   = `deny`.
2. `SOUL.md`: diagnose + target + impact + rollback + expliciet akkoord vereist.
3. Server-side forced-command allowlist (dispatcher).
4. Plantokens + tweede bevestiging voor dangerous + auditlog.

## Secrets

- Waarden staan uitsluitend live: `data/.env` (600), `data/secrets/` (700),
  SSH-keys (600), `authorized_keys` (600 root). Niets daarvan komt in deze repo;
  `tools/check-secrets.sh` scant vóór elke commit.
- Bekende opruimpunten (bewust nog niet gewijzigd): SSH-keys staan gedupliceerd in
  `data/.ssh` én `data/home/.ssh`; het ArrSight-adminwachtwoord staat twee keer;
  Sonarr/SAB-keys in `.env` worden door de monitor niet gebruikt.

## Bekende resterende risico's

- Beide SSH-identiteiten komen binnen als root; de forced-command allowlist is de enige
  grens — een dispatcherbug is root.
- Telegram-account- en OpenRouter-providerketen maken deel uit van het vertrouwensmodel.
- De operator-allowlist is ruimer dan de v1-documentatie beschreef (compose, VM-beheer,
  file-replace, dangerous-plans); `docs/history/HERMES-SECURITY-v1.md` is daarin
  verouderd — dit document is leidend.
