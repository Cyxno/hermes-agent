# Runbook — Hermes homelab

## Statuscheck

```bash
docker ps -a --filter name=hermes
sqlite3 "file:/mnt/user/appdata/hermes/data/homelab/samples.db?mode=ro" \
  'select datetime(ts,"unixepoch","localtime"), vdisk_pct, mem_used_pct from samples order by ts desc limit 3;'
tail -3 /mnt/user/appdata/hermes/operator-audit.jsonl
```

## Repo → live uitrollen

```bash
cd /mnt/user/src/hermes-setup
tools/check-secrets.sh
deploy/install.sh --check     # dry-run; exit 1 bij pending wijzigingen
deploy/install.sh             # uitvoeren
```

SSH-identiteiten/authorized_keys alleen bewust wijzigen:
`deploy/install-ssh-identities.sh` (idempotent; herschrijft de twee hermes-regels in
`/root/.ssh/authorized_keys` en vult `known_hosts`).

## Host-sampler (fase 1)

- Handmatig: `bash /boot/config/plugins/hermes-host-sampler.sh` (met
  `HERMES_SAMPLER_VERBOSE=1` voor JSON-op stdout; de flash is noexec, dus altijd
  via `bash` aanroepen — net als de dispatchers).
- Cron: user.scripts-entry "Hermes host sampler", `*/5 * * * *` — draait bewust
  ónáfhankelijk van de Hermes-container.
- DB: `/mnt/user/appdata/hermes/data/homelab/samples.db` (WAL, busy_timeout 5000,
  raw 48 u, rollup 90 d, owner 10000:10000).

## Hermes container

```bash
docker start hermes                                   # gateway start automatisch
docker exec -it hermes bash                           # binnenwerken (root)
```
Monitoring-jobs (fase 3+) worden via Hermes' interne cron beheerd; staat de container
uit dan blijft de host-sampler gewoon draaien.

## Noodprocedure

- Sampler stil: `tail /var/log/syslog | grep hermes-sampler`; handmatige run met
  `bash -x`.
- Verdenking op lock: `sqlite3 samples.db 'pragma integrity_check;'` — WAL herstelt
  zelf na crash; nooit handmatig `-wal`/`-shm` wissen terwijl processen leven.
- Rollback deployment: vorige git-revisie uitchecken + `deploy/install.sh`.
