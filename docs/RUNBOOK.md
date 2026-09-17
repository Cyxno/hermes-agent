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

## Evaluator (fase 3, dry-run)

```bash
# handmatig (one-shot container, uid 10000; geen gateway/telegram)
docker run --rm -u 10000:10000 --entrypoint /opt/hermes/.venv/bin/python \
  -v /mnt/user/appdata/hermes/data:/opt/data -e HERMES_HOME=/opt/data \
  nousresearch/hermes-agent:latest /opt/data/scripts/hermes_evaluator.py fast   # of deep / test
```

- Synthetische tests: `… hermes_evaluator.py test` (20 cases, verwacht 20/20).
- Baseline: `… hermes_evaluator.py baseline-report` → `homelab/baseline-report.json`.
- Audit: `jq -r '[.ts,.fingerprint,.severity,.state,.reason]|@tsv' homelab/evaluator-events.jsonl`.
- State: `homelab/agent_state.db` — incidents/metric_state/counters/cursors.
- Cron: user.scripts "Hermes evaluator fast" (7,22,37,52) + "deep" (23 * * * *).

## Telegram-notificaties (fase 4.5, deterministisch)

- `hermes_notifier.py` — 100% deterministic: geen LLM, geen remediation.
- Policy: `config/notifications.yaml` (min_severity, cooldowns, retry/backoff).
  NORMAL/NOTICE -> nooit; WARNING -> alleen nieuw/escalatie; URGENT/CRITICAL ->
  direct (+ reminder na cooldown); RESOLVED -> één herstelbericht na eerdere melding.
- Escalatie negeert cooldowns altijd; unchanged incidents worden niet herhaald.
- Integratie: evaluator `fast` roept de notifier na afloop aan (failure-isolated);
  ook standalone: `… python hermes_notifier.py run|test|send-test`.
- Audit: `jq -c '{ts,fingerprint,severity,event,attempted,delivered,error}' homelab/notifications.jsonl`.
- Token: uitsluitend `TELEGRAM_BOT_TOKEN`/`TELEGRAM_HOME_CHANNEL` in `data/.env`
  (nooit gelogd, nooit in Git of state-db).
- Delivery-failure: pending + retry met backoff (60s→max 15min); ≥3 mislukkingen
  achter elkaar = lokaal incident `notifications:delivery`, geen Telegram-recursie.

## LLM-router (fase 5) — NOG NIET ACTIEF (llm.enabled: false)

```bash
# live micro-smoketest per tier (gebruikt .env key):
docker run --rm -u 10000:10000 --entrypoint /opt/hermes/.venv/bin/python \
  -v /mnt/user/appdata/hermes/data:/opt/data -e HERMES_HOME=/opt/data \
  nousresearch/hermes-agent:latest /opt/data/scripts/hermes_router.py smoke tier1 5
```

- Audit: `jq -c '{ts,requested_model,actual_model,confidence,routing_violation,error}' \
  homelab/router_calls.jsonl`
- Limieten/drempels: `thresholds.yaml` sectie `llm` (3/incident, 8/dag, conf-stop 0,85).
- Routerstate: llm_*-kolommen op `incidents` in agent_state.db.
