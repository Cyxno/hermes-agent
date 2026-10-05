# Migratie, shadow mode, cutover en rollback

Status per 2026-10-05: Hermes v1 draait onaangetast als productie
(container `hermes`, repo `/mnt/cache/src/hermes-setup`). Dit document is het
stappenplan voor de gecontroleerde overgang naar v2 (spec §48/§60-63).

## 0. Vereiste eenmalig: Beacon Agent API activeren

Beacon's Agent API is momenteel uit (geen token → 403 `DISABLED`). Hermes v2
heeft Beacon als primaire bron nodig.

1. Genereer een token (min. 32 tekens), bijv.:
   `openssl rand -hex 24`
2. Zet in de Unraid template `/boot/config/plugins/dockerMan/templates-user/my-unraid-dashboard.xml`
   het veld `AGENT_API_TOKEN` (staat er al, leeg) op die waarde.
   **Backup eerst**: `cp my-unraid-dashboard.xml my-unraid-dashboard.xml.bak-$(date +%Y%m%d-%H%M)`
3. Recreate de `unraid-dashboard` container via de Unraid Docker-tab (Update).
4. Verifieer: `curl -s -H "Authorization: Bearer <token>" http://127.0.0.1:8090/api/agent/v1/capabilities`
5. Vul hetzelfde token in de Hermes v2 template (`BEACON_AGENT_API_TOKEN`).

**Rollback**: token uit template halen → container opnieuw recreate → API is weer
403. Geen state-verlies (Beacon slaat niets van de Agent API persistent op).

## 1. Installatie v2 (shadow)

```bash
# 1. template plaatsen
cp unraid/hermes-agent.xml /boot/config/plugins/dockerMan/templates/my-Hermes-Agent.xml
# 2. config + secrets migreren vanuit v1 (schrijft ALLEEN in het v2-datapad)
docker run --rm -v /mnt/user/appdata/hermes-v2/data:/data -v /mnt/user/appdata/hermes/data:/legacy:ro \
  ghcr.io/cyxno/hermes-agent:latest --config /data/config.yaml migrate-legacy --legacy-home /legacy
#    -> /data/config.yaml (mode: shadow), /data/secrets.env (0600), migration-report.json
# 3. secrets.env waarden in de container-env zetten (Unraid template) of:
#    env van secrets.env in de template velden plakken
# 4. container starten via Unraid Apps (mode=shadow, executor=dry-run)
```

In shadow mode: volledige observatie + incidentvorming, **geen** echte meldingen
(optioneel `debug_chat_id`), executor geforceerd droog. Legacy Hermes blijft
draaien — **dubbele Telegram-alerts zijn onmogelijk** (v2 verstuurt niets).

## 2. Shadow-validatie (parallel, minimaal ~1 week)

Vergelijk dagelijks (v1: `notifications.jsonl`/`evaluator-events.jsonl` vs
v2: `hermes.db` incidents/signals + logs):

- false positives (v1 alarmeerde, v2 niet → terecht?)
- false negatives (v2 zag het niet)
- transient-suppressie, correlatiegroepering, AI-aantal, resource-footprint.

`curl http://<host>:8643` is niet extern bereikbaar; in de container:
`wget -qO- http://127.0.0.1:8643/diagnostics`.

## 3. Cutover (pas na geslaagde validatie)

```text
1. freeze legacy notifications  (v1: notifications.yaml telegram.enabled=false,
   of v1 container stoppen — kies bij voorkeur eerst alleen notificaties uit)
2. bevestig v2 shadow-state (geen openstaande valse incidenten)
3. v2 mode: shadow -> normal  (HERMES_MODE=normal + herstart v2)
4. observeer één dag
5. legacy Hermes container stoppen (niet verwijderen!)
6. na observatieperiode: executor mode dry-run -> guarded (bewuste stap)
7. legacy verwijderen (stap 4)
```

Update-gedrag: v2 updaten via de normale Unraid Docker-workflow (template-tag of
`latest`); `/data` volume behoudt state; schema-migraties draaien bij startup met
automatische backup (`hermes.db.pre-migrate-*`).

## 4. Rollback (bewezen pad)

```text
1. HERMES_MODE=shadow of container v2 stoppen
2. v1: notificaties weer aanzetten / container starten
3. v1 state is nooit aangeraakt door v2 (v2 schrijft alleen in /data van v2)
```

## 5. Legacy cleanup (stap 4 — alleen na bewijs)

Verwijderen (met backup in `/mnt/user/appdata/hermes/legacy-archive-<datum>/`):

- v1 container + compose (behoud image-tag referentie in backup)
- `/boot/config/plugins/user.scripts/scripts/Hermes evaluator fast|deep`,
  `Hermes host sampler`, `Docker event log` + bijbehorende cron-regels
- `/boot/config/plugins/hermes-host-sampler.sh`, `hermes-read-dispatch.sh`
  (alleen als v2-SSH-probe/operator ze niet meer gebruikt!), anders behouden
- `/mnt/cache/appdata/hermes/repo` (stale tweede working copy)
- v1 `.env`-sleutels die dood zijn: `HOMELAB_SNAPSHOT_URL`
- stray files: `data/agent_state.db` (0-byte), `data/backfill_occurrences.py`

Niet aanraken: Beacon, Netdata, Prometheus, gedeelde netwerken, andere cronjobs.
De `go`-file DUMB-referenties (rclone-mount die op een niet-bestaande container
wacht) zijn een aparte opschoontaak buiten Hermes-scope.
