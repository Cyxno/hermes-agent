# Changelog — hermes-setup

## 2026-09-24 — hardening: drift-repair, DUMBscope centraal, sampler-gap, fase 8 Netdata

- **Drift-repair (repo ← live)**: notifier, prometheus-module en host-sampler
  (DUMB/InfiniDysk v2 observe-only) waren live nieuwer dan de repo; live-versies
  zijn teruggezet in de repo. `hermes_changes.py` en `hermes_infinidysk.py`
  (verplichte imports van de evaluator) zijn nieuw in de repo + install-MAP.
  Na deze release is repo == live voor alle 16 deploy-targets; deploys
  uitsluitend via `deploy/install.sh`.
- **fase 8 — Netdata-alarminput** (`scripts/hermes_netdata.py`): read-only
  spiegel van actieve Netdata-alarms (GET /api/v1/alarms), allowlist, dedup
  tegen bestaande Hermes-checks (covered = evidence-only; critical alleen met
  bevestigende Hermes-sample), uncovered onderwerpen via de centrale
  incident-machine, recovery/stale/availability-semantiek. Zie
  `docs/ARCHITECTURE.md` fase 8.
- **fase 9a — DUMBscope centraal**: DUMBscope-incidenten lopen nu via
  `incident_upsert()` door de gewone incident/notifier-pipeline (warning+
  kan Telegram bereiken, recovery eenmaal, cooldowns/escalatie onveranderd).
  Fingerprint ongewijzigd; `dumbscope_incidents` blijft detail/history.
  Eénmalige silent seed van actieve incidenten bij activering.
- **fase 9b — sampler-gap** (`hermes:sampler:stale`): >10 min geen host-sample
  → warning, >30 min → urgent, herstel eenmaal met piek-staleness; DB-read-
  failure is nooit een (vals) herstel.
- **Tests**: run_test 122 cases (was 108): +DS1–DS7, +GAP1–GAP6b; netdata/
  dumbscope-clients in tests standaard gemockt (geen live HTTP).

## Eerder

Zie `docs/history/` en de git-geschiedenis (fase 0–7: sampler, evaluator,
deep-checks, DUMBscope-poll, notifier, LLM-router, Prometheus-context).

## 2026-09-24 (2) — seed-semantiek DUMBscope-centraal gerepareerd

- De initial seed van actieve DUMBscope-incidenten in de centrale
  incident-machine dempt de notificatie-graad naar notice (huispatroon,
  zie InfiniDysk-seed): state wél vastgelegd, géén Telegram en géén
  LLM-analyse bij koppeling; reële severity in last_reason; de eerste
  echte transitie daarna (escalatie/heropen) notificeert wél.
- Tests: DS8-DS10 (125/125). gepusht naar github.com/Cyxno/hermes-agent.
