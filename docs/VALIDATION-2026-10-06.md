# Shadow-validatierapport — 2026-10-06

Periode: eerste shadow-sessies (2026-10-05 21:36 → 2026-10-06, meerdere herdeploys
na fixes; containers herstart tellen als v2-restarts, geen v1-raken). De doorlopende
shadow-periode start met image `10776fd` (git `548f4f8`-opvolger); de tooling
(`tools/shadow_report.py`) verzamelt de statistieken dagelijks verder.

## 1. State-verificatie bij start (bewijs)

| check | resultaat |
|---|---|
| v1 draait + verstuurt productie | ✅ `hermes` Up 3 days; `notifications.jsonl` laatste verzending 2026-10-05 18:22 UTC; 10–24 meldingen/dag |
| v2 shadow | ✅ `/diagnostics`: mode=shadow, executor=dry-run, sse=ok |
| Beacon Agent API | ✅ capabilities 200 (beaconVersion 1.3.18) |
| Netdata | ✅ v2.11.1 bereikbaar |
| SQLite | ✅ `integrity_check: ok` |
| v2 Telegram | ✅ 0 verzonden, 0 polls (bot-token bewust niet gezet in shadow) |
| Dubbele productie-alerts | ✅ onmogelijk: v2 verstuurt niets (notifier shadow-record) |

## 2. Desired-state audit + "hemer"

- **`hemer` bestaat niet** in de registry; de entries zijn `DUMB, decypharr, hermes`
  → "hemer" is een typo van `hermes` in de rapportage.
- `hermes → RETIRED` is bewust en bewijsbaar: v1 `thresholds.yaml`
  `docker_daemon.known_stopped: [hermes]` — de legacy-container is bij cutover
  verwacht-afwezig; v2 mag er nooit een incident op genereren.
- **Correctie uitgevoerd** (met bewijs): `postgres` stond MANAGED maar er bestaat
  géén container `postgres` op de host → `postgres → RETIRED`
  (`origin=validation-2026-10-06`). Het daaruit ontstane test-incident
  `container_exit:postgres` is via absence-resolutie vanzelf opgelost; nul notificaties.
- `plexdb-ro → MANAGED` (origin=validation): productie-kritieke Plex-postgres,
  het enige echte actieve incident; nodig voor een betekenisvol dry-run-voorbeeld.
- Legacy-incidenten in v2: 0 (grep: geen legacy-code behalve migratie-strings).

## 3. Gevalideerde fixes deze fase (elk met bewijs + test)

| # | bevinding | bewijs | fix | test |
|---|---|---|---|---|
| F1 | MANAGED-container die volledig uit de inventaris verdwijnt gaf nooit een signaal | `postgres` MANAGED + afwezig + 0 incidents | absence-regel voor MANAGED-entities | `test_managed_absence_from_inventory_detected` |
| F2 | final-recheck voor container_exit behandelde inventaris-afwezigheid als herstel | radarr-repro: PENDING→RESOLVED→PENDING | afwezigheid = bevestiging voor MANAGED | idem + suite |
| F3 | raw-signalen werden niet bewaard → noise-funnel onmeetbaar | signals-tabel leeg | bounded persist (1 row/fingerprint/5min + escalaties) | `test_signal_rows_bounded_per_fingerprint` |
| F4 | `storage_used_pct` was dode code (collector vulde niets) | 0 metingen in 12u shadow | Beacon capacity+disks → band | `test_storage_pressure_band_from_beacon` |
| F5 | gestopte container (netdata `not_running_unhealthy`) → 5 valse unhealthy-transients + onterecht pattern-incident (watchtower) | transients-tabel + netdata-dims | `not_running_unhealthy → None` (lifecycle is Beacon-domein) | `test_netdata_container_health_states` |
| F6 | runbook-CLI had geen HTTP-wiring (`container_exists` faalde foutief) | live run | `HermesApp.wire_http()` | suite + live dry-run |
| F7 | storage-recheck haalde geen verse storage-data op | code-review | `_fresh_beacon(storage=True)` | suite |

## 4. Threshold-beoordeling (alleen 1 wijziging, met bewijs)

| metric | waarde | echte historie | besluit |
|---|---|---|---|
| RAM % | warn 90 / crit 95 | 48u p95=74 max=77; 90d uurlijkse p99=82.2, max 91 (1x) | **behouden** — ruim p99-marge, waarschuwt alleen bij uitzonderlijke events |
| host CPU % | warn 85 / crit 95, sustain 300s | 7d (20min-avg): p95=33 p99=49 max=64 | **behouden** — nooit ruis; alleen echte all-core episodes (load5 tot 477!) |
| load5/core | warn 2.0 | load5 p95=11.8 (0.74/core), p99=142 (8.9/core) | **behouden, watch-list** — episodes zijn echt (builds); v1/netdata alerteren hier ook op (pariteit) |
| package temp | warn 95 / crit 98, **sustain 180→600s** | 48u: p50=75, p95=91, **p99=100 (Tjmax)**; v1 stuurde vandaag 4 temp-berichten (new+recovery paren) | **gewijzigd** — oude waarde 180s zou bij elke build alarmeren; 600s = v1's eigen "≥10 min"-urgentlijn. Verwacht effect: alleen aanhoudende thermische load melding, micro-spikes stil |
| disk await | warn 50 / crit 200 ms | 7d p99 max 26.8 (sdf), max 30.9 | **behouden** — normale drukte blijft ver onder drempel; falende schijf scoort honderden ms |
| container throttling | warn 25% | 7d: plex/immich-ml throttle = 0 (geen CPU-limieten) | **behouden** — alleen betekenisvol bij gelimiteerde containers |
| container unhealthy | debounce 90s | plexdb-ro 2-bronnen-bevestigd; watchtower valse transients = F5 | **behouden** (na F5-fix schoon) |
| storage pressure | warn 80 / crit 88 | cache 41%, array 62% huidig | **behouden** + collector-fix F4 |
| anomaly rate | warn 0.05, sustain 600s | 12u: p50=0.0057, p95=0.0526, max=0.1324, 3 geïsoleerde punten >0.05 → geen enkele alert | **behouden** — sustain dempt isolatie pieken precies goed |

## 5. Beacon ↔ Netdata fusie (live bewijs)

| situatie | waarneming | v2-gedrag |
|---|---|---|
| Beacon unhealthy + Netdata unhealthy | plexdb-ro | CONFIRM (2 bronnen) → warning incident ✓ |
| Beacon "unhealthy" (maar gestopt) + Netdata `not_running_unhealthy` | watchtower, helper-pre-cachemig | geen alarm (bewust gestopte containers) ✓ na F5 |
| Netdata anomaly > warn (isolatie pieken) | 3/60 punten in 12u | geen alert (sustain) ✓ latent candidate mecanisme actief |
| Beacon warning + Netdata normaal | load-alarm episode | incident blijft single-source warning met expliciete evidence "alleen beacon" ✓ |

## 6. Final-recheck, flapping, correlatie

- **Final-recheck**: mechanisme live getriggerd tijdens F2-repro (postgres-candidaat
  geannuleerd door recheck vóór verzending; daarna correct omgekeerde semantiek).
  Suite dekt alle 4 gevallen (cancel, transient, reminder, root). Teller in
  `shadow_report.py` ("final-recheck cancellations") bewaakt de productie-gate.
- **Flapping**: 84/86-CPU-test bewijst geen band-open; watchtower toonde aan dat
  flapperende valse signalen als transients landen en pas bij ≥5/6u een pattern-
  incident vormen (mechanisme live bewezen; na F5 tegelijkertijd de foute bron weg).
- **Correlatie**: geen echte multi-service storage-episode in deze korte window;
  mechanisme is suite-bewezen (3 containers + disk-await → 1 root, children
  suppressed, 1 alert). Root-recheck gelekt niet meer (F2-familie fix).

## 7. Executor (dry-run, live voorbeeld)

Live runbook op het echte incident `container_unhealthy:plexdb-ro`:

```text
outcome=would_execute runbook=container_unhealthy
audit e3946889: capability=docker.restart target=plexdb-ro
  preconditions={"lifecycle":"MANAGED","attempts":0}  policy=allow
  result=would_execute mode=dry_run
```

- Voorafging: zelfde runbook op DISCOVERED-target → policy **deny** (safe-default bewezen).
- Geen echte mutaties uitgevoerd; er is ook géén SSH-operator-key geconfigureerd
  (transport-fysiek afwezig).

## 8. AI

- `ai_calls` = 0; key bewust niet gezet → NullProvider ("deterministic path default").
- Tier-config verifieerbaar: tier1 `inclusionai/ling-3.0-flash`, tier2
  `deepseek/deepseek-v4-flash-0731` alleen via deterministische escalatiecriteria
  (suite: low-confidence, invalid-output, insufficient-evidence, budget-tests).
- De pipeline bevat géén AI-call-site: geen metric/event kan een LLM-call veroorzaken.
- AI-`proposedActions` worden nergens uitgevoerd (alleen getoond in `/investigate`);
  executor-input komt uitsluitend uit runbooks + policy.

## 9. Statistieken (startsessies, zie tools/shadow_report.py voor doorlopende cijfers)

| metric | waarde |
|---|---|
| shadow runtime | ~3u over 4 deploys (doorlopende meting start nu) |
| cycles | ~40 fast + 8 reconcile (foutvrij na laatste deploy) |
| incidenten gezien | 11 (waarvan 1 test-uit-loop postgres) |
| confirmed | 10 |
| suppressed transients | 5 (alle watchtower, pre-F5) |
| final-recheck cancellations | 1 (F2-casus) |
| notificatiewaardig (shadow) | 8 records, 0 verzonden |
| false positives gevonden | F5-watchtower (5), postgres-absence (F1/F2, 1) — beide gefixt |
| suspected false negatives | v1 temperature-paren (door sustain-fix gedekt), storage-dead-rule (F4) |
| AI calls | 0 |
| executor proposals | 1 would_execute (plexdb-ro), 1 deny (DISCOVERED-target) |
| errors in logs | 0 na laatste deploy |
| v2 restarts | 4 (deploys door fixes) |
| footprint | 37 MiB RAM, 0.00% idle CPU, cycle 3–5s/min |
