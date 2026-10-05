# CA / Unraid Apps — readiness checklist (status 2026-10-06)

Verschil in één zin: de lokale DockerMan-template (`templates-user/my-Hermes-Agent.xml`)
maakt de **draaiende container beheerbaar in de Unraid Docker-tab**; Community
Applications-readiness vereist een **publieke, vindbare release-keten** (repo →
GHCR → template-bron → CA-submission) zodat "Apps → zoeken → Install" werkt voor
iedereen, met update-detectie en een schone first-install.

## Checklist

| # | item | status | actie |
|---|---|---|---|
| 1 | Repository push | ❌ lokaal alleen | `git push github main` naar `github.com/Cyxno/hermes-agent` (remote bestaat al in v1-repo-conventie) |
| 2 | GHCR release | ❌ | tag `v2.0.0` pushen → `release.yml` bouwt en pusht `ghcr.io/cyxno/hermes-agent:{2.0.0,2.0,latest}` (tag==pyproject wordt afgedwongen) |
| 3 | Immutable digest | ✅ workflow | semver-tags zijn immutable; `latest` beweegt; digest in release notes vastleggen |
| 4 | Traceability | ✅ | VERSION/GIT_SHA/BUILD_TIME in image (verifieerbaar via `hermes version` + `/diagnostics`) |
| 5 | Template-bron | 🔶 | template staat in repo (`unraid/hermes-agent.xml`); voor CA: template moet via een publieke URL (raw.githubusercontent) of in de CA-template-repo-PR beschikbaar zijn; `Repository:`-veld wijst nu naar `:latest` |
| 6 | CA submission | ❌ | PR/registratie bij Community Applications (template + XML-conventies checken tegen de actuele CA-conventies op submission-moment; conventies zijn niet stabiel genoeg om nu blind te codificeren) |
| 7 | Icon/support/project URLs | ✅ | icon (selfhst CDN), support/project → GitHub-issues/repo |
| 8 | Update-detectie | 🔶 | werkt zodra GHCR-tags bestaan; het lokaal draaiende testexemplaar gebruikt lokale tag `2.0.0` en zal "update-check" pas vinden na release 1 |
| 9 | Clean install | 🔶 | getest in containers/venv, niet als CA-first-install; doe één handmatige first-install-test na release (lege /data → wizard = config.example kopiëren is gedocumenteerd) |
| 10 | Upgrade-install | ✅ ontwerp | state/config in `/data`-volume overleeft recreate; schema-migraties met automatische backup; verifiëren bij eerste echte update |
| 11 | Persistentie | ✅ | `/data`: hermes.db + config.yaml + secrets.env (0600) |
| 12 | Rollback | ✅ | image-tag terugdraaien = recreate op oude digest; `/data` migraties maken een `.pre-migrate`-backup dat handmatig terug te zetten is |
| 13 | Veilige defaults | ✅ | template default `HERMES_MODE=shadow`, executor `dry-run` |

## Volgorde na deze validatiefase

1. push repo → 2. tag `v2.0.0` (GHCR live) → 3. template-URL fixen (raw GitHub) →
4. eigen first/upgrade-install testen → 5. CA-submission → 6. cutover-besluit
(volgens `docs/MIGRATION.md`).
