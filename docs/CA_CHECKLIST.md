# CA / Unraid Apps — readiness checklist (status 2026-10-06)

Verschil in één zin: de lokale DockerMan-template (`templates-user/my-Hermes-Agent.xml`)
maakt de **draaiende container beheerbaar in de Unraid Docker-tab**; Community
Applications-readiness vereist een **publieke, vindbare release-keten** (repo →
GHCR → template-bron → CA-submission) zodat "Apps → zoeken → Install" werkt voor
iedereen, met update-detectie en een schone first-install.

## Audit 2026-10-06 (bij soak-freeze rc.2)

- **Remote ontbreekt** — de homelab-kloon (én de v1-repo) heeft géén `git remote`;
  item 1 en de CI-workflows zijn daardoor nu onuitvoerbaar. Stap 1 is dus éerst:
  `git remote add github <URL-van-Cyxno/hermes-agent> && git push github main`.
- **GHCR-push werkt handmatig** — `~/.docker/config.json` heeft een geldige
  `ghcr.io`-auth; daarom bestaat `ghcr.io/cyxno/hermes-agent:2.0.0` al zonder dat
  er een git-tag of GitHub-release bestaat.
- **Tag-besluit nodig bij release**: die handmatige `2.0.0`-image verschilt van
  de soak-candidate (rc.2, zie `docs/SOAK-2026-10.md`). Advies: na een geslaagde
  soak uitbrengen als `v2.0.1` (schone, immutable keten). `v2.0.0` opnieuw pushen
  mag alleen vóór de eerste publieke aankondiging.
- `release.yml`/`ci.yml` zijn inhoudelijk correct (tag==pyproject wordt
  afgedwongen, GHCR-naming `ghcr.io/cyxno/hermes-agent`, semver+`latest`).

## Checklist

| # | item | status | actie |
|---|---|---|---|
| 1 | Repository push | ❌ lokaal alleen, géén remote geconfigureerd | `git remote add github <URL>` → `git push github main` |
| 2 | GHCR release | ❌ | tag pushen → `release.yml` bouwt en pusht `ghcr.io/cyxno/hermes-agent:{X.Y.Z,X.Y,latest}` (tag==pyproject wordt afgedwongen); tag-versie: zie audit-advies hierboven |
| 3 | Immutable digest | ✅ workflow | semver-tags zijn immutable; `latest` beweegt; digest in release notes vastleggen |
| 4 | Traceability | ✅ | VERSION/GIT_SHA/BUILD_TIME in image (verifieerbaar via `hermes version` + `/diagnostics`) |
| 5 | Template-bron | 🔶 | template staat in repo (`unraid/hermes-agent.xml`); voor CA: template moet via een publieke URL (raw.githubusercontent) of in de CA-template-repo-PR beschikbaar zijn; `Repository:`-veld wijst nu naar `:latest` |
| 6 | CA submission | ❌ | PR/registratie bij Community Applications (template + XML-conventies checken tegen de actuele CA-conventies op submission-moment; conventies zijn niet stabiel genoeg om nu blind te codificeren) |
| 7 | Icon/support/project URLs | ✅ | icon (selfhst CDN), support/project → GitHub-issues/repo |
| 8 | Update-detectie | 🔶 | werkt zodra GHCR-tags bestaan; het lokaal draaiende testexemplaar gebruikt lokale tag `2.0.0-rc.2` en zal "update-check" pas vinden na release 1 |
| 9 | Clean install | 🔶 | getest in containers/venv, niet als CA-first-install; doe één handmatige first-install-test na release (lege /data → wizard = config.example kopiëren is gedocumenteerd) |
| 10 | Upgrade-install | ✅ ontwerp | state/config in `/data`-volume overleeft recreate; schema-migraties met automatische backup; verifiëren bij eerste echte update |
| 11 | Persistentie | ✅ | `/data`: hermes.db + config.yaml + secrets.env (0600) |
| 12 | Rollback | ✅ | image-tag terugdraaien = recreate op oude digest; `/data` migraties maken een `.pre-migrate`-backup dat handmatig terug te zetten is |
| 13 | Veilige defaults | ✅ | template default `HERMES_MODE=shadow`, executor `dry-run` |

## Volgorde na deze validatiefase

1. push repo → 2. tag `v2.0.0` (GHCR live) → 3. template-URL fixen (raw GitHub) →
4. eigen first/upgrade-install testen → 5. CA-submission → 6. cutover-besluit
(volgens `docs/MIGRATION.md`).
