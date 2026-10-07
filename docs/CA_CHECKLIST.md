# CA / Unraid Apps — readiness checklist (status 2026-10-07)

One-sentence difference: the local DockerMan template
(`templates-user/my-Hermes-Agent.xml`) makes the **running container
manageable in the Unraid Docker tab**; Community Applications readiness
requires a **public, discoverable release chain** (repo → GHCR → template
source → CA submission) so that "Apps → search → Install" works for everyone,
with update detection and a clean first install.

## Audit 2026-10-06 (soak freeze rc.2) — updated 2026-10-07

- **Remote** — resolved 2026-10-06: `github` remote configured
  (`git@github.com:Cyxno/hermes-agent.git`); main and tags are pushed.
- **GitHub Actions** — workflows exist and are syntactically valid
  (`ci.yml`: push/PR to main; `release.yml`: tags `v*`), but no run was ever
  observed, including after `v2.0.0`/`v2.0.1` tag pushes. Everything points at
  repository-level Actions being disabled; the 2.1 release process re-tests
  this via the `v2.1.0-rc.1` tag and documents the outcome.
- **GHCR** — works manually (`~/.docker/config.json` has valid ghcr.io auth);
  `2.0.0`, `2.0.1`, `2.0`, `latest` and the rc tags exist.
- **Tag decision** — v2.0.0/v2.0.1 are released; 2.1.0 introduces guarded
  self-healing (semver: minor bump).
- `release.yml`/`ci.yml` are content-correct (tag==pyproject enforced, GHCR
  naming `ghcr.io/cyxno/hermes-agent`, semver + `latest`, rc tags must not
  move `latest`).

## Checklist

| # | item | status | action |
|---|------|--------|--------|
| 1 | Repository push | ✅ | `github` remote; main + tags pushed |
| 2 | GHCR release | ✅ (manual fallback) / ⏳ pipeline proof | tag push → `release.yml` builds/pushes `{X.Y.Z,X.Y,latest}`; see RELEASE.md |
| 3 | Immutable digests | ✅ | semver tags immutable-by-convention; `latest` moves; digest recorded per release |
| 4 | Traceability | ✅ | VERSION/GIT_SHA/BUILD_TIME embedded (verify via `hermes version` + `/diagnostics`) |
| 5 | Template source | 🔶 | template lives in repo (`unraid/hermes-agent.xml`); for CA it must be reachable via a public URL (raw GitHub) or the CA template repo PR; `Repository:` field currently points to `:latest` |
| 6 | CA submission | ❌ | PR/registration with Community Applications (validate XML conventions at submission time) |
| 7 | Icon/support/project URLs | ✅ | icon (selfhst CDN), support/project → GitHub issues/repo |
| 8 | Update detection | ✅ | works now that GHCR tags exist (`2.0`/`latest` channels) |
| 9 | Clean install | ✅ | proven 2026-10-07 (isolated empty `/data`: boots, schema init, dry-run default) |
| 10 | Upgrade install | ✅ | proven 2.0.0→2.0.1 and rc→2.0.0; `/data` survives recreates, auto schema migration + `.pre-migrate` backup |
| 11 | Persistence | ✅ | `/data`: hermes.db + config.yaml + secrets.env (0600) |
| 12 | Rollback | ✅ | image tag rollback = recreate on old digest; schema migrations create a `.pre-migrate` backup |
| 13 | Safe defaults | ✅ | template defaults `HERMES_MODE=shadow`, executor `dry-run`, `real_actions_enabled=false` |

## Order after this phase

1. prove Actions via `v2.1.0-rc.1` → 2. release `v2.1.0` through the pipeline
→ 3. template URL fix (raw GitHub) → 4. first/upgrade install tests → 5. CA
submission.
