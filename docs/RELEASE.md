# Release process

## Versioning

- Semver: `MAJOR.MINOR.PATCH`. New capabilities → minor (2.1.0 was guarded
  self-healing); pure fixes → patch.
- **Single source of truth**: `pyproject.toml` `project.version`. Runtime
  (`hermes/__init__.VERSION` via importlib.metadata), `/diagnostics`,
  `/status`, CLI output and image metadata all derive from it.
- Prereleases: `X.Y.Z-rc.N` (e.g. `2.1.0-rc.1`) for validation only.

## Immutable tags (hard rule)

> Once a release tag has been pushed: **NEVER move it, NEVER force-update it.**

- Broken release `2.0.1`? → release `2.0.2`. Never "move v2.0.1".
- Anyone with a checkout of the old tag would silently get different bits.
- Exception that required a forced tag move must never happen again; it is
  on record only because it happened within the same minute as the initial
  push, before anyone consumed the tag (2.0.1, 2026-10-07).

## Pipeline

1. commit → 2. version bump in `pyproject.toml` → 3. CI green on main
   (`ci.yml`: pytest + ruff + secret-pattern gate + container build sanity)
   → 4. push immutable tag `vX.Y.Z` → 5. `release.yml`:
   - gate: tag version == pyproject version (enforced, fails otherwise)
   - pytest + ruff
   - buildx build → push to GHCR:
     `ghcr.io/cyxno/hermes-agent:{X.Y.Z, X.Y, latest}`
     - stable tags only; `X.Y.Z-rc.*` prereleases publish
       `X.Y.Z-rc.N` + `X.Y-rc` and **never** move `latest`
   - GitHub release with notes (image, git sha, build time, digest)

## Verification after publication

```bash
docker pull ghcr.io/cyxno/hermes-agent:X.Y.Z
docker run --rm --entrypoint python ghcr.io/cyxno/hermes-agent:X.Y.Z \
  -m hermes --config /dev/null version
# expect: X.Y.Z (<git sha> built <build time>) — must match the tag commit
```

Record tag → commit → digest in the release notes.

## Manual fallback (emergency only)

If GitHub Actions is unavailable (see CA_CHECKLIST.md audit history):
build locally with workflow-identical arguments and push the exact same tags:

```bash
docker build \
  --build-arg VERSION=X.Y.Z \
  --build-arg GIT_SHA=$(git rev-parse HEAD) \
  --build-arg BUILD_TIME=$(date -u +%Y-%m-%dT%H:%M:%SZ) \
  -t ghcr.io/cyxno/hermes-agent:X.Y.Z \
  -t ghcr.io/cyxno/hermes-agent:X.Y \
  -t ghcr.io/cyxno/hermes-agent:latest .
docker push ghcr.io/cyxno/hermes-agent:X.Y.Z   # etc.
```

Document every manual release in the audit trail; the pipeline remains the
normal expected mechanism.

## Production upgrade

1. Back up `/mnt/user/appdata/hermes-v2/data/` (hermes.db, config.yaml,
   secrets.env).
2. Recreate the container on the new image tag, same env/volumes.
3. Verify `/diagnostics` (VERSION/GIT_SHA), DB integrity, state counts,
   Beacon/Netdata/Telegram health; expect **zero notification storm**
   (existing incidents keep their notification bookkeeping).
4. Executor defaults stay safe: upgrades never change the configured
   executor mode or `real_actions_enabled`.
