# Migration, shadow mode, cutover and rollback

Status 2026-10-07: Hermes v2 is the production monitoring agent (2.0.1+);
Hermes v1 is stopped and retained as a rollback archive. This document
describes the original controlled migration path (spec §48/§60-63) and how a
fresh install joins the current baseline.

## 0. One-time prerequisite: enable the Beacon Agent API

Beacon's Agent API must be enabled (no token → 403 `DISABLED`). Hermes v2
needs Beacon as its primary source.

1. Generate a token (min. 32 chars), e.g.:
   `openssl rand -hex 24`
2. Put it in the unraid-dashboard template field `AGENT_API_TOKEN` and
   recreate the dashboard container.
3. Verify: `curl -s -H "Authorization: Bearer <token>" http://127.0.0.1:8090/api/agent/v1/capabilities`
4. Put the same token in the Hermes v2 template (`BEACON_AGENT_API_TOKEN`).

**Rollback**: remove the token from the template → recreate → the API is
disabled again.

## 1. Fresh install (2.x)

1. Install the app from the Unraid template (`unraid/hermes-agent.xml`);
   defaults: `HERMES_MODE=shadow`, executor `dry-run`.
2. Fill in: `BEACON_AGENT_API_TOKEN`, `TELEGRAM_BOT_TOKEN`,
   `TELEGRAM_HOME_CHAT_ID`, optional `OPENROUTER_API_KEY`,
   optional `HERMES_TG_ALLOWED` / `HERMES_TG_ALLOWED_USER_IDS`.
3. Start; verify `/health` and `/diagnostics`; watch shadow behaviour
   (nothing leaves the machine).
4. Promote: set `HERMES_MODE=normal`. Executor stays `dry-run`.

## 2. Migration from v1 (historical path)

`hermes migrate-legacy` imports the v1 `.env` values (Telegram/OpenRouter)
into `/data/secrets.env` (0600) and maps v1 thresholds. Wire the secret values
into the container environment; `secrets.env` itself is not read at runtime.

## 3. Cutover (done 2026-10-06)

- v1 scheduling disabled (cron + user.scripts), v1 container stopped,
  restart policy `no` — rollback archive retained under
  `/mnt/cache/appdata/hermes/` (see its `migration-backup-*/RESTORE.md`).
- v2 promoted to `mode=normal` with executor `dry-run`.

## 4. Rollback to v1 (emergency only)

Documented in the backup's `RESTORE.md`: stop v2 → re-enable v1 cron lines
(+ SIGHUP crond) → `docker update --restart unless-stopped hermes && docker
start hermes`.

## 5. Upgrades (2.x → 2.x)

Back up `/mnt/user/appdata/hermes-v2/data/` (hermes.db, config.yaml,
secrets.env) → recreate the container on the new image tag → verify
`/diagnostics` (version/GIT_SHA), DB integrity and state counts. SQLite
schema migrations run automatically and create a `.pre-migrate` backup.
