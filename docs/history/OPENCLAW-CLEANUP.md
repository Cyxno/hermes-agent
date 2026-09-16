# OpenClaw-cleanup

Uitgevoerd op 1 september 2026 nadat Hermes, Telegram, OpenRouter, cron en beide SSH-routes waren getest.

Verwijderd:

- container `openclaw`;
- image `ghcr.io/openclaw/openclaw:2026.8.1`;
- `/mnt/user/appdata/openclaw` inclusief compose, state, cache en oude jobs;
- Unraid Docker-template `my-OpenClaw.xml`;
- OpenClaw template-mapping uit Dynamix My Servers.

Gecontroleerd:

- geen OpenClaw-container;
- geen OpenClaw-appdata;
- geen OpenClaw-image;
- geen OpenClaw-cron/templateverwijzing;
- slechts Hermes gebruikt de Telegram-bot.

Behouden backup:

`/mnt/user/appdata/openclaw-backup-20260901-160741`

De backup is mode `0700` en bevat alleen de relevante config, `.env` en composefile. Hij bevat secrets en moet daarom niet naar Git of een onbeveiligde share worden gekopieerd. Gedeelde dependencies zoals Docker, Node.js, Python en Git zijn niet verwijderd.
