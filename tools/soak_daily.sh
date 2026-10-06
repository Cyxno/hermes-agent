#!/bin/bash
# Dagelijkse shadow-soak rapportage (host-side wrapper).
#
# Roept tools/shadow_report.py aan in een one-shot container (zelfde image als
# de shadow-candidate) en vult de host-reliability metrics aan vanuit docker:
# error-logregels, gefaalde cycli, beacon/netdata-faalcycli, SSE-disconnects,
# restarts en uptime. Read-only naar alle data; schrijft alleen het rapport.
#
# Output: /mnt/user/appdata/hermes-v2/reports/shadow-YYYY-MM-DD.md
set -euo pipefail

REPO=/mnt/user/src/hermes-v2
V2DATA=/mnt/user/appdata/hermes-v2/data
V1DATA=/mnt/user/appdata/hermes/data/homelab
OUTDIR=$V2DATA/reports
IMAGE=ghcr.io/cyxno/hermes-agent:2.0.0-rc.2
WINDOW_H=24

mkdir -p "$OUTDIR"

LOGS=$(docker logs --since "${WINDOW_H}h" hermes-v2 2>&1 || true)
docker_errors=$(grep -c '"level": "error"' <<<"$LOGS" || true)
cycle_failures=$(grep -c 'cycle faalde' <<<"$LOGS" || true)
beacon_failures=$(grep -c '"beacon": {"ok": false' <<<"$LOGS" || true)
netdata_failures=$(grep -c '"netdata": {"ok": false' <<<"$LOGS" || true)
sse_disconnects=$(grep -c 'stream error' <<<"$LOGS" || true)
restarts=$(docker inspect hermes-v2 --format '{{.RestartCount}}')
started=$(docker inspect hermes-v2 --format '{{.State.StartedAt}}')
uptime_s=$(( $(date +%s) - $(date -u -d "$started" +%s) ))
uptime_hours=$(awk "BEGIN{printf \"%.1f\", $uptime_s/3600}")

docker run --rm \
  -v "$REPO":/work:ro \
  -v "$V2DATA":/data:ro \
  -v "$V1DATA":/legacy/homelab:ro \
  --entrypoint python "$IMAGE" /work/tools/shadow_report.py \
    --v2-db /data/hermes.db \
    --v1-notifications /legacy/homelab/notifications.jsonl \
    --window-hours "$WINDOW_H" \
    --docker-errors "$docker_errors" \
    --cycle-failures "$cycle_failures" \
    --beacon-failures "$beacon_failures" \
    --netdata-failures "$netdata_failures" \
    --sse-disconnects "$sse_disconnects" \
    --restarts "$restarts" \
    --uptime-hours "$uptime_hours" \
  > "$OUTDIR/shadow-$(date +%F).md"

echo "rapport geschreven: $OUTDIR/shadow-$(date +%F).md"
