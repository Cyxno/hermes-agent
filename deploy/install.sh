#!/bin/bash
# deploy/install.sh — idempotente installatie: repo → live locaties.
#
# Gebruik:
#   deploy/install.sh --check      dry-run: toont wat er zou veranderen (exit 1 bij wijzigingen)
#   deploy/install.sh              voert de installatie uit
#   deploy/install.sh --check -v   dry-run met diff-uitvoer
#
# Deze installer:
#   - kopieert uitsluitend de bestanden uit MAP hieronder, met vaste rechten/owner;
#   - raakt GEEN secrets aan (.env, ssh-keys, secrets/ blijven live-only);
#   - raakt authorized_keys/known_hosts NIET aan — dat is expliciet
#     deploy/install-ssh-identities.sh werk (apart, bewust uitvoeren).
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HERMES_APPDATA=/mnt/user/appdata/hermes
CHECK=0; VERBOSE=0
for arg in "$@"; do
  case "$arg" in
    --check) CHECK=1 ;;
    -v) VERBOSE=1 ;;
    *) echo "onbekend argument: $arg" >&2; exit 64 ;;
  esac
done

# bron (repo, relatief) | doel (absoluut) | mode | uid | gid
MAP=(
  "compose/docker-compose.yml|$HERMES_APPDATA/compose/docker-compose.yml|600|0|0"
  "config/config.yaml|$HERMES_APPDATA/data/config.yaml|600|10000|10000"
  "config/SOUL.md|$HERMES_APPDATA/data/SOUL.md|600|10000|10000"
  "config/thresholds.yaml|$HERMES_APPDATA/data/thresholds.yaml|600|10000|10000"
  "config/notifications.yaml|$HERMES_APPDATA/data/notifications.yaml|600|10000|10000"
  "host/hermes-read-dispatch.sh|/boot/config/plugins/hermes-read-dispatch.sh|700|0|0"
  "host/hermes-operator-dispatch.sh|/boot/config/plugins/hermes-operator-dispatch.sh|700|0|0"
  "host/hermes-host-sampler.sh|/boot/config/plugins/hermes-host-sampler.sh|700|0|0"
  "scripts/hermes_evaluator.py|$HERMES_APPDATA/data/scripts/hermes_evaluator.py|700|10000|10000"
  "scripts/hermes_router.py|$HERMES_APPDATA/data/scripts/hermes_router.py|700|10000|10000"
  "scripts/hermes_dumbscope.py|$HERMES_APPDATA/data/scripts/hermes_dumbscope.py|700|10000|10000"
  "scripts/hermes_notifier.py|$HERMES_APPDATA/data/scripts/hermes_notifier.py|700|10000|10000"
)

pending=0; installed=0; same=0; skipped=0
printf '%-42s %-8s %s\n' "BESTAND" "STATUS" "DOEL"
printf '%.0s-' {1..110}; echo

for entry in "${MAP[@]}"; do
  IFS='|' read -r src dst mode uid gid <<<"$entry"
  if [[ ! -f $REPO/$src ]]; then
    printf '%-42s %-8s %s\n' "$src" "SKIP" "(bron bestaat nog niet — latere fase)"
    skipped=$((skipped+1)); continue
  fi
  status="SAME"; action="geen"
  if [[ ! -f $dst ]]; then
    status="MISSING"; action="installeren"
  elif ! cmp -s "$REPO/$src" "$dst"; then
    status="DIFFERS"; action="update"
  fi
  if [[ $status == SAME ]]; then
    # rechten/owner handhaven (idempotentie). De flash (/boot) is vfat: modes
    # worden daar door de mount-mask bepaald, dus alleen uid afdwingen.
    cur_mode=$(stat -c %a "$dst"); cur_uid=$(stat -c %u "$dst")
    if [[ $cur_uid != "$uid" ]]; then
      status="META"; action="chown $uid"
    elif [[ $dst != /boot/* && $cur_mode != "$mode" ]]; then
      status="META"; action="chmod $mode"
    fi
  fi
  printf '%-42s %-8s %s\n' "$src" "$status" "$dst"
  if [[ $VERBOSE == 1 && $status == DIFFERS ]]; then
    diff -u "$dst" "$REPO/$src" | head -40 || true
  fi
  if [[ $status == SAME ]]; then same=$((same+1)); continue; fi
  pending=$((pending+1))
  if [[ $CHECK == 0 ]]; then
    install -d -m 755 "$(dirname "$dst")"
    install -m "$mode" -o "$uid" -g "$gid" "$REPO/$src" "$dst"
    installed=$((installed+1))
    echo "    -> $action uitgevoerd"
  fi
done

echo
if [[ $CHECK == 1 ]]; then
  echo "DRY-RUN: $pending wijziging(en) pending, $same identiek, $skipped overgeslagen."
  (( pending == 0 )) && echo "install.sh --check: source-of-truth-flow is consistent (repo == live)." \
                     || echo "install.sh --check: WIJZIGINGEN PENDING — draai zonder --check om toe te passen."
  (( pending == 0 ))
else
  echo "GEINSTALLEERD: $installed bestand(en), $same al identiek, $skipped overgeslagen."
  echo "Let op: SSH-identiteiten/authorized_keys worden NIET door dit script beheerd"
  echo "(expliciet: deploy/install-ssh-identities.sh)."
fi
