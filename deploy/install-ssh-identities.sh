#!/bin/bash
set -euo pipefail
H=/mnt/user/appdata/hermes/data
install -d -m 700 "$H/home/.ssh" /root/.ssh
install -d -m 700 -o 10000 -g 10000 "$H/operator-staging"
install -d -m 700 /mnt/user/appdata/hermes/operator-state /mnt/user/appdata/hermes/operator-backups
for role in read operator; do
  key="$H/home/.ssh/agent-$role"
  if [[ ! -f $key ]]; then
    docker exec -u hermes hermes ssh-keygen -q -t ed25519 -N '' -C "hermes-agent-$role@homeserver" -f "/opt/data/home/.ssh/agent-$role"
  fi
done
cp /mnt/user/appdata/hermes/compose/hermes-read-dispatch.sh /boot/config/plugins/hermes-read-dispatch.sh
cp /mnt/user/appdata/hermes/compose/hermes-operator-dispatch.sh /boot/config/plugins/hermes-operator-dispatch.sh
chmod 700 /boot/config/plugins/hermes-read-dispatch.sh /boot/config/plugins/hermes-operator-dispatch.sh
read_pub=$(cat "$H/home/.ssh/agent-read.pub")
operator_pub=$(cat "$H/home/.ssh/agent-operator.pub")
tmp=$(mktemp)
grep -v 'hermes-agent-read@homeserver\|hermes-agent-operator@homeserver' /root/.ssh/authorized_keys > "$tmp" || true
printf 'restrict,command="/bin/bash /boot/config/plugins/hermes-read-dispatch.sh" %s\n' "$read_pub" >> "$tmp"
printf 'restrict,command="/bin/bash /boot/config/plugins/hermes-operator-dispatch.sh" %s\n' "$operator_pub" >> "$tmp"
install -m 600 "$tmp" /root/.ssh/authorized_keys
rm -f "$tmp"
ssh-keyscan -H 192.168.1.2 > "$H/home/.ssh/known_hosts.tmp" 2>/dev/null
chown 10000:10000 "$H/home/.ssh/known_hosts.tmp"
chmod 600 "$H/home/.ssh/known_hosts.tmp"
mv "$H/home/.ssh/known_hosts.tmp" "$H/home/.ssh/known_hosts"
