#!/bin/bash
set -euo pipefail
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
deny() { echo "DENIED: $*" >&2; exit 64; }
valid_name() { [[ $1 =~ ^[A-Za-z0-9_.:-]+$ ]]; }
decode_b64() { printf '%s' "$1" | base64 -d 2>/dev/null || deny "invalid base64 argument"; }
safe_read_path() {
  local p; p=$(realpath -e -- "$1" 2>/dev/null) || deny "path does not exist"
  case "$p" in */.env|*/.env.*|*.pem|*.key|*.p12|*/secrets/*|*/credentials*|*/authorized_keys|*/operator-state/*) deny "secret or security state is not readable";; esac
  case "$p" in /mnt/user/appdata/*|/mnt/vm_storage/*|/boot/config/plugins/*|/etc/libvirt/*) printf '%s' "$p";; *) deny "path outside read allowlist";; esac
}
read -r -a argv <<< "${SSH_ORIGINAL_COMMAND:-status}"
action=${argv[0]:-status}
case "$action" in
  status) uptime; free -h; df -h /mnt/user; docker ps --format '{{.Names}}|{{.Status}}' | sed -n '1,80p' ;;
  docker-ps) docker ps -a --format '{{.Names}}|{{.Image}}|{{.Status}}' | sed -n '1,120p' ;;
  docker-inspect) valid_name "${argv[1]:-}" || deny "invalid container"; docker inspect --format '{{json .State}}' "${argv[1]}" | head -c 30000 ;;
  docker-logs)
    valid_name "${argv[1]:-}" || deny "invalid container"; [[ ${argv[2]:-1h} =~ ^[0-9]+[smhd]$ ]] || deny "invalid since"; [[ ${argv[3]:-200} =~ ^[0-9]+$ ]] || deny "invalid line count"
    lines=${argv[3]:-200}; (( lines <= 500 )) || lines=500; docker logs --since "${argv[2]:-1h}" --tail "$lines" "${argv[1]}" 2>&1 | head -c 50000 ;;
  docker-stats) docker stats --no-stream --format '{{.Name}}|{{.CPUPerc}}|{{.MemUsage}}|{{.BlockIO}}' | sed -n '1,120p' ;;
  compose-status) dir=$(safe_read_path "$(decode_b64 "${argv[1]:-}")"); [[ -f $dir/docker-compose.yml || -f $dir/compose.yml ]] || deny "no compose file"; docker compose --project-directory "$dir" ps --format json | head -c 30000 ;;
  vm-list) virsh list --all | head -c 30000 ;;
  vm-info) name=$(decode_b64 "${argv[1]:-}"); [[ -n $name && ${#name} -le 128 && $name != *$'\n'* ]] || deny "invalid VM name"; virsh dominfo "$name" | head -c 30000 ;;
  vm-xml) name=$(decode_b64 "${argv[1]:-}"); [[ -n $name && ${#name} -le 128 && $name != *$'\n'* ]] || deny "invalid VM name"; virsh dumpxml --inactive "$name" | head -c 50000 ;;
  mounts) findmnt -rn -o TARGET,SOURCE,FSTYPE,OPTIONS | grep -E '^/(mnt|var/lib/docker|boot)(/| )' | sed -n '1,160p' ;;
  mount-info) path=$(decode_b64 "${argv[1]:-}"); [[ $path == /mnt/* ]] || deny "invalid mount path"; findmnt --target "$path" -o TARGET,SOURCE,FSTYPE,OPTIONS,SIZE,USED,AVAIL | head -c 30000 ;;
  disk) df -h /mnt/user /mnt/cache /mnt/vm_storage 2>/dev/null || df -h /mnt/user ;;
  block-devices) lsblk -J -o NAME,KNAME,PATH,SIZE,TYPE,FSTYPE,MOUNTPOINTS,RO,MODEL,SERIAL | head -c 50000 ;;
  smart-health) dev=${argv[1]:-}; [[ $dev =~ ^/dev/(sd[a-z]+|nvme[0-9]+n[0-9]+)$ ]] || deny "invalid device"; smartctl -H -A "$dev" 2>&1 | head -c 50000 ;;
  nvme-health) dev=${argv[1]:-}; [[ $dev =~ ^/dev/nvme[0-9]+(n[0-9]+)?$ ]] || deny "invalid NVMe device"; nvme smart-log "$dev" 2>&1 | head -c 30000 ;;
  service-status) svc=${argv[1]:-}; [[ $svc =~ ^[A-Za-z0-9_.-]+$ ]] || deny "invalid service"; script=/etc/rc.d/rc.$svc; [[ -x $script ]] || deny "unknown Unraid service"; timeout 20 "$script" status 2>&1 | head -c 30000 ;;
  processes) ps -eo pid,ppid,user,stat,comm,%mem,%cpu --sort=-%cpu | sed -n '1,80p' ;;
  memory) free -h; ps -eo pid,comm,%mem,%cpu --sort=-%mem | sed -n '1,25p' ;;
  network) ip -brief address; ss -lntup | sed -n '1,120p' ;;
  kernel-errors) since=${argv[1]:-1h}; [[ $since =~ ^[0-9]+[smhd]$ ]] || deny "invalid since"; dmesg --level=emerg,alert,crit,err --since "$since" 2>/dev/null | tail -n 300 | head -c 50000 ;;
  syslog) [[ ${argv[1]:-200} =~ ^[0-9]+$ ]] || deny "invalid line count"; lines=${argv[1]:-200}; (( lines <= 500 )) || lines=500; tail -n "$lines" /var/log/syslog | head -c 50000 ;;
  file-read) path=$(safe_read_path "$(decode_b64 "${argv[1]:-}")"); [[ -f $path ]] || deny "not a regular file"; size=$(stat -c %s "$path"); (( size <= 100000 )) || deny "file exceeds 100 KB"; sed -n '1,1600p' "$path" | head -c 100000 ;;
  audit-tail) [[ ${argv[1]:-50} =~ ^[0-9]+$ ]] || deny "invalid line count"; lines=${argv[1]:-50}; (( lines <= 200 )) || lines=200; tail -n "$lines" /mnt/user/appdata/hermes/operator-audit.jsonl 2>/dev/null | head -c 50000 ;;
  *) echo "DENIED: unknown read action" >&2; exit 126 ;;
esac
