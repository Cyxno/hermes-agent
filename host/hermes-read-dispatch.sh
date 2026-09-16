#!/bin/bash
set -euo pipefail
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
deny() { echo "DENIED: $*" >&2; exit 64; }
valid_name() { [[ $1 =~ ^[A-Za-z0-9_.:-]+$ ]]; }
decode_b64() { printf '%s' "$1" | base64 -d 2>/dev/null || deny "invalid base64 argument"; }
valid_since() { [[ ${1:-} =~ ^[0-9]+[smhd]$ ]]; }
safe_read_path() {
  local p; p=$(realpath -e -- "$1" 2>/dev/null) || deny "path does not exist"
  case "$p" in */.env|*/.env.*|*.pem|*.key|*.p12|*/secrets/*|*/credentials*|*/authorized_keys|*/operator-state/*|*/.ssh/*|*/.ssh) deny "secret or security state is not readable";; esac
  case "$p" in /mnt/user/appdata/*|/mnt/vm_storage/*|/boot/config/plugins/*|/etc/libvirt/*) printf '%s' "$p";; *) deny "path outside read allowlist";; esac
}

# ── fase 2 helpers: compacte JSON-envelopes, opbouw-gebonden begrensd ───────
# Elke f2_*-functie print exact één keer, alleen aan het eind (abort halverwege
# levert géén halve JSON; de case-subshell vangt dat af met een fail-envelope).
# Max antwoordgrootte ~16 KB: docker-rijen ≤ 80 a ~150 B; lijsten ≤ 40 a 300 B.
# JSON-lettertekens staan in single-quoted printf-formats; waarden via %s.
ok()   { printf '{"ok":true,"action":"%s","ts":%s,"data":%s}' "$1" "$(date +%s)" "$2"; }
fail() { printf '{"ok":false,"action":"%s","ts":%s,"error":"%s"}' "$1" "$(date +%s)" "$(printf '%s' "${2:-error}" | cut -c1-160 | tr -d '"' | tr -d '\n')"; }
jnum() { if [[ -n ${1:-} && ${1:-} != "null" ]]; then echo "$1"; else echo null; fi; }
jlines() {  # stdin → begrensde JSON-stringarray
  head -n "${1:-40}" | cut -c1-"${2:-300}" | awk 'BEGIN{printf "["}
    {gsub(/\\/,"\\\\"); gsub(/"/,"\\\""); gsub(/\t/," ");
     printf "%s\"%s\"", (NR>1?",":""), $0}
    END{printf "]"}'
}
san() {  # filter: als argument (san "$x") of via stdin (… | san)
  if (( $# )); then
    printf '%s' "$1" | tr -d '"' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | cut -c1-120
  else
    tr -d '"' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | cut -c1-120
  fi
}
f2_ssd_temp() {  # alleen always-on SSD's; -n standby wekt nooit
  local o x
  o=$(timeout 8 smartctl -n standby -A "$1" 2>/dev/null) || true
  x=$(awk '/^Temperature:/{print $2; exit}' <<<"${o:-}") || true
  [[ -z ${x:-} ]] && x=$(awk '$1==194{print $10; exit}' <<<"${o:-}" | awk '{print $1}')
  [[ ${x:-} =~ ^[0-9]+$ ]] && echo "$x" || echo null
}

f2_host_summary() {
  local up kern l1 l5 l15 mt ma used_pct=null docker_ok mdstate mounts sep="" m src pct
  up=$(uptime -p 2>/dev/null | sed 's/^up //') || true
  kern="$(uname -r)/$(cat /etc/unraid-version 2>/dev/null | head -1 | cut -d= -f2 | xargs)" || true
  read -r l1 l5 l15 _ <<<"$(awk '{print $1, $2, $3}' /proc/loadavg)"
  read -r _ mt _ _ _ ma <<<"$(free -k | awk '/^Mem:/{print $2, $3, $4, $5, $6, $7}')"
  [[ -n ${mt:-} && ${mt:-} -gt 0 && -n ${ma:-} ]] && used_pct=$(( (mt - ma) * 100 / mt ))
  if timeout 3 docker info -f '{{.ServerVersion}}' >/dev/null 2>&1; then docker_ok=true; else docker_ok=false; fi
  mdstate=$(mdcmd status 2>/dev/null | grep -oE 'mdState=[A-Z_:]*' | head -1 | cut -d= -f2) || true
  mounts="["
  while read -r m; do
    src=$(findmnt -no SOURCE "$m" 2>/dev/null) || src="?"
    pct=$(df -kP "$m" 2>/dev/null | awk 'NR==2{gsub("%","",$5); print $5}') || true
    mounts+="$sep{\"mount\":\"$m\",\"src\":\"$(san "$src")\",\"pct\":$(jnum "$pct")}"; sep=","
  done <<'EOF'
/var/lib/docker
/var/log
/
/mnt/cache
/mnt/vm_storage
/mnt/user
EOF
  mounts+="]"
  ok host-summary "$(printf '{"uptime":"%s","kernel":"%s","load":[%s,%s,%s],"mem_used_pct":%s,"mem_avail_kb":%s,"docker_ok":%s,"array_state":"%s","mounts":%s}' \
    "$(san "$up")" "$(san "$kern")" "$(jnum "$l1")" "$(jnum "$l5")" "$(jnum "$l15")" \
    "$used_pct" "$(jnum "$ma")" "$docker_ok" "$(san "${mdstate:-unknown}")" "$mounts")"
}

f2_memory_status() {
  local mt ma st sf buf cached oom used_pct=null top
  mt=$(awk '/^MemTotal:/{print $2}' /proc/meminfo) || true
  ma=$(awk '/^MemAvailable:/{print $2}' /proc/meminfo) || true
  st=$(awk '/^SwapTotal:/{print $2}' /proc/meminfo) || true
  sf=$(awk '/^SwapFree:/{print $2}' /proc/meminfo) || true
  buf=$(awk '/^Buffers:/{print $2}' /proc/meminfo) || true
  cached=$(awk '/^Cached:/{print $2}' /proc/meminfo) || true
  oom=$(awk '$1 == "oom_kill" {print $2}' /proc/vmstat 2>/dev/null) || true
  [[ -n ${mt:-} && ${mt:-} -gt 0 && -n ${ma:-} ]] && used_pct=$(( (mt - ma) * 100 / mt ))
  top=$(ps -eo rss,comm,pid --sort=-rss --no-headers 2>/dev/null | head -n 10 |
        awk '{gsub(/"/,""); printf "%s{\"pid\":%s,\"comm\":\"%s\",\"rss_kb\":%s}", (seen++?",":""), $3, $2, $1}') || true
  ok memory-status "$(printf '{"mem_total_kb":%s,"mem_avail_kb":%s,"mem_used_pct":%s,"buffers_kb":%s,"cached_kb":%s,"swap_total_kb":%s,"swap_used_kb":%s,"oom_kills_total":%s,"top10_rss":[%s]}' \
    "$(jnum "$mt")" "$(jnum "$ma")" "$used_pct" "$(jnum "$buf")" "$(jnum "$cached")" \
    "$(jnum "${st:-0}")" "$(( ${st:-0} - ${sf:-0} ))" "$(jnum "$oom")" "$top")"
}

f2_oom_events() {
  local oom lines total
  oom=$(awk '$1 == "oom_kill" {print $2}' /proc/vmstat 2>/dev/null) || true
  lines=$(dmesg -T --since "$1" 2>/dev/null | grep -iE 'out of memory|oom-killer|oom_reaper|killed process|memory cgroup out' | tail -n 30 | jlines 30 300) || true
  total=$(dmesg -T --since "$1" 2>/dev/null | grep -icE 'out of memory|oom-killer|oom_reaper|killed process|memory cgroup out') || true
  ok oom-events "$(printf '{"oom_kills_total":%s,"since":"%s","matched":%s,"events":%s}' \
    "$(jnum "$oom")" "$1" "$(jnum "${total:-0}")" "${lines:-[]}")"
}

f2_docker_rows() {  # één docker-inspect voor max 80 containers
  local ids; ids=$(docker ps -aq --format '{{.ID}}' 2>/dev/null | head -n 80) || true
  [[ -n ${ids:-} ]] || return 0
  # shellcheck disable=SC2086
  timeout 12 docker inspect $ids --format \
    '{{.Name}}|{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}|{{.RestartCount}}|{{.State.StartedAt}}|{{.State.ExitCode}}|{{.HostConfig.Memory}}' 2>/dev/null | cut -c1-160 || true
}

f2_docker_status() {
  local rows json count
  rows=$(f2_docker_rows) || true
  json=$(printf '%s\n' "${rows:-}" | sed 's#^/##' | awk -F'|' 'NF>=7 {
      st=substr($5,1,19);
      printf "%s{\"name\":\"%s\",\"state\":\"%s\",\"health\":\"%s\",\"restarts\":%s,\"started\":\"%s\",\"exit_code\":%s,\"mem_limit_bytes\":%s}",
        (seen++?",":""), $1, $2, $3, $4, st, $6, $7}') || true
  count=$(printf '%s\n' "${rows:-}" | grep -c .) || true
  ok docker-status "$(printf '{"count":%s,"containers":[%s]}' "${count:-0}" "$json")"
}

f2_docker_restarts() {
  local rows json
  rows=$(f2_docker_rows) || true
  json=$(printf '%s\n' "${rows:-}" | sed 's#^/##' | awk -F'|' 'NF>=7 && ($4+0 > 0 || $2 != "running") {
      st=substr($5,1,19);
      printf "%s{\"name\":\"%s\",\"state\":\"%s\",\"restarts\":%s,\"last_start\":\"%s\",\"last_exit_code\":%s}",
        (seen++?",":""), $1, $2, $4, st, $6}') || true
  ok docker-restarts "$(printf '{"note":"alleen restarts>0 of niet-running","containers":[%s]}' "$json")"
}

f2_docker_vdisk_status() {
  local line total used avail pct="" alloc path=/mnt/cache/system/docker/docker-xfs.img mounted=0
  line=$(df -kP /var/lib/docker 2>/dev/null | awk 'NR==2{print $2, $3, $4, $5}') || true
  if [[ -n ${line:-} ]]; then
    read -r total used avail pct <<<"$line"; pct=${pct%\%}; mounted=1
  fi
  alloc=$(du -sm "$path" 2>/dev/null | awk '{print $1}') || true
  ok docker-vdisk-status "$(printf '{"mounted":%s,"total_kb":%s,"used_kb":%s,"avail_kb":%s,"pct":%s,"image_alloc_mb":%s,"image_path":"%s","note":"df op loop-mount = GUI-authoritatief; du = alleen cache-pool-allocatie"}' \
    "$mounted" "$(jnum "$total")" "$(jnum "$used")" "$(jnum "$avail")" "$(jnum "$pct")" "$(jnum "$alloc")" "$path")"
}

f2_docker_space_detail() {
  local sysdf images
  sysdf=$(timeout 12 docker system df 2>/dev/null | awk 'NR>1 && NF>=5 {
      if ($2 ~ /^[0-9]+$/) { ty=$1; tot=$2; act=$3; sz=$4; rec=$5" "$6 }
      else { ty=$1" "$2; tot=$3; act=$4; sz=$5; rec=$6" "$7 }
      printf "%s{\"type\":\"%s\",\"total\":%s,\"active\":%s,\"size\":\"%s\",\"reclaimable\":\"%s\"}", (seen++?",":""), ty, tot, act, sz, rec}') || true
  images=$(timeout 10 docker images --format '{{.Size}}|{{.Repository}}:{{.Tag}}' 2>/dev/null | sort -t'|' -k1,1 -rh | head -n 10 |
           awk -F'|' '{printf "%s{\"size\":\"%s\",\"ref\":\"%s\"}", (seen++?",":""), $1, $2}') || true
  ok docker-space-detail "$(printf '{"summary":[%s],"largest_images":[%s],"note":"read-only diagnose; geen cleanup"}' "$sysdf" "$images")"
}

f2_logfs_status() {
  local line total used pct="" top
  line=$(df -kP /var/log 2>/dev/null | awk 'NR==2{print $2, $3, $5}') || true
  read -r total used pct <<<"${line:-}"; pct=${pct%\%}
  top=$(du -xk /var/log/* 2>/dev/null | sort -rn | head -n 10 |
        awk '{printf "%s{\"path\":\"%s\",\"kb\":%s}", (seen++?",":""), $2, $1}') || true
  ok logfs-status "$(printf '{"total_kb":%s,"used_kb":%s,"pct":%s,"top10":[%s]}' \
    "$(jnum "$total")" "$(jnum "$used")" "$(jnum "$pct")" "$top")"
}

f2_pool_status() {
  local out="[" sep="" m line src fstype opts rw pct
  for m in /mnt/cache /mnt/vm_storage /mnt/user; do
    line=$(findmnt -no SOURCE,FSTYPE,OPTIONS "$m" 2>/dev/null) || line=""
    src=$(awk '{print $1}' <<<"${line:-}") || true
    fstype=$(awk '{print $2}' <<<"${line:-}") || true
    opts=$(awk '{print $3}' <<<"${line:-}") || true
    pct=$(df -kP "$m" 2>/dev/null | awk 'NR==2{gsub("%","",$5); print $5}') || true
    rw=true; [[ ${opts:-} == ro* ]] && rw=false
    out+="$sep$(printf '{"mount":"%s","source":"%s","fstype":"%s","rw":%s,"pct":%s}' \
      "$m" "$(san "$src")" "$(san "$fstype")" "$rw" "$(jnum "$pct")")"
    sep=","
  done
  ok pool-status "${out}]"
}

f2_disk_health() {
  local want=$1 dv d devs outi h out="[" sep="" model health temp rel pend uc wear med
  if [[ -n $want ]]; then
    d=$want; [[ $d == /dev/* ]] || d="/dev/$d"; devs="$d"
  else
    devs="sda sdb sdc sdd sde sdf sdg"
  fi
  for dv in $devs; do
    d="$dv"; [[ $d == /dev/* ]] || d="/dev/$d"
    outi=$(timeout 8 smartctl -n standby -i "$d" 2>/dev/null) || true
    if grep -qi 'device is in standby' <<<"${outi:-}"; then
      out+="$sep$(printf '{"device":"%s","state":"standby","note":"niet gewekt"}' "$d")"; sep=","; continue
    fi
    model=$(grep -m1 -E 'Device Model|Model Number|Product:' <<<"${outi:-}" | sed 's/.*:[[:space:]]*//' | san) || true
    h=$(timeout 8 smartctl -n standby -H -A "$d" 2>/dev/null) || true
    health=$(grep -m1 -iE 'overall-health' <<<"${h:-}" | sed 's/.*:[[:space:]]*//' | san) || true
    temp=$(awk '/^Temperature:/{print $2; exit}' <<<"${h:-}") || true
    [[ -z ${temp:-} ]] && temp=$(awk '$1==194{print $10; exit}' <<<"${h:-}" | awk '{print $1}')
    rel=$(awk '$1==5 || $1==196{print $10; exit}' <<<"${h:-}" | awk '{print $1}') || true
    pend=$(awk '$1==197{print $10; exit}' <<<"${h:-}" | awk '{print $1}') || true
    uc=$(awk '$1==198{print $10; exit}' <<<"${h:-}" | awk '{print $1}') || true
    wear=$(grep -m1 'Percentage Used' <<<"${h:-}" | sed 's/.*:[[:space:]]*//' | tr -d '%') || true
    [[ -z ${wear:-} ]] && wear=$(awk '$1==177 || $1==231{print $10; exit}' <<<"${h:-}" | awk '{print $1}')
    med=$(grep -m1 'Media and Data Integrity Errors' <<<"${h:-}" | sed 's/.*:[[:space:]]*//' | tr -d '%') || true
    crc=$(awk '$1==199{print $10; exit}' <<<"${h:-}" | awk '{print $1}') || true
    out+="$sep$(printf '{"device":"%s","state":"active","model":"%s","health":"%s","temp_c":%s,"reallocated":%s,"pending":%s,"offline_uncorrectable":%s,"media_errors":%s,"crc_errors":%s,"wear_pct":%s}' \
      "$d" "$(san "$model")" "$(san "$health")" "$(jnum "$temp")" "$(jnum "$rel")" \
      "$(jnum "$pend")" "$(jnum "$uc")" "$(jnum "$med")" "$(jnum "$crc")" "$(jnum "$wear")")"
    sep=","
  done
  ok disk-health "${out}]"
}

f2_temperature_status() {
  local d t lbl pkg="" coremax="" val sda sdd
  for d in /sys/class/hwmon/hwmon*; do
    for t in "$d"/temp*_input; do
      [[ -r $t ]] || continue
      local raw; raw=$(<"$t") || true
      [[ ${raw:-} =~ ^[0-9]+$ ]] || continue
      lbl=""; [[ -r ${t%_input}_label ]] && lbl=$(<"${t%_input}_label")
      val=$(( raw / 1000 ))
      case "$lbl" in
        *ackage*) pkg=$val ;;
        Core*|core*) [[ -z ${coremax:-} || $val -gt ${coremax:-0} ]] && coremax=$val ;;
      esac
    done
  done
  sda=$(f2_ssd_temp /dev/sda); sdd=$(f2_ssd_temp /dev/sdd)
  ok temperature-status "$(printf '{"package_temp_c":%s,"core_max_temp_c":%s,"ssd_vm_storage_c":%s,"ssd_cache_c":%s,"note":"arraydisks bewust niet gepolld (geen spin-up)"}' \
    "$(jnum "$pkg")" "$(jnum "$coremax")" "$sda" "$sdd")"
}

f2_array_status() {
  local st mdstate raction rpos rsize pct="" synced
  st=$(mdcmd status 2>/dev/null) || true
  mdstate=$(grep -oE 'mdState=[A-Z_:]*' <<<"${st:-}" | head -1 | cut -d= -f2) || true
  raction=$(grep -oE 'mdResyncAction=[A-Za-z_-]*' <<<"${st:-}" | head -1 | cut -d= -f2) || true
  rpos=$(grep -oE 'mdResyncPos=[0-9]*' <<<"${st:-}" | head -1 | cut -d= -f2) || true
  rsize=$(grep -oE 'mdResyncSize=[0-9]*' <<<"${st:-}" | head -1 | cut -d= -f2) || true
  synced=$(grep -oE 'sbSynced=[0-9]*' <<<"${st:-}" | head -1 | cut -d= -f2) || true
  [[ -n ${rsize:-} && ${rsize:-0} -gt 0 ]] && pct=$(( rpos * 100 / rsize ))
  ok array-status "$(printf '{"state":"%s","parity_synced":%s,"resync_action":"%s","resync_pct":%s,"note":"read-only mdcmd status"}' \
    "$(san "${mdstate:-unknown}")" "$(jnum "$synced")" "$(san "${raction:-none}")" "$(jnum "$pct")")"
}

f2_kernel_errors() {
  local pat='I/O error|[Xx]FS|BTRFS|EXT4-fs|read-only|remount|NVMe|nvme|[Mm]achine check|mce|hung task|blocked for more|oops|BUG:|corrupt|overlay'
  local lines total
  lines=$(dmesg --level=emerg,alert,crit,err --since "$1" 2>/dev/null | grep -iE "$pat" | tail -n 40 | jlines 40 300) || true
  total=$(dmesg --level=emerg,alert,crit,err --since "$1" 2>/dev/null | grep -icE "$pat") || true
  ok kernel-errors "$(printf '{"since":"%s","matched":%s,"lines":%s,"note":"gefilterd op storage/fs/nvme/mce/hang; geen volledige dump"}' \
    "$1" "$(jnum "${total:-0}")" "${lines:-[]}")"
}

f2_fs_errors() {
  local pat='XFS|BTRFS|EXT4-fs|remount.*read-only|read-only.*remount|I/O error|corrupt|metadata error|filesystem.*error'
  local lines total
  lines=$(dmesg -T --since "$1" 2>/dev/null | grep -E "$pat" | tail -n 40 | jlines 40 300) || true
  total=$(dmesg -T --since "$1" 2>/dev/null | grep -cE "$pat") || true
  ok fs-errors "$(printf '{"since":"%s","matched":%s,"lines":%s}' "$1" "$(jnum "${total:-0}")" "${lines:-[]}")"
}

read -r -a argv <<< "${SSH_ORIGINAL_COMMAND:-status}"
action=${argv[0]:-status}
case "$action" in
  status) uptime; free -h; df -h /mnt/user; docker ps --format '{{.Names}}|{{.Status}}' | sed -n '1,80p' ;;
  docker-ps) docker ps -a --format '{{.Names}}|{{.Image}}|{{.Status}}' | sed -n '1,120p' ;;
  docker-inspect) valid_name "${argv[1]:-}" || deny "invalid container"; docker inspect --format '{{json .State}}' "${argv[1]}" | head -c 30000 ;;
  docker-logs)
    valid_name "${argv[1]:-}" || deny "invalid container"; valid_since "${argv[2]:-1h}" || deny "invalid since"; [[ ${argv[3]:-200} =~ ^[0-9]+$ ]] || deny "invalid line count"
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
  kernel-errors) valid_since "${argv[1]:-1h}" || deny "invalid since"; ( f2_kernel_errors "${argv[1]:-1h}" ) || fail kernel-errors "runtime error" ;;
  syslog) [[ ${argv[1]:-200} =~ ^[0-9]+$ ]] || deny "invalid line count"; lines=${argv[1]:-200}; (( lines <= 500 )) || lines=500; tail -n "$lines" /var/log/syslog | head -c 50000 ;;
  file-read) path=$(safe_read_path "$(decode_b64 "${argv[1]:-}")"); [[ -f $path ]] || deny "not a regular file"; size=$(stat -c %s "$path"); (( size <= 100000 )) || deny "file exceeds 100 KB"; sed -n '1,1600p' "$path" | head -c 100000 ;;
  audit-tail) [[ ${argv[1]:-50} =~ ^[0-9]+$ ]] || deny "invalid line count"; lines=${argv[1]:-50}; (( lines <= 200 )) || lines=200; tail -n "$lines" /mnt/user/appdata/hermes/operator-audit.jsonl 2>/dev/null | head -c 50000 ;;
  # ── fase 2: compacte JSON-deepchecks (subshell: abort → fail-envelope) ──
  host-summary)        ( f2_host_summary )        || fail host-summary "runtime error" ;;
  memory-status)       ( f2_memory_status )       || fail memory-status "runtime error" ;;
  oom-events)          valid_since "${argv[1]:-24h}" || deny "invalid since"; ( f2_oom_events "${argv[1]:-24h}" ) || fail oom-events "runtime error" ;;
  docker-status)       ( f2_docker_status )       || fail docker-status "runtime error" ;;
  docker-restarts)     ( f2_docker_restarts )     || fail docker-restarts "runtime error" ;;
  docker-vdisk-status) ( f2_docker_vdisk_status ) || fail docker-vdisk-status "runtime error" ;;
  docker-space-detail) ( f2_docker_space_detail ) || fail docker-space-detail "runtime error" ;;
  logfs-status)        ( f2_logfs_status )        || fail logfs-status "runtime error" ;;
  pool-status)         ( f2_pool_status )         || fail pool-status "runtime error" ;;
  disk-health)
    if [[ -n ${argv[1]:-} ]]; then [[ ${argv[1]} =~ ^/dev/(sd[a-z]+|nvme[0-9]+n[0-9]+)$ ]] || deny "invalid device"; fi
    ( f2_disk_health "${argv[1]:-}" ) || fail disk-health "runtime error" ;;
  temperature-status)  ( f2_temperature_status )  || fail temperature-status "runtime error" ;;
  array-status)        ( f2_array_status )        || fail array-status "runtime error" ;;
  fs-errors)           valid_since "${argv[1]:-24h}" || deny "invalid since"; ( f2_fs_errors "${argv[1]:-24h}" ) || fail fs-errors "runtime error" ;;
  *) echo "DENIED: unknown read action" >&2; exit 126 ;;
esac
