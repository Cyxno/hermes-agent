#!/bin/bash
# hermes-host-sampler.sh — deterministische host-metric sampler (fase 1).
#
# Architectuur: Unraid cron → metrics verzamelen → 1 SQLite-sample → klaar.
# GEEN LLM, GEEN Telegram, GEEN severity/incident-engine, GEEN remediation,
# GEEN DUMBscope-/Prometheus-calls. Alle evaluatie gebeurt in Hermes.
#
# Doel-DB : /mnt/user/appdata/hermes/data/homelab/samples.db (WAL, owner 10000:10000)
# Retentie: raw 48 uur, hourly-rollups 90 dagen.
# Arraydisks worden NIET gepolld; alleen de always-on SSD's sda/sdd (smartctl -n standby).
# Docker-vDisk: primair `df -kP /var/lib/docker` (loop2/xfs, GUI-authoritatief);
#               `du` op het image is uitsluitend cache-pool-allocatie, nooit usage-%.
#
# Output: stil bij succes; bij falen één regel via logger -t hermes-sampler.
# VERBOSE: HERMES_SAMPLER_VERBOSE=1 print de sample als JSON op stdout.
set -u

DB=/mnt/user/appdata/hermes/data/homelab/samples.db
DOCKER_IMG=/mnt/cache/system/docker/docker-xfs.img
LOCK=/var/lock/hermes-host-sampler.lock
SAMPLER_VER=1
RAW_RETENTION_S=$((48 * 3600))
ROLLUP_RETENTION_S=$((90 * 86400))
VERBOSE=${HERMES_SAMPLER_VERBOSE:-0}

log() { logger -t hermes-sampler "$*"; }

# ---- tegen overlappende runs: flock ------------------------------------------
exec 9>"$LOCK" 2>/dev/null || exec 9>"/tmp/hermes-host-sampler.lock"
flock -n 9 || { log "overgeslagen: vorige run nog actief"; exit 0; }

# ---- helpers -----------------------------------------------------------------
# v <waarde> → SQL-getal of NULL (alle waarden zijn numeriek)
v() { [[ -n ${1:-} && ${1:-} != "" ]] && echo "$1" || echo "NULL"; }
dfk() { df -kP "$1" 2>/dev/null | awk 'NR==2{print $2, $3, $4, $5}'; }
pct() { local p=${1%\%}; [[ -n $p ]] && echo "$p" || echo ""; }

# ---- metrics verzamelen (alles best-effort, lege waarde → NULL) --------------
ts=$(date +%s)

read -r mem_total mem_used mem_avail _ < <(free -k | awk '/^Mem:/{print $2, $3, $7}')
mem_used_pct=""
[[ -n ${mem_total:-} && ${mem_total:-} -gt 0 ]] && mem_used_pct=$((100 * mem_used / mem_total))

psi_mem_some=$(awk '/^some/{sub("avg10=","",$2); print $2}' /proc/pressure/memory 2>/dev/null)
psi_mem_full=$(awk '/^full/{sub("avg10=","",$2); print $2}' /proc/pressure/memory 2>/dev/null)
psi_cpu_some=$(awk '/^some/{sub("avg10=","",$2); print $2}' /proc/pressure/cpu 2>/dev/null)
psi_io_some=$(awk '/^some/{sub("avg10=","",$2); print $2}' /proc/pressure/io 2>/dev/null)

read -r swap_total swap_used <<<"$(free -k | awk '/^Swap:/{print $2, $3}')"
oom_kills=$(awk '$1 == "oom_kill" {print $2}' /proc/vmstat 2>/dev/null)
read -r load1 load5 load15 <<<"$(awk '{print $1, $2, $3}' /proc/loadavg)"

# CPU-temperaturen: package-label + hoogste core (milligraden → graden)
pkg_temp=""; core_max=""
for d in /sys/class/hwmon/hwmon*; do
  for t in "$d"/temp*_input; do
    [[ -r $t ]] || continue
    lbl=""; [[ -r ${t%_input}_label ]] && lbl=$(<"${t%_input}_label")
    val=$(( $(<"$t") / 1000 ))
    case "$lbl" in
      *ackage*) pkg_temp=$val ;;
      Core*|core*) if [[ -z $core_max || $val -gt $core_max ]]; then core_max=$val; fi ;;
    esac
  done
done

# Always-on SSD's alleen (-n standby voorkomt elke wake-poging)
ssd_temp() {
  local out t
  out=$(smartctl -n standby -A "$1" 2>/dev/null) || { echo ""; return; }
  t=$(awk '/^Temperature:/{print $2; exit}' <<<"$out")                 # NVMe-formaat
  if [[ -z $t ]]; then
    t=$(awk '$1 == 194 {print $10; exit}' <<<"$out" | awk '{print $1}') # ATA attr 194
  fi
  [[ $t =~ ^[0-9]+$ ]] && echo "$t" || echo ""
}
ssd_sda_temp=$(ssd_temp /dev/sda)
ssd_sdd_temp=$(ssd_temp /dev/sdd)

# Docker daemon + container-counts (één docker ps -a call)
if timeout 5 docker info -f '{{.ServerVersion}}' >/dev/null 2>&1; then docker_ok=1; else docker_ok=0; fi
read -r c_run c_exit c_unhealthy c_restarting <<<"$(docker ps -a --format '{{.State}} {{.Status}}' 2>/dev/null |
  awk '{if ($1=="running") r++; else if ($1=="exited") e++;
        if ($0 ~ /unhealthy/) u++;
        if ($1=="restarting") rs++}
        END {print r+0, e+0, u+0, rs+0}')"

# Docker-vDisk: df op de loop-mount is de authoritative usage-metriek
vdisk_mounted=0; vdisk_total=""; vdisk_used=""; vdisk_avail=""; vdisk_pct=""
if line=$(dfk /var/lib/docker); [[ -n $line ]]; then
  read -r vdisk_total vdisk_used vdisk_avail dpct <<<"$line"
  vdisk_pct=$(pct "$dpct"); vdisk_mounted=1
fi
vdisk_alloc_mb=$(du -sm "$DOCKER_IMG" 2>/dev/null | awk '{print $1}')

# Filesystem-metrics
read -r logfs_total logfs_used _ lpct <<<"$(dfk /var/log)";  logfs_pct=$(pct "${lpct:-}")
read -r _ _ _ rpct          <<<"$(dfk /)";                   rootfs_pct=$(pct "${rpct:-}")
read -r _ cache_used cache_total cpct <<<"$(dfk /mnt/cache)";  cache_pct=$(pct "${cpct:-}")
read -r _ _ _ vpct          <<<"$(dfk /mnt/vm_storage)";      vm_pct=$(pct "${vpct:-}")
read -r _ _ _ upct          <<<"$(dfk /mnt/user)";            user_pct=$(pct "${upct:-}")

# ---- DB: init, één korte transactie, retentie ---------------------------------
mkdir -p "$(dirname "$DB")"
if [[ ! -f $DB ]]; then
  sqlite3 "$DB" <<'SQL'
    pragma journal_mode=wal;
    create table samples(
      ts integer primary key, sampler_ver integer,
      mem_total_kb integer, mem_used_kb integer, mem_avail_kb integer, mem_used_pct real,
      psi_mem_some real, psi_mem_full real, psi_cpu_some real, psi_io_some real,
      swap_total_kb integer, swap_used_kb integer, oom_kills integer,
      load1 real, load5 real, load15 real,
      package_temp_c integer, core_max_temp_c integer,
      ssd_sda_temp_c integer, ssd_sdd_temp_c integer,
      docker_ok integer, containers_running integer, containers_exited integer,
      containers_unhealthy integer, containers_restarting integer,
      vdisk_mounted integer, vdisk_total_kb integer, vdisk_used_kb integer,
      vdisk_avail_kb integer, vdisk_pct real, vdisk_alloc_mb integer,
      logfs_total_kb integer, logfs_used_kb integer, logfs_pct real,
      rootfs_pct real, cache_used_kb integer, cache_total_kb integer, cache_pct real,
      vm_pct real, user_pct real
    );
    create table rollup_hourly(
      hour_ts integer, metric text, avg real, min real, max real,
      primary key (hour_ts, metric)
    ) without rowid;
    insert into meta values ('schema_version', '1');
SQL
  chown 10000:10000 "$DB"
fi
# ownership handhaven (root draait de sampler; container-lezer is uid 10000)
[[ $(stat -c %u "$DB") != 10000 ]] && chown 10000:10000 "$DB"

rollup_sql=""
for m in vdisk_pct cache_pct vm_pct logfs_pct rootfs_pct user_pct mem_used_pct \
         package_temp_c core_max_temp_c load1 ssd_sda_temp_c ssd_sdd_temp_c; do
  rollup_sql+="insert or replace into rollup_hourly
    select strftime('%s','now')/3600*3600, '$m', avg($m), min($m), max($m)
    from samples where ts >= strftime('%s','now')/3600*3600 and $m is not null;"
done

if ! out=$(sqlite3 -cmd "pragma busy_timeout=5000" "$DB" 2>&1 <<SQL
  pragma synchronous=normal;
  begin;
  insert into samples values (
    $(v "$ts"), $(v "$SAMPLER_VER"),
    $(v "$mem_total"), $(v "$mem_used"), $(v "$mem_avail"), $(v "$mem_used_pct"),
    $(v "$psi_mem_some"), $(v "$psi_mem_full"), $(v "$psi_cpu_some"), $(v "$psi_io_some"),
    $(v "$swap_total"), $(v "$swap_used"), $(v "$oom_kills"),
    $(v "$load1"), $(v "$load5"), $(v "$load15"),
    $(v "$pkg_temp"), $(v "$core_max"), $(v "$ssd_sda_temp"), $(v "$ssd_sdd_temp"),
    $(v "$docker_ok"), $(v "$c_run"), $(v "$c_exit"), $(v "$c_unhealthy"), $(v "$c_restarting"),
    $(v "$vdisk_mounted"), $(v "$vdisk_total"), $(v "$vdisk_used"), $(v "$vdisk_avail"),
    $(v "$vdisk_pct"), $(v "$vdisk_alloc_mb"),
    $(v "$logfs_total"), $(v "$logfs_used"), $(v "$logfs_pct"),
    $(v "$rootfs_pct"), $(v "$cache_used"), $(v "$cache_total"), $(v "$cache_pct"),
    $(v "$vm_pct"), $(v "$user_pct")
  );
  $rollup_sql
  delete from samples where ts < strftime('%s','now') - $RAW_RETENTION_S;
  delete from rollup_hourly where hour_ts < strftime('%s','now') - $ROLLUP_RETENTION_S;
  commit;
SQL
); then
  log "sqlite-fout: ${out:0:200}"
  chown 10000:10000 "$DB" "$DB-wal" "$DB-shm" 2>/dev/null || true
  exit 1
fi
# sidecars (na crash achtergebleven) altijd uid 10000 geven voor de container-lezer
chown 10000:10000 "$DB" "$DB-wal" "$DB-shm" 2>/dev/null || true

# ---- VERBOSE: JSON op stdout ---------------------------------------------------
if [[ $VERBOSE == 1 ]]; then
  cat <<EOF
{"ts":$ts,"sampler_ver":$SAMPLER_VER,"mem_total_kb":$(v "$mem_total"),"mem_used_kb":$(v "$mem_used"),"mem_avail_kb":$(v "$mem_avail"),"mem_used_pct":$(v "$mem_used_pct"),"psi_mem_some":$(v "$psi_mem_some"),"psi_mem_full":$(v "$psi_mem_full"),"psi_cpu_some":$(v "$psi_cpu_some"),"psi_io_some":$(v "$psi_io_some"),"swap_total_kb":$(v "$swap_total"),"swap_used_kb":$(v "$swap_used"),"oom_kills":$(v "$oom_kills"),"load1":$(v "$load1"),"load5":$(v "$load5"),"load15":$(v "$load15"),"package_temp_c":$(v "$pkg_temp"),"core_max_temp_c":$(v "$core_max"),"ssd_sda_temp_c":$(v "$ssd_sda_temp"),"ssd_sdd_temp_c":$(v "$ssd_sdd_temp"),"docker_ok":$docker_ok,"containers_running":$(v "$c_run"),"containers_exited":$(v "$c_exit"),"containers_unhealthy":$(v "$c_unhealthy"),"containers_restarting":$(v "$c_restarting"),"vdisk_mounted":$vdisk_mounted,"vdisk_total_kb":$(v "$vdisk_total"),"vdisk_used_kb":$(v "$vdisk_used"),"vdisk_avail_kb":$(v "$vdisk_avail"),"vdisk_pct":$(v "$vdisk_pct"),"vdisk_alloc_mb":$(v "$vdisk_alloc_mb"),"logfs_pct":$(v "$logfs_pct"),"rootfs_pct":$(v "$rootfs_pct"),"cache_pct":$(v "$cache_pct"),"vm_pct":$(v "$vm_pct"),"user_pct":$(v "$user_pct")}
EOF
fi
exit 0
