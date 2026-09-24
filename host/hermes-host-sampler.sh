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

# ---- DUMB/InfiniDysk-metrics (v2, 2026-09-21) — observe-only ------------------
# Bronnen: /proc van NzbWebDAV (host-pid via docker top), cgroup van DUMB,
# infinidysk-hostlog (bind) en de in-container rclone-mount. Geen remediation.
dumb_rss=""; dumb_anon_kb=""; dumb_threads=""; dumb_cpu_pct=""
dumb_rss_growth=""; dumb_repairs1h=""; dumb_mount=0; dumb_restarted=""
leak_suspect=0; repair_storm_suspect=0
DUMB_CG=/sys/fs/cgroup/docker/$(docker inspect -f '{{.Id}}' DUMB 2>/dev/null)
DUMB_HP=$(docker top DUMB -eo pid,comm 2>/dev/null | awk '$2=="NzbWebDAV"{print $1; exit}')
if [[ -n $DUMB_HP && -r /proc/$DUMB_HP/status ]]; then
  dumb_rss=$(awk '/^VmRSS/{print $2}' /proc/$DUMB_HP/status)
  dumb_threads=$(awk '/^Threads/{print $2}' /proc/$DUMB_HP/status)
  dumb_utime=$(awk '{print $14 + $15}' /proc/$DUMB_HP/stat)
fi
[[ -r $DUMB_CG/memory.stat ]] && dumb_anon_kb=$(awk '$1=="anon"{print int($2/1024)}' "$DUMB_CG/memory.stat")
docker exec DUMB timeout 5 ls /mnt/remote/nzbdav/completed-symlinks >/dev/null 2>&1 && dumb_mount=1
LOGF=/mnt/user/appdata/DUMB/log/infinidysk.log
if [[ -r $LOGF ]]; then
  cutoff_epoch=$(date -d '1 hour ago' +%s)
  dumb_repairs1h=$(tail -n 3000 "$LOGF" |
    grep -E 'Starting repair|Scheduled dynamic repair' |
    while read -r l; do
      t=$(date -d "${l:0:20}" +%s 2>/dev/null) || continue
      (( t >= cutoff_epoch )) && echo x
    done | wc -l)
fi
DSTATE=/var/lock/hermes-dumb-sampler.state
prev_ts=""; prev_utime=""; prev_started=""; prev_high=""; prev_max=""; prev_ref=""
[[ -r $DSTATE ]] && read -r prev_ts _ prev_utime prev_started prev_high prev_max prev_ref <<<"$(cat "$DSTATE")"
started_now=$(docker inspect -f '{{.State.StartedAt}}' DUMB 2>/dev/null)
[[ -n $started_now && -n $prev_started && $started_now != "$prev_started" ]] && dumb_restarted=1
# CPU% t.o.v. vorige run (5-min cyclus: zinvol)
if [[ -n $prev_ts && ${ts:-0} -gt $prev_ts && -n ${dumb_utime:-} && -n ${prev_utime:-} ]]; then
  dumb_cpu_pct=$(awk -v u="$dumb_utime" -v q="$prev_utime" -v d="$((ts - prev_ts))" 'BEGIN{printf "%.1f",(u-q)*100/d/100}')
fi
# RSS-groei op 1-uursbasis: vergelijk met het sample van ~1 uur geleden in de DB
# (kortewindow-deltas zijn ruis). Semantiek: "RSS groeit > 500 MB/uur -> leak".
if [[ -f $DB && -n ${dumb_rss:-} ]]; then
  rss_ref=$(sqlite3 -cmd '.timeout 3000' "$DB" \
    "select nzbdav_rss_kb from dumb_samples where nzbdav_rss_kb is not null
     and ts between $((ts - 3900)) and $((ts - 3300)) order by ts limit 1" 2>/dev/null)
  [[ -n $rss_ref ]] && dumb_rss_growth=$(awk -v r="$dumb_rss" -v p="$rss_ref" 'BEGIN{printf "%.0f",(r-p)*1}')
fi
# cgroup-memory-signaal (v3, 2026-09-22): events.high/max + file-refault als
# rate per uur t.o.v. de vorige run; anon-groei op 1-uursbasis. PSI bestaat
# niet op deze host (geen /proc/pressure, geen cgroup memory.pressure) —
# daarom geen PSI-kolom; max-events zijn hier het drukproxy.
ev_high=""; ev_max=""; ws_ref=""
if [[ -r $DUMB_CG/memory.events ]]; then
  ev_high=$(awk '$1=="high"{print $2}' "$DUMB_CG/memory.events")
  ev_max=$(awk '$1=="max"{print $2}' "$DUMB_CG/memory.events")
fi
[[ -r $DUMB_CG/memory.stat ]] && ws_ref=$(awk '$1=="workingset_refault_file"{print $2}' "$DUMB_CG/memory.stat")
mem_events_high_rate=""; mem_events_max_rate=""; ws_refault_rate=""; anon_growth_kbph=""
if [[ -n $prev_ts && ${ts:-0} -gt $prev_ts ]]; then
  dt=$((ts - prev_ts))
  [[ -n ${ev_high:-} && -n ${prev_high:-} ]] && \
    mem_events_high_rate=$(awk -v e="$ev_high" -v p="$prev_high" -v d="$dt" 'BEGIN{printf "%.0f",(e-p)*3600/d}')
  [[ -n ${ev_max:-} && -n ${prev_max:-} ]] && \
    mem_events_max_rate=$(awk -v e="$ev_max" -v p="$prev_max" -v d="$dt" 'BEGIN{printf "%.0f",(e-p)*3600/d}')
  [[ -n ${ws_ref:-} && -n ${prev_ref:-} ]] && \
    ws_refault_rate=$(awk -v e="$ws_ref" -v p="$prev_ref" -v d="$dt" 'BEGIN{printf "%.0f",(e-p)*3600/d}')
fi
if [[ -f $DB && -n ${dumb_anon_kb:-} ]]; then
  anon_ref=$(sqlite3 -cmd '.timeout 3000' "$DB" \
    "select dumb_anon_kb from dumb_samples where dumb_anon_kb is not null
     and ts between $((ts - 3900)) and $((ts - 3300)) order by ts limit 1" 2>/dev/null)
  [[ -n $anon_ref ]] && anon_growth_kbph=$(awk -v r="$dumb_anon_kb" -v p="$anon_ref" 'BEGIN{printf "%.0f",(r-p)*1}')
fi
# Signaalvlaggen (uitsluitend observatie; evaluatie/melden gebeurt in Hermes):
#  - leak_suspect: RSS-groei > 500 MB/uur (voorbeeldregel opdracht)
#  - repair_storm_suspect: > 30 repair-starts/dynamische repairs per uur
#  - mem_pressure: ALLEEN echte druk bij oplopende max-events (>50k/u) ÉN
#    tegelijk groeiende anon (>100 MB/u). Hoog memory.current alléén is nooit
#    een alarm: een cachevolle container mag 85-95% gebruiken zolang reclaim
#    gezond verloopt (watermark 6,5 GiB / max 8 GiB, sinds 2026-09-22).
[[ -n ${dumb_rss_growth:-} && ${dumb_rss_growth%%.*} -gt 512000 ]] && leak_suspect=1
[[ -n ${dumb_repairs1h:-} && $dumb_repairs1h -gt 30 ]] && repair_storm_suspect=1
mem_pressure=0
max_r=${mem_events_max_rate%%.*}; [[ -z $max_r ]] && max_r=0
anon_r=${anon_growth_kbph%%.*}; [[ -z $anon_r ]] && anon_r=0
if (( max_r > 50000 )) && (( anon_r > 102400 )); then mem_pressure=1; fi
printf '%s %s %s %s %s %s %s\n' "${ts:-0}" "${dumb_rss:-0}" "${dumb_utime:-0}" \
  "${started_now:-}" "${ev_high:-0}" "${ev_max:-0}" "${ws_ref:-0}" > "$DSTATE" 2>/dev/null || true

# ---- DB: init, één korte transactie, retentie ---------------------------------
# insert-or-replace: twee runs binnen dezelfde seconde (alleen bij handmatig
# hameren; cron staat op */5) overschrijven elkaar dan zonder fout.
mkdir -p "$(dirname "$DB")"
if [[ ! -f $DB ]]; then
  sqlite3 "$DB" >/dev/null <<'SQL'
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
# dumb_samples (v2, 2026-09-21): aparte tabel — breekt het bestaande schema niet.
if ! sqlite3 -cmd '.timeout 5000' "$DB" "select 1 from dumb_samples limit 1" >/dev/null 2>&1; then
  sqlite3 -cmd '.timeout 5000' "$DB" <<'SQL'
    create table if not exists dumb_samples(
      ts integer primary key, sampler_ver integer,
      nzbdav_rss_kb integer, dumb_anon_kb integer, nzbdav_threads integer,
      nzbdav_cpu_pct real, nzbdav_rss_growth_kbph real,
      infinidysk_repairs_1h integer, mount_ok integer,
      dumb_restarted integer, leak_suspect integer, repair_storm_suspect integer
    );
SQL
  chown 10000:10000 "$DB"
fi
# v3 (2026-09-22): cgroup-memory-signalen als kolommen (migratie voor oudere DB's)
for cold in "mem_events_high_rate real" "mem_events_max_rate real" \
            "ws_refault_rate real" "anon_growth_kbph real" "mem_pressure integer"; do
  cn=${cold%% *}
  if ! sqlite3 -cmd '.timeout 3000' "$DB" \
      "select 1 from pragma_table_info('dumb_samples') where name='$cn'" | grep -q 1; then
    sqlite3 -cmd '.timeout 3000' "$DB" "alter table dumb_samples add column $cold" && \
      chown 10000:10000 "$DB"
  fi
done
# ownership handhaven (root draait de sampler; container-lezer is uid 10000)
[[ $(stat -c %u "$DB") != 10000 ]] && chown 10000:10000 "$DB"

rollup_sql=""
for m in vdisk_pct cache_pct vm_pct logfs_pct rootfs_pct user_pct mem_used_pct \
         package_temp_c core_max_temp_c load1 ssd_sda_temp_c ssd_sdd_temp_c; do
  rollup_sql+="insert or replace into rollup_hourly
    select strftime('%s','now')/3600*3600, '$m', avg($m), min($m), max($m)
    from samples where ts >= strftime('%s','now')/3600*3600 and $m is not null;"
done
# nzbdav_rss_kb staat in dumb_samples (niet in samples) — eigen rollup-insert.
rollup_sql+="insert or replace into rollup_hourly
  select strftime('%s','now')/3600*3600, 'nzbdav_rss_kb', avg(nzbdav_rss_kb),
         min(nzbdav_rss_kb), max(nzbdav_rss_kb)
  from dumb_samples where ts >= strftime('%s','now')/3600*3600
    and nzbdav_rss_kb is not null;"

if ! out=$(sqlite3 -cmd '.timeout 5000' "$DB" 2>&1 <<SQL
  pragma synchronous=normal;
  begin;
  insert or replace into samples values (
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
  insert or replace into dumb_samples(ts, sampler_ver, nzbdav_rss_kb,
    dumb_anon_kb, nzbdav_threads, nzbdav_cpu_pct, nzbdav_rss_growth_kbph,
    infinidysk_repairs_1h, mount_ok, dumb_restarted, leak_suspect,
    repair_storm_suspect, mem_events_high_rate, mem_events_max_rate,
    ws_refault_rate, anon_growth_kbph, mem_pressure) values (
    $(v "$ts"), $(v "$SAMPLER_VER"),
    $(v "$dumb_rss"), $(v "$dumb_anon_kb"), $(v "$dumb_threads"),
    $(v "$dumb_cpu_pct"), $(v "$dumb_rss_growth"),
    $(v "$dumb_repairs1h"), $(v "$dumb_mount"),
    $(v "$dumb_restarted"), $(v "$leak_suspect"), $(v "$repair_storm_suspect"),
    $(v "$mem_events_high_rate"), $(v "$mem_events_max_rate"),
    $(v "$ws_refault_rate"), $(v "$anon_growth_kbph"), $(v "$mem_pressure")
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
