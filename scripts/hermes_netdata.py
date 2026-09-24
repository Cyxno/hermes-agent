#!/usr/bin/env python3
"""hermes_netdata.py — read-only Netdata-alarminput (fase 8).

Netdata als EXTRA signaalbron, nooit als aparte alert-engine: dit dekt
uitsluitend het ophalen en normaliseren van de actieve alarm-set. Severity-
state, incidenten, dedup en notificaties blijven volledig bij de bestaande
Hermes-evaluator/notifier (run_netdata in hermes_evaluator.py).

Principes:
- READ-ONLY: uitsluitend GET /api/v1/alarms (alleen niet-CLEAR alarms; licht
  endpoint, geen /all- of transitions-query's die onder load kunnen hangen).
  Er worden nooit alerts/disks/silencers in Netdata gewijzigd.
- ALLOWLIST: alleen alarms binnen de afgesproken onderwerpen (container-health,
  host-CPU/iowait, load, ram, oom-space-time, swap, disk space/inode,
  net-drops/fifo, thermals). Alles buiten scope en alle niet-WARNING/CRITICAL
  statussen (Clear/Undefined/Removed — de voorbijvliegende korte containers)
  worden hier al genegeerd: nooit blind doorsturen.
- GEEN secrets, GEEN auth: de lokale Netdata API is onauthentiek read-only.
"""
import json, re, urllib.error, urllib.request

DEFAULT_BASE_URL = "http://192.168.1.2:19999"


class NetdataError(Exception):
    def __init__(self, reason, status=None, detail=""):
        super().__init__(f"{reason}" + (f" ({status})" if status else "") + (f": {detail}" if detail else ""))
        self.reason = reason
        self.status = status


class NetdataClient:
    def __init__(self, base_url=DEFAULT_BASE_URL, timeout=8):
        self.base = base_url.rstrip("/")
        self.timeout = timeout

    def active_alarms(self):
        """Lijst van ruwe alarm-dicts die nu niet CLEAR zijn (WARNING/CRITICAL
        plus initialisatieruis — de allowlist filtert die hieronder weg)."""
        req = urllib.request.Request(
            self.base + "/api/v1/alarms",
            headers={"Accept": "application/json",
                     "User-Agent": "hermes-evaluator/1 (read-only)"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                code, payload = r.status, r.read()
        except urllib.error.HTTPError as e:
            e.read()
            raise NetdataError("http_error", e.code, "/api/v1/alarms") from None
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            raise NetdataError("unavailable", None, str(e)[:120]) from None
        if code != 200:
            raise NetdataError("http_error", code, "/api/v1/alarms")
        try:
            data = json.loads(payload)
        except ValueError:
            raise NetdataError("bad_payload", code, "antwoord is geen JSON") from None
        alarms = data.get("alarms")
        if not isinstance(alarms, dict):
            raise NetdataError("bad_payload", code, "'alarms'-object ontbreekt")
        return list(alarms.values())


def make_client(cfg):
    ncfg = dict(cfg.get("netdata") or {})
    return NetdataClient(base_url=ncfg.get("base_url", DEFAULT_BASE_URL),
                         timeout=int(ncfg.get("timeout_s", 8)))


# ------------------------------------------------------------- allowlist --
SEV_MAP = {"WARNING": "warning", "CRITICAL": "critical"}
CONTAINER_CHART = re.compile(r"^docker_local\.container_(.+)_health_status$")
CPU_NAMES = {"10min_cpu_usage", "10min_cpu_iowait"}
LOAD_NAMES = {"load_average_1", "load_average_5", "load_average_15"}
RAM_NAMES = {"ram_in_use"}
SWAP_NAMES = {"used_swap"}
OOM_RISK_NAMES = {"out_of_memory_space_time"}
DISK_NAMES = {"disk_space_usage", "disk_inode_usage"}
NET_NAMES = {"outbound_packets_dropped_ratio", "inbound_packets_dropped_ratio",
             "10min_fifo_errors"}
THERM_NAMES = {"cpu_temperature", "cpu_thermal_zone_temp", "thermal_zone_temp"}


def classify(name, chart):
    """(kind, subject) binnen de allowlist, of None = buiten scope.

    cgroup-alarms (qemu-VM's, korte containers) zijn bewust buiten scope:
    daarvoor levert Netdata hier ruis zonder dat hermes er iets mee kan."""
    m = CONTAINER_CHART.match(chart or "")
    if name == "docker_container_unhealthy" and m:
        return ("container", m.group(1))
    if chart == "system.cpu" and name in CPU_NAMES:
        return ("cpu", name)
    if chart == "system.load" and name in LOAD_NAMES:
        return ("load", name)
    if chart == "system.ram" and name in RAM_NAMES:
        return ("memory", name)
    if chart == "system.swap" and name in SWAP_NAMES:
        return ("swap", name)
    if name in OOM_RISK_NAMES:
        return ("memory", name)
    if (chart or "").startswith("disk_") and name in DISK_NAMES:
        return ("disk", chart)
    if (chart or "").startswith("net_") and name in NET_NAMES:
        return ("network", chart)
    if name in THERM_NAMES and ("temp" in (chart or "") or "thermal" in (chart or "")):
        return ("thermal", chart)
    return None


def fingerprint(kind, subject, name):
    """Stabiele hermes-fingerprint per Netdata-alarm (1 alarm = 1 fingerprint;
    per-container/per-interface detail zit in het subject)."""
    if kind == "container":
        return f"netdata:container:{subject}"
    if kind in ("disk", "network", "thermal"):
        return f"netdata:{kind}:{name}:{subject}"
    return f"netdata:{kind}:{name}"


def normalize(raw):
    """Ruwe alarm-entry -> hermes-intern formaat, of None bij ruis/buiten scope."""
    sev = SEV_MAP.get(raw.get("status"))
    if not sev:
        return None  # Clear/Undefined/Uninitialized/Removed: geen signaal
    cls = classify(raw.get("name") or "", raw.get("chart") or "")
    if not cls:
        return None
    kind, subject = cls
    name = raw.get("name") or ""
    try:
        value = float(raw.get("value"))
    except (TypeError, ValueError):
        value = None
    return {"fingerprint": fingerprint(kind, subject, name),
            "name": name, "chart": raw.get("chart") or "", "kind": kind,
            "subject": subject, "severity": sev, "value": value,
            "info": (raw.get("info") or raw.get("summary") or "")[:200],
            "last_status_change": raw.get("last_status_change")}


# ------------------------------------------------- dedup met hermes-checks --
_DISK_SPACE_TABLE = ((".mnt.cache", "host:cache:high", "cache_pct"),
                     ("vm_storage", "host:vm_storage:high", "vm_pct"),
                     (".mnt.user", "host:user_share:high", "user_pct"))


def covered_check(cfg, n):
    """(hermes_fingerprint, sample_metric, confirm_drempel) als hermes dit
    onderwerp al met eigen drempels bewaakt — hermes blijft dan leidend en
    Netdata is evidence. None = hermes heeft hier geen check (netdata = enige
    sensor en mag een incident maken). confirm_drempel: een netdata-CRITICAL
    wordt alleen op het hermes-incident gezet als de laatste hermes-sample
    hierboven zit (direction-confirm); een netdata-WARNING op een covered
    metric is altijd evidence-only."""
    kind, name, subject = n["kind"], n["name"], n["subject"]
    if kind == "memory" and name == "ram_in_use":
        return ("host:memory:high", "mem_used_pct",
                float((cfg.get("memory") or {}).get("warn_pct", 90)))
    if kind == "thermal":
        # temperaturen zijn op deze host bimodaal (nachtelijk 91-100C):
        # bevestiging vraagt de urgent-band, niet de warn-band.
        return ("host:temperature:package", "package_temp_c",
                float((cfg.get("temperatures") or {}).get("package_urgent_c", 95)))
    if kind == "disk" and name == "disk_space_usage":
        for pat, fp, metric in _DISK_SPACE_TABLE:
            if pat in subject:
                return (fp, metric, float((cfg.get("storage") or {}).get("warn_pct", 80)))
    return None
