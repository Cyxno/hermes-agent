#!/usr/bin/env python3
"""hermes_prometheus.py — fase 6: optionele historical-context provider.

READ-ONLY: uitsluitend instant/range queries. Geen admin/write-API, geen
Grafana, geen credentials. Prometheus is NOOIT een harde dependency:
  - CURRENT   -> SSH/sampler (blijft source of truth);
  - kort      -> samples.db (fallback);
  - lang      -> Prometheus (alleen als beschikbaar én vers).
Bij uitval: trends vallen terug op samples.db; na meerdere failures één
lokaal availability-incident (notice; pas na langdurige storing warning ->
eenmalig Telegram via de gewone fase-4.5 policy).

Caps: max queries per run, begrensde range-resolutie (<= ~60 punten),
timeout, korte TTL-cache. Geen query storm.

Modes: dry-run (SSH/samples/Prometheus-vergelijking), test (synthetisch,
faked transport).
"""
import json, os, time, urllib.error, urllib.parse, urllib.request
from pathlib import Path

HOME = Path(os.environ.get("HERMES_HOME", "/opt/data"))

DEFAULTS = {
    "enabled": True,
    "base_url": "http://192.168.1.2:9090",
    "timeout_s": 5,
    "freshness_s": 600,        # oudere data wordt genegeerd (stale)
    "cache_ttl_s": 600,
    "max_queries_per_run": 4,
    "failure_notice_polls": 3,   # lokaal notice-event (geen Telegram)
    "failure_warning_polls": 12, # langdurig (~3u) -> warning -> fase-4.5 policy
}

# Expressies (alle read-only, instant aggregeerbaar). Ontbreekt een metric,
# dan levert de query 0 series en valt de evaluator terug op samples.db.
EXPR = {
    "ram_pct": '100*(1-node_memory_MemAvailable_bytes/node_memory_MemTotal_bytes)',
    "load1": 'node_load1',
    "package_temp_c": 'node_hwmon_temp_celsius{chip="platform_coretemp_0",sensor="temp1"}',
    "vdisk_pct": '100*(1-node_filesystem_avail_bytes{mountpoint="/var/lib/docker"}/'
                 'node_filesystem_size_bytes{mountpoint="/var/lib/docker"})',
    "cache_pct": '100*(1-node_filesystem_avail_bytes{mountpoint="/mnt/cache"}/'
                 'node_filesystem_size_bytes{mountpoint="/mnt/cache"})',
    "logfs_pct": '100*(1-node_filesystem_avail_bytes{mountpoint="/var/log"}/'
                 'node_filesystem_size_bytes{mountpoint="/var/log"})',
    "oom_kills": 'node_vmstat_oom_kill',
    "container_mem_bytes": 'sum(container_memory_working_set_bytes{id=~"/docker/.*"})',
}
# fingerprint -> relevante metrics (evaluator gebruikt dit om selectief te vragen)
RELEVANCE = {
    "host:memory:high": ("ram_pct", "load1", "oom_kills"),
    "host:memory:oom": ("ram_pct", "oom_kills"),
    "host:temperature:package": ("package_temp_c",),
    "host:temperature:core": ("package_temp_c",),
    "host:docker_vdisk:high": ("vdisk_pct",),
    "host:docker_vdisk:growth": ("vdisk_pct",),
    "host:cache:high": ("cache_pct",),
    "host:logfs:high": ("logfs_pct",),
    "host:logfs:growth": ("logfs_pct",),
}
WINDOW_STEP = {0.25: "30s", 1: "60s", 6: "5m", 24: "15m", 168: "2h"}


class PromError(Exception):
    def __init__(self, reason, status=None, detail=""):
        super().__init__(f"{reason}" + (f" ({status})" if status else "") +
                         (f": {detail}" if detail else ""))
        self.reason = reason
        self.status = status


def load_cfg(home=None):
    """prometheus-sectie uit thresholds.yaml (mini-yaml van de evaluator)."""
    from hermes_evaluator import mini_yaml
    p = (home or HOME) / "thresholds.yaml"
    raw = mini_yaml(p.read_text()).get("prometheus", {}) if p.exists() else {}

    def merge(base, over):
        out = dict(base)
        for k, v in (over or {}).items():
            out[k] = merge(base[k], v) if isinstance(v, dict) and isinstance(base.get(k), dict) else v
        return out
    return merge(DEFAULTS, raw)


def _step_for(hours):
    for h, step in sorted(WINDOW_STEP.items()):
        if hours <= h:
            return step
    return "2h"


class PromClient:
    """Read-only query client met timeout, TTL-cache en staleness-regel."""

    def __init__(self, cfg=None, transport=None, now=None):
        self.cfg = {**DEFAULTS, **(cfg or {})}
        self.base = self.cfg["base_url"].rstrip("/")
        self._transport = transport or self._http_get
        self._now = now or (lambda: time.time())
        self._cache = {}  # expr -> (ts, data)

    # ------------------------------------------------------------ transport --
    def _http_get(self, path, params):
        url = self.base + path + "?" + urllib.parse.urlencode(params)
        req = urllib.request.Request(url, headers={"Accept": "application/json",
                                                   "User-Agent": "hermes-evaluator/1 (read-only)"})
        try:
            with urllib.request.urlopen(req, timeout=self.cfg["timeout_s"]) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            e.read()
            return e.code, None
        except Exception as e:  # noqa: BLE001 — transportfouten zijn verwacht
            raise PromError("unavailable", None, f"{type(e).__name__}: {e}"[:120]) from None

    def _get(self, path, params):
        key = path + str(sorted(params.items()))
        ts, data = self._cache.get(key, (None, None))
        if data is not None and self._now() - ts < self.cfg["cache_ttl_s"]:
            return data, True
        status, body = self._transport(path, params)
        if status != 200:
            raise PromError("http_error", status, f"{path}")
        if not isinstance(body, dict) or body.get("status") != "success":
            raise PromError("http_error", status, "onverwachte response")
        self._cache[key] = (self._now(), body)
        return body, False

    # --------------------------------------------------------------- API --
    def instant(self, expr):
        """Nieuwste waarde; None als er geen series zijn; PromError bij stale? nee:
        geeft (value, ts, stale) — stale wordt door de caller genegeerd."""
        body, _ = self._get("/api/v1/query", {"query": expr})
        res = body.get("data", {}).get("result") or []
        if not res:
            return None
        ts, val = res[0]["value"]
        try:
            val = float(val)
            ts = float(ts)
        except (TypeError, ValueError):
            return None
        return {"value": val, "ts": int(ts),
                "stale": (self._now() - ts) > self.cfg["freshness_s"]}

    def range(self, expr, hours, points=60):
        body, cached = self._get("/api/v1/query_range", {
            "query": expr, "start": self._now() - hours * 3600,
            "end": self._now(), "step": _step_for(hours)})
        res = body.get("data", {}).get("result") or []
        if not res:
            return None
        pts = []
        for ts, val in res[0]["values"][-points:]:
            try:
                pts.append((int(float(ts)), float(val)))
            except (TypeError, ValueError):
                continue
        return pts

    def summary(self, expr, hours):
        """Compacte samenvatting van een range: geen ruwe series."""
        pts = self.range(expr, hours)
        if not pts:
            return None
        vals = [v for _, v in pts]
        d_first = (vals[-1] - vals[0])
        return {"n": len(pts), "first": round(vals[0], 3), "last": round(vals[-1], 3),
                "min": round(min(vals), 3), "max": round(max(vals), 3),
                "delta": round(d_first, 3),
                "direction": ("rising" if d_first > 0.5 else
                              "falling" if d_first < -0.5 else "stable")}


# ------------------------------------------------------- availability-state --
def availability_update(c, ok, err, cfgn, events, emit=None, mode="fast"):
    """Degraded mode (§9): lokaal event na meerdere failures, pas warning
    (Telegram) na langdurige storing; RESOLVED bij herstel. Anti-spam door
    incident-dedup + fase-4.5 policy."""
    from hermes_evaluator import incident_upsert, emit as ev_emit, now_iso

    def failures():
        row = c.execute("select value from cursors where name='prometheus:failures'").fetchone()
        return int(float(row[0])) if row else 0

    def set_failures(n):
        c.execute("insert into cursors(name, value, last_checked)"
                  " values('prometheus:failures', ?, ?) on conflict(name) do update"
                  " set value=excluded.value, last_checked=excluded.last_checked",
                  (str(n), now_iso()))
    if ok:
        n = failures()
        if n:
            set_failures(0)
        _, etype = incident_upsert(c, "prometheus:availability", source="prometheus",
                                   itype="prometheus", sev_level=0, value=0,
                                   reason="Prometheus weer bereikbaar")
        if etype == "resolved" and emit:
            events.append(emit(mode, "prometheus_availability", "prometheus:availability",
                               severity="normal", provisional=True, state="resolved",
                               baseline_pending=True, source="prometheus",
                               reason=f"hersteld na {n} mislukte runs"))
        return
    n = failures() + 1
    set_failures(n)
    lvl = (2 if n >= int(cfgn.get("failure_warning_polls", 12)) else
           (1 if n >= int(cfgn.get("failure_notice_polls", 3)) else 0))
    if lvl:
        from hermes_evaluator import NAME
        _, etype = incident_upsert(c, "prometheus:availability", source="prometheus",
                                   itype="prometheus", sev_level=lvl, value=n,
                                   reason=f"{n} opeenvolgende mislukte runs ({err})")
        if etype in ("new", "escalated") and emit:
            events.append(emit(mode, "prometheus_availability", "prometheus:availability",
                               current=n, severity=NAME[lvl], provisional=True,
                               state="active", baseline_pending=True, source="prometheus",
                               reason=f"Prometheus onbereikbaar: {err} ({n} runs)"
                                      + (" — historische context valt terug op samples.db"
                                         if lvl == 1 else " — langdurig; alerting via fase-4.5")))


# --------------------------------------------------------- context-verzamelaar --
PROM_HISTORY_SCHEMA = ("create table if not exists prom_history(metric text primary key,"
                       " updated_at text, data_json text);")


def run_prometheus_context(cfg, c, events, *, home=None, client=None, emit=None, mode="fast"):
    """Selective context (§10): alleen bij relevante actieve incidenten; max
    max_queries_per_run queries; resultaten compact in prom_history (§13-cache
    zit in de client). Faalt alles -> degraded mode, evaluator crasht nooit."""
    cfgn = load_cfg(home)
    if not cfgn.get("enabled", True):
        return {"prometheus": "disabled"}
    if client is None:
        client = PromClient(cfgn)
    relevant = set()
    for (fp,) in c.execute("select fingerprint from incidents where state in"
                           " ('active','recovering') and current_severity in"
                           " ('warning','urgent','critical')").fetchall():
        relevant.update(RELEVANCE.get(fp, ()))
    metrics = sorted(relevant)[:int(cfgn.get("max_queries_per_run", 4))]
    if not metrics:
        return {"prometheus": "idle (geen relevante incidenten)", "queries": 0}
    c.execute(PROM_HISTORY_SCHEMA)
    stats = {"prometheus": "ok", "queries": 0, "failed": 0, "history": {}}
    err = None
    for m in metrics:
        expr = EXPR.get(m)
        if not expr:
            continue
        try:
            cur = client.instant(expr)
            # metric bestaat niet in Prometheus -> geen range-queries verspillen
            s1 = client.summary(expr, 1) if cur and not cur.get("stale") else None
            s24 = (client.summary(expr, 24) if cur and not cur.get("stale") and
                   m in ("ram_pct", "vdisk_pct", "cache_pct", "logfs_pct",
                         "package_temp_c") else None)
            stats["queries"] += 1 + (1 if s1 else 0) + (1 if s24 else 0)
            data = {"latest": cur, "h1": s1, "h24": s24}
        except PromError as e:
            err = e.reason
            stats["failed"] += 1
            continue
        stats["history"][m] = data
        c.execute("insert into prom_history(metric, updated_at, data_json)"
                  " values(?,?,?) on conflict(metric) do update set"
                  " updated_at=excluded.updated_at, data_json=excluded.data_json",
                  (m, json.dumps(cur["ts"]) if cur else None, json.dumps(data)))
        if emit:
            events.append(emit(mode, "prometheus_context", f"prometheus:{m}",
                               current=(cur or {}).get("value"),
                               severity="notice", provisional=True, state="context",
                               baseline_pending=True, source="prometheus",
                               reason=f"historische context: 1h={_short(s1)} 24h={_short(s24)}"
                                      + (" [STALE genegeerd]" if cur and cur.get("stale") else "")))
    if stats["failed"] and not stats["history"]:
        stats["prometheus"] = f"unavailable ({err})"
        availability_update(c, False, err, cfgn, events, emit=emit, mode=mode)
    else:
        availability_update(c, True, None, cfgn, events, emit=emit, mode=mode)
    return stats


def _short(s):
    if not s:
        return "-"
    return f"{s['first']}→{s['last']} ({s['direction']}, max {s['max']})"


# ------------------------------------------------------------- LLM-context --
def llm_trend_lines(c, fingerprint=None):
    """Compacte trend-summary (§11) voor de router-context: max ~8 korte
    regels, geen ruwe series. Max ≈ 200 tokens."""
    needed = RELEVANCE.get(fingerprint, ()) if fingerprint else None
    out = []
    for metric, data_json in c.execute("select metric, data_json from prom_history"
                                       " order by metric"):
        if needed and metric not in needed:
            continue
        try:
            d = json.loads(data_json)
        except (ValueError, TypeError):
            continue
        cur = (d.get("latest") or {}).get("value")
        if cur is None:
            continue  # metric bestaat niet in Prometheus: geen lege regels
        h1, h24 = d.get("h1"), d.get("h24")
        line = f"{metric}:"
        if cur is not None:
            line += f" now={round(cur, 1)}"
        if h1:
            line += f" 1h {h1['first']}→{h1['last']} ({h1['direction']}, max {h1['max']})"
        if h24:
            line += f" 24h max {h24['max']} delta {h24['delta']}"
        out.append(line[:200])
        if len(out) >= 8:
            break
    return out


# ------------------------------------------------------------------- CLI --
def dry_run(home=None, client=None):
    """Live vergelijking: sampler (=SSH-truth) vs samples.db vs Prometheus."""
    from hermes_evaluator import fetch_series
    cfgn = load_cfg(home)
    client = client or PromClient(cfgn)
    print(f"Prometheus {cfgn['base_url']} (freshness {cfgn['freshness_s']}s, "
          f"timeout {cfgn['timeout_s']}s, cache {cfgn['cache_ttl_s']}s)")
    print(f"{'metric':<18} {'sampler':>10} {'prom_now':>10} {'1h':>24} {'24h':>24}")
    for m, expr in EXPR.items():
        col = {"ram_pct": "mem_used_pct"}.get(m, m)
        s_pts = fetch_series(col, 1)
        samp = f"{s_pts[-1][1]:.1f}" if s_pts else "-"
        try:
            cur = client.instant(expr)
            prom = f"{cur['value']:.1f}" + ("!" if cur["stale"] else "") if cur else "-"
            h1 = client.summary(expr, 1)
            h24 = client.summary(expr, 24)
            print(f"{m:<18} {samp:>10} {prom:>10} {_short(h1):>24} {_short(h24):>24}")
        except PromError as e:
            print(f"{m:<18} {samp:>10} {'DOWN':>10}  ({e})")
    return 0


# ------------------------------------------------------------------ test --
def run_test():
    """Synthetische cases (§14) met faked transport; geen echte calls."""
    import sqlite3, tempfile
    results = []

    def check(name, cond, detail=""):
        results.append((name, bool(cond), detail))

    def fake_transport(series_by_expr, fail=False, latency_fail=False):
        def t(path, params):
            if fail:
                raise PromError("unavailable", None, "synthetische storing")
            if latency_fail:
                return 504, None
            expr = params["query"]
            pts = series_by_expr.get(expr)
            if pts is None:
                return 200, {"status": "success", "data": {"result": []}}
            if path == "/api/v1/query":
                ts, v = pts[-1]
                return 200, {"status": "success", "data": {"result": [
                    {"metric": {}, "value": [str(ts), str(v)]}]}}
            return 200, {"status": "success", "data": {"result": [
                {"metric": {}, "values": [[str(ts), str(v)] for ts, v in pts]}]}}
        return t

    def mkdb():
        tmp = Path(tempfile.mkdtemp())
        (tmp / "homelab").mkdir(parents=True)
        con = sqlite3.connect(tmp / "homelab" / "agent_state.db")
        con.executescript("""
        create table incidents(fingerprint text primary key, source text, type text,
          state text, current_severity text, previous_severity text, first_seen text,
          last_seen text, last_changed text, resolved_at text, occurrences integer,
          last_value real, peak_value real, last_alert_at text, suppression_until text,
          good_samples integer, last_reason text);
        create table cursors(name text primary key, value text, last_checked text);
        create table metric_state(metric text primary key, last_value real,
          previous_value real, last_ts text, trend text, slope real, sustained_since text,
          peak real, baseline_pending integer);
        """)
        con.commit()
        return tmp, con

    def ins(con, fp, sev="warning", state="active", value=85.0):
        con.execute("insert or replace into incidents values(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (fp, "fast", "t", state, sev, "normal", "t", "t", "t", None, 1,
                     value, value, "t", None, 0, "synthetic"))
        con.commit()

    RAM_EXPR = EXPR["ram_pct"]
    now = time.time()
    rising = [(now - i * 900, 85 - i * 5) for i in range(4)][::-1]     # 65->85
    falling = [(now - i * 900, 85 + i * (7 / 3)) for i in range(4)][::-1]  # 92->85
    stable = [(now - i * 900, 70.0) for i in range(4)][::-1]
    rapid = [(now - (3 - i) * 900, 54 + i * 2) for i in range(4)]      # 54->60, stijgend

    # 1: beschikbaar -> history toegevoegd
    tmp, con = mkdb()
    ins(con, "host:memory:high")
    cl = PromClient({**DEFAULTS, "cache_ttl_s": 0}, transport=fake_transport({RAM_EXPR: rising}))
    st = run_prometheus_context({"enabled": True}, con, [], home=tmp, client=cl, emit=None)
    ram_row = con.execute("select data_json from prom_history where metric='ram_pct'"
                          ).fetchone()
    check("1: beschikbaar -> history toegevoegd",
          ram_row is not None
          and json.loads(ram_row[0])["h1"]["direction"] == "rising", str(st))

    # 2: unavailable -> fallback, geen crash
    tmp, con = mkdb()
    ins(con, "host:memory:high")
    cl = PromClient({**DEFAULTS}, transport=fake_transport({}, fail=True))
    st = run_prometheus_context({"enabled": True}, con, [], home=tmp, client=cl, emit=None)
    check("2: unavailable -> fallback/geen crash",
          "unavailable" in st["prometheus"] and st["history"] == {}, str(st))

    # 3: stale -> genegeerd
    tmp, con = mkdb()
    ins(con, "host:memory:high")
    stale_pts = [(now - 7200, 99.0)] * 4
    cl = PromClient({**DEFAULTS, "freshness_s": 600}, transport=fake_transport({RAM_EXPR: stale_pts}))
    st = run_prometheus_context({"enabled": True}, con, [], home=tmp, client=cl, emit=None)
    check("3: stale -> gemarkeerd als stale",
          st["history"].get("ram_pct", {}).get("latest", {}).get("stale") is True, str(st))

    # 4+5: dalende vs stijgende historie -> direction in context
    tmp, con = mkdb()
    ins(con, "host:memory:high")
    cl = PromClient({**DEFAULTS}, transport=fake_transport({RAM_EXPR: falling}))
    st = run_prometheus_context({"enabled": True}, con, [], home=tmp, client=cl, emit=None)
    lines = llm_trend_lines(con, "host:memory:high")
    check("4: SSH 85 + prom dalend 92->85 -> direction=falling in context",
          "falling" in " ".join(lines) and "now=85" in " ".join(lines), str(lines))
    tmp, con = mkdb()
    ins(con, "host:memory:high")
    cl = PromClient({**DEFAULTS}, transport=fake_transport({RAM_EXPR: rising}))
    run_prometheus_context({"enabled": True}, con, [], home=tmp, client=cl, emit=None)
    lines = llm_trend_lines(con, "host:memory:high")
    check("5: SSH 85 + prom stijgend 65->85 -> direction=rising in context",
          "rising" in " ".join(lines), str(lines))

    # 6: temperatuur spike vs sustained
    spike = [(now - 1200, 70.0), (now - 900, 94.0), (now - 300, 74.0)]
    sustained = [(now - i * 900, 94.0) for i in range(4)][::-1]
    TMP_EXPR = EXPR["package_temp_c"]
    tmp, con = mkdb()
    ins(con, "host:temperature:package")
    cl = PromClient({**DEFAULTS}, transport=fake_transport({TMP_EXPR: spike}))
    run_prometheus_context({"enabled": True}, con, [], home=tmp, client=cl, emit=None)
    d_spike = json.loads(con.execute("select data_json from prom_history").fetchone()[0])
    tmp, con = mkdb()
    ins(con, "host:temperature:package")
    cl = PromClient({**DEFAULTS}, transport=fake_transport({TMP_EXPR: sustained}))
    run_prometheus_context({"enabled": True}, con, [], home=tmp, client=cl, emit=None)
    d_sust = json.loads(con.execute("select data_json from prom_history").fetchone()[0])
    check("6: temp spike vs sustained onderscheiden in 1h-context",
          d_spike["h1"]["max"] == 94.0 and d_spike["h1"]["last"] < 80
          and d_sust["h1"]["last"] == 94.0 and d_sust["h1"]["min"] == 94.0,
          f"{d_spike['h1']} vs {d_sust['h1']}")

    # 7: storage stable vs rapid growth
    VD_EXPR = EXPR["vdisk_pct"]
    tmp, con = mkdb()
    ins(con, "host:docker_vdisk:high")
    cl = PromClient({**DEFAULTS}, transport=fake_transport({VD_EXPR: stable}))
    run_prometheus_context({"enabled": True}, con, [], home=tmp, client=cl, emit=None)
    d_st = json.loads(con.execute("select data_json from prom_history").fetchone()[0])
    tmp, con = mkdb()
    ins(con, "host:docker_vdisk:high")
    cl = PromClient({**DEFAULTS}, transport=fake_transport({VD_EXPR: rapid}))
    run_prometheus_context({"enabled": True}, con, [], home=tmp, client=cl, emit=None)
    d_rp = json.loads(con.execute("select data_json from prom_history").fetchone()[0])
    check("7: storage stable vs rapid growth (delta/direction)",
          d_st["h24"]["direction"] == "stable" and d_rp["h24"]["direction"] == "rising"
          and d_rp["h24"]["delta"] > 0, f"{d_st['h24']} vs {d_rp['h24']}")

    # 8: disagreement -> SSH current wint (context bevat beide, current=SSH)
    tmp, con = mkdb()
    ins(con, "host:memory:high", value=85.0)
    prom82 = [(now - i * 900, 82.0) for i in range(4)][::-1]
    cl = PromClient({**DEFAULTS}, transport=fake_transport({RAM_EXPR: prom82}))
    run_prometheus_context({"enabled": True}, con, [], home=tmp, client=cl, emit=None)
    d = json.loads(con.execute("select data_json from prom_history where metric='ram_pct'"
                               ).fetchone()[0])
    ssh_current = con.execute("select last_value from incidents"
                              " where fingerprint='host:memory:high'").fetchone()[0]
    ms_row = con.execute("select last_value from metric_state where metric='mem_used_pct'"
                         ).fetchone()
    check("8: disagreement -> SSH current (85) wint, prom alleen als reeks",
          ssh_current == 85.0 and d["latest"]["value"] == 82.0 and ms_row is None,
          f"ssh={ssh_current} prom={d['latest']['value']} ms={ms_row}")

    # 9: query timeout -> geen crash (exit 0)
    tmp, con = mkdb()
    ins(con, "host:memory:high")
    cl = PromClient({**DEFAULTS}, transport=fake_transport({}, latency_fail=True))
    try:
        st = run_prometheus_context({"enabled": True}, con, [], home=tmp, client=cl, emit=None)
        ok9 = "unavailable" in st["prometheus"]
    except Exception as e:  # noqa: BLE001
        ok9 = False
    check("9: http-fout -> evaluator blijft normaal", ok9, "")

    # 10+11: repeated failure -> availability incident; recovery -> resolved
    tmp, con = mkdb()
    evs = []
    cfgn = {**DEFAULTS}
    for i in range(3):
        availability_update(con, False, "synthetische storing", cfgn, evs, emit=None)
    row = con.execute("select state, current_severity from incidents"
                      " where fingerprint='prometheus:availability'").fetchone()
    check("10: 3 failures -> lokaal notice-incident (geen warning/telegram)",
          row == ("active", "notice"), str(row))
    for i in range(9):
        availability_update(con, False, "synthetische storing", cfgn, evs, emit=None)
    row = con.execute("select state, current_severity from incidents"
                      " where fingerprint='prometheus:availability'").fetchone()
    check("10b: langdurig (12 runs) -> warning (fase-4.5 policy eenmalig)",
          row == ("active", "warning"), str(row))
    availability_update(con, True, None, cfgn, evs, emit=None)
    row = con.execute("select state from incidents"
                      " where fingerprint='prometheus:availability'").fetchone()
    check("11: herstel -> resolved", row == ("resolved",), str(row))

    # 12: LLM-context krijgt alleen compacte summary
    tmp, con = mkdb()
    ins(con, "host:memory:high")
    cl = PromClient({**DEFAULTS}, transport=fake_transport({RAM_EXPR: rising}))
    run_prometheus_context({"enabled": True}, con, [], home=tmp, client=cl, emit=None)
    lines = llm_trend_lines(con, "host:memory:high")
    raw = json.dumps(lines)
    check("12: LLM-context compact (<=8 regels, geen ruwe series)",
          len(lines) == 1 and len(raw) < 400 and "values" not in raw, raw[:120])

    fails = [r for r in results if not r[1]]
    for name, okk, detail in results:
        print(f"{'PASS' if okk else 'FAIL'}  {name}" + (f"  [{detail}]" if detail and not okk else ""))
    print(f"\n{len(results) - len(fails)}/{len(results)} geslaagd")
    return 0 if not fails else 1


if __name__ == "__main__":
    import sys
    mode = sys.argv[1] if len(sys.argv) > 1 else "dry-run"
    if mode == "test":
        sys.exit(run_test())
    if mode == "dry-run":
        sys.exit(dry_run())
    print("gebruik: hermes_prometheus.py dry-run|test", file=sys.stderr)
    sys.exit(64)
