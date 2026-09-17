#!/usr/bin/env python3
"""hermes_evaluator.py — deterministische evaluator (fase 3, DRY-RUN).

Modes:
  fast             samples.db -> trends/severity/incident-state (geen SSH);
                   replayt nieuwe samples met cursor (catch-up na downtime)
  deep             fast-regels zijn al gedraaid; hier read-only SSH deep checks
                   (disk-health, array, docker, pool, kernel/fs errors;
                   docker-space-detail alleen bij actief groei-incident,
                   oom-events alleen bij OOM-delta)
  baseline-report  per metriek min/p50/p95/p99/max + suggested thresholds
  test             synthetische cases (tempdirs; zelfde codepad als productie)

DRY-RUN: geen LLM, geen Telegram, geen remediation, geen DUMBscope, geen
Prometheus. Output: agent_state.db + evaluator-events.jsonl (alleen lokaal log).
"""
import json, hashlib, math, os, re, shutil, sqlite3, statistics, subprocess, sys, tempfile, uuid
from datetime import datetime, timezone
from pathlib import Path

DRY_RUN = True  # fase 3: dit bestand bevat structureel geen LLM/Telegram/remediation

HOME = Path(os.environ.get("HERMES_HOME", "/opt/data"))
HL = HOME / "homelab"
SAMPLES_DB = HL / "samples.db"
STATE_DB = HL / "agent_state.db"
EVENTS = HL / "evaluator-events.jsonl"
THRESHOLDS = HOME / "thresholds.yaml"

LEVELS = {"normal": 0, "notice": 1, "warning": 2, "urgent": 3, "critical": 4}
NAME = {v: k for k, v in LEVELS.items()}
RUN_ID = uuid.uuid4().hex[:12]

# ---------------------------------------------------------------- mini-yaml --
def mini_yaml(text):
    """Beperkte parser voor thresholds.yaml: nesting op indent, scalairen,
    inline-lijsten [a, b], comments. Geen anchors/geneste lijsten."""
    root = {}
    stack = [(-1, root)]
    for raw in text.splitlines():
        line = re.sub(r"#.*$", "", raw).rstrip()
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip())
        key, _, val = line.strip().partition(":")
        key, val = key.strip(), val.strip()
        while stack and indent <= stack[-1][0]:
            stack.pop()
        parent = stack[-1][1]
        if val == "":
            parent[key] = {}
            stack.append((indent, parent[key]))
        elif val.startswith("[") and val.endswith("]"):
            parent[key] = [v.strip().strip("'\"") for v in val[1:-1].split(",") if v.strip()]
        elif val.lower() in ("true", "false"):
            parent[key] = val.lower() == "true"
        else:
            try:
                parent[key] = int(val)
            except ValueError:
                try:
                    parent[key] = float(val)
                except ValueError:
                    parent[key] = val.strip("'\"")
    return root

def load_cfg():
    cfg = mini_yaml(THRESHOLDS.read_text()) if THRESHOLDS.exists() else {}
    cfg.setdefault("defaults", {"exit_margin_pp": 5, "sustained_samples": 2})
    cfg.setdefault("recovery", {"good_samples_to_resolve": 2})
    return cfg

def cfg_recovery(cfg):
    return int(cfg.get("recovery", {}).get("good_samples_to_resolve", 2))

# ------------------------------------------------------------------- state --
def state_db():
    c = sqlite3.connect(STATE_DB, timeout=10)
    c.execute("pragma journal_mode=wal")
    c.execute("pragma busy_timeout=5000")
    c.execute("pragma synchronous=normal")
    c.executescript("""
    create table if not exists incidents(
      fingerprint text primary key, source text, type text, state text,
      current_severity text, previous_severity text,
      first_seen text, last_seen text, last_changed text, resolved_at text,
      occurrences integer default 1, last_value real, peak_value real,
      last_alert_at text, suppression_until text,
      good_samples integer default 0, last_reason text);
    create table if not exists metric_state(
      metric text primary key, last_value real, previous_value real, last_ts text,
      trend text, slope real, sustained_since text, peak real, baseline_pending integer);
    create table if not exists counters(
      name text primary key, device text, previous_value real, current_value real,
      delta real, last_checked text);
    create table if not exists cursors(
      name text primary key, value text, last_checked text);
    create table if not exists prom_history(
      metric text primary key, updated_at text, data_json text);
    create table if not exists dumbscope_incidents(
      fingerprint text primary key, source_fingerprint text, incident_id text,
      status text, severity text, title text, last_seen_ms integer,
      resolved_at_ms integer, occurrences integer, last_processed_at text,
      host_correlations text);
    """)
    # migraties (fase 5): llm-state op incidents, dumbscope-contextvelden
    for table, col, decl in (
            ("incidents", "llm_last_analyzed_at", "text"),
            ("incidents", "llm_last_model", "text"),
            ("incidents", "llm_summary", "text"),
            ("incidents", "llm_confidence", "real"),
            ("incidents", "llm_root_cause", "text"),
            ("incidents", "llm_analysis_version", "integer default 0"),
            ("incidents", "llm_context_hash", "text"),
            ("incidents", "llm_call_count", "integer default 0"),
            ("dumbscope_incidents", "summary", "text"),
            ("dumbscope_incidents", "root_cause_service", "text"),
            ("dumbscope_incidents", "affected_services", "text"),
            ("dumbscope_incidents", "evidence_json", "text")):
        cols = [r[1] for r in c.execute(f"pragma table_info({table})")]
        if col not in cols:
            c.execute(f"alter table {table} add column {col} {decl}")
    return c

def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

def emit(mode, check, fp, *, current=None, previous=None, trend=None, mn=None, mx=None,
         severity="normal", provisional=True, state="observed", baseline_pending=True,
         reason="", recommended_diagnostic=None, source="fast", sample_ts=None, extra=None):
    row = {"ts": now_iso(), "run_id": RUN_ID, "mode": mode, "check": check,
           "fingerprint": fp, "current": current, "previous": previous,
           "trend": trend or {}, "min24": mn, "max24": mx, "severity": severity,
           "state": state, "baseline_pending": baseline_pending,
           "provisional": provisional, "reason": reason,
           "recommended_diagnostic": recommended_diagnostic, "source": source,
           "sample_ts": sample_ts, "dry_run": DRY_RUN}
    if extra:
        row.update(extra)
    with EVENTS.open("a") as f:
        f.write(json.dumps(row, ensure_ascii=False) + "\n")
    return row

def incident_upsert(c, fp, *, source, itype, sev_level, value, reason):
    """Deterministische incident-state-machine -> (state, event_type)."""
    now = now_iso()
    sev = NAME[sev_level]
    row = c.execute("select state, current_severity, occurrences, peak_value from incidents"
                    " where fingerprint=?", (fp,)).fetchone()
    if row is None:
        if sev_level <= 0:
            return "none", "none"  # normal is geen incident
        c.execute("insert into incidents(fingerprint, source, type, state, current_severity,"
                  " previous_severity, first_seen, last_seen, last_changed, occurrences,"
                  " last_value, peak_value, last_alert_at, last_reason)"
                  " values(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                  (fp, source, itype, "active", sev, "normal", now, now, now, 1,
                   value, value, now, reason))
        return "active", "new"
    state, cur_sev, occ, peak = row[0], row[1], row[2], row[3]
    if sev_level <= 0 and state in ("active", "recovering"):
        # non-pct regels: eerste goede waarde lost direct op (pct heeft eigen recovery-pad)
        c.execute("update incidents set state='resolved', current_severity='normal',"
                  " previous_severity=?, last_changed=?, resolved_at=?, good_samples=0,"
                  " last_reason=? where fingerprint=?",
                  (cur_sev, now, now, "opgelost: waarde terug op normaal", fp))
        return "resolved", "resolved"
    prev_level = LEVELS.get(cur_sev, 0)
    peak = max(peak or 0, value or 0)
    if state == "resolved":
        if sev_level >= 2:
            c.execute("update incidents set state='active', current_severity=?, previous_severity=?,"
                      " occurrences=occurrences+1, last_seen=?, last_changed=?, resolved_at=NULL,"
                      " good_samples=0, peak_value=?, last_value=?, last_reason=? where fingerprint=?",
                      (sev, cur_sev, now, now, peak, value, reason, fp))
            return "active", "reopened"
        c.execute("update incidents set last_seen=?, last_value=? where fingerprint=?", (now, value, fp))
        return "resolved", "none"
    if state == "recovering":
        if sev_level >= 2:
            c.execute("update incidents set state='active', current_severity=?, previous_severity=?,"
                      " occurrences=occurrences+1, last_seen=?, last_changed=?, good_samples=0,"
                      " peak_value=?, last_value=?, last_reason=? where fingerprint=?",
                      (sev, cur_sev, now, now, peak, value, reason, fp))
            return "active", "escalated"
        c.execute("update incidents set last_seen=?, last_value=? where fingerprint=?", (now, value, fp))
        return "recovering", "none"
    # active
    if sev_level > prev_level:
        c.execute("update incidents set current_severity=?, previous_severity=?, last_seen=?,"
                  " last_changed=?, peak_value=?, last_value=?, last_reason=? where fingerprint=?",
                  (sev, cur_sev, now, now, peak, value, reason, fp))
        return "active", "escalated"
    c.execute("update incidents set last_seen=?, last_value=?, peak_value=?, last_reason=? where fingerprint=?",
              (now, value, peak, reason, fp))
    return "active", "none"

# ------------------------------------------------------------------ trends --
def fetch_series(metric, hours=24):
    if not SAMPLES_DB.exists():
        return []
    try:
        c = sqlite3.connect(f"file:{SAMPLES_DB}?mode=ro", uri=True, timeout=10)
        rows = c.execute(
            f"select ts, {metric} from samples where {metric} is not null and ts >= ?"
            " order by ts", (int(datetime.now(timezone.utc).timestamp()) - hours * 3600,)).fetchall()
        c.close()
    except sqlite3.OperationalError:
        return []
    return [(float(t), float(v)) for t, v in rows]

def nearest(points, target, tol=180):
    best_v, best_d = None, None
    for ts, v in points:
        d = abs(ts - target)
        if d <= tol and (best_d is None or d < best_d):
            best_v, best_d = v, d
    return best_v

def trend_of(points, eps=0.5):
    if not points:
        return {}
    now_ts, cur = points[-1]
    d = {"current": cur}
    for key, secs in (("d15m", 900), ("d1h", 3600), ("d6h", 21600)):
        v = nearest(points, now_ts - secs)
        d[key] = round(cur - v, 3) if v is not None else None
    win = [p for p in points if now_ts - p[0] <= 3900][-12:]
    slope = None
    if len(win) >= 3:
        x = [(p[0] - win[0][0]) / 3600 for p in win]
        y = [p[1] for p in win]
        mx, my = statistics.mean(x), statistics.mean(y)
        den = sum((a - mx) ** 2 for a in x)
        slope = sum((a - mx) * (b - my) for a, b in zip(x, y)) / den if den else 0.0
    d["slope_per_h"] = round(slope, 3) if slope is not None else None
    d["direction"] = ("rising" if (slope or 0) > eps else
                      "falling" if (slope or 0) < -eps else "stable")
    d["min24"] = min(p[1] for p in points)
    d["max24"] = max(p[1] for p in points)
    return d

def sustained_above(points, threshold, max_gap=660):
    n, last_ts = 0, None
    for ts, v in reversed(points):
        if v is None or v < threshold:
            break
        if last_ts is not None and last_ts - ts > max_gap:
            break
        n += 1
        last_ts = ts
    return n

# --------------------------------------------------------------- band-regel --
def band_level(value, th):
    if value >= th.get("critical_pct", 10**9): return 4
    if value >= th.get("urgent_pct", 10**9): return 3
    if value >= th.get("warn_pct", 10**9): return 2
    return 0

def eval_band(value, th, sustained, need, rising_fast, cap_notice_first=False, slope=None):
    """Deterministisch: crit altijd; urgent bij sustain of rising_fast; warning
    bij sustain of rising_fast; allereerste breach-sample -> notice (cap).
    lvl 2 + snel stijgend + nabij urgent -> urgent (§7)."""
    lvl = band_level(value, th)
    bits = []
    if lvl == 4:
        return 4, False, [f">=critical({th.get('critical_pct')})"]
    if cap_notice_first and sustained < 2 and lvl >= 1:
        return 1, True, [f"eerste breach-sample ({value}) -> notice (cap, §7)"]
    if lvl == 3:
        if sustained >= need:
            return 3, False, [f">=urgent sustained({sustained})"]
        if rising_fast:
            return 3, True, [">=urgent + rising_fast"]
        return 2, True, [">=urgent single sample -> warning provisional"]
    if lvl == 2:
        if sustained >= need:
            return 2, False, [f">=warn sustained({sustained})"]
        if rising_fast:
            urgent_at = th.get("urgent_pct")
            if urgent_at is not None and value >= urgent_at - 2 and (slope or 0) >= float(th.get("rise_urgent_ppc_per_hour", 5)):
                return 3, True, [">=warn + snel stijgend richting urgent"]
            return 2, True, [">=warn + rising_fast"]
        return 1, True, [">=warn single sample -> notice"]
    return 0, False, []

def exit_threshold(sev_level, th, margin=5):
    table = {1: th.get("warn_pct"), 2: th.get("warn_pct"), 3: th.get("urgent_pct"),
             4: th.get("critical_pct")}
    v = table.get(sev_level)
    return (v - margin) if v is not None else None

# -------------------------------------------------------------- pct-metriek --
def metric_state_update(c, metric, value, trend, baseline_pending=True):
    c.execute("insert into metric_state(metric, last_value, previous_value, last_ts, trend,"
              " slope, sustained_since, peak, baseline_pending) values(?,?,?,?,?,?,?,?,?)"
              " on conflict(metric) do update set previous_value=metric_state.last_value,"
              " last_value=excluded.last_value, last_ts=excluded.last_ts, trend=excluded.trend,"
              " slope=excluded.slope,"
              " peak=max(coalesce(metric_state.peak, excluded.last_value), excluded.last_value)",
              (metric, value,
               trend.get("d15m") if trend else None, now_iso(),
               (trend or {}).get("direction"), (trend or {}).get("slope_per_h"), None,
               value, 1 if baseline_pending else 0))

def pct_metric(c, cfg, events, *, fp, metric, label, th, sustain_need, value, points,
               trend, rising_fast=False, cap_notice_first=False, eps=0.5, mode="fast",
               sample_ts=None, source="fast"):
    """Bands + hysteresis + recovery voor één pct-metriek op één sample."""
    bp = bool(th.get("baseline_pending", True))
    margin = int(cfg.get("defaults", {}).get("exit_margin_pp", 5))
    need_resolve = cfg_recovery(cfg)
    metric_state_update(c, metric, value, trend, bp)
    row = c.execute("select state, current_severity, good_samples from incidents"
                    " where fingerprint=?", (fp,)).fetchone()
    prev_state = row[0] if row else "observed"
    prev_sev = LEVELS.get(row[1], 0) if row else 0
    good = (row[2] if row else 0) or 0
    sust = sustained_above(points, th.get("warn_pct", 10**9))
    lvl, prov, bits = eval_band(value, th, sust, sustain_need, rising_fast, cap_notice_first,
                                slope=(trend or {}).get("slope_per_h"))

    if row and prev_state in ("active", "recovering"):
        exit_at = exit_threshold(prev_sev, th, margin)
        if lvl < prev_sev:
            if exit_at is not None and value < exit_at:
                good += 1
                if good >= need_resolve:
                    c.execute("update incidents set state='resolved', current_severity='normal',"
                              " previous_severity=?, last_seen=?, last_changed=?, resolved_at=?,"
                              " good_samples=0, last_reason=? where fingerprint=?",
                              (NAME[prev_sev], now_iso(), now_iso(), now_iso(),
                               f"recovery: {good} goede samples < exit {exit_at}", fp))
                    events.append(emit(mode, label, fp, current=value, trend=trend, severity="normal",
                                       provisional=bp, state="resolved", baseline_pending=bp,
                                       reason=f"hersteld: {good} goede samples < exit {exit_at}",
                                       source=source, sample_ts=sample_ts))
                    return "normal", True
                sev_name = NAME[max(prev_sev - 1, 1)]
                c.execute("update incidents set state='recovering', current_severity=?, good_samples=?,"
                          " last_seen=?, last_value=?, last_reason=? where fingerprint=?",
                          (sev_name, good, now_iso(), value, f"recovering ({good}/{need_resolve})", fp))
                events.append(emit(mode, label, fp, current=value, trend=trend, severity=sev_name,
                                   provisional=bp, state="recovering", baseline_pending=bp,
                                   reason=f"herstel bezig ({good}/{need_resolve} goede samples)",
                                   source=source, sample_ts=sample_ts))
                return sev_name, True
            bits.append("hysteresis: binnen marge, severity gehouden")
            lvl = prev_sev
        elif lvl == prev_sev:
            bits.append("hysteresis: severity gehouden")

    name, etype = incident_upsert(c, fp, source=source, itype=metric, sev_level=lvl,
                                  value=value, reason="; ".join(bits) or "normal")
    if etype in ("new", "escalated", "reopened") or (lvl >= 1 and prov):
        events.append(emit(mode, label, fp, current=value, trend=trend, severity=NAME[lvl],
                           provisional=prov and bp, state=name, baseline_pending=bp,
                           reason="; ".join(bits) or f"{label}={value}",
                           source=source, sample_ts=sample_ts))
    return NAME[lvl], prov

# ---------------------------------------------------------------- dumbscope --
def make_client(cfg):
    """Factory (testbaar: tests monkeypatchen deze)."""
    import hermes_dumbscope as hd
    d = cfg.get("dumbscope", {})
    return hd.DumbScopeClient(base_url=d.get("base_url", "http://192.168.1.2:8091"),
                              username=d.get("username", "remco"),
                              secrets_dir=str(HOME / "secrets"),
                              timeout=int(d.get("timeout_s", 15)))

def run_dumbscope(cfg, c, events, mode="fast"):
    """DUMBscope-poll in de fast evaluator. Failure-isolation (§21): een fout
    hier crasht de host-evaluatie nooit; beschikbaarheid krijgt eigen
    incident-state met anti-flapping (pas na N opeenvolgende mislukkingen)."""
    dcfg = dict(cfg.get("dumbscope") or {})
    bp = bool(dcfg.get("baseline_pending", True))
    fail_warn = int(dcfg.get("failure_warning_polls", 3))
    fail_urgent = int(dcfg.get("failure_urgent_polls", 12))
    resolved_limit = int(dcfg.get("resolved_poll_limit", 20))
    st = {}

    def failures():
        row = c.execute("select value from cursors where name='dumbscope:failures'").fetchone()
        return int(float(row[0])) if row else 0

    def set_failures(n):
        c.execute("insert into cursors(name, value, last_checked)"
                  " values('dumbscope:failures', ?, ?) on conflict(name) do update"
                  " set value=excluded.value, last_checked=excluded.last_checked",
                  (str(n), now_iso()))

    try:
        client = make_client(cfg)
        result = client.poll(resolved_limit=resolved_limit)
    except Exception as e:  # noqa: BLE001 — bewust breed: isolatie is het doel
        reason = getattr(e, "reason", type(e).__name__)
        n = failures() + 1
        set_failures(n)
        lvl = 3 if n >= fail_urgent else (2 if n >= fail_warn else 0)
        if lvl:
            _, etype = incident_upsert(c, "dumbscope:availability", source="dumbscope",
                                       itype="availability", sev_level=lvl, value=n,
                                       reason=f"{n} opeenvolgende mislukte polls ({reason})")
            if etype in ("new", "escalated"):
                events.append(emit(mode, "dumbscope_availability", "dumbscope:availability",
                                   current=n, severity=NAME[lvl], provisional=bp, state="active",
                                   baseline_pending=bp,
                                   reason=f"DUMBscope onbereikbaar/auth: {reason} ({n} polls)",
                                   source="dumbscope"))
        c.commit()
        st["dumbscope"] = f"unavailable ({reason}, poll {n})"
        return st

    # succes: herstel availability-incident indien aanwezig
    n = failures()
    if n:
        set_failures(0)
        _, etype = incident_upsert(c, "dumbscope:availability", source="dumbscope",
                                   itype="availability", sev_level=0, value=0,
                                   reason="DUMBscope weer bereikbaar")
        if etype == "resolved":
            events.append(emit(mode, "dumbscope_availability", "dumbscope:availability",
                               severity="normal", provisional=bp, state="resolved",
                               baseline_pending=True, reason=f"hersteld na {n} mislukte polls",
                               source="dumbscope"))
    c.execute("insert into cursors(name, value, last_checked) values('dumbscope:last_poll', ?, ?)"
              " on conflict(name) do update set value=excluded.value, last_checked=excluded.last_checked",
              (now_iso(), now_iso()))
    st["dumbscope"] = result["health"].get("dumb")
    st["dumbscope_active"] = result["metrics"].get("active_count")
    st["dumbscope_payload"] = result["metrics"].get("payload_bytes")

    # host-correlaties: gelijktijdige actieve hostproblemen (geen oorzaak-claim, §13)
    hostcor = [r[0] for r in c.execute(
        "select fingerprint from incidents where (source is null or source != 'dumbscope')"
        " and state in ('active','recovering')"
        " and current_severity in ('warning','urgent','critical')")]

    seeded_row = c.execute("select value from cursors where name='dumbscope:seeded'").fetchone()
    seeded = seeded_row is not None
    changed = 0

    def emit_ds(inc, ev_state, sev, changed_fields, reason):
        events.append(emit(mode, "dumbscope_incident", inc["fingerprint"],
                           current={"status": inc["source_status"], "occurrences": inc["occurrences"],
                                    "last_seen": inc["last_seen"]},
                           severity=sev, provisional=bp and not inc["severity_unmapped"],
                           state=ev_state, baseline_pending=bp, reason=reason,
                           source="dumbscope",
                           extra={"source_status": inc["source_status"],
                                  "source_incident_id": inc["source_incident_id"],
                                  "title": inc["title"],
                                  "root_cause_service": inc["root_cause_service"],
                                  "affected_services": inc["affected_services"],
                                  "occurrences": inc["occurrences"],
                                  "changed_fields": changed_fields,
                                  "host_correlations": hostcor,
                                  "evidence": inc["evidence"][:3],
                                  "severity_source": inc["severity_source"],
                                  "severity_unmapped": inc["severity_unmapped"]}))

    for inc in result["incidents"]:
        fp = inc["fingerprint"]
        ds_ctx = (json.dumps(inc["evidence"][:10]), inc["summary"],
                  inc["root_cause_service"], json.dumps(inc["affected_services"]))
        row = c.execute("select incident_id, status, severity, occurrences, last_seen_ms"
                        " from dumbscope_incidents where fingerprint=?", (fp,)).fetchone()
        if row is None:
            c.execute("insert into dumbscope_incidents values(?,?,?,?,?,?,?,?,?,?,?,"
                      "?,?,?,?)",
                      (fp, inc["source_fingerprint"], inc["source_incident_id"], inc["source_status"],
                       inc["severity"], inc["title"], inc["last_seen_ms"], inc["resolved_at_ms"],
                       inc["occurrences"], now_iso(), json.dumps(hostcor),
                       ds_ctx[0], ds_ctx[1], ds_ctx[2], ds_ctx[3]))
            if seeded:
                emit_ds(inc, "resolved" if inc["state"] == "resolved" else "active",
                        inc["severity"], ["new"], "nieuw DUMBscope-incident")
                changed += 1
            continue
        c.execute("update dumbscope_incidents set incident_id=?, status=?, severity=?,"
                  " occurrences=?, last_seen_ms=?, resolved_at_ms=?, last_processed_at=?,"
                  " host_correlations=?, summary=?, root_cause_service=?,"
                  " affected_services=?, evidence_json=? where fingerprint=?",
                  (inc["source_incident_id"], inc["source_status"], inc["severity"],
                   inc["occurrences"], inc["last_seen_ms"], inc["resolved_at_ms"], now_iso(),
                   json.dumps(hostcor), ds_ctx[1], ds_ctx[2], ds_ctx[3], ds_ctx[0], fp))
        inc_id, s_status, s_sev, s_occ, s_last = row
        changed_fields = []
        if s_status != inc["source_status"]:
            changed_fields.append(f"status:{s_status}->{inc['source_status']}")
        if (inc["occurrences"] or 0) > (s_occ or 0):
            changed_fields.append(f"occurrences:{s_occ}->{inc['occurrences']}")
        if s_sev != inc["severity"]:
            changed_fields.append(f"severity:{s_sev}->{inc['severity']}")
        if not changed_fields:
            continue  # identieke poll: geen event (§18)
        # lifecycle: DUMBscope kent active/resolved — Hermes volgt 1-op-1 (§9)
        if inc["source_status"] == "resolved":
            ev_state, sev = "resolved", "normal"
        elif s_status == "resolved":
            ev_state, sev = "reopened", inc["severity"]
        elif "severity:" in " ".join(changed_fields):
            ev_state, sev = "active", inc["severity"]  # escalatie/de-escalatie
        else:
            ev_state, sev = "active", inc["severity"]
        reason = "wijziging: " + ", ".join(changed_fields)
        if inc["severity_unmapped"]:
            reason += f" [onbekende severity '{inc['severity_source']}' -> notice]"
        emit_ds(inc, ev_state, sev, changed_fields, reason)
        changed += 1

    if not seeded:
        n_all = c.execute("select count(*) from dumbscope_incidents").fetchone()[0]
        c.execute("insert into cursors(name, value, last_checked)"
                  " values('dumbscope:seeded', '1', ?) on conflict(name) do update"
                  " set value=excluded.value, last_checked=excluded.last_checked", (now_iso(),))
        events.append(emit(mode, "dumbscope_baseline", "dumbscope:baseline",
                           current={"seeded": n_all, "active": result["metrics"].get("active_count")},
                           severity="normal", provisional=bp, state="seeded", baseline_pending=bp,
                           reason=f"eerste poll: {n_all} bekende incidenten geseed (geen per-incident events)",
                           source="dumbscope"))
    c.commit()
    st["dumbscope_changed"] = changed
    return st

# -------------------------------------------------------------------- fast --
# ------------------------------------------------------------- llm-laag (5) --
def needs_llm_analysis(c, fp, severity, state):
    """Deterministische skip/route-beslissing (§4). Geeft (route, reden).
    Tier 0 blijft source of truth: bekende oorzaak = geen LLM."""
    if state != "active":
        return False, "skip:resolved_of_niet_actief"
    if severity not in ("warning", "urgent", "critical"):
        return False, "skip:severity_onder_warning"
    if fp == "dumbscope:availability":
        return False, "skip:bekende_oorzaak(availability/auth)"
    if fp == "prometheus:availability" or fp.startswith("notifications:"):
        return False, "skip:bekende_oorzaak(infra_delivery)"
    if fp.startswith("dumbscope:"):
        d = c.execute("select root_cause_service, evidence_json, host_correlations"
                      " from dumbscope_incidents where fingerprint=?", (fp,)).fetchone()
        if d and d[0] and d[1] and d[1] != "[]" and (d[2] in (None, "[]", "")):
            return False, "skip:duidelijke_root_cause_met_evidence"
        return True, "route:dumbscope_onzeker_of_multi_system_of_hostcorrelatie"
    for pref in ("host:cache:high", "host:vm_storage:high", "host:user_share:high",
                 "host:rootfs:high", "host:logfs:high", "host:logfs:growth",
                 "host:docker_vdisk:high", "host:docker_vdisk:growth",
                 "host:memory:high", "host:memory:oom", "host:docker_daemon:down",
                 "host:swap:active", "host:array:", "host:containers:unhealthy"):
        if fp.startswith(pref):
            return False, "skip:bekende_deterministische_oorzaak"
    if ":restarts" in fp:
        return False, "skip:simpele_restart_delta"
    if "_growth" in fp and ":crc" in fp:
        return False, "skip:crc_delta_zonder_onzekerheid"
    if fp.startswith("disk:") and ":smart_failed" in fp:
        return False, "skip:smart_health_expliciet"
    return True, "route:oorzaak_onbekend"

def build_context(c, fp, sev):
    """Compacte modelcontext (§5) — hard begrensd door de router-sanitizer/cap."""
    ctx = {"fingerprint": fp, "severity": sev}
    row = c.execute("select source, last_value, peak_value, last_reason from incidents"
                    " where fingerprint=?", (fp,)).fetchone()
    if row:
        ctx.update({"source": row[0], "last_value": row[1], "peak": row[2],
                    "reason": (row[3] or "")[:240]})
    ms = c.execute("select last_value, slope, trend from metric_state where metric=("
                   "select case substr(fingerprint, 6) when 'memory:high' then 'mem_used_pct'"
                   " when 'docker_vdisk:high' then 'vdisk_pct' when 'logfs:high' then 'logfs_pct'"
                   " when 'cache:high' then 'cache_pct' when 'vm_storage:high' then 'vm_pct'"
                   " when 'user_share:high' then 'user_pct' when 'rootfs:high' then 'rootfs_pct'"
                   " when 'temperature:package' then 'package_temp_c'"
                   " when 'temperature:core' then 'core_max_temp_c' end"
                   " from incidents where fingerprint=?)", (fp,)).fetchone()
    if ms and ms[0] is not None:
        ctx["metric"] = {"last": ms[0], "slope_per_h": ms[1], "direction": ms[2]}
    others = [r[0] for r in c.execute(
        "select fingerprint from incidents where state in ('active','recovering')"
        " and fingerprint != ? and current_severity in ('warning','urgent','critical')", (fp,))]
    if others:
        ctx["concurrent_incidents"] = others[:8]
    try:
        import hermes_prometheus as hprom
        trends = hprom.llm_trend_lines(c, fp)
        if trends:
            ctx["prom_trends"] = trends  # compact, max ~8 regels (fase 6)
    except Exception:  # noqa: BLE001 — context is best-effort, nooit kritiek
        pass
    d = c.execute("select title, summary, severity, status, root_cause_service,"
                  " affected_services, occurrences, evidence_json, host_correlations"
                  " from dumbscope_incidents where fingerprint=?", (fp,)).fetchone()
    if d:
        ctx.update({"title": d[0], "summary": (d[1] or "")[:500], "source_severity": d[2],
                    "status": d[3], "root_cause_service": d[4],
                    "affected_services": json.loads(d[5]) if d[5] else [],
                    "occurrences": d[6],
                    "evidence": (json.loads(d[7]) if d[7] else [])[:10],
                    "host_correlations": json.loads(d[8]) if d[8] else []})
    return ctx

def run_llm_layer(cfg, c, events):
    """Fase 5: kandidaten -> router (Ling->DeepSeek->GLM->Luna) -> llm-state."""
    lcfg = dict(cfg.get("llm") or {})
    if not lcfg.get("enabled", False):
        return {"llm": "disabled"}
    try:
        import hermes_router as hr
    except Exception as e:
        return {"llm": f"import_error: {e}"}
    api_key = hr.load_env_key()
    if not api_key:
        return {"llm": "geen OPENROUTER_API_KEY"}
    today = now_iso()[:10]
    drow = c.execute("select current_value from counters where name=?",
                     (f"llm_calls_daily:{today}",)).fetchone()
    daily = int(drow[0]) if drow else 0
    stats = {"kandidaten": 0, "tier0_skips": 0, "geanalyseerd": 0, "llm_calls": 0}
    rows = c.execute("select fingerprint, source, current_severity, state,"
                     " llm_context_hash, llm_call_count from incidents where state='active'"
                     " and current_severity in ('warning','urgent','critical')").fetchall()
    for fp, source, sev, state, chash, ccount in rows:
        route, why = needs_llm_analysis(c, fp, sev, state)
        if not route:
            stats["tier0_skips"] += 1
            continue
        stats["kandidaten"] += 1
        ctx = build_context(c, fp, sev)
        h = hashlib.sha1(json.dumps(
            {k: ctx.get(k) for k in ("severity", "occurrences", "reason", "evidence",
                                     "status", "host_correlations", "last_value")},
            sort_keys=True, default=str).encode()).hexdigest()[:16]
        if h == chash:
            stats["tier0_skips"] += 1
            continue  # ongewijzigd sinds laatste analyse (§18)
        bp = bool((cfg.get("llm") or {}).get("baseline_pending", True))
        final, calls = hr.analyze(fp, source=source or "fast", severity=sev,
                                  task="incident_analyse", context=ctx, llm_cfg=lcfg,
                                  api_key=api_key, per_incident_calls=ccount or 0,
                                  daily_calls=daily)
        ok_calls = [x for x in calls if x.get("success")]
        daily += len(ok_calls)
        c.execute("insert into counters(name, device, previous_value, current_value, delta,"
                  " last_checked) values(?,?,?,?,?,?) on conflict(name) do update set"
                  " current_value=excluded.current_value",
                  (f"llm_calls_daily:{today}", "router", daily - len(ok_calls), daily, len(ok_calls), now_iso()))
        analysis = final.get("analysis") or {}
        model = ok_calls[-1].get("actual_model") if ok_calls else None
        summary = (analysis.get("summary") or analysis.get("diagnosis") or "")[:300]
        c.execute("update incidents set llm_last_analyzed_at=?, llm_last_model=?, llm_summary=?,"
                  " llm_confidence=?, llm_root_cause=?, llm_analysis_version=llm_analysis_version+1,"
                  " llm_context_hash=?, llm_call_count=llm_call_count+? where fingerprint=?",
                  (now_iso(), model, summary, final.get("confidence"),
                   ((analysis.get("likely_root_cause") or analysis.get("diagnosis") or ""))[:200],
                   h, len(calls), fp))
        stats["geanalyseerd"] += 1
        stats["llm_calls"] += len(calls)
        events.append(emit("fast", "llm_analysis", fp, severity=sev,
                           provisional=bp, state=final.get("status", "done"),
                           baseline_pending=bp,
                           reason=(f"{final.get('status')} tier={final.get('tier')} "
                                   f"calls={len(calls)} conf={final.get('confidence')} "
                                   f"reason={[x.get('escalation_reason') or x.get('error') for x in calls]}")[:300],
                           source="llm",
                           extra={"llm": {"tier": final.get("tier"), "confidence": final.get("confidence"),
                                          "calls": len(calls),
                                          "models": [x.get("actual_model") for x in calls],
                                          "routing_violations": [x.get("routing_violation") for x in calls],
                                          "summary": summary}}))
    return stats

PCT_RULES_FAST = [
    ("mem_used_pct", "host:memory:high", "memory", "memory", 0.5),
    ("vdisk_pct", "host:docker_vdisk:high", "docker_vdisk", "docker_vdisk", 0.3),
    ("logfs_pct", "host:logfs:high", "logfs", "logfs", 0.5),
    ("cache_pct", "host:cache:high", "cache", "storage", 0.3),
    ("vm_pct", "host:vm_storage:high", "vm_storage", "storage", 0.3),
    ("user_pct", "host:user_share:high", "user_share", "storage", 0.3),
    ("rootfs_pct", "host:rootfs:high", "rootfs", "storage", 0.3),
    ("package_temp_c", "host:temperature:package", "package_temp", "temperatures", 1.0),
    ("core_max_temp_c", "host:temperature:core", "core_temp", "temperatures", 1.0),
]
CAP_NOTICE_METRICS = {"package_temp_c", "core_max_temp_c"}

def run_fast(cfg, events):
    c = state_db()
    need = int(cfg.get("defaults", {}).get("sustained_samples", 2))
    st = {}
    series = {m: fetch_series(m) for m, *_ in PCT_RULES_FAST}
    series["vdisk_used_kb"] = fetch_series("vdisk_used_kb")

    row = c.execute("select value from cursors where name='fast:last_ts'").fetchone()
    last_ts = int(float(row[0])) if row else 0
    all_ts = sorted({ts for s in series.values() for ts, _ in s})
    new_ts = [ts for ts in all_ts if ts > last_ts]

    for ts in new_ts:
        points = {m: [p for p in s if p[0] <= ts] for m, s in series.items()}
        for metric, fp, label, sect, eps in PCT_RULES_FAST:
            pts = points[metric]
            if not pts or pts[-1][0] != ts:
                continue
            tr = trend_of(pts, eps=eps)
            th = dict(cfg.get(sect, {}))
            sneed = need
            if sect == "temperatures":
                # band-engine verwacht warn_pct/urgent_pct/critical_pct
                th["warn_pct"] = th.get("package_warn_c")
                th["urgent_pct"] = th.get("package_urgent_c")
                th["critical_pct"] = th.get("package_critical_c")
                sneed = max(1, math.ceil(int(th.get("sustained_minutes", 15)) / 5))
            rising_fast = ((tr.get("slope_per_h") or 0) >=
                           float(th.get("rise_rate_pct_per_hour", th.get("rise_urgent_ppc_per_hour", 5))))
            sev, prov = pct_metric(c, cfg, events, fp=fp, metric=metric, label=label, th=th,
                                   sustain_need=sneed, value=tr["current"], points=pts, trend=tr,
                                   rising_fast=rising_fast,
                                   cap_notice_first=metric in CAP_NOTICE_METRICS,
                                   eps=eps, mode="fast", sample_ts=ts)
            st[label] = sev

    # vDisk-groei: delta 1h/24h op vdisk_used_kb (alleen laatste stand)
    kb = series["vdisk_used_kb"]
    if len(kb) >= 2:
        tr = trend_of(kb, eps=200 * 1024)
        limit = float(cfg.get("docker_vdisk", {}).get("growth_warn_gb_per_24h", 2)) * 1024**2
        d1h, d24h = tr.get("d1h"), tr.get("d24h")
        eff = max(x or 0 for x in (d1h * 24 if d1h is not None else 0, d24h or 0))
        lvl = 2 if eff > limit else 0
        _, etype = incident_upsert(c, "host:docker_vdisk:growth", source="fast", itype="vdisk_growth",
                                   sev_level=lvl, value=round(eff / 1024**2, 2),
                                   reason=f"d1h={d1h}KB d24h={d24h}KB limit={int(limit)}KB",
                                   )
        if etype in ("new", "escalated"):
            events.append(emit("fast", "docker_vdisk_growth", "host:docker_vdisk:growth",
                               current=round(eff / 1024**2, 2), trend={"d1h_kb": d1h, "d24h_kb": d24h},
                               severity=NAME[lvl], provisional=True, state="active", baseline_pending=True,
                               reason="groei > growth_warn_gb_per_24h (24u of geëxtrapoleerd uit 1u)",
                               recommended_diagnostic="docker-space-detail"))
        elif etype == "resolved":
            events.append(emit("fast", "docker_vdisk_growth", "host:docker_vdisk:growth",
                               current=round(eff / 1024**2, 2), severity="normal", provisional=True,
                               state="resolved", baseline_pending=True, reason="groei terug onder grens"))
        metric_state_update(c, "vdisk_growth_kb24", round(eff / 1024**2, 2), tr)

    # /var/log-groei: klein tmpfs, snelle groei weegt extra zwaar (§9)
    # eff_rate = max(OLS-slope, 15-min-delta x 4): stapsgroei wordt niet weggedrukt
    lpts = series["logfs_pct"]
    if len(lpts) >= 3:
        ltr = trend_of(lpts, eps=0.5)
        glimit = float(cfg.get("logfs", {}).get("growth_warn_pp_per_hour", 5))
        eff_rate = max(ltr.get("slope_per_h") or 0, (ltr.get("d15m") or 0) * 4)
        glvl = 2 if eff_rate >= glimit else 0
        _, etype = incident_upsert(c, "host:logfs:growth", source="fast", itype="logfs_growth",
                                   sev_level=glvl, value=round(eff_rate, 2),
                                   reason=f"groeirate {round(eff_rate,2)}pp/h >= {glimit}pp/h")
        if etype in ("new", "escalated"):
            events.append(emit("fast", "logfs_growth", "host:logfs:growth", current=round(eff_rate, 2),
                               trend=ltr, severity=NAME[glvl], provisional=True, state="active",
                               baseline_pending=True, reason="snelle groei klein filesystem",
                               recommended_diagnostic="logfs-status"))
        elif etype == "resolved":
            events.append(emit("fast", "logfs_growth", "host:logfs:growth", current=round(eff_rate, 2),
                               severity="normal", provisional=True, state="resolved",
                               baseline_pending=True, reason="groei terug onder grens"))
        metric_state_update(c, "logfs_growth_pph", ltr.get("slope_per_h"), ltr)

    # OOM monotone counter (primaire bron: sampler /proc/vmstat)
    oom = fetch_series("oom_kills", 3)
    if oom:
        cur = oom[-1][1]
        row = c.execute("select current_value from counters where name='oom_kills'").fetchone()
        prev = row[0] if row else cur  # eerste waarneming = baseline
        delta = cur - prev
        c.execute("insert into counters(name, device, previous_value, current_value, delta,"
                  " last_checked) values('oom_kills','host',?,?,?,?) on conflict(name) do update"
                  " set previous_value=counters.current_value, current_value=excluded.current_value,"
                  " delta=excluded.delta, last_checked=excluded.last_checked",
                  (prev, cur, delta, now_iso()))
        if delta > 0:
            sev_name = cfg.get("memory", {}).get("oom_event_severity", "critical")
            _, etype = incident_upsert(c, "host:memory:oom", source="fast", itype="oom",
                                       sev_level=LEVELS[sev_name], value=delta,
                                       reason=f"oom_kills {int(prev)} -> {int(cur)}", )
            if etype in ("new", "escalated"):
                events.append(emit("fast", "oom", "host:memory:oom", current=int(cur), previous=int(prev),
                                   severity=sev_name, provisional=True, state="active",
                                   baseline_pending=True, reason=f"OOM-teller +{delta}",
                                   recommended_diagnostic="oom-events"))
        st["oom_kills"] = int(cur)

    # docker daemon down (sampler), swap, unhealthy-teller: laatste sample
    for metric, fp, label, lvl0, reason in (
            ("docker_ok", "host:docker_daemon:down", "docker_daemon", 4, "docker daemon onbereikbaar"),
            ("containers_unhealthy", "host:containers:unhealthy", "containers_unhealthy", 1,
             "unhealthy containers aanwezig")):
        pts = fetch_series(metric, 1)
        if pts and pts[-1][1] == (0 if metric == "docker_ok" else pts[-1][1]) and \
           ((metric == "docker_ok" and pts[-1][1] == 0) or (metric != "docker_ok" and pts[-1][1] > 0)):
            value = pts[-1][1]
            _, etype = incident_upsert(c, fp, source="fast", itype=metric, sev_level=lvl0,
                                       value=value, reason=reason, )
            if etype in ("new", "escalated"):
                events.append(emit("fast", label, fp, current=value, severity=NAME[lvl0],
                                   provisional=True, state="active", baseline_pending=True,
                                   reason=reason, source="fast"))
    sw = fetch_series("swap_used_kb", 1)
    if sw and sw[-1][1] > 0:
        lvl = 2 if sw[-1][1] > int(cfg.get("swap", {}).get("used_kb_warn", 262144)) else 1
        _, etype = incident_upsert(c, "host:swap:active", source="fast", itype="swap",
                                   sev_level=lvl, value=sw[-1][1],
                                   reason="swap actief (host heeft standaard geen swap)", )
        if etype in ("new", "escalated"):
            events.append(emit("fast", "swap", "host:swap:active", current=sw[-1][1],
                               severity=NAME[lvl], provisional=True, state="active",
                               baseline_pending=True, reason="swap verscheen onverwacht"))

    if new_ts:
        c.execute("insert into cursors(name, value, last_checked) values('fast:last_ts', ?, ?)"
                  " on conflict(name) do update set value=excluded.value, last_checked=excluded.last_checked",
                  (str(int(new_ts[-1])), now_iso()))
    # DUMBscope-poll (fase 4): failure-isolated — een fout hier raakt de
    # host-evaluatie niet (§21); nog vóór de slot-commit van run_fast.
    try:
        ds = run_dumbscope(cfg, c, events, mode="fast")
        st.update({k: v for k, v in ds.items()})
    except Exception as e:  # noqa: BLE001 — isolatie bewust breed
        events.append(emit("fast", "dumbscope_integration", "dumbscope:integration_error",
                           severity="notice", provisional=True, state="observed",
                           baseline_pending=True,
                           reason=f"integratiefout (host-monitoring onaangetast): {type(e).__name__}: {e}"[:240],
                           source="dumbscope"))
        st["dumbscope"] = "integration_error"
    try:
        llm_stats = run_llm_layer(cfg, c, events)
        st.update({f"llm_{k}": v for k, v in llm_stats.items()})
    except Exception as e:  # noqa: BLE001 — isolatie bewust breed (§21-analoog)
        events.append(emit("fast", "llm_integration", "llm:integration_error",
                           severity="notice", provisional=True, state="observed",
                           baseline_pending=True,
                           reason=f"llm-laag faalde (host-monitoring onaangetast): "
                                  f"{type(e).__name__}: {e}"[:240], source="llm"))
        st["llm"] = "integration_error"
    # Prometheus historische context (fase 6): optioneel, selectief, read-only.
    # Faalt Prometheus, dan crasht dit nooit en valt alles terug op samples.db.
    try:
        import hermes_prometheus as hprom
        if (cfg.get("prometheus") or {}).get("enabled", True):
            prom = hprom.run_prometheus_context(cfg, c, events, home=HOME, emit=emit, mode="fast")
            st["prometheus"] = {k: v for k, v in prom.items() if k != "history"}
            st["prom_metrics"] = sorted(prom.get("history", {}))
    except Exception as e:  # noqa: BLE001 — isolatie bewust breed (§21-analoog)
        events.append(emit("fast", "prometheus_integration", "prometheus:integration_error",
                           severity="notice", provisional=True, state="observed",
                           baseline_pending=True,
                           reason=f"prometheus-context faalde (host-monitoring onaangetast): "
                                  f"{type(e).__name__}: {e}"[:240], source="prometheus"))
        st["prometheus"] = "integration_error"
    active = c.execute("select count(*) from incidents where state in ('active','recovering')").fetchone()[0]
    c.commit(); c.close()
    return {"mode": "fast", "run_id": RUN_ID, "ts": now_iso(), "events": len(events),
            "samples_replayed": len(new_ts), "incidents_active": active,
            "dry_run": DRY_RUN, **{f"sev_{k}": v for k, v in st.items()}}

# -------------------------------------------------------------------- deep --
SSH_KEY = HOME / "home/.ssh/agent-read"
SSH_KH = HOME / "home/.ssh/known_hosts"
SSH_HOST = "192.168.1.2"

def ssh_action(action, *args, timeout=45):
    cmd = ["ssh", "-i", str(SSH_KEY), "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
           "-o", "UserKnownHostsFile=" + str(SSH_KH), "-o", "ConnectTimeout=10",
           f"root@{SSH_HOST}", action, *args]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if p.returncode != 0:
            return {"ok": False, "error": f"ssh exit {p.returncode}: {p.stderr[:120]}"}
        return json.loads(p.stdout)
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": f"timeout {timeout}s"}
    except Exception as e:
        return {"ok": False, "error": str(e)[:120]}

def counter(c, name, device, value):
    row = c.execute("select current_value from counters where name=?", (name,)).fetchone()
    prev = row[0] if row else value  # eerste waarneming = baseline, geen delta-event
    delta = value - prev
    c.execute("insert into counters(name, device, previous_value, current_value, delta,"
              " last_checked) values(?,?,?,?,?,?) on conflict(name) do update set"
              " previous_value=counters.current_value, current_value=excluded.current_value,"
              " delta=excluded.delta, last_checked=excluded.last_checked",
              (name, device, prev, value, delta, now_iso()))
    return prev, delta

def line_fingerprint(line):
    norm = re.sub(r"\d+", "N", line.lower())
    norm = re.sub(r"\[[^\]]*\]", "", norm)
    return hashlib.sha1(norm.encode()).hexdigest()[:16]

def run_deep(cfg, events):
    c = state_db()
    st = {}

    # disk-health: health + monotone counters (§12)
    dh = ssh_action("disk-health")
    if dh.get("ok"):
        for d in dh["data"]:
            dev = d["device"]
            if d.get("state") == "standby":
                continue  # slapende disk: counters NIET aanraken (geen vals reset-signaal)
            if (d.get("health") or "").upper() not in ("PASSED", "OK", ""):
                _, etype = incident_upsert(c, f"disk:{dev}:smart_failed", source="deep", itype="smart",
                                           sev_level=4, value=0,
                                           reason=f"health={d.get('health')}", )
                if etype in ("new", "escalated"):
                    events.append(emit("deep", "disk_health", f"disk:{dev}:smart_failed",
                                       current=d.get("health"), severity="critical", provisional=True,
                                       state="active", baseline_pending=True,
                                       reason=f"SMART health {d.get('health')}", source="deep"))
            for field, short in (("crc_errors", "crc"), ("reallocated", "reallocated"),
                                 ("pending", "pending"), ("offline_uncorrectable", "offline_unc"),
                                 ("media_errors", "media_errors")):
                v = d.get(field)
                if v is None:
                    continue
                prev, delta = counter(c, f"smart:{dev}:{short}", dev, v)
                if short == "pending" and v > 0:
                    _, etype = incident_upsert(c, f"disk:{dev}:pending_absolute", source="deep",
                                               itype="smart", sev_level=2, value=v,
                                               reason=f"pending sectors aanwezig ({v})", )
                    if etype in ("new", "escalated"):
                        events.append(emit("deep", "disk_health", f"disk:{dev}:pending_absolute",
                                           current=v, previous=prev, severity="warning",
                                           provisional=True, state="active", baseline_pending=True,
                                           reason="pending > 0 (absolute regel, §12)", source="deep"))
                if delta > 0:
                    jump = int(cfg.get("counters", {}).get("crc_jump_warning", 50))
                    lvl = 2 if (delta >= jump or short != "crc") else 1
                    _, etype = incident_upsert(c, f"disk:{dev}:{short}_growth", source="deep",
                                               itype="smart_counter", sev_level=lvl, value=delta,
                                               reason=f"{short} {int(prev)} -> {int(v)} (+{int(delta)})",
                                               )
                    if etype in ("new", "escalated") or lvl >= 2:
                        events.append(emit("deep", "disk_health", f"disk:{dev}:{short}_growth",
                                           current=int(v), previous=int(prev), severity=NAME[lvl],
                                           provisional=True, state="active", baseline_pending=True,
                                           reason=f"monotone teller +{int(delta)} (delta-regel, §12)",
                                           source="deep"))
                elif delta == 0 and short == "crc":
                    pass  # identiek: geen event (§12)
        st["disks"] = len(dh["data"])
    else:
        events.append(emit("deep", "disk_health", "ssh:disk_health", severity="notice",
                           provisional=True, state="observed", baseline_pending=True,
                           reason=f"deep check mislukt: {dh.get('error')}", source="deep"))

    # array-status: alleen pos/size/pct bepaalt actieve operatie (§13)
    ar = ssh_action("array-status")
    if ar.get("ok"):
        data = ar["data"]
        if data.get("state") != "STARTED":
            _, etype = incident_upsert(c, "host:array:stopped", source="deep", itype="array",
                                       sev_level=4, value=0, reason=f"state={data.get('state')}",
                                       )
            if etype in ("new", "escalated"):
                events.append(emit("deep", "array_status", "host:array:stopped", current=data.get("state"),
                                   severity="critical", provisional=True, state="active",
                                   baseline_pending=True, reason="array niet STARTED", source="deep"))
        if data.get("resync_pct") not in (None, 0, 100):
            _, etype = incident_upsert(c, "host:array:resync", source="deep", itype="array",
                                       sev_level=1, value=data.get("resync_pct"),
                                       reason=f"resync {data.get('resync_action')} @ {data.get('resync_pct')}%",
                                       )
            if etype in ("new", "escalated"):
                events.append(emit("deep", "array_status", "host:array:resync", current=data.get("resync_pct"),
                                   severity="notice", provisional=True, state="active",
                                   baseline_pending=True,
                                   reason="parity/resync werkelijk actief (pos/size, §13)", source="deep"))
        st["array"] = data.get("state")

    # pool read-only → CRITICAL (§10)
    ps = ssh_action("pool-status")
    if ps.get("ok"):
        for p in ps["data"]:
            if not p.get("rw", True):
                _, etype = incident_upsert(c, f"pool:{p['mount']}:readonly", source="deep", itype="pool",
                                           sev_level=4, value=0, reason="read-only remount", )
                if etype in ("new", "escalated"):
                    events.append(emit("deep", "pool_status", f"pool:{p['mount']}:readonly", current=p,
                                       severity="critical", provisional=True, state="active",
                                       baseline_pending=True, reason="pool read-only gemount", source="deep"))

    # docker containers: restart-delta + exit-classificatie (§14)
    known = set(cfg.get("docker_daemon", {}).get("known_stopped", []))
    loop_delta = int(cfg.get("docker_daemon", {}).get("restart_loop_delta", 3))
    ds = ssh_action("docker-status")
    if ds.get("ok"):
        for cont in ds["data"]["containers"]:
            name = cont["name"]
            restarts = int(cont.get("restarts") or 0)
            state = cont["state"]
            prev, delta = counter(c, f"restarts:{name}", name, restarts)
            lvl = 2 if delta >= loop_delta else (1 if delta > 0 else 0)
            if lvl:
                _, etype = incident_upsert(c, f"docker:{name}:restarts", source="deep",
                                           itype="docker_restarts", sev_level=lvl, value=delta,
                                           reason=f"restarts {int(prev)} -> {restarts} (+{int(delta)})",
                                           )
                if etype in ("new", "escalated"):
                    events.append(emit("deep", "docker_restarts", f"docker:{name}:restarts",
                                       current=restarts, previous=int(prev), severity=NAME[lvl],
                                       provisional=True, state="active", baseline_pending=True,
                                       reason=f"restart-delta +{int(delta)} (loop-kandidaat bij >= {loop_delta})",
                                       source="deep"))
            if state != "running":
                events.append(emit("deep", "docker_exited", f"docker:{name}:exited", current=state,
                                   severity="notice", provisional=True, state="classified",
                                   baseline_pending=True,
                                   reason=("bekend bewust gestopt (suppressed in later stadium)"
                                           if name in known else
                                           "exited container (niet in known_stopped)"), source="deep"))
        st["containers"] = ds["data"].get("count")

    # vdisk deep-vs-sampler bevestiging
    dv = ssh_action("docker-vdisk-status")
    if dv.get("ok"):
        pts = fetch_series("vdisk_pct", 1)
        if pts and dv["data"].get("pct") is not None:
            diff = abs(dv["data"]["pct"] - pts[-1][1])
            if diff > 2:
                events.append(emit("deep", "vdisk_confirm", "host:docker_vdisk:mismatch",
                                   current=dv["data"]["pct"], previous=pts[-1][1], severity="notice",
                                   provisional=True, state="observed", baseline_pending=True,
                                   reason=f"deep vs sampler verschil {diff:.1f}pp", source="deep"))
        st["vdisk_pct"] = dv["data"].get("pct")

    # kernel/fs errors: fingerprint-dedup (§17); ro-remount = CRITICAL
    for action, source, since in (("kernel-errors", "kernel_errors", "6h"),
                                  ("fs-errors", "fs_errors", "24h")):
        r = ssh_action(action, since)
        if r.get("ok"):
            for line in r["data"].get("lines", []):
                fp = f"host:{source}:{line_fingerprint(line)}"
                crit = bool(re.search(r"remount.{0,20}read-only|read-only.{0,20}remount", line, re.I))
                lvl = 4 if crit else 2
                _, etype = incident_upsert(c, fp, source=source, itype=source, sev_level=lvl,
                                           value=0, reason=line[:200], )
                if etype in ("new", "escalated"):
                    events.append(emit("deep", source, fp, current=line[:240], severity=NAME[lvl],
                                       provisional=True, state="active", baseline_pending=True,
                                       reason="nieuw error-fingerprint", source="deep"))
            c.execute("insert into cursors(name, value, last_checked) values(?,?,?)"
                      " on conflict(name) do update set value=excluded.value,"
                      " last_checked=excluded.last_checked", (source, since, now_iso()))

    # memory-status crosscheck OOM-teller (§11: lege dmesg is géén bewijs)
    ms = ssh_action("memory-status")
    if ms.get("ok"):
        st["oom_kills_deep"] = ms["data"].get("oom_kills_total")

    # docker-space-detail alleen bij actief groei-incident (§8)
    growth = c.execute("select state from incidents where fingerprint='host:docker_vdisk:growth'").fetchone()
    if growth and growth[0] == "active":
        sp = ssh_action("docker-space-detail", timeout=60)
        events.append(emit("deep", "docker_space_detail", "host:docker_vdisk:growth",
                           current=sp if sp.get("ok") else sp.get("error"), severity="notice",
                           provisional=True, state="diagnostic", baseline_pending=True,
                           reason="aanbevolen diagnose bij actief groei-incident", source="deep"))

    active = c.execute("select count(*) from incidents where state in ('active','recovering')").fetchone()[0]
    c.commit(); c.close()
    return {"mode": "deep", "run_id": RUN_ID, "ts": now_iso(), "events": len(events),
            "incidents_active": active, "dry_run": DRY_RUN,
            **{f"info_{k}": v for k, v in st.items()}}

# ---------------------------------------------------------------- baseline --
def run_baseline(cfg, events):
    metrics = ["mem_used_pct", "vdisk_pct", "logfs_pct", "cache_pct", "vm_pct", "user_pct",
               "rootfs_pct", "package_temp_c", "core_max_temp_c", "load1"]
    out = {}
    for m in metrics:
        pts = fetch_series(m, 48)
        if len(pts) < 4:
            continue
        vals = sorted(v for _, v in pts)
        q = lambda p: vals[min(len(vals) - 1, round(p * (len(vals) - 1)))]
        slopes = []
        for i in range(max(1, len(pts) - 12)):
            t = trend_of(pts[i:i + 13])
            if t.get("slope_per_h") is not None:
                slopes.append(t["slope_per_h"])
        sect = (cfg.get("memory", {}) if m == "mem_used_pct" else
                cfg.get("docker_vdisk", {}) if m == "vdisk_pct" else
                cfg.get("logfs", {}) if m == "logfs_pct" else
                cfg.get("temperatures", {}) if "temp" in m else
                cfg.get("storage", {}) if m.endswith("_pct") else {})
        cur = sect.get("warn_pct") if sect else None
        sugg = round(min(99.0, q(0.99) + 5), 1) if "temp" not in m else round(q(0.99) + 3, 1)
        out[m] = {"n": len(vals), "min": round(min(vals), 2), "p50": round(q(0.5), 2),
                  "p95": round(q(0.95), 2), "p99": round(q(0.99), 2), "max": round(max(vals), 2),
                  "typical_slope_per_h": round(statistics.median(slopes), 3) if slopes else None,
                  "current_warn": cur, "suggested_warn": sugg}
    (HL / "baseline-report.json").write_text(json.dumps(out, indent=1))
    print(json.dumps(out, indent=1))
    return {"mode": "baseline-report", "run_id": RUN_ID, "ts": now_iso(),
            "metrics": len(out), "dry_run": DRY_RUN}

# -------------------------------------------------------------------- test --
SAMPLES_SCHEMA = """create table samples(
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
  vm_pct real, user_pct real);"""

def run_test(cfg):
    """Synthetische cases; zelfde codepad als productie (replay + state-db)."""
    # tests mogen nooit echte LLM-calls maken; routertests mocken het transport
    cfg = dict(cfg)
    cfg["llm"] = dict(cfg.get("llm") or {}, enabled=False)
    cfg["notifications"] = dict(cfg.get("notifications") or {}, enabled=False)  # tests: nooit echt verzenden
    cfg["prometheus"] = dict(cfg.get("prometheus") or {}, enabled=False)  # tests: geen live HTTP
    results = []
    def check(name, cond, detail=""):
        results.append((name, bool(cond), detail))

    def fresh(series, minutes=5, seed_counters=None):
        tmp = Path(tempfile.mkdtemp())
        (tmp / "homelab").mkdir(parents=True)
        con = sqlite3.connect(tmp / "homelab" / "samples.db")
        con.executescript(SAMPLES_SCHEMA)
        n = max(len(v) for v in series.values())
        now = int(datetime.now(timezone.utc).timestamp())
        cols = ["ts"] + list(series.keys())
        for i in range(n):
            vals = [now - (n - 1 - i) * minutes * 60]
            for seq in series.values():
                vals.append(seq[i] if i < len(seq) else seq[-1])
            con.execute(f"insert into samples({','.join(cols)})"
                        f" values({','.join('?' for _ in cols)})", vals)
        con.commit(); con.close()
        if seed_counters:
            scon = sqlite3.connect(tmp / "homelab" / "agent_state.db")
            scon.execute("create table counters(name text primary key, device text,"
                         " previous_value real, current_value real, delta real, last_checked text)")
            scon.executemany("insert into counters values(?,?,?,?,?,?)",
                             [(n_, d_, p_, c_, 0, "seed") for n_, d_, p_, c_ in seed_counters])
            scon.commit(); scon.close()
        return tmp

    def eval_in(tmp, mode="fast"):
        old = (HOME, SAMPLES_DB, STATE_DB, EVENTS)
        globals().update(HOME=tmp, SAMPLES_DB=tmp / "homelab" / "samples.db",
                         STATE_DB=tmp / "homelab" / "agent_state.db",
                         EVENTS=tmp / "homelab" / "evaluator-events.jsonl")
        try:
            evs = []
            con = state_db()
            (run_fast if mode == "fast" else run_deep)(cfg, evs)
            con.close()
            inc = {}
            c2 = sqlite3.connect(STATE_DB)
            for fp, state, sev in c2.execute("select fingerprint, state, current_severity from incidents"):
                inc[fp] = (state, sev)
            c2.close()
            return inc, evs
        finally:
            globals().update(HOME=old[0], SAMPLES_DB=old[1], STATE_DB=old[2], EVENTS=old[3])
            shutil.rmtree(tmp, ignore_errors=True)

    # RAM
    inc, _ = eval_in(fresh({"mem_used_pct": [60, 70, 80, 90]}))
    check("RAM 60->70->80->90 stijgend -> warning (provisional)",
          inc.get("host:memory:high") == ("active", "warning"), str(inc.get("host:memory:high")))
    inc, _ = eval_in(fresh({"mem_used_pct": [95, 95, 90, 84, 80, 80]}))
    check("RAM 95->84 dalend -> recovering/resolved",
          inc.get("host:memory:high", ("missing", "?"))[0] in ("resolved", "recovering"),
          str(inc.get("host:memory:high")))
    inc, _ = eval_in(fresh({"mem_used_pct": [90, 90, 90]}))
    check("RAM 90 stabiel x3 -> warning",
          inc.get("host:memory:high", ("", ""))[1] == "warning", str(inc.get("host:memory:high")))
    inc, evs = eval_in(fresh({"mem_used_pct": [40] * 3, "oom_kills": [2, 2, 2]}))
    check("OOM baseline (eerste waarneming) -> geen incident",
          "host:memory:oom" not in inc, str(inc.get("host:memory:oom")))
    inc, evs = eval_in(fresh({"mem_used_pct": [40] * 4, "oom_kills": [2, 2, 2, 3]},
                             seed_counters=[("oom_kills", "host", 2, 2)]))
    check("OOM +1 -> critical incident",
          inc.get("host:memory:oom", ("", ""))[1] == "critical", str(inc.get("host:memory:oom")))
    # Docker vDisk
    inc, _ = eval_in(fresh({"vdisk_pct": [70] * 8, "vdisk_used_kb": [107374182] * 8}))
    check("vdisk stabiel 70 -> geen incident",
          "host:docker_vdisk:high" not in inc and "host:docker_vdisk:growth" not in inc, str(list(inc)))
    kb0, kb1 = 0.70 * 157286400, 0.80 * 157286400
    inc, _ = eval_in(fresh({"vdisk_pct": [70] * 12 + [80], "vdisk_used_kb": [kb0] * 12 + [kb1]}))
    check("vdisk 70->80 in 1u -> growth warning",
          inc.get("host:docker_vdisk:growth", ("", ""))[1] == "warning", str(inc.get("host:docker_vdisk:growth")))
    inc, _ = eval_in(fresh({"vdisk_pct": [95, 95, 90, 84, 80]}))
    check("vdisk 95->80 dalend -> recovering/resolved",
          inc.get("host:docker_vdisk:high", ("missing", "?"))[0] in ("resolved", "recovering"),
          str(inc.get("host:docker_vdisk:high")))
    # Temperatuur (§7)
    inc, _ = eval_in(fresh({"package_temp_c": [75, 75, 93]}))
    check("temp één sample 93 -> notice (cap)",
          inc.get("host:temperature:package", ("", ""))[1] == "notice", str(inc.get("host:temperature:package")))
    inc, _ = eval_in(fresh({"package_temp_c": [93, 93, 93]}))
    check("temp sustained 93 -> warning",
          inc.get("host:temperature:package", ("", ""))[1] == "warning", str(inc.get("host:temperature:package")))
    inc, _ = eval_in(fresh({"package_temp_c": [93, 93, 88, 84, 82]}))
    check("temp 93->82 dalend -> recovering/resolved",
          inc.get("host:temperature:package", ("missing", "?"))[0] in ("resolved", "recovering"),
          str(inc.get("host:temperature:package")))
    inc, _ = eval_in(fresh({"package_temp_c": [80, 85, 90, 94]}))
    check("temp 80->85->90->94 stijgend -> urgent",
          inc.get("host:temperature:package", ("", ""))[1] == "urgent", str(inc.get("host:temperature:package")))
    # /var/log
    inc, _ = eval_in(fresh({"logfs_pct": [60] * 12 + [68]}))
    check("logfs snelle groei -> warning growth",
          inc.get("host:logfs:growth", ("", ""))[1] == "warning", str(inc.get("host:logfs:growth")))
    inc, _ = eval_in(fresh({"logfs_pct": [80, 80, 74, 60, 55]}))
    check("logfs hoog-dalend -> recovering/resolved",
          inc.get("host:logfs:high", ("missing", "?"))[0] in ("resolved", "recovering", "missing"),
          str(inc.get("host:logfs:high")))
    # SMART counters (§12) via fake SSH in deep-mode
    def dh(crc, real, pend, unc):
        return {"ok": True, "data": [{"device": "/dev/sda", "state": "active", "health": "PASSED",
                                      "crc_errors": crc, "reallocated": real, "pending": pend,
                                      "offline_uncorrectable": unc, "media_errors": None, "wear_pct": 81}]}
    steps = [dh(458813, 0, 0, 0), dh(458813, 0, 0, 0), dh(458814, 0, 1, 0)]
    def fake_ssh_factory(seq, disk_health="__seq__", docker_status="__seq__"):
        i = {"n": 0}
        def fake(action, *a, **k):
            if action == "disk-health":
                if disk_health != "__seq__":
                    return disk_health
                r = seq[min(i["n"], len(seq) - 1)]; return r
            if action == "docker-status":
                if docker_status != "__seq__":
                    return docker_status[min(i["n"], len(docker_status) - 1)]
                return {"ok": True, "data": {"count": 0, "containers": []}}
            if action == "docker-restarts": return {"ok": True, "data": {"containers": []}}
            if action == "array-status": return {"ok": True, "data": {"state": "STARTED",
                "parity_synced": 0, "resync_action": "check", "resync_pct": 0}}
            if action == "pool-status": return {"ok": True, "data": [{"mount": "/mnt/cache", "rw": True}]}
            if action == "docker-vdisk-status": return {"ok": True, "data": {"pct": None}}
            if action in ("kernel-errors", "fs-errors"): return {"ok": True, "data": {"lines": []}}
            if action == "memory-status": return {"ok": True, "data": {"oom_kills_total": 0}}
            return {"ok": False, "error": "onverwacht"}
        return fake, i
    tmp = Path(tempfile.mkdtemp()); (tmp / "homelab").mkdir(parents=True)
    old = (HOME, SAMPLES_DB, STATE_DB, EVENTS)
    globals().update(HOME=tmp, SAMPLES_DB=tmp / "none.db", STATE_DB=tmp / "homelab" / "agent_state.db",
                     EVENTS=tmp / "homelab" / "events.jsonl")
    fake, i = fake_ssh_factory(steps)
    real_ssh = ssh_action
    globals()["ssh_action"] = fake
    try:
        con = sqlite3.connect(SAMPLES_DB); con.close()
        evs = []; con = state_db(); run_deep(cfg, evs); con.close()   # baseline
        i["n"] = 1
        evs = []; con = state_db(); run_deep(cfg, evs); con.close()   # 458813 -> 458813
        check("SMART crc 458813->458813 -> geen event",
              not any("crc_growth" in e["fingerprint"] for e in evs), str(len(evs)))
        i["n"] = 2
        evs = []; con = state_db(); run_deep(cfg, evs); con.close()   # +1 crc, pending 0->1
        crc_ev = [e for e in evs if e["fingerprint"] == "disk:/dev/sda:crc_growth"]
        pend_ev = [e for e in evs if e["fingerprint"] == "disk:/dev/sda:pending_absolute"]
        check("SMART crc 458813->458814 -> notice event",
              len(crc_ev) == 1 and crc_ev[0]["severity"] == "notice", str(crc_ev)[:140])
        check("SMART pending 0->1 -> warning (absolute)",
              len(pend_ev) == 1 and pend_ev[0]["severity"] == "warning", str(pend_ev)[:140])
    finally:
        globals()["ssh_action"] = real_ssh
        globals().update(HOME=old[0], SAMPLES_DB=old[1], STATE_DB=old[2], EVENTS=old[3])
        shutil.rmtree(tmp, ignore_errors=True)
    # Docker restarts (§14)
    seq = [{"ok": True, "data": {"count": 1, "containers": [
                {"name": "plex", "state": "running", "health": "healthy", "restarts": 12,
                 "started": "2026-01-01T00:00:00", "exit_code": 0, "mem_limit_bytes": 0}]}},
           {"ok": True, "data": {"count": 1, "containers": [
                {"name": "plex", "state": "running", "health": "healthy", "restarts": 12,
                 "started": "2026-01-01T00:00:00", "exit_code": 0, "mem_limit_bytes": 0}]}},
           {"ok": True, "data": {"count": 1, "containers": [
                {"name": "plex", "state": "running", "health": "healthy", "restarts": 15,
                 "started": "2026-01-01T00:00:00", "exit_code": 0, "mem_limit_bytes": 0}]}}]
    tmp = Path(tempfile.mkdtemp()); (tmp / "homelab").mkdir(parents=True)
    old = (HOME, SAMPLES_DB, STATE_DB, EVENTS)
    globals().update(HOME=tmp, SAMPLES_DB=tmp / "none.db", STATE_DB=tmp / "homelab" / "agent_state.db",
                     EVENTS=tmp / "homelab" / "events.jsonl")
    fake, i = fake_ssh_factory(seq, disk_health={"ok": True, "data": []},
                               docker_status=seq)
    globals()["ssh_action"] = fake
    try:
        con = sqlite3.connect(SAMPLES_DB); con.close()
        evs = []; con = state_db(); run_deep(cfg, evs); con.close()   # baseline 12
        i["n"] = 1
        evs = []; con = state_db(); run_deep(cfg, evs); con.close()   # 12 -> 12
        check("restarts 12->12 -> geen event",
              not any("docker:plex:restarts" in e["fingerprint"] for e in evs), str(len(evs)))
        i["n"] = 2
        evs = []; con = state_db(); run_deep(cfg, evs); con.close()   # 12 -> 15
        r = [e for e in evs if e["fingerprint"] == "docker:plex:restarts"]
        check("restarts 12->15 (+3) -> warning loop-kandidaat",
              len(r) == 1 and r[0]["severity"] == "warning", str(r)[:140])
    finally:
        globals()["ssh_action"] = real_ssh
        globals().update(HOME=old[0], SAMPLES_DB=old[1], STATE_DB=old[2], EVENTS=old[3])
        shutil.rmtree(tmp, ignore_errors=True)
    # Recovery (§16): WARNING -> goede sample(s) -> RECOVERING -> RESOLVED
    inc, _ = eval_in(fresh({"mem_used_pct": [91, 91, 80, 80, 80]}))
    st, sev = inc.get("host:memory:high", ("missing", "?"))
    check("recovery WARNING -> RECOVERING/RESOLVED", st in ("recovering", "resolved"), f"{st}/{sev}")

    # ── DUMBscope-integratie (§18) ──
    def raw_inc(fp, sev="warning", status="active", occ=1, rid=None):
        return {"id": rid or f"inc-{fp}", "fingerprint": fp, "severity": sev, "status": status,
                "title": f"title {fp}", "summary": "s", "rootCauseService": "plex",
                "affectedServices": ["plex"], "firstSeen": 1000, "lastSeen": 2000,
                "resolvedAt": 3000 if status == "resolved" else None,
                "occurrences": occ, "evidence": [{"at": 1, "message": "ev1"}, {"at": 2, "message": "ev2"}]}

    def dsresult(incidents):
        import hermes_dumbscope as _hd
        _n = _hd.normalize_incident
        n_active = len([i for i in incidents if i["status"] == "active"])
        return {"ok": True, "health": {"status": "ok", "dumb": "connected"}, "incidents": [_n(i) for i in incidents],
                "metrics": {"active_count": n_active, "resolved_fetched":
                            len([i for i in incidents if i["status"] == "resolved"]),
                            "payload_bytes": 1234, "runtime_s": 0.05}}

    class FakeDS:
        def __init__(self, steps): self.steps, self.i = steps, 0
        def poll(self, resolved_limit=20):
            s = self.steps[min(self.i, len(self.steps) - 1)]
            self.i += 1
            if isinstance(s, Exception):
                raise s
            return s

    def ds_scenario(steps, seed_host_warning=False, polls=1):
        tmp = Path(tempfile.mkdtemp()); (tmp / "homelab").mkdir(parents=True)
        old = (HOME, SAMPLES_DB, STATE_DB, EVENTS)
        globals().update(HOME=tmp, SAMPLES_DB=tmp / "none.db",
                         STATE_DB=tmp / "homelab" / "agent_state.db",
                         EVENTS=tmp / "homelab" / "events.jsonl")
        real_mc = globals().get("make_client")
        fake_ds = FakeDS(steps)
        globals()["make_client"] = lambda cfg: fake_ds
        all_evs = []
        rows, avail = {}, None
        try:
            con = sqlite3.connect(SAMPLES_DB); con.close()
            for _ in range(polls):
                con = state_db()
                if seed_host_warning:
                    con.execute("insert or ignore into incidents(fingerprint, source, type, state,"
                                " current_severity, previous_severity, first_seen, last_seen,"
                                " last_changed, occurrences, last_value, peak_value, last_alert_at,"
                                " last_reason) values('host:memory:high','fast','mem','active',"
                                "'warning','normal','t','t','t',1,90,90,'t','synthetic')")
                con.commit()
                evs = []
                run_dumbscope(cfg, con, evs, mode="fast")
                con.close()
                all_evs.extend(evs)
            c2 = sqlite3.connect(STATE_DB)
            for fp, status, sev, occ in c2.execute(
                    "select fingerprint, status, severity, occurrences from dumbscope_incidents"):
                rows[fp] = (status, sev, occ)
            avail = c2.execute("select state, current_severity from incidents"
                               " where fingerprint='dumbscope:availability'").fetchone()
            c2.close()
            return all_evs, rows, avail
        finally:
            globals()["make_client"] = real_mc
            globals().update(HOME=old[0], SAMPLES_DB=old[1], STATE_DB=old[2], EVENTS=old[3])
            shutil.rmtree(tmp, ignore_errors=True)

    def ds_events(evs):
        return [e for e in evs if e["check"] == "dumbscope_incident"]

    # 1+2: baseline-seed (poll leeg) -> daarna nieuw incident -> precies 1 event
    steps = [dsresult([]), dsresult([raw_inc("p1")]), dsresult([raw_inc("p1")])]
    evs, rows, _ = ds_scenario(steps, polls=3)
    p1 = [e for e in ds_events(evs) if e["fingerprint"] == "dumbscope:p1"]
    check("DUMBscope nieuw incident -> 1 event", len(p1) == 1 and p1[0]["state"] == "active",
          str(len(p1)))
    check("DUMBscope herhaalde poll -> geen nieuw event", len(ds_events(evs)) == 1, str(len(ds_events(evs))))
    # 3: occurrences 2 -> 3 -> changed event, geen nieuw incident
    steps = [dsresult([]), dsresult([raw_inc("p1", occ=2)]), dsresult([raw_inc("p1", occ=3)])]
    evs, rows, _ = ds_scenario(steps, polls=3)
    occ_ev = [e for e in ds_events(evs) if any(f.startswith("occurrences:") for f in e.get("changed_fields", []))]
    check("DUMBscope occurrences 2->3 -> changed event",
          len(occ_ev) == 1 and rows.get("dumbscope:p1", ("", "", 0))[2] == 3, str(occ_ev)[:120])
    # 4: severity warning -> critical -> escalatie-event
    steps = [dsresult([]), dsresult([raw_inc("p1", sev="warning")]),
             dsresult([raw_inc("p1", sev="critical")])]
    evs, rows, _ = ds_scenario(steps, polls=3)
    sev_ev = [e for e in ds_events(evs) if any(f.startswith("severity:") for f in e.get("changed_fields", []))]
    check("DUMBscope severity warning->critical -> escalatie",
          len(sev_ev) == 1 and sev_ev[0]["severity"] == "critical", str(sev_ev)[:120])
    # 5: resolve
    steps = [dsresult([]), dsresult([raw_inc("p1")]), dsresult([raw_inc("p1", status="resolved")])]
    evs, rows, _ = ds_scenario(steps, polls=3)
    res_ev = [e for e in ds_events(evs) if e["state"] == "resolved"]
    check("DUMBscope resolve -> RESOLVED event", len(res_ev) == 1, str(len(res_ev)))
    # 6: reopen
    steps = [dsresult([]), dsresult([raw_inc("p1", status="resolved")]),
             dsresult([raw_inc("p1", status="active", occ=2)])]
    evs, rows, _ = ds_scenario(steps, polls=3)
    reop = [e for e in ds_events(evs) if e["state"] == "reopened"]
    check("DUMBscope reopen -> reopened lifecycle",
          len(reop) == 1 and rows.get("dumbscope:p1", ("",))[0] == "active", str(reop)[:120])
    # 7+8: unavailable — anti-flapping en herstel (§12)
    import hermes_dumbscope as _hd
    err = _hd.DumbScopeError("unavailable", None, "synthetic")
    evs, rows, avail = ds_scenario([dsresult([]), err, err], polls=3)
    check("DUMBscope 2 failures -> nog geen availability-incident", avail is None, str(avail))
    evs, rows, avail = ds_scenario([dsresult([]), err, err, err], polls=4)
    check("DUMBscope 3 failures -> availability warning",
          avail is not None and avail[0] == "active" and avail[1] == "warning", str(avail))
    evs, rows, avail = ds_scenario([dsresult([]), err, err, err, dsresult([raw_inc("p1")])], polls=5)
    check("DUMBscope herstel -> availability resolved", avail is not None and avail[0] == "resolved",
          str(avail))
    # 9: host-correlatie (geen oorzaak-claim)
    steps = [dsresult([]), dsresult([raw_inc("plex-degraded")])]
    evs, rows, _ = ds_scenario(steps, seed_host_warning=True, polls=2)
    p1 = [e for e in ds_events(evs) if e["fingerprint"] == "dumbscope:plex-degraded"]
    check("host-correlatie toegevoegd (geen causale claim)",
          len(p1) == 1 and p1[0].get("host_correlations") == ["host:memory:high"], str(p1)[:140])
    # 10: onbekende severity -> notice + gemarkeerd
    steps = [dsresult([]), dsresult([raw_inc("odd", sev="fatal")])]
    evs, rows, _ = ds_scenario(steps, polls=2)
    odd = [e for e in ds_events(evs) if e["fingerprint"] == "dumbscope:odd"]
    check("onbekende severity -> notice + gemarkeerd",
          len(odd) == 1 and odd[0]["severity"] == "notice" and odd[0].get("severity_unmapped") is True,
          str(odd)[:120])
    # ── LLM-router (§20) ──
    import hermes_router as hr
    rtmp = Path(tempfile.mkdtemp()); (rtmp / "homelab").mkdir(parents=True, exist_ok=True)
    hr.ROUTER_CALLS = rtmp / "homelab" / "router_calls.jsonl"
    hr_real_http = hr.http_post_openrouter

    def or_resp(model, content=None, status=200, pt=100, ct=40, rt=0, provider="FakeProv"):
        if status != 200:
            return status, None, f"http {status}", 0.05
        return 200, {"model": model, "provider": provider,
                     "choices": [{"message": {"content": content}}],
                     "usage": {"prompt_tokens": pt, "completion_tokens": ct,
                               "prompt_tokens_details": {"cached_tokens": 0},
                               "completion_tokens_details": {"reasoning_tokens": rt}}}, None, 0.05

    def ling_content(conf=0.95, checks=None, needs=False, wrap=False):
        c = json.dumps({"summary": "samenvatting", "classification": "known_cause",
                        "likely_cause": "oorzaak", "confidence": conf,
                        "needs_more_analysis": needs, "recommended_checks": checks or []})
        return ("Volgens mij: " + c) if wrap else c

    queue = []
    captured = []
    def fake_http(body, key, timeout=75):
        captured.append(body)
        return queue.pop(0) if queue else or_resp(body["model"], None, status=500)

    hr.http_post_openrouter = fake_http
    llmcfg = {"output_max_tokens": {"tier1": 300, "tier2": 600, "tier4": 700},
              "confidence_stop": 0.85, "max_calls_per_incident": 3, "max_calls_per_day": 8,
              "ling_input_chars_cap": 4800, "deepseek_input_chars_cap": 24000}
    dsc = {"fingerprint": "dumbscope:mystery", "severity": "warning",
           "affected_services": ["plex"], "host_correlations": [], "title": "t",
           "summary": "s", "status": "active", "occurrences": 1, "evidence": ["e"],
           "root_cause_service": None}

    # 1: gezonde/normal severity -> geen LLM
    r, why = needs_llm_analysis(sqlite3.connect(":memory:"), "host:cache:high", "normal", "active")
    check("router 1: normal -> geen LLM", r is False, why)
    # 2: simpele deterministische warning -> skip
    r, why = needs_llm_analysis(sqlite3.connect(":memory:"), "host:cache:high", "warning", "active")
    check("router 2: deterministische storage-warning -> skip", r is False, why)
    # 3+4: nieuw onzeker incident -> Ling; conf 0.95 -> stop
    queue = [or_resp(hr.MODELS["tier1"], ling_content(0.95))]
    final, calls_ = hr.analyze("dumbscope:mystery", source="dumbscope", severity="warning",
                               task="t", context=dsc, llm_cfg=llmcfg, api_key="test",
                               per_incident_calls=0, daily_calls=0, multi_system=False)
    check("router 3: onzeker incident -> Ling aangeroepen",
          len(calls_) == 1 and calls_[0]["requested_model"] == hr.MODELS["tier1"],
          str(len(calls_)))
    check("router 4: conf 0.95 -> stop bij Ling", final.get("tier") == "tier1", str(final))
    # 5: conf 0.60 -> DeepSeek
    queue = [or_resp(hr.MODELS["tier1"], ling_content(0.60)),
             or_resp(hr.MODELS["tier2"], json.dumps({"diagnosis": "d", "likely_root_cause": "rc",
                                                     "confidence": 0.7, "recommended_checks": []}))]
    final, calls_ = hr.analyze("dumbscope:mystery", source="dumbscope", severity="warning",
                               task="t", context=dsc, llm_cfg=llmcfg, api_key="test",
                               per_incident_calls=0, daily_calls=0, multi_system=False)
    check("router 5: conf 0.60 -> DeepSeek", len(calls_) == 2 and final.get("tier") == "tier2",
          str(len(calls_)))
    # 6a: Ling ongeldige JSON -> repair faalt -> DeepSeek
    queue = [or_resp(hr.MODELS["tier1"], "geen json hier"),
             or_resp(hr.MODELS["tier2"], json.dumps({"diagnosis": "d", "confidence": 0.7,
                                                     "recommended_checks": []}))]
    final, calls_ = hr.analyze("dumbscope:mystery", source="dumbscope", severity="warning",
                               task="t", context=dsc, llm_cfg=llmcfg, api_key="test",
                               per_incident_calls=0, daily_calls=0, multi_system=False)
    check("router 6a: Ling invalid JSON -> DeepSeek", len(calls_) == 2 and final.get("tier") == "tier2",
          str(len(calls_)))
    # 6b: Ling JSON met rommel ervoor -> extractie-repair werkt
    queue = [or_resp(hr.MODELS["tier1"], ling_content(0.9, wrap=True))]
    final, calls_ = hr.analyze("dumbscope:mystery", source="dumbscope", severity="warning",
                               task="t", context=dsc, llm_cfg=llmcfg, api_key="test",
                               per_incident_calls=0, daily_calls=0, multi_system=False)
    check("router 6b: Ling JSON-in-tekst -> repair extractie slaagt",
          final.get("tier") == "tier1", str(final))
    # 7: Ling 429 -> DeepSeek met expliciete provider-reden
    queue = [or_resp(hr.MODELS["tier1"], None, status=429),
             or_resp(hr.MODELS["tier2"], json.dumps({"diagnosis": "d", "confidence": 0.7,
                                                     "recommended_checks": []}))]
    final, calls_ = hr.analyze("dumbscope:mystery", source="dumbscope", severity="warning",
                               task="t", context=dsc, llm_cfg=llmcfg, api_key="test",
                               per_incident_calls=0, daily_calls=0, multi_system=False)
    check("router 7: Ling 429 -> DeepSeek (ling_provider_error)",
          len(calls_) == 2 and calls_[1]["escalation_reason"] == "ling_provider_error",
          str(calls_[1]["escalation_reason"]))
    # 8: DeepSeek providerfout -> GLM (tier 3)
    queue = [or_resp(hr.MODELS["tier1"], ling_content(0.5)),
             or_resp(hr.MODELS["tier2"], None, status=500),
             or_resp(hr.MODELS["tier3"], json.dumps({"diagnosis": "g", "confidence": 0.8,
                                                     "recommended_checks": []}))]
    final, calls_ = hr.analyze("dumbscope:mystery", source="dumbscope", severity="warning",
                               task="t", context=dsc, llm_cfg=llmcfg, api_key="test",
                               per_incident_calls=0, daily_calls=0, multi_system=False)
    check("router 8: DeepSeek providerfout -> GLM",
          len(calls_) == 3 and final.get("tier") == "tier3"
          and calls_[2]["escalation_reason"] == "deepseek_provider_error", str(final))
    # 9: DeepSeek conf <0.5 + multi-system CRITICAL -> Luna toegestaan
    ctx9 = dict(dsc, affected_services=["plex", "sonarr"], severity="critical")
    queue = [or_resp(hr.MODELS["tier1"], ling_content(0.45)),
             or_resp(hr.MODELS["tier2"], json.dumps({"diagnosis": "d", "confidence": 0.4,
                                                     "recommended_checks": []})),
             or_resp(hr.MODELS["tier4"], json.dumps({"diagnosis": "L", "confidence": 0.8,
                                                     "recommended_checks": []}))]
    final, calls_ = hr.analyze("dumbscope:mystery", source="dumbscope", severity="critical",
                               task="t", context=ctx9, llm_cfg=llmcfg, api_key="test",
                               per_incident_calls=0, daily_calls=0, multi_system=True)
    check("router 9: multi-system CRITICAL conf<0.5 -> Luna",
          len(calls_) == 3 and final.get("tier") == "tier4", str(final))
    # 13/14: budget
    final, calls_ = hr.analyze("dumbscope:mystery", source="dumbscope", severity="warning",
                               task="t", context=dsc, llm_cfg=llmcfg, api_key="test",
                               per_incident_calls=0, daily_calls=8, multi_system=False)
    check("router 13: daglimiet -> geen call (audit)",
          final.get("status") == "skipped" and final.get("reason") == "llm_budget_exhausted:daily",
          str(final))
    final, calls_ = hr.analyze("dumbscope:mystery", source="dumbscope", severity="warning",
                               task="t", context=dsc, llm_cfg=llmcfg, api_key="test",
                               per_incident_calls=3, daily_calls=0, multi_system=False)
    check("router 14: incidentlimiet -> geen call (audit)",
          final.get("status") == "skipped" and final.get("reason") == "llm_budget_exhausted:incident",
          str(final))
    # 15: requested != actual -> routing violation, response onvertrouwd -> DeepSeek
    queue = [or_resp(hr.MODELS["tier2"], ling_content(0.95)),
             or_resp(hr.MODELS["tier2"], json.dumps({"diagnosis": "d", "confidence": 0.7,
                                                     "recommended_checks": []}))]
    final, calls_ = hr.analyze("dumbscope:mystery", source="dumbscope", severity="warning",
                               task="t", context=dsc, llm_cfg=llmcfg, api_key="test",
                               per_incident_calls=0, daily_calls=0, multi_system=False)
    check("router 15: requested != actual -> routing_violation + escalatie",
          calls_ and calls_[0]["routing_violation"] is True and final.get("tier") == "tier2",
          str(calls_[0].get("routing_violation")) if calls_ else "geen calls")
    # 16: onbekend diagnostic-command -> gefilterd
    queue = [or_resp(hr.MODELS["tier1"], ling_content(0.95, checks=["disk-health", "rm -rf /", "reboot now"]))]
    final, calls_ = hr.analyze("dumbscope:mystery", source="dumbscope", severity="warning",
                               task="t", context=dsc, llm_cfg=llmcfg, api_key="test",
                               per_incident_calls=0, daily_calls=0, multi_system=False)
    pchecks = (final.get("analysis") or {}).get("recommended_checks")
    check("router 16: onbekende commands gefilterd",
          pchecks == ["disk-health"] and "rm -rf /" not in json.dumps(pchecks), str(pchecks))
    # 17: sanitizer redigeert secrets vóór de call
    secret_ctx = dict(dsc, summary="key=sk-abcdefghij1234567890 token=bot123456:ABCDEFGHIJKLMNOPQRSTUVWXYZABC"),
    queue = [or_resp(hr.MODELS["tier1"], ling_content(0.95))]
    final, calls_ = hr.analyze("dumbscope:mystery", source="dumbscope", severity="warning",
                               task="t", context=secret_ctx[0], llm_cfg=llmcfg, api_key="test",
                               per_incident_calls=0, daily_calls=0, multi_system=False)
    sent = json.dumps(captured[-1])
    check("router 17: secrets geredigeerd vóór call",
          "sk-abcdefghij" not in sent and "bot123456:" not in sent
          and calls_[-1].get("context_redactions", 0) > 0, str(calls_[-1].get("context_redactions")))
    hr.http_post_openrouter = hr_real_http
    import shutil as _sh
    _sh.rmtree(rtmp, ignore_errors=True)

    # 10/11/12: unchanged/escalatie/reopen op evaluator-niveau (hash + analyze-teller)
    analyze_calls = {"n": 0}
    def fake_analyze(fp, **kw):
        analyze_calls["n"] += 1
        return ({"status": "done", "tier": "tier1", "analysis": {"summary": "ok"},
                 "confidence": 0.9}, [{"success": True, "actual_model": hr.MODELS["tier1"]}])
    tmp = Path(tempfile.mkdtemp()); (tmp / "homelab").mkdir(parents=True)
    old = (HOME, SAMPLES_DB, STATE_DB, EVENTS)
    globals().update(HOME=tmp, SAMPLES_DB=tmp / "none.db",
                     STATE_DB=tmp / "homelab" / "agent_state.db",
                     EVENTS=tmp / "homelab" / "events.jsonl")
    real_analyze = globals().get("run_llm_layer")
    globals()["make_client"] = globals().get("make_client")
    try:
        con = sqlite3.connect(SAMPLES_DB); con.close()
        con = state_db()
        con.execute("insert into incidents(fingerprint, source, type, state, current_severity,"
                    " previous_severity, first_seen, last_seen, last_changed, occurrences,"
                    " last_value, peak_value, last_alert_at, last_reason)"
                    " values('dumbscope:mystery','dumbscope','ds','active','warning',"
                    "'normal','t','t','t',1,1,1,'t','onzeker')")
        con.execute("insert into dumbscope_incidents(fingerprint, source_fingerprint,"
                    " incident_id, status, severity, title, last_seen_ms, resolved_at_ms,"
                    " occurrences, last_processed_at, host_correlations, summary,"
                    " root_cause_service, affected_services, evidence_json)"
                    " values('dumbscope:mystery','mystery','i1','active','warning','t',"
                    "1,2,1,'t','[]','s',NULL,'[\"plex\"]','[\"e\"]')")
        con.commit()
        globals()["run_llm_layer_orig"] = None
        # monkeypatch hr.analyze
        hr_analyze_real = hr.analyze
        hr_lev_real = hr.load_env_key
        hr.load_env_key = lambda env_path=None: "test"  # fixture: .env bestaat niet in tempdir-HOME
        hr.analyze = fake_analyze
        llm_on = dict(cfg.get("llm") or {}, enabled=True)
        llm_on = {"llm": dict(cfg.get("llm") or {}, enabled=True)}
        s1 = run_llm_layer(llm_on, con, [])
        h1 = con.execute("select llm_context_hash from incidents where fingerprint='dumbscope:mystery'").fetchone()[0]
        n1 = analyze_calls["n"]
        s2 = run_llm_layer(llm_on, con, [])  # ongewijzigd
        n2 = analyze_calls["n"]
        con.execute("update incidents set current_severity='critical' where fingerprint='dumbscope:mystery'")
        con.commit()
        s3 = run_llm_layer(llm_on, con, [])  # severity escalatie -> nieuw
        n3 = analyze_calls["n"]
        con.execute("update incidents set state='resolved', current_severity='normal' where fingerprint='dumbscope:mystery'")
        con.execute("update incidents set state='active', current_severity='warning' where fingerprint='dumbscope:mystery'")
        con.execute("update dumbscope_incidents set occurrences=2 where fingerprint='dumbscope:mystery'")
        con.commit()
        s4 = run_llm_layer(llm_on, con, [])  # reopen + occurrences -> nieuw
        n4 = analyze_calls["n"]
        hr.analyze = hr_analyze_real
        con.close()
        check("router 10: ongewijzigd incident -> geen nieuwe analyse", n2 == n1, f"{n1}->{n2}")
        check("router 11: severity-escalatie -> nieuwe analyse", n3 > n1, f"{n1}->{n3}")
        check("router 12: reopen/occurrences -> nieuwe analyse", n4 > n3, f"{n3}->{n4}")
    finally:
        globals().update(HOME=old[0], SAMPLES_DB=old[1], STATE_DB=old[2], EVENTS=old[3])
        hr.analyze = hr_analyze_real
        hr.load_env_key = hr_lev_real
        _sh.rmtree(tmp, ignore_errors=True)


    fails = [r for r in results if not r[1]]
    for name, okk, detail in results:
        print(f"{'PASS' if okk else 'FAIL'}  {name}" + (f"  [{detail}]" if detail and not okk else ""))
    print(f"\n{len(results) - len(fails)}/{len(results)} geslaagd")
    return 0 if not fails else 1

# --------------------------------------------------------------------- main --
def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "fast"
    cfg = load_cfg()
    if mode == "test":
        sys.exit(run_test(cfg))
    HL.mkdir(parents=True, exist_ok=True)
    import fcntl
    lock = open(HL / "evaluator.lock", "w")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        print("evaluator: vorige run nog actief; overgeslagen")
        return
    events = []
    if mode == "fast":
        summary = run_fast(cfg, events)
        # fase 4.5: deterministische Telegram-notificatie van state-transities
        # (geen LLM, geen remediation). Failure-isolated: host-monitoring raakt
        # het niet als de notifier faalt.
        if (cfg.get("notifications") or {}).get("enabled", True):
            try:
                import hermes_notifier
                summary["notifications"] = hermes_notifier.run_notifications(
                    cfg, home=HOME, state_db_path=STATE_DB, samples_db_path=SAMPLES_DB)
            except Exception as e:  # noqa: BLE001 — isolatie bewust breed
                events.append(emit("fast", "notification_integration",
                                   "notifications:integration_error", severity="notice",
                                   provisional=True, state="observed", baseline_pending=True,
                                   reason=f"notifier faalde (host-monitoring onaangetast): "
                                          f"{type(e).__name__}: {e}"[:240], source="notifier"))
                summary["notifications"] = f"error: {type(e).__name__}"
    elif mode == "deep":
        summary = run_deep(cfg, events)
    elif mode == "baseline-report":
        summary = run_baseline(cfg, events)
    else:
        print(f"onbekende mode: {mode}"); sys.exit(64)
    print(json.dumps(summary, ensure_ascii=False))

if __name__ == "__main__":
    main()
