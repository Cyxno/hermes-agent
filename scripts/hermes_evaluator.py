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
import json, hashlib, math, os, re, shutil, sqlite3, statistics, subprocess, sys, tempfile, time, uuid
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
    create table if not exists infinidysk_repairs(
      fingerprint text, ts integer, kind text, ts_iso text,
      primary key(fingerprint, ts, kind));
    create table if not exists infinidysk_loop(
      fingerprint text primary key, display text, last_reason text,
      updated_at text);
    create table if not exists pending_transitions(
      id integer primary key autoincrement,
      fingerprint text not null, ts text, event_type text, severity text,
      reason text);
    create table if not exists changes(
      kind text, key text, ts text, detail text, primary key(kind, key, ts));
    create table if not exists occurrence_log(
      fingerprint text, ts text, severity text, primary key(fingerprint, ts));
    create table if not exists netdata_alarms(
      fingerprint text primary key, name text, chart text, kind text, subject text,
      last_status text, last_severity text, last_value real, alert_state text,
      first_seen text, last_seen text, resolved_at text, last_reason text);
    """)
    c.execute("create index if not exists idx_occurrence_fp"
              " on occurrence_log(fingerprint, ts)")
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

    def record_pending(etype_, why):
        """Replay-veiligheid: notificatie-waardige transitie (>= warning)
        onverliesbaar vastleggen. De notifier (fase 4.5) blijft policy-leidend:
        zonder deze vastlegging zou een transitie verdwijnen als het incident
        binnen dezelfde replay-run alweer resolved raakt."""
        if etype_ in ("new", "escalated", "reopened") and sev_level >= 2:
            c.execute("insert into pending_transitions(fingerprint, ts, event_type,"
                      " severity, reason) values(?,?,?,?,?)",
                      (fp, now, etype_, sev, (why or "")[:200]))

    def record_occurrence():
        """Fase 4: occurrence-historie voor deterministische recurrentie-
        detectie; alleen bij nieuwe episode-transities (goedkoop, begrensd)."""
        try:
            import hermes_changes as hc
            hc.record_occurrence(c, fp, now, sev)
        except Exception:  # noqa: BLE001 — recurrentie-bron mag nooit storen
            pass

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
        record_pending("new", reason)
        record_occurrence()
        return "active", "new"
    state, cur_sev, occ, peak = row[0], row[1], row[2], row[3]
    if sev_level <= 0 and state in ("active", "recovering"):
        # non-pct regels: eerste goede waarde lost direct op (pct heeft eigen recovery-pad)
        c.execute("update incidents set state='resolved', current_severity='normal',"
                  " previous_severity=?, last_changed=?, resolved_at=?, good_samples=0,"
                  " llm_call_count=0, last_reason=? where fingerprint=?",
                  (cur_sev, now, now, "opgelost: waarde terug op normaal", fp))
        return "resolved", "resolved"
    prev_level = LEVELS.get(cur_sev, 0)
    peak = max(peak or 0, value or 0)
    if state == "resolved":
        if sev_level >= 2:
            c.execute("update incidents set state='active', current_severity=?, previous_severity=?,"
                      " occurrences=occurrences+1, last_seen=?, last_changed=?, resolved_at=NULL,"
                      " good_samples=0, llm_call_count=0, peak_value=?, last_value=?, last_reason=?"
                      " where fingerprint=?",
                      (sev, cur_sev, now, now, peak, value, reason, fp))
            record_pending("reopened", reason)
            record_occurrence()
            return "active", "reopened"
        c.execute("update incidents set last_seen=?, last_value=? where fingerprint=?", (now, value, fp))
        return "resolved", "none"
    if state == "recovering":
        if sev_level >= 2:
            c.execute("update incidents set state='active', current_severity=?, previous_severity=?,"
                      " occurrences=occurrences+1, last_seen=?, last_changed=?, good_samples=0,"
                      " peak_value=?, last_value=?, last_reason=? where fingerprint=?",
                      (sev, cur_sev, now, now, peak, value, reason, fp))
            record_pending("escalated", reason)
            record_occurrence()
            return "active", "escalated"
        c.execute("update incidents set last_seen=?, last_value=? where fingerprint=?", (now, value, fp))
        return "recovering", "none"
    # active
    if sev_level > prev_level:
        c.execute("update incidents set current_severity=?, previous_severity=?, last_seen=?,"
                  " last_changed=?, peak_value=?, last_value=?, last_reason=? where fingerprint=?",
                  (sev, cur_sev, now, now, peak, value, reason, fp))
        record_pending("escalated", reason)
        record_occurrence()
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
    """Deterministisch: crit bij sustain; urgent bij sustain of rising_fast; warning
    bij sustain of rising_fast; allereerste breach-sample -> notice (cap).
    lvl 2 + snel stijgend + nabij urgent -> urgent (§7).
    §7b temperatuur-micro-spikes (2026-09-23): met critical_needs_sustain is één
    critical-band sample max notice — pas critical bij sustained>=need (de volgende
    sample moet het bevestigen). Met urgent_sustained_samples escaleert een lang
    genoeg sustained warn-band alsnog naar urgent (tenminste 10 min boven warn)."""
    lvl = band_level(value, th)
    bits = []
    if lvl == 4:
        if th.get("critical_needs_sustain") and sustained < need:
            return 1, True, [f">=critical({th.get('critical_pct')}) single sample -> notice (critical_needs_sustain, §7b)"]
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
        us = th.get("urgent_sustained_samples")
        if us and sustained >= int(us):
            return 3, False, [f">=warn sustained({sustained}) -> urgent (urgent_sustained_samples={us}, §7b)"]
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
                              " good_samples=0, llm_call_count=0, last_reason=? where fingerprint=?",
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

    # Centrale incident-routing (fase 9): DUMBscope-incidenten lopen via
    # incident_upsert -> incidents-tabel -> bestaande notifier-policy. Eerste
    # run na activering: huidige actieve incidenten stilletjes overnemen
    # (cursor dumbscope:incidents_seeded) zodat de koppeling geen alertstorm
    # veroorzaakt; elke latere transitie (new/escalated/reopened/resolved)
    # volgt gewoon de machine en kan Telegram bereiken.
    inc_seeded_row = c.execute("select value from cursors where name="
                               "'dumbscope:incidents_seeded'").fetchone()

    def ds_incident_upsert(inc_, sev_level_, reason_):
        """DUMBscope-incident -> centrale state-machine. Resolved/seeds zonder
        openstaand incident zijn stil; verder doet de machine alles."""
        return incident_upsert(c, inc_["fingerprint"], source="dumbscope",
                               itype="dumbscope", sev_level=sev_level_,
                               value=float(inc_["occurrences"] or 0), reason=reason_)

    if not inc_seeded_row:
        now = now_iso()
        for inc_ in result["incidents"]:
            if inc_["state"] != "active":
                continue
            c.execute("insert or ignore into incidents(fingerprint, source, type, state,"
                      " current_severity, previous_severity, first_seen, last_seen,"
                      " last_changed, occurrences, last_value, peak_value, last_alert_at,"
                      " last_reason) values(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                      (inc_["fingerprint"], "dumbscope", "dumbscope", "active",
                       inc_["severity"], "normal", now, inc_["last_seen"] or now, now,
                       inc_["occurrences"] or 1, float(inc_["occurrences"] or 0),
                       float(inc_["occurrences"] or 0), now,
                       f"seed: {inc_['title']}"[:200]))
        c.execute("insert into cursors(name, value, last_checked)"
                  " values('dumbscope:incidents_seeded', '1', ?) on conflict(name)"
                  " do update set value=excluded.value, last_checked=excluded.last_checked",
                  (now_iso(),))
        events.append(emit(mode, "dumbscope_baseline", "dumbscope:incidents_seeded",
                           current={"seeded": sum(1 for i_ in result["incidents"]
                                                  if i_["state"] == "active")},
                           severity="normal", provisional=bp, state="seeded",
                           baseline_pending=bp, source="dumbscope",
                           reason="actieve DUMBscope-incidenten overgenomen in de centrale"
                                  " incident-machine (geen notificaties)"))

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
                if inc["state"] == "active":
                    # fase 9: via centrale machine -> notifier-policy (warning+ -> pending)
                    ds_incident_upsert(inc, LEVELS.get(inc["severity"], 1),
                                       f"nieuw DUMBscope-incident: {inc['title']}"[:200])
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
        # fase 9: zelfde transitie door de centrale machine; 'resolved' herstelt
        # (notifier: recovery precies eenmaal), escalaties negeren cooldown,
        # occurrences-only wijzigingen zijn 'none' (geen duplicate-alerts).
        if inc["source_status"] == "resolved":
            ds_incident_upsert(inc, 0, f"DUMBscope hersteld: {inc['title']}"[:200])
        elif s_status == "resolved":
            ds_incident_upsert(inc, LEVELS.get(inc["severity"], 1),
                               f"DUMBscope heropend: {inc['title']}"[:200])
        else:
            ds_incident_upsert(inc, LEVELS.get(inc["severity"], 1),
                               f"{reason}; {inc['title']}"[:200])
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


def _infinidysk_dumb_context():
    """Begrensde DUMB-context uit samples.db (read-only): rss, rss-groei/u,
    totale repairs/u en mount-status. Geen logregels. Faalt de DB of tabel ->
    geen context (best-effort)."""
    try:
        s = sqlite3.connect(f"file:{SAMPLES_DB}?mode=ro", uri=True, timeout=3)
        row = s.execute(
            "select ts, nzbdav_rss_kb, nzbdav_rss_growth_kbph,"
            " infinidysk_repairs_1h, mount_ok from dumb_samples"
            " order by ts desc limit 1").fetchone()
        s.close()
        if not row:
            return {}
        age = int(time.time() - row[0]) // 60 if row[0] else None
        return {"dumb": {"rss_kb": row[1], "rss_growth_kbph": row[2],
                         "repairs_1h_total": row[3], "mount_ok": row[4],
                         "sample_age_min": age}}
    except Exception:  # noqa: BLE001 — context is best-effort
        return {}


def run_infinidysk(cfg, c, events, mode="fast", now=None):
    """Per-bestand repair-loop-detectie (fase 7) — volledig deterministisch,
    read-only t.o.v. DUMB; schrijft uitsluitend eigen state-tabellen en gebruikt
    de bestaande incident-state-machine (incident_upsert). Policy
    (thresholds.yaml: infinidysk): >= warning_count (5) repairs/60min -> warning,
    >= urgent_count (10) -> urgent, 1-4 met laatste repair binnen
    resolve_after_minutes (120) -> notice (incident blijft open, geen nieuwe
    notificaties: geen pending_transition), daarna -> normal (machine resolved).
    Eerste waarneming (geen cursor) is een seed-run: state wél, maar
    notificatie-graad gedempt naar notice (zelfde patroon als dumbscope:seed).
    Gezonde run: 0 events, 0 LLM-kandidaten."""
    import hermes_infinidysk as hi
    icfg = dict(cfg.get("infinidysk") or {})
    bp = bool(icfg.get("baseline_pending", True))
    warn_n = int(icfg.get("warning_count", 5))
    urg_n = int(icfg.get("urgent_count", 10))
    window_min = int(icfg.get("window_minutes", 60))
    resolve_min = int(icfg.get("resolve_after_minutes", 120))
    window_s, resolve_s = window_min * 60, resolve_min * 60
    backlog_s = int(icfg.get("initial_backlog_hours", 24)) * 3600
    log_path = icfg.get("log_path") or "/opt/dumblog/infinidysk.log"
    tz_name = icfg.get("log_tz") or "Europe/Amsterdam"
    now = int(now if now is not None else
              datetime.now(timezone.utc).timestamp())
    st = {}

    # --- bron-beschikbaarheid (zelfde anti-flap-patroon als dumbscope) -------
    fail_row = c.execute("select value from cursors where"
                         " name='infinidysk:log_fail'").fetchone()
    fails = int(float(fail_row[0])) if fail_row else 0
    cur_row = c.execute("select value from cursors where"
                        " name='infinidysk:log_cursor'").fetchone()
    try:
        cursor = json.loads(cur_row[0]) if cur_row else None
    except Exception:  # noqa: BLE001 — corrupte cursor = opnieuw beginnen
        cursor = None
    try:
        lines, cursor, _note = hi.tail_new_lines(
            log_path, cursor, now, initial_backlog_s=backlog_s, tz_name=tz_name)
    except Exception as e:  # noqa: BLE001 — isolatie: bron uit = geen detectie
        fails += 1
        c.execute("insert into cursors(name, value, last_checked)"
                  " values('infinidysk:log_fail', ?, ?) on conflict(name)"
                  " do update set value=excluded.value,"
                  " last_checked=excluded.last_checked", (str(fails), now_iso()))
        lvl = 3 if fails >= 12 else (2 if fails >= 3 else 0)
        if lvl:
            _, etype = incident_upsert(c, "infinidysk:log_unavailable",
                                       source="infinidysk", itype="availability",
                                       sev_level=lvl, value=fails,
                                       reason=f"log onleesbaar ({fails} runs): "
                                              f"{type(e).__name__}")
            if etype in ("new", "escalated"):
                events.append(emit(mode, "infinidysk_availability",
                                   "infinidysk:log_unavailable", current=fails,
                                   severity=NAME[lvl], provisional=bp,
                                   state="active", baseline_pending=bp,
                                   reason=f"InfiniDysk-log onleesbaar: "
                                          f"{type(e).__name__} ({fails} runs)",
                                   source="infinidysk"))
        c.commit()
        st["infinidysk"] = f"log_onleesbaar ({fails})"
        return st
    if fails:
        c.execute("insert into cursors(name, value, last_checked)"
                  " values('infinidysk:log_fail', '0', ?) on conflict(name)"
                  " do update set value=excluded.value,"
                  " last_checked=excluded.last_checked", (now_iso(),))
        _, etype = incident_upsert(c, "infinidysk:log_unavailable",
                                   source="infinidysk", itype="availability",
                                   sev_level=0, value=0,
                                   reason="log weer leesbaar")
        if etype == "resolved":
            events.append(emit(mode, "infinidysk_availability",
                               "infinidysk:log_unavailable", severity="normal",
                               provisional=bp, state="resolved",
                               baseline_pending=True,
                               reason="log weer leesbaar", source="infinidysk"))
    c.execute("insert into cursors(name, value, last_checked)"
              " values('infinidysk:log_cursor', ?, ?) on conflict(name)"
              " do update set value=excluded.value,"
              " last_checked=excluded.last_checked", (json.dumps(cursor), now_iso()))
    seeded_run = cur_row is None

    # --- ingest (PK-dedup: exact dubbele regels tellen niet dubbel) ----------
    for ln in lines:
        ev = hi.parse_line(ln, tz_name)
        if not ev:
            continue
        norm = hi.normalize_path(ev["path"])
        ifp = f"infinidysk:repair_loop:{hi.fingerprint(norm)}"
        disp = hi.display_name(ev["path"])
        if ev["kind"] in hi.START_KINDS:
            c.execute("insert or ignore into infinidysk_repairs"
                      "(fingerprint, ts, kind, ts_iso) values(?,?,?,?)",
                      (ifp, ev["ts"], ev["kind"], now_iso()))
            c.execute("insert into infinidysk_loop(fingerprint, display,"
                      " last_reason, updated_at) values(?,?,?,?)"
                      " on conflict(fingerprint) do update set"
                      " display=excluded.display, updated_at=excluded.updated_at",
                      (ifp, disp, None, now_iso()))
        elif ev.get("reason"):
            c.execute("update infinidysk_loop set last_reason=?, updated_at=?"
                      " where fingerprint=?",
                      (ev["reason"][:200], now_iso(), ifp))

    # --- begrensde retentie ---------------------------------------------------
    c.execute("delete from infinidysk_repairs where ts < ?",
              (now - (resolve_s + 3600),))
    c.execute("delete from infinidysk_repairs where rowid not in"
              " (select rowid from infinidysk_repairs order by ts desc limit 20000)")
    stale_cutoff = datetime.fromtimestamp(now - 7 * 86400,
                                          timezone.utc).isoformat(timespec="seconds")
    c.execute("delete from infinidysk_loop where updated_at < ?"
              " and fingerprint not in"
              " (select fingerprint from infinidysk_repairs)", (stale_cutoff,))

    # --- policy per bestand -> bestaande state-machine ------------------------
    fps = [r[0] for r in c.execute(
        "select fingerprint from infinidysk_loop order by updated_at desc"
        " limit 500")]
    emitted = 0
    total60 = 0
    for ifp in fps:
        ts_list = [r[0] for r in c.execute(
            "select ts from infinidysk_repairs where fingerprint=? order by ts",
            (ifp,))]
        n60 = len([t for t in ts_list if t >= now - window_s])
        total60 += n60
        last = max(ts_list) if ts_list else 0
        disp, last_reason = c.execute(
            "select display, last_reason from infinidysk_loop where"
            " fingerprint=?", (ifp,)).fetchone()
        age_min = round((now - last) / 60) if last else None
        if n60 >= urg_n:
            lvl = 3
            reason = f"{n60} repairs/{window_min}min (>= {urg_n}): {disp}"
        elif n60 >= warn_n:
            lvl = 2
            reason = f"{n60} repairs/{window_min}min (>= {warn_n}): {disp}"
        elif last and (now - last) < resolve_s:
            lvl = 1
            reason = (f"{n60} repairs/{window_min}min; laatste repair "
                      f"{age_min} min geleden: {disp}")
        else:
            lvl = 0
            reason = (f"geen repairs meer (laatste {age_min} min geleden): "
                      f"{disp}")
        istate_row = c.execute("select state from incidents where"
                               " fingerprint=?", (ifp,)).fetchone()
        istate = istate_row[0] if istate_row else None
        if lvl == 0 and istate in (None, "resolved"):
            continue  # niets open, niets nieuws: geen run-activiteit
        if seeded_run and lvl >= 2:
            lvl = 1
            reason = f"baseline-seed (gedempt): {reason}"
        _, etype = incident_upsert(c, ifp, source="infinidysk",
                                   itype="repair_loop", sev_level=lvl,
                                   value=n60, reason=reason[:200])
        if etype in ("new", "escalated", "reopened", "resolved"):
            emitted += 1
            events.append(emit(mode, "infinidysk_repair_loop", ifp,
                               current={"repairs_60m": n60,
                                        "last_repair_age_min": age_min},
                               severity=NAME[lvl] if lvl else "normal",
                               provisional=bp,
                               state=("resolved" if etype == "resolved"
                                      else "active"),
                               baseline_pending=bp, reason=reason[:240],
                               source="infinidysk",
                               extra={"file": disp,
                                      "last_reason": (last_reason or "")[:160],
                                      "thresholds": {
                                          "warning": warn_n, "urgent": urg_n,
                                          "window_min": window_min,
                                          "resolve_min": resolve_min},
                                      **_infinidysk_dumb_context()}))
    st["infinidysk"] = "ok"
    st["infinidysk_loops_tracked"] = len(fps)
    st["infinidysk_total_60m"] = total60
    st["infinidysk_events"] = emitted
    c.commit()  # zelfstandig (zelfde patroon als run_dumbscope); idempotent in run_fast
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
    if fp.startswith("infinidysk:repair_loop:"):
        d = c.execute("select last_reason from infinidysk_loop where"
                      " fingerprint=?", (fp,)).fetchone()
        if d and d[0] and re.search(
                r"430|no such article|not found|missing articles|"
                r"missing/corrupt segment|dmca|expired", d[0], re.I):
            return False, "skip:bekende_deterministische_oorzaak(dode_artikelen)"
        return True, "route:repair_loop_oorzaak_onzeker"
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
    # fase 4: change-correlation + recurrentie — deterministisch, lokaal, gratis.
    # Alleen bereikt als dit incident al een LLM-candidate is; gezonde runs
    # komen hier nooit (geen extra LLM-calls, §6). Hash bevat deze velden niet:
    # correlation rijdt mee met bestaande analyses, veroorzaakt er geen.
    try:
        import hermes_changes as hc
        ccfg = hc.load_cfg()
        exclude_key = fp.split(":")[1] if fp.startswith("docker:") and \
            (":restarts" in fp or ":exited" in fp) else None
        ch = hc.correlate(c, now_iso(), exclude_key=exclude_key, cfg=ccfg)
        if ch:
            ctx["recent_changes"] = ch
        rec = hc.recurrence(c, fp, label=fp, cfg=ccfg)
        if rec:
            ctx["recurrence"] = rec
    except Exception:  # noqa: BLE001 — context is best-effort, nooit kritiek
        pass
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
    if fp.startswith("infinidysk:repair_loop:"):
        lo = c.execute("select display, last_reason from infinidysk_loop"
                       " where fingerprint=?", (fp,)).fetchone()
        if lo:
            ctx.update({"file": (lo[0] or "")[:120],
                        "last_failure_reason": (lo[1] or "")[:160]})
        try:
            n60 = c.execute("select count(*) from infinidysk_repairs where"
                            " fingerprint=? and ts >= ?",
                            (fp, int(time.time()) - 3600)).fetchone()[0]
            ctx["repairs_60m"] = n60
        except Exception:  # noqa: BLE001 — context is best-effort
            pass
        dctx = _infinidysk_dumb_context()
        if dctx:
            ctx.update(dctx)
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

# ----------------------------------------------------------------- netdata --
# fase 8: Netdata-alarmspiegel. Client/allowlist/normalisatie staan in
# hermes_netdata.py (read-only, uitsluitend GET /api/v1/alarms). Hermes blijft
# leidend: metrics met eigen drempels (memory, temperaturen, disk-space) zijn
# evidence-only en een netdata-critical telt daar alleen als de laatste
# hermes-sample het bevestigt; uncovered onderwerpen (cpu/iowait, load,
# per-container health, net-drops, swap, oom-space-time) gaan via de gewone
# incident-machine -> bestaande notifier-policy (dedup/cooldown/recovery).
NETDATA_SEV_ORDER = {"warning": 2, "critical": 4}


def _netdata_container_covered(c, subject):
    """True als een bestaande hermes-bron deze container al dekt: een actief
    DUMBscope-incident over deze container of een actief unhealthy-incident.
    Dan is netdata evidence, geen nieuw alarm (geen dubbele Telegram-alerts)."""
    like = f"%{subject.lower()}%"
    row = c.execute(
        "select 1 from dumbscope_incidents where status='active' and ("
        "lower(title) like ? or lower(coalesce(root_cause_service,'')) like ?"
        " or lower(coalesce(affected_services,'')) like ?"
        " or lower(substr(fingerprint, 11)) like ?) limit 1",
        (like, like, like, like)).fetchone()
    if row:
        return True
    row = c.execute("select 1 from incidents where fingerprint="
                    "'host:containers:unhealthy' and state in ('active','recovering')").fetchone()
    return row is not None


def _netdata_confirm_sample(metric, confirm_thr):
    """Laatste hermes-sample (1u-venster) voor direction-confirm van een
    netdata-critical; None = geen bevestigende sample."""
    pts = fetch_series(metric, 1)
    if not pts:
        return None
    val = pts[-1][1]
    return val if val >= confirm_thr else None


def _netdata_alert(c, events, cfg, n, *, mode, bp, situation):
    """Correlatie/dedup van één netdata-alarmovergang (nieuw of escalatie).
    Retourneert 'alerted' | 'confirmed' | 'evidence' | 'dedup'."""
    import hermes_netdata as hn
    sev_level = LEVELS[n["severity"]]
    extra = {"netdata": {"name": n["name"], "chart": n["chart"], "kind": n["kind"],
                         "subject": n["subject"], "value": n["value"],
                         "last_status_change": n["last_status_change"]}}
    reason = (f"netdata {n['name']} {n['severity']} ({n['value']}"
              f"{'; ' + situation if situation else ''})")[:240]

    if n["kind"] == "container" and _netdata_container_covered(c, n["subject"]):
        extra["dedup"] = "covered_evidence_only"
        events.append(emit(mode, "netdata_alarm", n["fingerprint"], current=n["value"],
                           severity=n["severity"], provisional=bp, state="observed",
                           baseline_pending=bp, source="netdata", extra=extra,
                           reason=reason + " -> al gedekt door actief dumbscope/unhealthy-incident"
                                             " (evidence-only)"))
        return "evidence"

    cov = hn.covered_check(cfg, n)
    if cov:
        hermes_fp, metric, confirm_thr = cov
        if n["severity"] != "critical":
            extra["dedup"] = "covered_evidence_only"
            events.append(emit(mode, "netdata_alarm", n["fingerprint"], current=n["value"],
                               severity=n["severity"], provisional=bp, state="observed",
                               baseline_pending=bp, source="netdata", extra=extra,
                               reason=reason + " -> hermes-check is leidend voor dit subject"
                                                 " (covered: evidence-only)"))
            return "evidence"
        sample = _netdata_confirm_sample(metric, confirm_thr)
        if sample is None:
            extra["dedup"] = "covered_evidence_only"
            events.append(emit(mode, "netdata_alarm", n["fingerprint"], current=n["value"],
                               severity=n["severity"], provisional=bp, state="observed",
                               baseline_pending=bp, source="netdata", extra=extra,
                               reason=reason + f" -> niet bevestigd door hermes-sample"
                                                 f" {metric} (>= {confirm_thr:g} vereist);"
                                                 f" evidence-only"))
            return "evidence"
        _, etype = incident_upsert(c, hermes_fp, source="netdata", itype="netdata_confirm",
                                   sev_level=sev_level, value=n["value"],
                                   reason=f"{reason}; bevestigd door hermes-sample"
                                          f" {metric}={sample:g} (>= {confirm_thr:g})")
        if etype in ("new", "escalated", "reopened"):
            extra["dedup"] = "covered_confirmed_critical"
            events.append(emit(mode, "netdata_alarm", hermes_fp, current=n["value"],
                               severity=n["severity"], provisional=bp, state="active",
                               baseline_pending=bp, source="netdata", extra=extra,
                               reason=reason + f"; bevestigd door hermes-sample {metric}={sample:g}"))
            return "confirmed"
        return "dedup"

    # uncovered: netdata is de enige sensor voor dit onderwerp -> gewoon
    # incident; notifier-policy bepaalt verzending (warning+ => pending).
    _, etype = incident_upsert(c, n["fingerprint"], source="netdata",
                               itype=f"netdata_{n['kind']}", sev_level=sev_level,
                               value=n["value"], reason=reason)
    if etype in ("new", "escalated", "reopened"):
        events.append(emit(mode, "netdata_alarm", n["fingerprint"], current=n["value"],
                           severity=n["severity"], provisional=bp, state="active",
                           baseline_pending=bp, source="netdata", extra=extra,
                           reason=reason))
        return "alerted" if etype != "escalated" else "confirmed"
    return "dedup"


def run_netdata(cfg, c, events, mode="fast"):
    """fase 8 — Netdata-alarmspiegel (read-only). Eerste geslaagde poll = seed
    (state vastleggen, geen events, geen alarmstorm bij eerste deployment).
    Daarna diffen: nieuw/escalatie -> _netdata_alert; verdwenen na geslaagde
    poll -> recovery via de incident-machine. Mislukte polls raken de
    alarm-state NIET (geen valse recoveries); >=N mislukkingen -> availability-
    incident (waarschuwingsdrempels uit thresholds.yaml)."""
    import hermes_netdata as hn
    ncfg = dict(cfg.get("netdata") or {})
    bp = bool(ncfg.get("baseline_pending", True))
    fail_warn = int(ncfg.get("failure_warning_polls", 3))
    fail_urgent = int(ncfg.get("failure_urgent_polls", 12))
    st = {"alarms_active": 0, "new_alerts": 0, "escalated": 0, "recovered": 0,
          "evidence_only": 0, "unavailable_polls": 0}

    def failures():
        row = c.execute("select value from cursors where name='netdata:failures'").fetchone()
        return int(float(row[0])) if row else 0

    def set_failures(n_):
        c.execute("insert into cursors(name, value, last_checked)"
                  " values('netdata:failures', ?, ?)"
                  " on conflict(name) do update set value=excluded.value,"
                  " last_checked=excluded.last_checked", (str(n_), now_iso()))

    try:
        client = hn.make_client(cfg)
        raws = client.active_alarms()
    except Exception as e:  # noqa: BLE001 — isolatie bewust breed (dumbscope-patroon)
        reason = getattr(e, "reason", type(e).__name__)
        n_ = failures() + 1
        set_failures(n_)
        st["unavailable_polls"] = n_
        lvl = 3 if n_ >= fail_urgent else (2 if n_ >= fail_warn else 0)
        if lvl:
            _, etype = incident_upsert(c, "netdata:availability", source="netdata",
                                       itype="availability", sev_level=lvl, value=n_,
                                       reason=f"{n_} opeenvolgende mislukte polls ({reason})")
            if etype in ("new", "escalated"):
                events.append(emit(mode, "netdata_availability", "netdata:availability",
                                   current=n_, severity=NAME[lvl], provisional=bp,
                                   state="active", baseline_pending=bp, source="netdata",
                                   reason=f"Netdata onbereikbaar: {reason} ({n_} polls)"))
        c.commit()
        return st

    n_ = failures()
    if n_:
        set_failures(0)
        st["unavailable_polls"] = 0
        _, etype = incident_upsert(c, "netdata:availability", source="netdata",
                                   itype="availability", sev_level=0, value=0,
                                   reason="Netdata weer bereikbaar")
        if etype == "resolved":
            events.append(emit(mode, "netdata_availability", "netdata:availability",
                               severity="normal", provisional=bp, state="resolved",
                               baseline_pending=True, source="netdata",
                               reason=f"hersteld na {n_} mislukte polls"))
    c.execute("insert into cursors(name, value, last_checked)"
              " values('netdata:last_poll', ?, ?)"
              " on conflict(name) do update set value=excluded.value,"
              " last_checked=excluded.last_checked", (now_iso(), now_iso()))

    alarms = {}
    for raw in raws:
        if not isinstance(raw, dict):
            continue
        if raw.get("disabled") or raw.get("silenced"):
            continue
        n = hn.normalize(raw)
        if n:
            alarms[n["fingerprint"]] = n
    st["alarms_active"] = len(alarms)

    seeded_row = c.execute("select value from cursors where name='netdata:seeded'").fetchone()
    if not seeded_row:
        for fp, n in sorted(alarms.items()):
            c.execute("insert or replace into netdata_alarms(fingerprint, name, chart,"
                      " kind, subject, last_status, last_severity, last_value,"
                      " alert_state, first_seen, last_seen, last_reason)"
                      " values(?,?,?,?,?,?,?,?,?,?,?,?)",
                      (fp, n["name"], n["chart"], n["kind"], n["subject"],
                       n["severity"].upper(), n["severity"], n["value"], "seeded",
                       now_iso(), now_iso(), "seed: bestaand alarm bij eerste poll"))
        c.execute("insert into cursors(name, value, last_checked)"
                  " values('netdata:seeded', '1', ?)"
                  " on conflict(name) do update set value=excluded.value,"
                  " last_checked=excluded.last_checked", (now_iso(),))
        events.append(emit(mode, "netdata_baseline", "netdata:baseline",
                           current={"seeded": len(alarms)}, severity="normal",
                           provisional=bp, state="seeded", baseline_pending=bp,
                           source="netdata",
                           reason=f"eerste poll: {len(alarms)} actieve netdata-alarms geseed"
                                  f" (geen per-alarm events)"))
        c.commit()
        return st

    for fp, n in sorted(alarms.items()):
        row = c.execute("select last_severity from netdata_alarms where fingerprint=?",
                        (fp,)).fetchone()
        prev_sev = row[0] if row else None
        c.execute("insert into netdata_alarms(fingerprint, name, chart, kind, subject,"
                  " last_status, last_severity, last_value, alert_state, first_seen,"
                  " last_seen, last_reason) values(?,?,?,?,?,?,?,?,?,?,?,?)"
                  " on conflict(fingerprint) do update set name=excluded.name,"
                  " chart=excluded.chart, kind=excluded.kind, subject=excluded.subject,"
                  " last_status=excluded.last_status, last_severity=excluded.last_severity,"
                  " last_value=excluded.last_value, last_seen=excluded.last_seen,"
                  " alert_state='active'",
                  (fp, n["name"], n["chart"], n["kind"], n["subject"],
                   n["severity"].upper(), n["severity"], n["value"], "active",
                   now_iso(), now_iso(), f"netdata {n['severity']} actief"))
        if row is None:
            r = _netdata_alert(c, events, cfg, n, mode=mode, bp=bp,
                               situation="nieuw sinds seed")
            if r == "alerted":
                st["new_alerts"] += 1
            elif r == "evidence":
                st["evidence_only"] += 1
        elif prev_sev != n["severity"] and \
                NETDATA_SEV_ORDER.get(n["severity"], 0) > NETDATA_SEV_ORDER.get(prev_sev, 0):
            r = _netdata_alert(c, events, cfg, n, mode=mode, bp=bp,
                               situation=f"escalatie {prev_sev}->{n['severity']}")
            if r == "confirmed":
                st["escalated"] += 1
            elif r == "evidence":
                st["evidence_only"] += 1
        # de-escalatie binnen de active-set of identiek alarm: alleen state,
        # geen event (duplicaat-demping; herstel is verdwijnen uit de set)

    for (fp,) in c.execute("select fingerprint from netdata_alarms"
                           " where alert_state='active'").fetchall():
        if fp in alarms:
            continue
        c.execute("update netdata_alarms set alert_state='resolved', resolved_at=?,"
                  " last_reason=? where fingerprint=?",
                  (now_iso(), "alarm verdwenen uit netdata active-set (herstel of verwijderd)", fp))
        irow = c.execute("select state from incidents where fingerprint=?", (fp,)).fetchone()
        if irow and irow[0] in ("active", "recovering"):
            _, etype = incident_upsert(c, fp, source="netdata", itype="netdata_recovery",
                                       sev_level=0, value=0,
                                       reason="netdata-alarm hersteld: verdwenen uit active-set")
            if etype == "resolved":
                events.append(emit(mode, "netdata_alarm", fp, severity="normal",
                                   provisional=bp, state="resolved", baseline_pending=True,
                                   source="netdata",
                                   reason="netdata-alarm hersteld: verdwenen uit active-set"))
                st["recovered"] += 1
    c.commit()
    return st


# ------------------------------------------------------------ sampler-gap --
def run_sampler_gap(cfg, c, events, mode="fast"):
    """fase 9 — detecteer stilgevallen van de host-sampler aan de hand van de
    laatste sample-ts in samples.db. >10 min geen sample -> warning,
    >30 min -> urgent (escalatie), herstel zodra sampling weer actueel is
    (recovery precies eenmaal via de centrale machine/notifier). Een
    lees-fout op samples.db is geen signaal: state onaangeroerd, NOOIT een
    valse recovery. Herhaalde polls op dezelfde stale-hoogte zijn 'none'
    (geen reminder-spam); alleen nieuw/escalatie/recovery leveren events."""
    try:
        s = sqlite3.connect(f"file:{SAMPLES_DB}?mode=ro", uri=True, timeout=5)
        row = s.execute("select max(ts) from samples").fetchone()
        s.close()
    except sqlite3.Error:
        return None
    if not row or not row[0]:
        return None
    age_min = (time.time() - float(row[0])) / 60.0
    lvl = 3 if age_min > 30 else (2 if age_min > 10 else 0)
    fp = "hermes:sampler:stale"
    if lvl:
        _, etype = incident_upsert(c, fp, source="fast", itype="sampler_stale",
                                   sev_level=lvl, value=round(age_min, 1),
                                   reason=f"laatste host-sample {int(age_min)} min geleden"
                                          f" (drempel 10/30 min)")
        if etype in ("new", "escalated", "reopened"):
            events.append(emit(mode, "sampler_gap", fp, current=round(age_min, 1),
                               severity=NAME[lvl], provisional=True, state="active",
                               baseline_pending=True,
                               reason=f"host-sampler stale: laatste sample {int(age_min)}"
                                      f" min geleden (drempel 10/30 min)",
                               recommended_diagnostic="hermes-host-sampler log/cron"))
            return {"age_min": round(age_min, 1), "level": NAME[lvl], "event": etype}
        return {"age_min": round(age_min, 1), "level": NAME[lvl], "event": "none"}
    # actueel: eventueel openstaand stale-incident laten herstellen
    irow = c.execute("select peak_value from incidents where fingerprint=?"
                     " and state in ('active','recovering')", (fp,)).fetchone()
    if irow is None:
        return {"age_min": round(age_min, 1), "level": "normal", "event": "none"}
    peak = irow[0]
    _, etype = incident_upsert(c, fp, source="fast", itype="sampler_stale",
                               sev_level=0, value=round(age_min, 1),
                               reason=f"hersteld: sampling weer actueel (was {int(peak or 0)}"
                                      f" min stale)")
    if etype == "resolved":
        events.append(emit(mode, "sampler_gap", fp, severity="normal", provisional=True,
                           state="resolved", baseline_pending=True,
                           reason=f"hersteld: sampler weer actueel na piek van"
                                  f" {int(peak or 0)} min stale"))
        return {"age_min": round(age_min, 1), "level": "normal", "event": "resolved"}
    return {"age_min": round(age_min, 1), "level": "normal", "event": "none"}


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
                rising_fast = False  # §7b: micro-spike-beleid — geen rate-escalatie; sustain doet het werk
            else:
                rising_fast = ((tr.get("slope_per_h") or 0) >=
                               float(th.get("rise_rate_pct_per_hour", th.get("rise_urgent_ppc_per_hour", 5))))
            sev, prov = pct_metric(c, cfg, events, fp=fp, metric=metric, label=label, th=th,
                                   sustain_need=sneed, value=tr["current"], points=pts, trend=tr,
                                   rising_fast=rising_fast,
                                   cap_notice_first=metric in CAP_NOTICE_METRICS,
                                   eps=eps, mode="fast", sample_ts=ts)
            st[label] = sev

    # vDisk-groei: per-uur groeirate uit vdisk_used_kb. Grens is per UUR
    # (growth_warn_gb_per_hour): d1h wordt nooit meer geëxtrapoleerd naar 24u —
    # dat veroorzaakte false warnings bij gewone groei.
    kb = series["vdisk_used_kb"]
    if len(kb) >= 2:
        tr = trend_of(kb, eps=200 * 1024)
        limit = float(cfg.get("docker_vdisk", {}).get("growth_warn_gb_per_hour", 2)) * 1024**2
        d1h, d6h = tr.get("d1h"), tr.get("d6h")
        rates = [x for x in (d1h, (d6h / 6) if d6h is not None else None) if x is not None]
        eff = max(rates) if rates else 0.0  # KB per uur
        lvl = 2 if eff > limit else 0
        _, etype = incident_upsert(c, "host:docker_vdisk:growth", source="fast", itype="vdisk_growth",
                                   sev_level=lvl, value=round(eff / 1024**2, 2),
                                   reason=(f"groeirate {eff / 1024**2:.2f} GiB/u"
                                           f" (d1h={d1h}KB d6h={d6h}KB)"
                                           f" limit={limit / 1024**2:.1f} GiB/u"),
                                   )
        if etype in ("new", "escalated", "reopened"):
            events.append(emit("fast", "docker_vdisk_growth", "host:docker_vdisk:growth",
                               current=round(eff / 1024**2, 2), trend={"d1h_kb": d1h, "d6h_kb": d6h},
                               severity=NAME[lvl], provisional=True, state="active", baseline_pending=True,
                               reason=f"groeirate {eff / 1024**2:.2f} GiB/u >= {limit / 1024**2:.1f} GiB/u",
                               recommended_diagnostic="docker-space-detail"))
        elif etype == "resolved":
            events.append(emit("fast", "docker_vdisk_growth", "host:docker_vdisk:growth",
                               current=round(eff / 1024**2, 2), severity="normal", provisional=True,
                               state="resolved", baseline_pending=True, reason="groei terug onder grens"))
        metric_state_update(c, "vdisk_growth_gib_per_h", round(eff / 1024**2, 2), tr)

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
            corr = c.execute("select current_severity from incidents"
                             " where fingerprint='host:memory:high'"
                             " and state in ('active','recovering')").fetchone()
            reason = f"oom_kills {int(prev)} -> {int(cur)}"
            if corr:
                reason += f"; correlatie: host:memory:high actief ({corr[0]})"
            _, etype = incident_upsert(c, "host:memory:oom", source="fast", itype="oom",
                                       sev_level=LEVELS[sev_name], value=delta,
                                       reason=reason, )
            if etype in ("new", "escalated", "reopened"):
                events.append(emit("fast", "oom", "host:memory:oom", current=int(cur), previous=int(prev),
                                   severity=sev_name, provisional=True, state="active",
                                   baseline_pending=True,
                                   reason=(f"OOM-teller +{delta}" +
                                           (f" (correlatie: host:memory:high actief)" if corr else "")),
                                   recommended_diagnostic="oom-events"))
        else:
            # counter ongewijzigd (of reset na reboot): event-incident Lost direct op;
            # eenzelfde counterwaarde mag nooit reminders genereren.
            _, etype = incident_upsert(c, "host:memory:oom", source="fast", itype="oom",
                                       sev_level=0, value=cur,
                                       reason="geen nieuwe OOM-delta (counter ongewijzigd)", )
            if etype == "resolved":
                events.append(emit("fast", "oom", "host:memory:oom", current=int(cur),
                                   severity="normal", provisional=True, state="resolved",
                                   baseline_pending=True,
                                   reason="OOM-counter ongewijzigd -> event afgesloten"))
        st["oom_kills"] = int(cur)

    # docker daemon down (sampler), swap, unhealthy-teller: laatste sample.
    # Herstel-pad (analoog OOM/counters): een gezonde waarde sluit een nog
    # openstaand state-incident; zonder row gebeurt er niets.
    for metric, fp, label, lvl0, reason in (
            ("docker_ok", "host:docker_daemon:down", "docker_daemon", 4, "docker daemon onbereikbaar"),
            ("containers_unhealthy", "host:containers:unhealthy", "containers_unhealthy", 1,
             "unhealthy containers aanwezig")):
        pts = fetch_series(metric, 1)
        if not pts:
            continue
        value = pts[-1][1]
        problem = (value == 0) if metric == "docker_ok" else (value > 0)
        if problem:
            _, etype = incident_upsert(c, fp, source="fast", itype=metric, sev_level=lvl0,
                                       value=value, reason=reason, )
            if etype in ("new", "escalated"):
                events.append(emit("fast", label, fp, current=value, severity=NAME[lvl0],
                                   provisional=True, state="active", baseline_pending=True,
                                   reason=reason, source="fast"))
        else:
            _, etype = incident_upsert(c, fp, source="fast", itype=metric, sev_level=0,
                                       value=value, reason="waarde terug op normaal")
            if etype == "resolved":
                events.append(emit("fast", label, fp, current=value, severity="normal",
                                   provisional=True, state="resolved", baseline_pending=True,
                                   reason="hersteld: waarde terug op normaal", source="fast"))
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
    elif sw:
        _, etype = incident_upsert(c, "host:swap:active", source="fast", itype="swap",
                                   sev_level=0, value=sw[-1][1], reason="swap weer 0")
        if etype == "resolved":
            events.append(emit("fast", "swap", "host:swap:active", current=sw[-1][1],
                               severity="normal", provisional=True, state="resolved",
                               baseline_pending=True, reason="swap terug op 0"))

    if new_ts:
        c.execute("insert into cursors(name, value, last_checked) values('fast:last_ts', ?, ?)"
                  " on conflict(name) do update set value=excluded.value, last_checked=excluded.last_checked",
                  (str(int(new_ts[-1])), now_iso()))
    # fase 4: deploy-events (changes-deploy.jsonl) in de change-ledger lezen.
    # Kosten zonder deploys: één stat()-call; failure-isolated.
    try:
        import hermes_changes as hc
        if (cfg.get("correlation") or {}).get("enabled", True):
            hc.collect_deploy_events(c, home=HOME)
    except Exception as e:  # noqa: BLE001 — isolatie bewust breed
        events.append(emit("fast", "changes_ledger", "changes:ingest_error",
                           severity="notice", provisional=True, state="observed",
                           baseline_pending=True,
                           reason=f"deploy-event ingest faalde (onaangetast): "
                                  f"{type(e).__name__}: {e}"[:240], source="fast"))
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
    # Per-bestand repair-loop-detectie (fase 7): deterministisch, read-only,
    # eigen state; faalt dit, dan raakt het de host-evaluatie niet (§21-analoog).
    try:
        inf = run_infinidysk(cfg, c, events, mode="fast")
        st.update({k: v for k, v in inf.items()})
    except Exception as e:  # noqa: BLE001 — isolatie bewust breed
        events.append(emit("fast", "infinidysk_integration",
                           "infinidysk:integration_error", severity="notice",
                           provisional=True, state="observed",
                           baseline_pending=True,
                           reason=f"integratiefout (host-monitoring onaangetast): "
                                  f"{type(e).__name__}: {e}"[:240],
                           source="infinidysk"))
        st["infinidysk"] = "integration_error"
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
    # Sampler-gap (fase 9): stilgevallen van de host-sampler -> centraal
    # incident (hermes:sampler:stale). Failure-isolated: leesfout = geen
    # signaal, geen valse recovery.
    try:
        st["sampler_gap"] = run_sampler_gap(cfg, c, events, mode="fast")
    except Exception as e:  # noqa: BLE001 — isolatie bewust breed
        events.append(emit("fast", "sampler_gap_integration", "sampler:integration_error",
                           severity="notice", provisional=True, state="observed",
                           baseline_pending=True,
                           reason=f"sampler-gap-check faalde: {type(e).__name__}: {e}"[:240]))
        st["sampler_gap"] = "integration_error"
    # Netdata-alarmspiegel (fase 8): read-only input, allowlist, dedup met
    # bestaande hermes-checks (die blijven leidend). Failure-isolated: een
    # netdata-storing raakt host-/dumbscope-monitoring niet (§21-analoog).
    try:
        if (cfg.get("netdata") or {}).get("enabled", True):
            st["netdata"] = run_netdata(cfg, c, events, mode="fast")
    except Exception as e:  # noqa: BLE001 — isolatie bewust breed
        events.append(emit("fast", "netdata_integration", "netdata:integration_error",
                           severity="notice", provisional=True, state="observed",
                           baseline_pending=True, source="netdata",
                           reason=f"netdata-input faalde (rest onaangetast):"
                                  f" {type(e).__name__}: {e}"[:240]))
        st["netdata"] = "integration_error"
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
                # monotone counters: event-beslissing op high-water-mark (§12).
                # Een dip is een lees-artifact/geen reset-bewijs; alleen een
                # waarde BOVEN het historisch maximum is een echt event.
                hwname = f"smart:{dev}:{short}:hw"
                hwrow = c.execute("select value from cursors where name=?", (hwname,)).fetchone()
                hw = float(hwrow[0]) if hwrow and hwrow[0] is not None else v
                if v > hw:
                    delta = int(v - hw)
                    jump = int(cfg.get("counters", {}).get("crc_jump_warning", 50))
                    if short == "crc":
                        # monotone-counter EVENT, geen state-incident (§12):
                        # severity volgt delta/snelheid; absolute teller is context
                        recent = False
                        pc = c.execute("select value from cursors where name=?",
                                       (f"smart:{dev}:{short}:last_change",)).fetchone()
                        if pc:
                            try:
                                pdt = datetime.fromisoformat(pc[0])
                                recent = (datetime.now(timezone.utc) - pdt).total_seconds() < 6 * 3600
                            except ValueError:
                                recent = False
                        if delta >= jump:
                            lvl = 3   # grote sprong -> urgent
                        elif (delta > 1 and recent) or delta >= 10:
                            lvl = 2   # meerdere in korte tijd -> warning
                        else:
                            lvl = 1   # +1 incidenteel -> notice
                    else:
                        lvl = 2
                    # counter-events: na resolve is ELKE nieuwe delta een nieuw
                    # event (ook notice-niveau) — oud incident (+occurrences) weg
                    prev_occ = 0
                    srow = c.execute("select state, occurrences from incidents"
                                     " where fingerprint=?", (f"disk:{dev}:{short}_growth",)).fetchone()
                    if srow and srow[0] in ("resolved", "recovering"):
                        prev_occ = srow[1] or 0
                        c.execute("delete from incidents where fingerprint=?",
                                  (f"disk:{dev}:{short}_growth",))
                    _, etype = incident_upsert(c, f"disk:{dev}:{short}_growth", source="deep",
                                               itype="smart_counter", sev_level=lvl, value=delta,
                                               reason=f"{short} {int(hw)} -> {int(v)} (+{delta};"
                                                      f" absolute teller {int(v)} is context)",
                                               )
                    if etype == "new" and prev_occ:
                        c.execute("update incidents set occurrences=occurrences+? where fingerprint=?",
                                  (prev_occ, f"disk:{dev}:{short}_growth"))
                    if etype in ("new", "escalated", "reopened"):
                        c.execute("insert into cursors(name, value, last_checked)"
                                  " values(?,?,?) on conflict(name) do update"
                                  " set value=excluded.value, last_checked=excluded.last_checked",
                                  (f"smart:{dev}:{short}:last_change", now_iso(), now_iso()))
                        events.append(emit("deep", "disk_health", f"disk:{dev}:{short}_growth",
                                           current=int(v), previous=int(hw), severity=NAME[lvl],
                                           provisional=True, state="active", baseline_pending=True,
                                           reason=f"monotone teller +{delta} boven maximum (§12)",
                                           source="deep"))
                elif v == hw:
                    # counter op maximum ongewijzigd: event-incident sluit direct;
                    # dezelfde counterwaarde mag nooit reminders genereren (§12)
                    _, etype = incident_upsert(c, f"disk:{dev}:{short}_growth", source="deep",
                                               itype="smart_counter", sev_level=0, value=v,
                                               reason="counter ongewijzigd -> event afgesloten", )
                    if etype == "resolved":
                        events.append(emit("deep", "disk_health", f"disk:{dev}:{short}_growth",
                                           current=int(v), severity="normal", provisional=True,
                                           state="resolved", baseline_pending=True,
                                           reason="counter ongewijzigd -> event afgesloten",
                                           source="deep"))
                # v < hw: dip = lees-artifact, geen event en geen state-reset
                if v >= hw or hwrow is None:
                    c.execute("insert into cursors(name, value, last_checked)"
                              " values(?,?,?) on conflict(name) do update"
                              " set value=excluded.value, last_checked=excluded.last_checked",
                              (hwname, str(v), now_iso()))
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
        else:
            _, etype = incident_upsert(c, "host:array:stopped", source="deep", itype="array",
                                       sev_level=0, value=0, reason="array weer STARTED")
            if etype == "resolved":
                events.append(emit("deep", "array_status", "host:array:stopped", current="STARTED",
                                   severity="normal", provisional=True, state="resolved",
                                   baseline_pending=True, reason="array weer STARTED", source="deep"))
        if data.get("resync_pct") not in (None, 0, 100):
            try:
                import hermes_changes as hc
                hc.record_change(c, "array_resync", "array", now_iso(),
                                 f"{data.get('resync_action')} @ {data.get('resync_pct')}%")
            except Exception:  # noqa: BLE001 — ledger mag deep-checks nooit storen
                pass
            _, etype = incident_upsert(c, "host:array:resync", source="deep", itype="array",
                                       sev_level=1, value=data.get("resync_pct"),
                                       reason=f"resync {data.get('resync_action')} @ {data.get('resync_pct')}%",
                                       )
            if etype in ("new", "escalated"):
                events.append(emit("deep", "array_status", "host:array:resync", current=data.get("resync_pct"),
                                   severity="notice", provisional=True, state="active",
                                   baseline_pending=True,
                                   reason="parity/resync werkelijk actief (pos/size, §13)", source="deep"))
        else:
            _, etype = incident_upsert(c, "host:array:resync", source="deep", itype="array",
                                       sev_level=0, value=data.get("resync_pct"),
                                       reason="resync klaar of geen data (pct 0/100/None)")
            if etype == "resolved":
                events.append(emit("deep", "array_status", "host:array:resync",
                                   current=data.get("resync_pct"), severity="normal",
                                   provisional=True, state="resolved", baseline_pending=True,
                                   reason="resync afgerond", source="deep"))
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
        try:
            import hermes_changes as hc
        except Exception:  # noqa: BLE001 — change-ledger is optioneel
            hc = None
        for cont in ds["data"]["containers"]:
            name = cont["name"]
            restarts = int(cont.get("restarts") or 0)
            state = cont["state"]
            if hc is not None:
                try:
                    # fase 4: started/state-waarnemingen -> change-ledger
                    hc.record_container_observation(c, name, state, cont.get("started"), now_iso())
                except Exception:  # noqa: BLE001 — ledger mag deep-checks nooit storen
                    pass
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
            elif delta == 0:
                # event-incident netjes afsluiten zodra de counter stilstaat
                # (analoog OOM/SMART: ongewijzigde counter mag geen open incident achterlaten)
                _, etype = incident_upsert(c, f"docker:{name}:restarts", source="deep",
                                           itype="docker_restarts", sev_level=0, value=restarts,
                                           reason="geen nieuwe restarts (delta 0)")
                if etype == "resolved":
                    events.append(emit("deep", "docker_restarts", f"docker:{name}:restarts",
                                       current=restarts, severity="normal", provisional=True,
                                       state="resolved", baseline_pending=True,
                                       reason="geen nieuwe restarts -> incident afgesloten",
                                       source="deep"))
            # exited-classificatie: alleen bij verandering emit-ten; eerste
            # waarneming = baseline (stil), cursor volgt de containerstate
            cur_ex = c.execute("select value from cursors where name=?",
                               (f"docker_exited:{name}",)).fetchone()
            last_state = cur_ex[0] if cur_ex else None
            c.execute("insert into cursors(name, value, last_checked) values(?,?,?)"
                      " on conflict(name) do update set value=excluded.value,"
                      " last_checked=excluded.last_checked",
                      (f"docker_exited:{name}", state, now_iso()))
            if state != "running" and last_state is not None and last_state != state:
                events.append(emit("deep", "docker_exited", f"docker:{name}:exited", current=state,
                                   severity="notice", provisional=True, state="classified",
                                   baseline_pending=True,
                                   reason=("bekend bewust gestopt (suppressed in later stadium)"
                                           if name in known else
                                           "exited container (niet in known_stopped)"), source="deep"))
        st["containers"] = ds["data"].get("count")
        if hc is not None:
            try:
                hc.bounded_cleanup(c)  # fase 4: ledger hard begrensd
            except Exception:  # noqa: BLE001
                pass

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
        if "temp" in m:  # temperatuur-sectie gebruikt package_warn_c
            cur = sect.get("package_warn_c")
        sugg = round(min(99.0, q(0.99) + 5), 1) if "temp" not in m else round(q(0.99) + 3, 1)
        # fase 4: gemiddelde/stddev (goedkoop uit dezelfde reeks) + tijdsvenster
        out[m] = {"n": len(vals), "min": round(min(vals), 2), "p50": round(q(0.5), 2),
                  "p95": round(q(0.95), 2), "p99": round(q(0.99), 2), "max": round(max(vals), 2),
                  "mean": round(statistics.mean(vals), 2),
                  "stdev": round(statistics.stdev(vals), 2) if len(vals) > 1 else 0.0,
                  "window_h": round((pts[-1][0] - pts[0][0]) / 3600, 1),
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

    # netdata/dumbscope (fase 9): tests raken nooit live endpoints. Deze
    # defaults gelden voor alle helpers; scenario-helpers overschrijven ze per
    # tmp-state en herstellen ze. _NoDs faalt exact zoals de echte client in
    # test-omstandigheden (geen secrets) — zelfde failure-pad, geen HTTP.
    import hermes_netdata as _hn
    import hermes_dumbscope as _hd

    class _NoNd:
        def active_alarms(self):
            return []

    class _NoDs:
        def poll(self, resolved_limit=20):
            raise _hd.DumbScopeError("unavailable", None, "test: geen live HTTP")

    _hn.make_client = lambda cfg_: _NoNd()
    globals()["make_client"] = lambda cfg_: _NoDs()

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
    def seq_eval(series, minutes=60, seed_counters=None):
        """N opeenvolgende run_fast-calls (productie-getrouw: per sample een run,
        gedeelde state-db) -> (incidents, events)."""
        tmp = Path(tempfile.mkdtemp())
        (tmp / "homelab").mkdir(parents=True)
        scon = sqlite3.connect(tmp / "homelab" / "agent_state.db")
        if seed_counters:
            scon.execute("create table counters(name text primary key, device text,"
                         " previous_value real, current_value real, delta real, last_checked text)")
            scon.executemany("insert into counters values(?,?,?,?,?,?)",
                             [(n_, d_, p_, c_, 0, "seed") for n_, d_, p_, c_ in seed_counters])
        scon.commit(); scon.close()
        con = sqlite3.connect(tmp / "homelab" / "samples.db")
        con.executescript(SAMPLES_SCHEMA)
        now = int(datetime.now(timezone.utc).timestamp())
        n = max(len(v) for v in series.values())
        all_evs = []
        for i in range(n):
            cols = ["ts"] + list(series.keys())
            vals = [now - (n - 1 - i) * minutes * 60] + \
                   [s[i] if i < len(s) else s[-1] for s in series.values()]
            con.execute(f"insert into samples({','.join(cols)})"
                        f" values({','.join('?' for _ in cols)})", vals)
            con.commit(); con.close()
            old = (HOME, SAMPLES_DB, STATE_DB, EVENTS)
            globals().update(HOME=tmp, SAMPLES_DB=tmp / "homelab" / "samples.db",
                             STATE_DB=tmp / "homelab" / "agent_state.db",
                             EVENTS=tmp / "homelab" / "evaluator-events.jsonl")
            try:
                evs = []
                c2 = state_db()
                run_fast(cfg, evs)
                c2.close()
                all_evs.extend(evs)
            finally:
                globals().update(HOME=old[0], SAMPLES_DB=old[1], STATE_DB=old[2], EVENTS=old[3])
            con = sqlite3.connect(tmp / "homelab" / "samples.db")
        con.close()
        inc = {}
        c2 = sqlite3.connect(tmp / "homelab" / "agent_state.db")
        for fp, state, sev in c2.execute("select fingerprint, state, current_severity from incidents"):
            inc[fp] = (state, sev)
        c2.close()
        shutil.rmtree(tmp, ignore_errors=True)
        return inc, all_evs

    # OOM-lifecycle: 3->4 = 1 alert; 4->4 x3 = 0 extra; 4->5 = opnieuw alert
    inc, evs = seq_eval({"mem_used_pct": [40] * 5, "oom_kills": [3, 4, 4, 4, 5]},
                        seed_counters=[("oom_kills", "host", 3, 3)])
    oom_alerts = [e for e in evs if e["check"] == "oom" and e["state"] == "active"]
    oom_res = [e for e in evs if e["check"] == "oom" and e["state"] == "resolved"]
    check("OOM 3->4 = 1 alert, 4->4 x3 = 0 extra, 4->5 = nieuwe alert",
          len(oom_alerts) == 2 and len(oom_res) >= 1 and
          inc.get("host:memory:oom", ("", ""))[0] == "active",
          f"alerts={len(oom_alerts)} res={len(oom_res)} inc={inc.get('host:memory:oom')}")
    inc, evs = seq_eval({"mem_used_pct": [40] * 4, "oom_kills": [4, 4, 4, 4]},
                        seed_counters=[("oom_kills", "host", 3, 4)])
    check("OOM counter unchanged -> geen incident, geen alerts",
          "host:memory:oom" not in inc and
          not [e for e in evs if e["check"] == "oom" and e["state"] == "active"],
          str(inc.get("host:memory:oom")))
    # Docker vDisk
    inc, _ = eval_in(fresh({"vdisk_pct": [70] * 8, "vdisk_used_kb": [107374182] * 8}))
    check("vdisk stabiel 70 -> geen incident",
          "host:docker_vdisk:high" not in inc and "host:docker_vdisk:growth" not in inc, str(list(inc)))
    kb0, kb1 = 0.70 * 157286400, 0.80 * 157286400
    inc, _ = eval_in(fresh({"vdisk_pct": [70] * 12 + [80], "vdisk_used_kb": [kb0] * 12 + [kb1]}))
    check("vdisk 70->80 in 1u -> growth warning",
          inc.get("host:docker_vdisk:growth", ("", ""))[1] == "warning", str(inc.get("host:docker_vdisk:growth")))
    # +300MB/uur (limiet 2 GiB/uur) -> geen growth-warning
    kb300 = [107374182 + i * 307200 for i in range(12)]  # ~100GiB + 300MB/u
    inc, _ = eval_in(fresh({"vdisk_pct": [70] * 12, "vdisk_used_kb": kb300}, minutes=60))
    check("vdisk +300MB/uur -> geen growth-warning",
          "host:docker_vdisk:growth" not in inc, str(inc.get("host:docker_vdisk:growth")))
    # +3GB/uur -> wel growth-warning
    kb3g = [107374182 + i * 3145728 for i in range(12)]
    inc, _ = eval_in(fresh({"vdisk_pct": [70] * 12, "vdisk_used_kb": kb3g}, minutes=60))
    check("vdisk +3GB/uur -> growth warning",
          inc.get("host:docker_vdisk:growth", ("", ""))[1] == "warning", str(inc.get("host:docker_vdisk:growth")))
    # groei stopt -> RESOLVED (actueel normaal = geen reminders meer)
    kbstop = [107374182 + i * 3145728 for i in range(12)] + [107374182 + 11 * 3145728] * 3
    inc, evs = seq_eval({"vdisk_pct": [70] * 15, "vdisk_used_kb": kbstop}, minutes=60)
    check("vdisk groei stopt -> resolved",
          inc.get("host:docker_vdisk:growth", ("", ""))[0] == "resolved",
          str(inc.get("host:docker_vdisk:growth")))
    inc, _ = eval_in(fresh({"vdisk_pct": [95, 95, 90, 84, 80]}))
    check("vdisk 95->80 dalend -> recovering/resolved",
          inc.get("host:docker_vdisk:high", ("missing", "?"))[0] in ("resolved", "recovering"),
          str(inc.get("host:docker_vdisk:high")))
    # Temperatuur (§7 + §7b micro-spike-beleid, 2026-09-23)
    # Banden (thresholds.yaml temperatures): warn=95, urgent=98, crit=100,
    # sustained_minutes=10 (need=2), critical_needs_sustain, urgent_sustained_samples=3.
    inc, evs = eval_in(fresh({"package_temp_c": [70, 100, 70]}))
    check("temp 70->100->70: losse 100C-sample -> geen telegram-waardig event",
          evs and all(e["severity"] not in ("warning", "urgent", "critical") for e in evs),
          str([(e["severity"], e["state"]) for e in evs]))
    inc, _ = eval_in(fresh({"package_temp_c": [70, 100, 70]}))
    check("temp 70->100->70: geen critical, herstel werkt",
          inc.get("host:temperature:package", ("", ""))[1] != "critical"
          and inc.get("host:temperature:package", ("missing", "?"))[0] in ("resolved", "recovering"),
          str(inc.get("host:temperature:package")))
    inc, evs = eval_in(fresh({"package_temp_c": [96, 97, 70]}))
    check("temp 96->97->70: 2 opeenvolgende >=95 -> warning (max warning, geen urgent/critical)",
          any(e["severity"] == "warning" for e in evs)
          and not any(e["severity"] in ("urgent", "critical") for e in evs),
          str([(e["severity"], e["state"]) for e in evs]))
    inc, _ = eval_in(fresh({"package_temp_c": [96, 97, 70]}))
    check("temp 96->97->70: daarna recovering/resolved",
          inc.get("host:temperature:package", ("missing", "?"))[0] in ("recovering", "resolved"),
          str(inc.get("host:temperature:package")))
    inc, _ = eval_in(fresh({"package_temp_c": [96, 96, 96]}))
    check("temp >=95 sustained >=10 min (3 samples) -> urgent",
          inc.get("host:temperature:package", ("", ""))[1] == "urgent", str(inc.get("host:temperature:package")))
    inc, _ = eval_in(fresh({"package_temp_c": [100, 100, 100]}))
    check("temp sustained 100C -> critical (behouden)",
          inc.get("host:temperature:package", ("", ""))[1] == "critical", str(inc.get("host:temperature:package")))
    inc, evs = seq_eval({"package_temp_c": [96] * 5}, minutes=5)
    sev_seq = [(e["severity"], e["state"]) for e in evs
               if e["fingerprint"].startswith("host:temperature")]
    check("temp severity gehouden -> geen duplicate events (alleen temp-fingerprints)",
          len(sev_seq) == len(set(sev_seq)), str(sev_seq))
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
    # CRC-event-lifecycle (§12): 458809->458810 = 1 alert; unchanged = 0;
    # 458810->458811 = nieuwe alert; +50 sprong = zwaardere (urgent) alert
    steps2 = [dh(458809, 0, 0, 0), dh(458810, 0, 0, 0), dh(458810, 0, 0, 0),
              dh(458811, 0, 0, 0), dh(458861, 0, 0, 0)]
    tmp = Path(tempfile.mkdtemp()); (tmp / "homelab").mkdir(parents=True)
    old = (HOME, SAMPLES_DB, STATE_DB, EVENTS)
    globals().update(HOME=tmp, SAMPLES_DB=tmp / "none.db", STATE_DB=tmp / "homelab" / "agent_state.db",
                     EVENTS=tmp / "homelab" / "events.jsonl")
    fake, i = fake_ssh_factory(steps2)
    globals()["ssh_action"] = fake
    try:
        con = sqlite3.connect(SAMPLES_DB); con.close()
        run_events = []
        for step in range(5):
            evs = []; con = state_db(); run_deep(cfg, evs); con.close()
            run_events.append(evs)
            i["n"] = step + 1
        def crc_alerts(k):
            return [e for e in run_events[k]
                    if e.get("fingerprint") == "disk:/dev/sda:crc_growth" and e["state"] == "active"]
        crc_resolved = [e for evs in run_events for e in evs
                        if e.get("fingerprint") == "disk:/dev/sda:crc_growth" and e["state"] == "resolved"]
        check("crc 458809->458810 = precies 1 alert", len(crc_alerts(1)) == 1, str(crc_alerts(1)))
        check("crc 458810->458810 = 0 alerts (geen reminders)",
              len(crc_alerts(2)) == 0 and len(crc_resolved) >= 1,
              f"{len(crc_alerts(2))}/{len(crc_resolved)}")
        check("crc 458810->458811 = nieuwe alert", len(crc_alerts(3)) == 1, str(crc_alerts(3)))
        check("crc 458811->458861 (+50) = urgent alert",
              len(crc_alerts(4)) == 1 and crc_alerts(4)[0]["severity"] == "urgent", str(crc_alerts(4)))
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
    # 14b: globale daglimiet blijft gelden na episode-reset (budget per episode
    # mag de dagcap niet omzeilen)
    final, calls_ = hr.analyze("dumbscope:mystery", source="dumbscope", severity="warning",
                               task="t", context=dsc, llm_cfg=llmcfg, api_key="test",
                               per_incident_calls=0, daily_calls=8, multi_system=False)
    check("budget 14b: daily-cap limiteert nog na episode-reset",
          final.get("status") == "skipped" and final.get("reason") == "llm_budget_exhausted:daily",
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
    analyze_budget_seen = []
    def fake_analyze(fp, **kw):
        analyze_calls["n"] += 1
        analyze_budget_seen.append(kw.get("per_incident_calls"))
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
        # budget per episode: resolve en reopen resetten llm_call_count
        con.execute("update incidents set llm_call_count=3, llm_context_hash=NULL"
                    " where fingerprint='dumbscope:mystery'")
        con.commit()
        incident_upsert(con, "dumbscope:mystery", source="dumbscope", itype="ds",
                        sev_level=0, value=0, reason="test: resolve")
        rowb = con.execute("select llm_call_count from incidents"
                           " where fingerprint='dumbscope:mystery'").fetchone()
        check("budget-episode 1: resolve reset llm_call_count", rowb == (0,), str(rowb))
        con.execute("update incidents set llm_call_count=3"
                    " where fingerprint='dumbscope:mystery'")
        con.commit()
        incident_upsert(con, "dumbscope:mystery", source="dumbscope", itype="ds",
                        sev_level=2, value=1, reason="test: reopen")
        rowb = con.execute("select llm_call_count from incidents"
                           " where fingerprint='dumbscope:mystery'").fetchone()
        check("budget-episode 2: reopen reset llm_call_count", rowb == (0,), str(rowb))
        n4b = analyze_calls["n"]
        s5 = run_llm_layer(llm_on, con, [])
        check("budget-episode 3: nieuwe episode analyseert met fris incident-budget",
              analyze_calls["n"] > n4b and analyze_budget_seen[-1] == 0,
              f"n={analyze_calls['n']}>{n4b}, per_incident={analyze_budget_seen[-1:] if analyze_budget_seen else 'geen'}")
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

    # ── replay-transities (notificatie-veiligheid) ──
    def eval_pending(series, minutes=5):
        """Één run_fast over N al aanwezige samples (replay) ->
        (pending_transitions, incidents, events)."""
        tmp = Path(tempfile.mkdtemp())
        (tmp / "homelab").mkdir(parents=True)
        old = (HOME, SAMPLES_DB, STATE_DB, EVENTS)
        globals().update(HOME=tmp, SAMPLES_DB=tmp / "homelab" / "samples.db",
                         STATE_DB=tmp / "homelab" / "agent_state.db",
                         EVENTS=tmp / "homelab" / "evaluator-events.jsonl")
        try:
            con = sqlite3.connect(SAMPLES_DB)
            con.executescript(SAMPLES_SCHEMA)
            now = int(datetime.now(timezone.utc).timestamp())
            n = max(len(v) for v in series.values())
            cols = ["ts"] + list(series.keys())
            for i in range(n):
                vals = [now - (n - 1 - i) * minutes * 60] + \
                       [s[i] if i < len(s) else s[-1] for s in series.values()]
                con.execute(f"insert into samples({','.join(cols)})"
                            f" values({','.join('?' for _ in cols)})", vals)
            con.commit(); con.close()
            evs = []
            con = state_db(); run_fast(cfg, evs); con.close()
            c2 = sqlite3.connect(STATE_DB)
            pend = c2.execute("select fingerprint, event_type, severity from pending_transitions"
                              " order by id").fetchall()
            incs = {fp: (st, sv) for fp, st, sv in c2.execute(
                "select fingerprint, state, current_severity from incidents")}
            c2.close()
            return pend, incs, evs
        finally:
            globals().update(HOME=old[0], SAMPLES_DB=old[1], STATE_DB=old[2], EVENTS=old[3])
            shutil.rmtree(tmp, ignore_errors=True)

    # A: normal → critical → resolved binnen één replay-run
    pend, incs, _ = eval_pending({"mem_used_pct": [97, 80, 80]})
    check("replay A: critical→resolved in één run -> critical-transitie bewaard",
          pend == [("host:memory:high", "new", "critical")], str(pend))
    check("replay A: eindstate resolved",
          incs.get("host:memory:high", ("",))[0] == "resolved", str(incs.get("host:memory:high")))
    # B: warning-escalatie binnen replay -> exact één transitie
    pend, _, _ = eval_pending({"mem_used_pct": [90, 90, 90]})
    check("replay B: notice-cap → warning-escalatie -> één transitie vastgelegd",
          pend == [("host:memory:high", "escalated", "warning")], str(pend))
    # D: critical → resolved → critical binnen één replay-run
    pend, incs, _ = eval_pending({"mem_used_pct": [97, 80, 80, 97]})
    check("replay D: critical→resolved→critical -> new + reopened vastgelegd",
          pend == [("host:memory:high", "new", "critical"),
                   ("host:memory:high", "reopened", "critical")], str(pend))
    check("replay D: eindstate active critical",
          incs.get("host:memory:high") == ("active", "critical"), str(incs.get("host:memory:high")))
    # gezonde reeks: geen transities, geen pending
    pend, _, _ = eval_pending({"mem_used_pct": [40, 41, 42]})
    check("replay healthy: geen pending-transities", pend == [], str(pend))

    # ── stale-resolve: state-incidenten sluiten bij gezonde waarde ──
    # (deze regels kijken per run naar de laatste sample -> scenario over
    #  opeenvolgende runs met gedeelde state-db)
    inc, _ = seq_eval({"containers_unhealthy": [3, 3, 0]}, minutes=5)
    check("stale 1: unhealthy 3→3→0 over runs -> incident resolved",
          inc.get("host:containers:unhealthy", ("missing", ""))[0] == "resolved",
          str(inc.get("host:containers:unhealthy")))
    inc, _ = seq_eval({"swap_used_kb": [300000, 0]}, minutes=5)
    check("stale 2: swap actief→0 over runs -> resolved",
          inc.get("host:swap:active", ("missing", ""))[0] == "resolved",
          str(inc.get("host:swap:active")))
    inc, _ = seq_eval({"containers_unhealthy": [3, 0, 0]}, minutes=5)
    check("stale 1b: na resolved geen her-open incident door blijvend 0",
          inc.get("host:containers:unhealthy", ("missing", ""))[0] == "resolved",
          str(inc.get("host:containers:unhealthy")))

    # stale-resolve: restart-delta 0 sluit het restart-incident (deep)
    rseq = [{"ok": True, "data": {"count": 1, "containers": [
        {"name": "plex", "state": "running", "health": "healthy", "restarts": rs,
         "started": "2026-01-01T00:00:00", "exit_code": 0, "mem_limit_bytes": 0}]}}
        for rs in (7, 10, 10)]
    tmp = Path(tempfile.mkdtemp()); (tmp / "homelab").mkdir(parents=True)
    old = (HOME, SAMPLES_DB, STATE_DB, EVENTS)
    globals().update(HOME=tmp, SAMPLES_DB=tmp / "none.db", STATE_DB=tmp / "homelab" / "agent_state.db",
                     EVENTS=tmp / "homelab" / "events.jsonl")
    fake, i = fake_ssh_factory(rseq, disk_health={"ok": True, "data": []},
                               docker_status=rseq)
    globals()["ssh_action"] = fake
    try:
        con = sqlite3.connect(SAMPLES_DB); con.close()
        for step in range(3):
            evs = []; con = state_db(); run_deep(cfg, evs); con.close()
            i["n"] = step + 1
        c2 = sqlite3.connect(STATE_DB)
        rrow = c2.execute("select state from incidents"
                          " where fingerprint='docker:plex:restarts'").fetchone()
        c2.close()
        check("stale 3: restart +3 -> incident; delta 0 -> resolved", rrow == ("resolved",), str(rrow))
    finally:
        globals()["ssh_action"] = real_ssh
        globals().update(HOME=old[0], SAMPLES_DB=old[1], STATE_DB=old[2], EVENTS=old[3])
        shutil.rmtree(tmp, ignore_errors=True)

    # docker_exited dedup: eerste waarneming = baseline (stil), emit alleen bij verandering
    def dstate(st):
        return {"ok": True, "data": {"count": 1, "containers": [
            {"name": "plex", "state": st, "health": "healthy", "restarts": 0,
             "started": "2026-01-01T00:00:00", "exit_code": 0, "mem_limit_bytes": 0}]}}
    eseq = [dstate("exited"), dstate("exited"), dstate("running"), dstate("exited")]
    tmp = Path(tempfile.mkdtemp()); (tmp / "homelab").mkdir(parents=True)
    old = (HOME, SAMPLES_DB, STATE_DB, EVENTS)
    globals().update(HOME=tmp, SAMPLES_DB=tmp / "none.db", STATE_DB=tmp / "homelab" / "agent_state.db",
                     EVENTS=tmp / "homelab" / "events.jsonl")
    fake, i = fake_ssh_factory(eseq, disk_health={"ok": True, "data": []},
                               docker_status=eseq)
    globals()["ssh_action"] = fake
    try:
        con = sqlite3.connect(SAMPLES_DB); con.close()
        all_exit_evs = []
        for step in range(4):
            evs = []; con = state_db(); run_deep(cfg, evs); con.close()
            all_exit_evs.extend(e for e in evs if e["check"] == "docker_exited")
            i["n"] = step + 1
        check("exited-dedup: baseline stil, alleen verandering -> 1 emit in 4 runs",
              len(all_exit_evs) == 1 and all_exit_evs[0]["current"] == "exited",
              str([(e["current"], e["ts"]) for e in all_exit_evs]))
    finally:
        globals()["ssh_action"] = real_ssh
        globals().update(HOME=old[0], SAMPLES_DB=old[1], STATE_DB=old[2], EVENTS=old[3])
        shutil.rmtree(tmp, ignore_errors=True)

    # ── fase 4 (§8): deploy/evaluator-locking ──
    import fcntl as _fcntl
    tmp = Path(tempfile.mkdtemp()); tmp.joinpath("homelab").mkdir(parents=True)
    old = (HOME, SAMPLES_DB, STATE_DB, EVENTS)
    globals().update(HOME=tmp, SAMPLES_DB=tmp / "none.db",
                     STATE_DB=tmp / "homelab" / "agent_state.db",
                     EVENTS=tmp / "homelab" / "events.jsonl")
    try:
        fd, why = acquire_deploy_lock(timeout_s=1, poll_s=1, path=tmp / "homelab" / "deploy.lock")
        check("lock 1: vrije deploy-lock -> LOCK_SH verkregen", fd is not None and why is None, str(why))
        if fd:
            _fcntl.flock(fd, _fcntl.LOCK_UN); fd.close()
        holder = open(tmp / "homelab" / "deploy.lock", "w")
        _fcntl.flock(holder, _fcntl.LOCK_EX | _fcntl.LOCK_NB)  # simuleert lopende deploy
        fd2, why2 = acquire_deploy_lock(timeout_s=1, poll_s=1, path=tmp / "homelab" / "deploy.lock")
        check("lock 2: bezette deploy-lock -> timeout, run overslaat (niet blokkeert)",
              fd2 is None and why2 is not None, str(why2))
        _fcntl.flock(holder, _fcntl.LOCK_UN); holder.close()
        fd3, why3 = acquire_deploy_lock(timeout_s=1, poll_s=1, path=tmp / "homelab" / "deploy.lock")
        check("lock 3: na einde deploy -> lock weer verkrijgbaar",
              fd3 is not None, str(why3))
        if fd3:
            _fcntl.flock(fd3, _fcntl.LOCK_UN); fd3.close()
    finally:
        globals().update(HOME=old[0], SAMPLES_DB=old[1], STATE_DB=old[2], EVENTS=old[3])
        shutil.rmtree(tmp, ignore_errors=True)

    # ── fase 4: change-ledger in de fast-run (deploy-events + occurrence-log) ──
    tmp = Path(tempfile.mkdtemp()); tmp.joinpath("homelab").mkdir(parents=True)
    old = (HOME, SAMPLES_DB, STATE_DB, EVENTS)
    globals().update(HOME=tmp, SAMPLES_DB=tmp / "homelab" / "samples.db",
                     STATE_DB=tmp / "homelab" / "agent_state.db",
                     EVENTS=tmp / "homelab" / "evaluator-events.jsonl")
    try:
        con = sqlite3.connect(SAMPLES_DB)
        con.executescript(SAMPLES_SCHEMA)
        now = int(datetime.now(timezone.utc).timestamp())
        for i in range(3):
            con.execute("insert into samples(ts, mem_used_pct, oom_kills) values(?,?,?)",
                        (now - (3 - i) * 300, 40, 2))
        con.commit(); con.close()
        (tmp / "homelab" / "changes-deploy.jsonl").write_text(
            json.dumps({"ts": now_iso(), "kind": "deploy", "key": "hermes",
                        "detail": "regressietest"}) + "\n")
        con = state_db()
        evs = []
        run_fast(cfg, evs)
        n_changes = con.execute("select count(*) from changes").fetchone()[0]
        con.close()
        c2 = sqlite3.connect(STATE_DB)
        led = c2.execute("select kind, key from changes").fetchall()
        c2.close()
        check("changes 1: fast-run leest deploy-events in de ledger",
              led == [("deploy", "hermes")], str(led))
        # occurrence-log: warning-transitie vastgelegd door incident_upsert
        tmp2 = Path(tempfile.mkdtemp()); tmp2.joinpath("homelab").mkdir(parents=True)
        globals().update(SAMPLES_DB=tmp2 / "homelab" / "samples.db",
                         STATE_DB=tmp2 / "homelab" / "agent_state.db",
                         EVENTS=tmp2 / "homelab" / "events.jsonl")
        scon = sqlite3.connect(SAMPLES_DB)
        scon.executescript(SAMPLES_SCHEMA)
        for i in range(3):
            scon.execute("insert into samples(ts, mem_used_pct) values(?,?)",
                         (now - (3 - i) * 300, 95))
        scon.commit(); scon.close()
        con = state_db()
        evs = []
        run_fast(cfg, evs)
        rows = con.execute("select fingerprint, count(*) from occurrence_log"
                           " group by fingerprint").fetchall()
        con.close()
        check("changes 2: warning-transitie -> occurrence_log gevuld",
              rows and rows[0][0] == "host:memory:high" and rows[0][1] >= 1, str(rows))
    finally:
        globals().update(HOME=old[0], SAMPLES_DB=old[1], STATE_DB=old[2], EVENTS=old[3])
        shutil.rmtree(tmp, ignore_errors=True)
        shutil.rmtree(tmp2, ignore_errors=True)

    # ── fase 7: infinidysk per-bestand repair-loop-detectie ──────────────────
    import hermes_infinidysk as _hi
    from zoneinfo import ZoneInfo
    T = int(datetime.now(timezone.utc).timestamp())

    def inf_line(ts, s):
        dt = datetime.fromtimestamp(ts, ZoneInfo("Europe/Amsterdam"))
        mon = [k for k, v in _hi.MONTHS.items() if v == dt.month][0]
        pre = (f"{mon} {dt.day:02d}, {dt.year} {dt.strftime('%H:%M:%S')} - INFO"
               f" - InfiniDysk subprocess: [{dt.strftime('%H:%M:%S')} INF] ")
        return pre + s

    def inf_rep(ts, path):
        return inf_line(ts, f"Health check classified {path} as failed: 100"
                            f" missing/corrupt segment(s) Starting repair.")

    def inf_new(now_ts):
        tmp = Path(tempfile.mkdtemp()); tmp.joinpath("homelab").mkdir(parents=True)
        old = (HOME, SAMPLES_DB, STATE_DB, EVENTS)
        globals().update(HOME=tmp, SAMPLES_DB=tmp / "homelab" / "samples.db",
                         STATE_DB=tmp / "homelab" / "agent_state.db",
                         EVENTS=tmp / "homelab" / "evaluator-events.jsonl")
        return {"tmp": tmp, "old": old, "log": tmp / "infinidysk.log", "now": now_ts}

    def inf_run(state, lines=(), now_ts=None):
        with state["log"].open("a") as f:
            for l in lines:
                f.write(l + "\n")
        con = state_db()
        evs = []
        icfg = {"infinidysk": {"log_path": str(state["log"]),
                               "warning_count": 5, "urgent_count": 10,
                               "window_minutes": 60, "resolve_after_minutes": 120},
                "defaults": {}}
        run_infinidysk(icfg, con, evs, mode="fast", now=now_ts or state["now"])
        con.close()
        c2 = sqlite3.connect(STATE_DB)
        inc = {fp: (stt, sev) for fp, stt, sev in c2.execute(
            "select fingerprint, state, current_severity from incidents"
            " where fingerprint like 'infinidysk:%'")}
        pend = c2.execute("select count(*) from pending_transitions where"
                          " fingerprint like 'infinidysk:%'").fetchone()[0]
        c2.close()
        return inc, evs, pend

    def inf_close(state):
        globals().update(HOME=state["old"][0], SAMPLES_DB=state["old"][1],
                         STATE_DB=state["old"][2], EVENTS=state["old"][3])
        shutil.rmtree(state["tmp"], ignore_errors=True)

    RAW_A = "/content/tv/Release.One.2026.S01E01/File.One.mkv"
    RAW_B = "/content/tv/Release.Two.2026.S01E01/File.Two.mkv"
    RAW_C = "/content/tv/Release.Three.2026.S01E01/File.Three.mkv"
    RAW_D = "/content/tv/Release.Four.2026.S01E01/File.Four.mkv"
    RAW_E = "/content/tv/Release.Old.2026.S01E01/File.Old.mkv"
    FP_A = "infinidysk:repair_loop:" + _hi.fingerprint(_hi.normalize_path(RAW_A))

    st1 = inf_new(T)
    try:
        inc, evs, pend = inf_run(st1)  # seed-run op leeg log
        check("INF 0: seed-run op leeg log -> 0 events, 0 incidenten, 0 pending",
              not evs and not inc and pend == 0, str((len(evs), inc, pend)))
        # Test 2: 5 repairs/60min -> warning (+ pending_transition)
        inc, evs, pend = inf_run(st1, [inf_rep(T - i * 300, RAW_A)
                                       for i in range(5)])
        check("INF 2: 5 repairs/60min -> warning-incident + pending",
              inc.get(FP_A, ("", ""))[1] == "warning" and pend >= 1,
              str((inc.get(FP_A), pend)))
        # Test 1: 4 repairs/60min -> GEEN warning (notice, geen pending)
        inc, evs, pend = inf_run(st1, [inf_rep(T - i * 300, RAW_B)
                                       for i in range(4)])
        check("INF 1: 4 repairs/60min -> geen warning-incident",
              inc.get("infinidysk:repair_loop:" +
                      _hi.fingerprint(_hi.normalize_path(RAW_B)),
                      ("", ""))[1] != "warning",
              str(inc))
        # Test 3: 10 repairs/60min -> urgent/escalatie
        fp_c = "infinidysk:repair_loop:" + _hi.fingerprint(
            _hi.normalize_path(RAW_C))
        inc, evs, pend = inf_run(st1, [inf_rep(T - i * 120, RAW_C)
                                       for i in range(10)])
        check("INF 3: 10 repairs/60min -> urgent",
              inc.get(fp_c, ("", ""))[1] == "urgent", str(inc.get(fp_c)))
        # Test 4: licht verschillend pad -> zelfde fingerprint (merge)
        inc, evs, pend = inf_run(st1, [
            inf_rep(T - 60, "/content/sonarr-default/release.one.2026.s01e01/file.one.mkv"),
            inf_rep(T - 30, "/content/tv/Release.One.2026.S01E01 (2)/File.One.mkv")])
        n_a = sqlite3.connect(STATE_DB).execute(
            "select count(*) from infinidysk_repairs where fingerprint=?",
            (FP_A,)).fetchone()[0]
        check("INF 4: padvariaties -> zelfde fingerprint, telling gemerged",
              n_a == 7 and inc.get(FP_A, ("", ""))[1] == "warning",
              str((n_a, inc.get(FP_A))))
        # Test 5: verschillende files -> afzonderlijke incidenten
        check("INF 5: aparte bestanden -> aparte incidenten",
              len(inc) == 3 and all(v[0] == "active" for v in inc.values()),
              str(inc))
        # Test 8: duplicate ingest -> niet dubbel tellen
        dup = inf_rep(T - 120, RAW_A)
        inc, evs, pend2 = inf_run(st1, [dup, dup])
        n_a2 = sqlite3.connect(STATE_DB).execute(
            "select count(*) from infinidysk_repairs where fingerprint=?",
            (FP_A,)).fetchone()[0]
        check("INF 8: exact dubbele regels -> 1 extra telling, geen extra pending",
              n_a2 == 8 and pend2 == pend, str((n_a2, pend, pend2)))
        # Test 6: repair buiten rolling window (90 min oud) -> notice, open
        inc, evs, pend = inf_run(st1, [inf_rep(T - 90 * 60, RAW_D)])
        fp_d = "infinidysk:repair_loop:" + _hi.fingerprint(
            _hi.normalize_path(RAW_D))
        check("INF 6: repair buiten 60min-window -> geen warning, wel open",
              inc.get(fp_d, ("", ""))[1] == "notice", str(inc.get(fp_d)))
        # Test 7: 2 uur geen repairs -> resolved
        inc, evs, pend = inf_run(st1, now_ts=T + 131 * 60)
        check("INF 7: >2h zonder repairs -> resolved",
              inc.get(fp_d, ("", ""))[0] == "resolved", str(inc.get(fp_d)))
    finally:
        inf_close(st1)

    # Test 9: gezonde run -> 0 events, 0 pending, 0 LLM-route
    st2 = inf_new(T)
    try:
        fp_e = "infinidysk:repair_loop:" + _hi.fingerprint(
            _hi.normalize_path(RAW_E))
        inc, evs, pend = inf_run(st2, [
            inf_rep(T - 3 * 3600, RAW_E),
            inf_line(T - 3 * 3600 + 60,
                     f"PAR2 repair error for {RAW_E} Reason: Article with"
                     f" message-id x@y not found. Server responded: 430 No"
                     f" such article")])
        check("INF 9: gezonde run (alleen oude repairs) -> 0 events, 0 pending",
              not evs and pend == 0 and not inc, str((len(evs), inc, pend)))
        con = state_db()
        route, why = needs_llm_analysis(con, fp_e, "warning", "active")
        con.close()
        check("INF 9b: 430/dode-artikelen-reden -> Tier-0 LLM-skip",
              route is False and "skip:" in why, f"{route} {why}")
    finally:
        inf_close(st2)

    # ------------------------------------------------------------------
    # Netdata-alarminput (fase 8): client gemockt — tests doen nooit live
    # HTTP naar Netdata. Eén poll = één run_fast; alarm-set per poll.
    import hermes_netdata as hn

    class _FakeNd:
        def __init__(self, polls):
            self.polls = list(polls)
            self.i = 0

        def active_alarms(self):
            p = self.polls[self.i] if self.i < len(self.polls) else []
            self.i += 1
            if p == "FAIL":
                raise hn.NetdataError("unavailable", None, "test-timeout")
            return p

    def nd_raw(name, chart, status, value, info="test"):
        return {"id": 1, "name": name, "chart": chart, "status": status,
                "value": value, "info": info, "last_status_change": 1790208000,
                "active": True, "disabled": False, "silenced": False}

    def nd_run(polls, samples):
        tmp = Path(tempfile.mkdtemp())
        (tmp / "homelab").mkdir(parents=True)
        con = sqlite3.connect(tmp / "homelab" / "samples.db")
        con.executescript(SAMPLES_SCHEMA)
        n_ = max(len(v) for v in samples.values())
        now = int(datetime.now(timezone.utc).timestamp())
        cols = ["ts"] + list(samples.keys())
        for i in range(n_):
            vals = [now - (n_ - i) * 300]
            for seq in samples.values():
                vals.append(seq[i] if i < len(seq) else seq[-1])
            con.execute(f"insert into samples({','.join(cols)})"
                        f" values({','.join('?' for _ in cols)})", vals)
        con.commit(); con.close()
        fake = _FakeNd(polls)
        old_make = hn.make_client
        hn.make_client = lambda cfg_: fake
        old = (HOME, SAMPLES_DB, STATE_DB, EVENTS)
        globals().update(HOME=tmp, SAMPLES_DB=tmp / "homelab" / "samples.db",
                         STATE_DB=tmp / "homelab" / "agent_state.db",
                         EVENTS=tmp / "homelab" / "evaluator-events.jsonl")
        inc, evs, pend = {}, [], []
        summaries = []
        try:
            con = state_db()
            for _ in polls:
                evs_run = []
                summaries.append(run_fast(cfg, evs_run))
                evs += evs_run
            con.close()
            c2 = sqlite3.connect(STATE_DB)
            for fp, state, sev in c2.execute(
                    "select fingerprint, state, current_severity from incidents"):
                inc[fp] = (state, sev)
            pend = [tuple(r) for r in c2.execute(
                "select fingerprint, event_type, severity from pending_transitions order by id")]
            c2.close()
            return inc, evs, pend, summaries
        finally:
            globals().update(HOME=old[0], SAMPLES_DB=old[1], STATE_DB=old[2], EVENTS=old[3])
            hn.make_client = old_make
            shutil.rmtree(tmp, ignore_errors=True)

    # ND 1: allowlist/normalisatie (pure functies, geen state)
    check("ND1a: ephemeral container (UNDEFINED-status) -> genegeerd (ruisfilter)",
          hn.normalize(nd_raw("docker_container_unhealthy",
                              "docker_local.container_x_health_status",
                              "UNDEFINED", 0)) is None)
    n_dumb = hn.normalize(nd_raw("docker_container_unhealthy",
                                 "docker_local.container_DUMB_health_status",
                                 "WARNING", 0.8))
    check("ND1b: DUMB container health -> netdata:container:DUMB warning",
          bool(n_dumb) and n_dumb["fingerprint"] == "netdata:container:DUMB"
          and n_dumb["severity"] == "warning", str(n_dumb))
    check("ND1c: alarm buiten allowlist -> genegeerd (nooit blind doorsturen)",
          hn.normalize(nd_raw("some_random_alarm", "system.ips", "CRITICAL", 5)) is None)
    check("ND1d: cgroup-alarm buiten scope (VM/container-ruis)",
          hn.normalize(nd_raw("cgroup_ram_in_use",
                              "cgroup_qemu_qemu_5.mem_usage", "WARNING", 80)) is None)

    # ND 2: netdata warning + hermes normal (covered) -> evidence-only
    inc, evs, pend, nd_sum = nd_run(
        [[], [nd_raw("ram_in_use", "system.ram", "WARNING", 91.0, "ram")]],
        {"mem_used_pct": [60, 61, 62]})
    check("ND2a: netdata RAM warning + hermes normaal -> GEEN netdata-incident",
          "netdata:memory:ram_in_use" not in inc and "host:memory:high" not in inc, str(inc))
    check("ND2b: covered warning -> geen pending transitions (geen Telegram)",
          pend == [], str(pend))
    check("ND2c: covered warning -> evidence-event vastgelegd",
          any(e["fingerprint"] == "netdata:memory:ram_in_use"
              and e.get("dedup") == "covered_evidence_only" for e in evs), str(len(evs)))

    # ND 3: netdata critical + bevestigende hermes-metric -> escalatie hermes-fp
    inc, evs, pend, nd_sum = nd_run(
        [[], [nd_raw("ram_in_use", "system.ram", "CRITICAL", 97.0, "ram")]],
        {"mem_used_pct": [92, 92, 92]})
    check("ND3a: netdata critical + hermes 92 (>=warn) -> host:memory:high critical",
          inc.get("host:memory:high") == ("active", "critical"),
          str(inc.get("host:memory:high")))
    check("ND3b: confirm -> pending op hermes-fp, GEEN netdata-duplicaat",
          any(p[0] == "host:memory:high" and p[1] == "escalated" and p[2] == "critical"
              for p in pend)
          and not any(p[0].startswith("netdata:") for p in pend), str(pend))

    # ND 4: duplicate alarm (tweede identieke poll)
    LOAD_W = nd_raw("load_average_15", "system.load", "WARNING", 40.0, "load")
    inc, evs, pend, nd_sum = nd_run([[], [LOAD_W], [dict(LOAD_W)]], {"mem_used_pct": [40]})
    check("ND4: duplicate identiek alarm -> 1 episode, 1 pending, 1 alert-event",
          inc.get("netdata:load:load_average_15") == ("active", "warning")
          and len([p for p in pend if p[0] == "netdata:load:load_average_15"]) == 1
          and len([e for e in evs if e["fingerprint"] == "netdata:load:load_average_15"
                   and e.get("state") == "active"]) == 1, str(pend))

    # ND 5: recovery (alarm verdwijnt uit active-set na geslaagde poll)
    inc, evs, pend, nd_sum = nd_run([[], [LOAD_W], []], {"mem_used_pct": [40]})
    check("ND5a: recovery: alarm verdwenen -> incident resolved",
          inc.get("netdata:load:load_average_15", ("", ""))[0] == "resolved",
          str(inc.get("netdata:load:load_average_15")))
    check("ND5b: recovery -> resolved-event, geen RECOVERY-pending (notifier doet herstel)",
          any(e["fingerprint"] == "netdata:load:load_average_15"
              and e.get("state") == "resolved" for e in evs)
          and not any(p[0] == "netdata:load:load_average_15" and p[1] != "new"
                      for p in pend), str(pend))

    # ND 6: stale alarm (blijft onveranderd actief) -> geen reminders
    inc, evs, pend, nd_sum = nd_run([[], [LOAD_W], [dict(LOAD_W)], [dict(LOAD_W)], [dict(LOAD_W)]],
                            {"mem_used_pct": [40]})
    check("ND6: stale onveranderd alarm x4 -> nog steeds 1 pending, incident intact",
          inc.get("netdata:load:load_average_15") == ("active", "warning")
          and len([p for p in pend if p[0] == "netdata:load:load_average_15"]) == 1, str(pend))

    # ND 7: netdata tijdelijk onbereikbaar
    inc, evs, pend, nd_sum = nd_run([[], "FAIL", "FAIL", "FAIL"], {"mem_used_pct": [40]})
    check("ND7a: 3 mislukte polls -> availability-warning + pending",
          inc.get("netdata:availability") == ("active", "warning")
          and any(p[0] == "netdata:availability" and p[1] == "new" for p in pend),
          str((inc.get("netdata:availability"),
               [(e.get("check"), e.get("fingerprint"), e.get("reason")) for e in evs
                if "netdata" in str(e.get("fingerprint", ""))],
               [s.get("sev_netdata") for s in nd_sum], pend)))
    check("ND7b: mislukte polls raken alarm-state niet (geen valse incidents)",
          "netdata:load:load_average_15" not in inc, str(inc))
    inc, evs, pend, nd_sum = nd_run([[], [LOAD_W], "FAIL"], {"mem_used_pct": [40]})
    check("ND7c: poll mislukt ná actief alarm -> incident blijft actief",
          inc.get("netdata:load:load_average_15") == ("active", "warning"),
          str(inc.get("netdata:load:load_average_15")))

    # ------------------------------------------------------------------
    # DUMBscope centrale incident-routing (fase 9): poll-resultaten gemockt
    # via de echte normalisatie (hermes_dumbscope.normalize_incident).
    class _FakeDs:
        def __init__(self, polls):
            self.polls = list(polls)
            self.i = 0

        def poll(self, resolved_limit=20):
            p = self.polls[self.i] if self.i < len(self.polls) else []
            self.i += 1
            if p == "FAIL":
                raise _hd.DumbScopeError("unavailable", None, "test-timeout")
            return {"ok": True, "health": {"dumb": "up"}, "incidents": list(p),
                    "metrics": {"active_count": len(p), "payload_bytes": 1,
                                "runtime_s": 0.0}}

    def ds_inc(fp_suffix, severity="warning", status="active", occurrences=1,
               title="Decypharr debrid mount: degraded", affected=None):
        return _hd.normalize_incident({
            "id": "src-" + fp_suffix, "fingerprint": "mount:" + fp_suffix,
            "severity": severity, "status": status, "title": title,
            "firstSeen": 1790200000000, "lastSeen": 1790208000000 + occurrences,
            "resolvedAt": None, "occurrences": occurrences,
            "affectedServices": affected or [], "rootCauseService": None,
            "summary": "test", "evidence": []})

    def ds_run(ds_polls, nd_polls=None):
        tmp = Path(tempfile.mkdtemp())
        (tmp / "homelab").mkdir(parents=True)
        con = sqlite3.connect(tmp / "homelab" / "samples.db")
        con.executescript(SAMPLES_SCHEMA)
        con.execute("insert into samples(ts, sampler_ver, mem_used_pct) values(?,?,?)",
                    (int(datetime.now(timezone.utc).timestamp()) - 120, 1, 40))
        con.commit(); con.close()
        fnd = _NoNd() if nd_polls is None else _FakeNd(nd_polls)
        fds = _FakeDs(ds_polls)
        old_ds, old_nd = globals()["make_client"], _hn.make_client
        globals()["make_client"] = lambda cfg_: fds
        _hn.make_client = lambda cfg_: fnd
        old = (HOME, SAMPLES_DB, STATE_DB, EVENTS)
        globals().update(HOME=tmp, SAMPLES_DB=tmp / "homelab" / "samples.db",
                         STATE_DB=tmp / "homelab" / "agent_state.db",
                         EVENTS=tmp / "homelab" / "evaluator-events.jsonl")
        inc, evs, pend = {}, [], []
        try:
            con = state_db()
            for _ in ds_polls:
                evs_run = []
                run_fast(cfg, evs_run)
                evs += evs_run
            con.close()
            c2 = sqlite3.connect(STATE_DB)
            for fp, state, sev in c2.execute(
                    "select fingerprint, state, current_severity from incidents"):
                inc[fp] = (state, sev)
            pend = [tuple(r) for r in c2.execute(
                "select fingerprint, event_type, severity from pending_transitions order by id")]
            c2.close()
            return inc, evs, pend
        finally:
            globals().update(HOME=old[0], SAMPLES_DB=old[1], STATE_DB=old[2], EVENTS=old[3])
            globals()["make_client"] = old_ds
            _hn.make_client = old_nd
            shutil.rmtree(tmp, ignore_errors=True)

    FPS = "dumbscope:mount:a1"
    inc, evs, pend = ds_run([[], [ds_inc("a1")]])
    check("DS1: nieuw DUMBscope-warning -> centraal incident + pending",
          inc.get(FPS) == ("active", "warning")
          and any(p[0] == FPS and p[1] == "new" and p[2] == "warning" for p in pend)
          and len([p for p in pend if p[0] == FPS]) == 1, str((inc.get(FPS), pend)))
    inc, evs, pend = ds_run([[], [ds_inc("c1", severity="critical")]])
    check("DS2: nieuw DUMBscope-critical -> centraal critical + pending",
          inc.get("dumbscope:mount:c1") == ("active", "critical")
          and any(p[0] == "dumbscope:mount:c1" and p[1] == "new"
                  and p[2] == "critical" for p in pend), str((inc.get("dumbscope:mount:c1"), pend)))
    inc, evs, pend = ds_run([[], [ds_inc("a1")],
                              [ds_inc("a1", severity="critical", occurrences=2)]])
    check("DS3: escalatie warning->critical -> escalated pending, geen duplicaat",
          inc.get(FPS) == ("active", "critical")
          and any(p[0] == FPS and p[1] == "escalated" and p[2] == "critical" for p in pend)
          and len([p for p in pend if p[0] == FPS]) == 2, str((inc.get(FPS), pend)))
    inc, evs, pend = ds_run([[], [ds_inc("a1")], [ds_inc("a1", occurrences=2)]])
    check("DS4: duplicate (occurrences-only) -> geen nieuwe pending",
          inc.get(FPS) == ("active", "warning")
          and len([p for p in pend if p[0] == FPS]) == 1, str(pend))
    inc, evs, pend = ds_run([[], [ds_inc("a1")],
                             [ds_inc("a1", status="resolved", occurrences=2)]])
    check("DS5: recovery -> centraal resolved, resolved-event, geen recovery-pending",
          inc.get(FPS, ("", ""))[0] == "resolved"
          and any(e["fingerprint"] == FPS and e.get("state") == "resolved" for e in evs)
          and len([p for p in pend if p[0] == FPS]) == 1, str((inc.get(FPS), pend)))
    inc, evs, pend = ds_run([[], [ds_inc("a1")],
                             [ds_inc("a1", status="resolved", occurrences=2)],
                             [ds_inc("a1", occurrences=3)]])
    check("DS6: heropen na recovery -> reopened pending",
          inc.get(FPS) == ("active", "warning")
          and any(p[0] == FPS and p[1] == "reopened" for p in pend), str(pend))
    inc, evs, pend = ds_run(
        [[], [ds_inc("a1", affected=["DUMB"])],
         [ds_inc("a1", affected=["DUMB"], occurrences=2)]],
        nd_polls=[[], [],
                  [nd_raw("docker_container_unhealthy",
                          "docker_local.container_DUMB_health_status", "WARNING", 1.0)]])
    check("DS7: netdata container-health + actief DUMBscope-incident -> evidence-only, 1 keten",
          "netdata:container:DUMB" not in inc
          and any(e["fingerprint"] == "netdata:container:DUMB"
                  and e.get("dedup") == "covered_evidence_only" for e in evs)
          and not any(p[0].startswith("netdata:") for p in pend), str(pend))

    # ------------------------------------------------------------------
    # Sampler-gap (fase 9): leeftijd van de laatste host-sample aan te sturen
    # per poll (minuten); "NO_DB" = samples.db onleesbaar/afwezig.
    def gap_run(seq):
        tmp = Path(tempfile.mkdtemp())
        (tmp / "homelab").mkdir(parents=True)
        old_ds, old_nd = globals()["make_client"], _hn.make_client
        globals()["make_client"] = lambda cfg_: _NoDs()
        _hn.make_client = lambda cfg_: _NoNd()
        old = (HOME, SAMPLES_DB, STATE_DB, EVENTS)
        globals().update(HOME=tmp, SAMPLES_DB=tmp / "homelab" / "samples.db",
                         STATE_DB=tmp / "homelab" / "agent_state.db",
                         EVENTS=tmp / "homelab" / "evaluator-events.jsonl")
        inc, evs, pend = {}, [], []
        try:
            con = state_db()
            for item in seq:
                spath = tmp / "homelab" / "samples.db"
                for suf in ("", "-wal", "-shm"):
                    pp = Path(str(spath) + suf)
                    if pp.exists():
                        pp.unlink()
                if item != "NO_DB":
                    sc = sqlite3.connect(spath)
                    sc.executescript(SAMPLES_SCHEMA)
                    ts = int(datetime.now(timezone.utc).timestamp()) - int(item * 60)
                    sc.execute("insert into samples(ts, sampler_ver, mem_used_pct)"
                               " values(?,?,?)", (ts, 1, 40))
                    sc.commit(); sc.close()
                evs_run = []
                run_fast(cfg, evs_run)
                evs += evs_run
            con.close()
            c2 = sqlite3.connect(STATE_DB)
            for fp, state, sev in c2.execute(
                    "select fingerprint, state, current_severity from incidents"):
                inc[fp] = (state, sev)
            pend = [tuple(r) for r in c2.execute(
                "select fingerprint, event_type, severity from pending_transitions order by id")]
            c2.close()
            return inc, evs, pend
        finally:
            globals().update(HOME=old[0], SAMPLES_DB=old[1], STATE_DB=old[2], EVENTS=old[3])
            globals()["make_client"] = old_ds
            _hn.make_client = old_nd
            shutil.rmtree(tmp, ignore_errors=True)

    SFP = "hermes:sampler:stale"
    inc, evs, pend = gap_run([5])
    check("GAP1: sample 5 min oud -> normal, geen incident",
          SFP not in inc, str(inc.get(SFP)))
    inc, evs, pend = gap_run([15])
    check("GAP2: sample 15 min oud -> warning + pending",
          inc.get(SFP) == ("active", "warning")
          and any(p[0] == SFP and p[1] == "new" and p[2] == "warning" for p in pend),
          str((inc.get(SFP), pend)))
    inc, evs, pend = gap_run([15, 45])
    check("GAP3: 15 -> 45 min -> escalatie naar urgent",
          inc.get(SFP) == ("active", "urgent")
          and any(p[0] == SFP and p[1] == "escalated" and p[2] == "urgent" for p in pend),
          str((inc.get(SFP), pend)))
    inc, evs, pend = gap_run([15, 45, 46])
    check("GAP4: meerdere stale polls -> geen duplicate pending",
          inc.get(SFP) == ("active", "urgent")
          and len([p for p in pend if p[0] == SFP]) == 2, str(pend))
    inc, evs, pend = gap_run([15, 3])
    check("GAP5: sampler hervat -> precies een recovery, geen recovery-pending",
          inc.get(SFP, ("", ""))[0] == "resolved"
          and any(e["fingerprint"] == SFP and e.get("state") == "resolved" for e in evs)
          and len([p for p in pend if p[0] == SFP]) == 1, str((inc.get(SFP), pend)))
    inc, evs, pend = gap_run([15, "NO_DB"])
    check("GAP6a: DB/read-failure -> geen valse recovery",
          inc.get(SFP) == ("active", "warning")
          and not any(e["fingerprint"] == SFP and e.get("state") == "resolved"
                      for e in evs), str(inc.get(SFP)))
    inc, evs, pend = gap_run([15, "NO_DB", 46])
    check("GAP6b: DB-failure tussen stale polls -> incident blijft bestaan",
          inc.get(SFP) == ("active", "urgent"), str(inc.get(SFP)))

    fails = [r for r in results if not r[1]]
    for name, okk, detail in results:
        print(f"{'PASS' if okk else 'FAIL'}  {name}" + (f"  [{detail}]" if detail and not okk else ""))
    print(f"\n{len(results) - len(fails)}/{len(results)} geslaagd")
    return 0 if not fails else 1

# --------------------------------------------------------------------- main --
def acquire_deploy_lock(timeout_s=90, poll_s=5, path=None):
    """Fase 4 (§8): gedeelde (LOCK_SH) deploy-lock. Een evaluator-run start
    niet tijdens een multi-file deploy; deploy.sh houdt LOCK_EX tijdens de
    vervanging. Bounded wait: na timeout -> (None, reden) zodat cron hooguit
    één run overslaat, nooit permanent blokkeert. Volgorde evaluator.lock ->
    deploy.lock is overal gelijk; deploy neemt alleen deploy.lock -> geen
    deadlock-cyclus mogelijk."""
    import fcntl, time
    fd = open(Path(path) if path else HL / "deploy.lock", "w")
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
            return fd, None
        except OSError:
            if time.monotonic() >= deadline:
                fd.close()
                return None, "deploy bezig (deploy.lock)"
            time.sleep(poll_s)


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
    dlock, why = acquire_deploy_lock()
    if dlock is None:
        print(f"evaluator: {why}; run overgeslagen")
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
