#!/usr/bin/env python3
"""hermes_changes.py — fase 4: goedkope, deterministische change-correlation
en recurrentie-detectie.

Doel: bij een nieuw/escalated/reopened incident relevante recente veranderingen
kunnen vermelden ("Recent: DUMB (her)gestart 18 min vóór incident") en simpele
terugkerende patronen herkennen ("Pattern: ... 4x in 7 dagen, tussen 01:20–02:40").
Hypotheses/context, GEEN causaliteit: een "root cause"-claim wordt hier
expliciet niet gemaakt.

Kostenmodel (§6):
  - gezonde runs: 0 LLM-calls, 0 netwerk, geen log-searches; de ledger wordt
    alleen beschreven bij een werkelijke verandering;
  - correlation/recurrence draait uitsluitend in het notificatie-/analysepad
    (candidate + build_context), nooit op gezonde samples;
  - hard begrensd: max max_items correlation-items, dedup per key, compacte
    tekstregels.

Bronnen (allemaal lokaal/read-only):
  - deep evaluator: container started-timestamps + state-overgangen
    (docker-status), array resync-start;
  - deploy.sh: changes-deploy.jsonl (één regel per echte deploy/rollback),
    door de fast evaluator ingelezen met een byte-offset cursor;
  - occurrence_log: bij new/escalated/reopened-transities geschreven door
    incident_upsert (fase-4 bron voor patronen, begrensd op 30 dagen).

Deterministisch: geen ML/LLM, geen nieuwe databases — uitsluitend tabellen in
de bestaande agent_state.db.
"""
import json, os, sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

HOME = Path(os.environ.get("HERMES_HOME", "/opt/data"))

DEFAULTS = {
    "enabled": True,
    "window_hours": 2,
    "max_items": 5,
    "occurrence_days": 7,
    "occurrence_min": 3,       # minder occurrences -> nooit een patroonclaim
    "cluster_minutes": 150,    # venster waarin occurrences "zelfde tijdstip" zijn
    "max_changes_rows": 4000,  # harde cap op de ledger
    "occurrence_retention_days": 30,
}

CHANGES_SCHEMA = ("create table if not exists changes("
                  "kind text, key text, ts text, detail text,"
                  " primary key(kind, key, ts));")
OCC_SCHEMA = ("create table if not exists occurrence_log("
              "fingerprint text, ts text, severity text,"
              " primary key(fingerprint, ts));")
OCC_INDEX = ("create index if not exists idx_occurrence_fp"
             " on occurrence_log(fingerprint, ts);")

# priority bij dedup: zelfde key in meerdere kinds -> informatiefste wint
KIND_RANK = {"deploy": 3, "container_started": 2, "array_resync": 2,
             "container_state": 1, "restart_delta": 0}
KIND_LABEL = {
    "container_started": "{key} (her)gestart",
    "container_state": "{key} {detail}",
    "restart_delta": "{key} +{detail} restarts",
    "deploy": "Hermes deploy",
    "array_resync": "parity/resync gestart",
}

DEPLOY_LOG = "changes-deploy.jsonl"
DEPLOY_CURSOR = "changes:deploy_offset"


def load_cfg(home=None):
    """correlation-sectie uit thresholds.yaml (mini-yaml van de evaluator)."""
    from hermes_evaluator import mini_yaml
    p = (home or HOME) / "thresholds.yaml"
    raw = mini_yaml(p.read_text()).get("correlation", {}) if p.exists() else {}

    def merge(base, over):
        out = dict(base)
        for k, v in (over or {}).items():
            out[k] = merge(base[k], v) if isinstance(v, dict) and isinstance(base.get(k), dict) else v
        return out
    return merge(DEFAULTS, raw)


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ------------------------------------------------------------------ ledger --
def record_change(c, kind, key, ts, detail=""):
    """Eén change-event. Idempotent op (kind, key, ts). Maakt de tabel zelf
    aan zodat ook kleinere test-databases dit aan kunnen."""
    c.execute(CHANGES_SCHEMA)
    c.execute("insert or ignore into changes(kind, key, ts, detail)"
              " values(?,?,?,?)", (kind, str(key), ts, str(detail or "")))


def bounded_cleanup(c, max_rows=None):
    """Ledger hard begrensd houden (§6). Eén call per deep-run, niet per rij."""
    c.execute(CHANGES_SCHEMA)
    n = int(max_rows or DEFAULTS["max_changes_rows"])
    c.execute("delete from changes where rowid not in"
              " (select rowid from changes order by ts desc limit ?)", (n,))


def record_container_observation(c, name, state, started, ts):
    """Per deep-run per container: vergelijk started/state met de vorige
    waarneming (cursors). Alleen bij verandering een change-row. Een nieuwe
    started-timestamp = (her)start; state-overgang = state-change. De allereerste
    waarneming is baseline (stil)."""
    c.execute(CHANGES_SCHEMA)
    prev = {}
    for cur_name, col in (("docker_started:", "started"), ("docker_state:", "state")):
        r = c.execute("select value from cursors where name=?", (cur_name + name,)).fetchone()
        prev[col] = r[0] if r else None
    changed = False
    if started and str(started) != prev["started"]:
        if prev["started"] is not None:
            record_change(c, "container_started", name, ts, "started")
            changed = True
        c.execute("insert into cursors(name, value, last_checked) values(?,?,?)"
                  " on conflict(name) do update set value=excluded.value,"
                  " last_checked=excluded.last_checked",
                  ("docker_started:" + name, str(started), ts))
    if state and str(state) != prev["state"]:
        if prev["state"] is not None:
            record_change(c, "container_state", name, ts, f"state {prev['state']}->{state}")
            changed = True
        c.execute("insert into cursors(name, value, last_checked) values(?,?,?)"
                  " on conflict(name) do update set value=excluded.value,"
                  " last_checked=excluded.last_checked",
                  ("docker_state:" + name, str(state), ts))
    return changed


def collect_deploy_events(c, home=None):
    """changes-deploy.jsonl (door deploy.sh gevuld) inlezen met byte-offset
    cursor. Bestaat het bestand niet, dan is dit één stat()-call."""
    c.execute(CHANGES_SCHEMA)
    p = (home or HOME) / "homelab" / DEPLOY_LOG
    if not p.exists():
        return 0
    size = p.stat().st_size
    row = c.execute("select value from cursors where name=?", (DEPLOY_CURSOR,)).fetchone()
    offset = int(float(row[0])) if row else 0
    if size < offset:  # rotatie/schoonvegen: opnieuw vanaf begin
        offset = 0
    if size == offset:
        return 0
    with p.open("r", encoding="utf-8", errors="replace") as f:
        f.seek(offset)
        data = f.read()
    new_offset = offset + len(data.encode("utf-8"))
    n = 0
    for line in data.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            ev = json.loads(line)
            record_change(c, ev.get("kind", "deploy"), ev.get("key", "hermes"),
                          ev.get("ts", ""), ev.get("detail", ""))
            n += 1
        except (ValueError, TypeError):
            continue
    c.execute("insert into cursors(name, value, last_checked) values(?,?,?)"
              " on conflict(name) do update set value=excluded.value,"
              " last_checked=excluded.last_checked", (DEPLOY_CURSOR, str(new_offset), now_iso()))
    return n


# --------------------------------------------------------------- correlate --
def _parse_iso(s):
    try:
        d = datetime.fromisoformat(s)
        return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return None


def correlate(c, when_iso, *, window_hours=None, limit=None, exclude_key=None, cfg=None):
    """Changes binnen [when - window, when] -> begrensde, gededupeerde lijst
    compacte tekstregels ('DUMB (her)gestart 18 min vóór incident').
    exclude_key: de verandering die het incident zélf is onderdrukken (een
    docker:<naam>:restarts-incident is zélf de change)."""
    cfgn = {**DEFAULTS, **(cfg or {})}
    if not cfgn.get("enabled", True):
        return []
    when = _parse_iso(when_iso)
    if when is None:
        return []
    c.execute(CHANGES_SCHEMA)
    hours = float(window_hours or cfgn["window_hours"])
    start = (when - timedelta(hours=hours)).isoformat(timespec="seconds")
    end = when.isoformat(timespec="seconds")
    rows = c.execute("select kind, key, ts, detail from changes"
                     " where ts >= ? and ts <= ? order by ts desc",
                     (start, end)).fetchall()
    best = {}
    for kind, key, ts, detail in rows:
        if exclude_key and key == exclude_key:
            continue
        rank = KIND_RANK.get(kind, 1)
        cur = best.get(key)
        if cur is None or rank > cur[0]:
            best[key] = (rank, kind, key, ts, detail)
    out = []
    for rank, kind, key, ts, detail in sorted(best.values(), key=lambda r: r[3], reverse=True):
        if len(out) >= int(limit or cfgn["max_items"]):
            break
        chg = _parse_iso(ts)
        if chg is None:
            continue
        mins = max(1, int((when - chg).total_seconds() // 60))
        label = KIND_LABEL.get(kind, "{key} {detail}").format(key=key, detail=detail)
        out.append(f"{label} {mins} min vóór incident")
    return out


# --------------------------------------------------------------- recurrentie --
def record_occurrence(c, fingerprint, ts, severity=""):
    """Door incident_upsert aangeroepen bij new/escalated/reopened. Begrensd:
    30 dagen retentie (fase-4 bron voor patroondetectie)."""
    c.execute(OCC_SCHEMA)
    c.execute(OCC_INDEX)
    c.execute("insert or ignore into occurrence_log(fingerprint, ts, severity)"
              " values(?,?,?)", (fingerprint, ts, severity or ""))
    cutoff = (datetime.now(timezone.utc) -
              timedelta(days=int(DEFAULTS["occurrence_retention_days"]))
              ).isoformat(timespec="seconds")
    c.execute("delete from occurrence_log where ts < ?", (cutoff,))


def recurrence(c, fingerprint, *, days=None, min_occurrences=None,
               cluster_minutes=None, label=None, cfg=None, now=None):
    """Deterministisch patroon over occurrence_log: 'Pattern: <label> Nx in D
    dagen, K opeenvolgende dagen, tussen HH:MM–HH:MM'. Onder de
    min_occurrences-grens: None (geen patroonclaim, §7)."""
    cfgn = {**DEFAULTS, **(cfg or {})}
    ndays = int(days or cfgn["occurrence_days"])
    minimum = int(min_occurrences or cfgn["occurrence_min"])
    cluster = int(cluster_minutes or cfgn["cluster_minutes"])
    now_dt = _parse_iso(now) if now else datetime.now(timezone.utc)
    cutoff = (now_dt - timedelta(days=ndays)).isoformat(timespec="seconds")
    c.execute(OCC_SCHEMA)
    rows = c.execute("select ts from occurrence_log where fingerprint=? and ts >= ?"
                     " order by ts", (fingerprint, cutoff)).fetchall()
    dts = [d for d in (_parse_iso(r[0]) for r in rows) if d]
    if len(dts) < minimum:
        return None
    n = len(dts)
    dates = sorted({d.date() for d in dts})
    longest = run = 1
    for a, b in zip(dates, dates[1:]):
        run = run + 1 if (b - a).days == 1 else 1
        longest = max(longest, run)
    # tijdcluster: spreiding van minuten-van-de-dag, met middennacht-wrap
    mods = sorted(d.hour * 60 + d.minute for d in dts)
    spread_plain = mods[-1] - mods[0]
    shifted = sorted(m - 1440 if m >= 1260 else m for m in mods)  # >=21u -> vóór middernacht
    spread_shift = shifted[-1] - shifted[0]
    parts = [f"Pattern: {label or fingerprint} {n}x in {ndays} dagen"]
    if longest >= 2:
        parts.append(f"{longest} opeenvolgende dagen")
    if spread_plain <= cluster or spread_shift <= cluster:
        if spread_shift < spread_plain:
            lo, hi = shifted[0] % 1440, shifted[-1] % 1440
        else:
            lo, hi = mods[0], mods[-1]
        parts.append(f"tussen {lo // 60:02d}:{lo % 60:02d}–{hi // 60:02d}:{hi % 60:02d}")
    return ", ".join(parts)


# ------------------------------------------------------------------- test --
def run_test():
    """Synthetische cases (§10): venster, begrenzing, dedup, kosten, patronen."""
    import tempfile
    results = []

    def check(name, cond, detail=""):
        results.append((name, bool(cond), detail))

    def mkdb():
        tmp = Path(tempfile.mkdtemp())
        con = sqlite3.connect(tmp / "agent_state.db")
        con.execute("create table cursors(name text primary key, value text,"
                    " last_checked text)")
        return tmp, con

    def minutes_ago(n):
        return (datetime.now(timezone.utc) - timedelta(minutes=n)).isoformat(timespec="seconds")

    NOW = "2026-09-20T22:00:00+00:00"

    # 1: change binnen venster -> zichtbaar met minuten-aanduiding
    tmp, con = mkdb()
    record_change(con, "container_started", "DUMB", "2026-09-20T21:42:00+00:00", "started")
    record_change(con, "deploy", "hermes", "2026-09-20T21:09:00+00:00", "3 bestanden")
    out = correlate(con, NOW)
    check("1: change binnen venster -> zichtbaar met minuten",
          any(x.startswith("DUMB (her)gestart 18 min") for x in out)
          and any(x.startswith("Hermes deploy 51 min") for x in out), str(out))

    # 2: change buiten venster -> niet zichtbaar
    tmp, con = mkdb()
    record_change(con, "container_started", "DUMB", "2026-09-20T19:00:00+00:00", "started")
    out = correlate(con, NOW, window_hours=2)
    check("2: change buiten venster (3u) -> niet zichtbaar", out == [], str(out))

    # 3: meerdere changes -> begrensd op max_items
    tmp, con = mkdb()
    for i in range(8):
        record_change(con, "container_started", f"app{i}", "2026-09-20T21:00:00+00:00", "started")
    out = correlate(con, NOW, limit=5)
    check("3: 8 changes -> begrensd op 5", len(out) == 5, str(len(out)))

    # 4: duplicates (zelfde key, meerdere kinds) -> één entry, informatiefste wint
    tmp, con = mkdb()
    record_change(con, "container_started", "DUMB", "2026-09-20T21:42:00+00:00", "started")
    record_change(con, "restart_delta", "DUMB", "2026-09-20T21:42:00+00:00", "3")
    record_change(con, "container_state", "DUMB", "2026-09-20T21:42:00+00:00",
                  "state exited->running")
    out = correlate(con, NOW)
    dumb = [x for x in out if "DUMB" in x]
    check("4: 3 kinds zelfde key -> één entry (container_started wint)",
          len(dumb) == 1 and "(her)gestart" in dumb[0], str(dumb))

    # 5: geen changes -> geen extra context
    tmp, con = mkdb()
    out = correlate(con, NOW)
    check("5: geen changes -> lege lijst", out == [], str(out))

    # 5b: exclude_key onderdrukt de change die het incident zélf is
    record_change(con, "container_started", "plex", "2026-09-20T21:30:00+00:00", "started")
    out = correlate(con, NOW, exclude_key="plex")
    check("5b: exclude_key -> eigen change niet in lijst", out == [], str(out))

    # 6: correlation veroorzaakt geen extra LLM-call (kostenmodel §6)
    import hermes_evaluator as he
    import hermes_router as hr
    calls = {"n": 0}

    def fake_analyze(fp, **kw):
        calls["n"] += 1
        return ({"status": "done", "tier": "tier1", "analysis": {"summary": "ok"},
                 "confidence": 0.9}, [{"success": True, "actual_model": "fake"}])

    real_key, real_analyze = hr.load_env_key, hr.analyze
    real_events = he.EVENTS
    hr.load_env_key = lambda env_path=None: "test"
    hr.analyze = fake_analyze
    tmp, con = mkdb()
    he.EVENTS = tmp / "events.jsonl"  # emit() schrijft hierheen (read-only HOME in CI)
    con.executescript("""
        create table incidents(fingerprint text primary key, source text, type text,
          state text, current_severity text, previous_severity text, first_seen text,
          last_seen text, last_changed text, resolved_at text, occurrences integer,
          last_value real, peak_value real, last_alert_at text, suppression_until text,
          good_samples integer, last_reason text,
          llm_last_analyzed_at text, llm_last_model text, llm_summary text,
          llm_confidence real, llm_root_cause text, llm_analysis_version integer default 0,
          llm_context_hash text, llm_call_count integer default 0);
        create table dumbscope_incidents(fingerprint text primary key,
          source_fingerprint text, incident_id text, status text, severity text,
          title text, last_seen_ms integer, resolved_at_ms integer, occurrences integer,
          last_processed_at text, host_correlations text, summary text,
          root_cause_service text, affected_services text, evidence_json text);
        create table counters(name text primary key, device text, previous_value real,
          current_value real, delta real, last_checked text);
        create table metric_state(metric text primary key, last_value real,
          previous_value real, last_ts text, trend text, slope real,
          sustained_since text, peak real, baseline_pending integer);
    """)
    # 6a: gezonde state (alleen resolved) + changes in ledger -> 0 LLM-calls
    con.execute("insert into incidents(fingerprint, source, type, state,"
                " current_severity, previous_severity, first_seen, last_seen,"
                " last_changed, resolved_at, occurrences, last_value, peak_value,"
                " last_alert_at, last_reason)"
                " values('host:memory:high','fast','mem','resolved','normal','warning',"
                "'t','t','t','t',2,60,90,'t','x')")
    record_change(con, "container_started", "DUMB", minutes_ago(18), "started")
    con.commit()
    llm_on = {"llm": {"enabled": True}}
    stats = he.run_llm_layer(llm_on, con, [])
    check("6a: gezonde state + changes in ledger -> 0 LLM-calls",
          calls["n"] == 0 and stats.get("kandidaten", 0) == 0, str(stats))
    # 6b: candidate (onzeker dumbscope-incident) -> ctx bevat recent_changes
    con.execute("insert into incidents(fingerprint, source, type, state,"
                " current_severity, previous_severity, first_seen, last_seen,"
                " last_changed, occurrences, last_value, peak_value, last_alert_at,"
                " last_reason)"
                " values('dumbscope:mystery','dumbscope','ds','active','warning',"
                "'normal','t','t','t',1,1,1,'t','x')")
    con.execute("insert into dumbscope_incidents(fingerprint, source_fingerprint,"
                " incident_id, status, severity, title, last_seen_ms, resolved_at_ms,"
                " occurrences, last_processed_at, host_correlations, summary,"
                " root_cause_service, affected_services, evidence_json)"
                " values('dumbscope:mystery','mystery','i1','active','warning','t',"
                "1,2,1,'t','[]','s',NULL,'[]','[]')")
    con.commit()
    ctx = he.build_context(con, "dumbscope:mystery", "warning")
    check("6b: ctx bevat recent_changes (changes rijden mee met bestaande analyse)",
          isinstance(ctx.get("recent_changes"), list)
          and "DUMB (her)gestart" in ctx["recent_changes"][0], str(ctx)[:200])
    # 6c: precies 1 analyze-call voor de candidate; correlation = 0 extra calls
    stats = he.run_llm_layer(llm_on, con, [])
    check("6c: candidate -> precies 1 analyze-call (correlation zelf = 0 extra)",
          calls["n"] == 1, str(calls))
    hr.load_env_key, hr.analyze = real_key, real_analyze
    he.EVENTS = real_events
    con.close()

    # 7: recurrence-positief (4 opeenvolgende nachten, zelfde tijdsvenster)
    tmp, con = mkdb()
    for d, h, m in ((14, 1, 20), (15, 1, 45), (16, 2, 10), (17, 2, 40)):
        record_occurrence(con, "host:temperature:package",
                          f"2026-09-{d:02d}T{h:02d}:{m:02d}:00+00:00", "warning")
    out = recurrence(con, "host:temperature:package",
                     label="package-temperature warning", now=NOW)
    check("7: recurrence 4 nachten -> patroonclaim met dagen en tijdvenster",
          out is not None and "4x" in out and "4 opeenvolgende dagen" in out
          and "tussen 01:20–02:40" in out, str(out))

    # 7b: gespreide dagen -> wel patroon, zonder 'opeenvolgende dagen'
    tmp, con = mkdb()
    for d in (14, 16, 18, 20):
        record_occurrence(con, "host:temperature:package",
                          f"2026-09-{d:02d}T01:30:00+00:00", "warning")
    out = recurrence(con, "host:temperature:package", now=NOW)
    check("7b: gespreide dagen -> patroon zonder 'opeenvolgende dagen'",
          out is not None and "opeenvolgende" not in out and "4x" in out, str(out))

    # 8: onvoldoende occurrences -> geen patroonclaim
    tmp, con = mkdb()
    record_occurrence(con, "host:memory:high", "2026-09-20T10:00:00+00:00", "warning")
    record_occurrence(con, "host:memory:high", "2026-09-20T18:00:00+00:00", "warning")
    out = recurrence(con, "host:memory:high", now=NOW)
    check("8: 2 occurrences (< min 3) -> None", out is None, str(out))

    # 9: deploy-events: ingest met cursor; alleen nieuwe regels tweede keer
    tmp, con = mkdb()
    (tmp / "homelab").mkdir(parents=True)
    logf = tmp / "homelab" / DEPLOY_LOG
    logf.write_text('{"ts":"2026-09-20T20:00:00+00:00","kind":"deploy","key":"hermes",'
                    '"detail":"2 bestanden"}\n')
    n = collect_deploy_events(con, home=tmp)
    check("9a: deploy-event ingelezen", n == 1, str(n))
    n2 = collect_deploy_events(con, home=tmp)
    check("9b: geen nieuwe regels -> 0 (cursor)", n2 == 0, str(n2))
    with logf.open("a") as f:
        f.write('{"ts":"2026-09-20T22:00:00+00:00","kind":"rollback","key":"hermes",'
                '"detail":"rollback"}\n')
    n3 = collect_deploy_events(con, home=tmp)
    rows = con.execute("select kind from changes order by ts").fetchall()
    check("9c: appended deploy-event -> alleen nieuwe regel",
          n3 == 1 and rows == [("deploy",), ("rollback",)], f"{n3} {rows}")

    # 9d: record_container_observation: eerste waarneming baseline, daarna change
    tmp, con = mkdb()
    record_container_observation(con, "DUMB", "running", "2026-09-20T10:00:00+00:00",
                                 "2026-09-20T21:23:00+00:00")
    n = con.execute("select count(*) from changes").fetchone()[0]
    check("9d-1: eerste waarneming = baseline (geen change)", n == 0, str(n))
    record_container_observation(con, "DUMB", "running", "2026-09-20T21:40:11+00:00",
                                 "2026-09-20T22:23:00+00:00")
    rows = con.execute("select kind, key from changes").fetchall()
    check("9d-2: nieuwe started-ts -> container_started change",
          rows == [("container_started", "DUMB")], str(rows))

    # 9e: bounded_cleanup houdt de ledger begrensd
    for i in range(50):
        record_change(con, "container_started", f"x{i}", "2026-09-20T21:00:00+00:00", "")
    bounded_cleanup(con, max_rows=10)
    n = con.execute("select count(*) from changes").fetchone()[0]
    check("9e: cleanup cap", n == 10, str(n))

    fails = [r for r in results if not r[1]]
    for name, okk, detail in results:
        print(f"{'PASS' if okk else 'FAIL'}  {name}" + (f"  [{detail}]" if detail and not okk else ""))
    print(f"\n{len(results) - len(fails)}/{len(results)} geslaagd")
    return 0 if not fails else 1


if __name__ == "__main__":
    import sys
    mode = sys.argv[1] if len(sys.argv) > 1 else "test"
    if mode == "test":
        sys.exit(run_test())
    print("gebruik: hermes_changes.py test", file=sys.stderr)
    sys.exit(64)
