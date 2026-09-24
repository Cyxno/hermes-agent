#!/usr/bin/env python3
"""hermes_notifier.py — fase 4.5: volledig deterministische Telegram-alerting.

Flow: agent_state.db (incident-state, bron: hermes_evaluator.py)
      -> notification policy (dit bestand, config: notifications.yaml)
      -> Telegram sendMessage (directe HTTPS-call, GEEN LLM, GEEN gateway,
         GEEN remediation).

Ontwerpregels:
  - De evaluator blijft source of truth; hier worden GEEN drempels herberekend.
  - NORMAL/NOTICE -> nooit versturen. WARNING -> alleen bij nieuw/escalatie.
    URGENT/CRITICAL -> direct; unchanged alleen reminder na cooldown.
    RECOVERING -> niets. RESOLVED -> één herstelbericht na eerdere WARNING+.
  - Dedup via fingerprint + notifications-tabel in agent_state.db.
  - Failed send -> pending + retry met backoff; incident mag niet als
    'notified' gelden voordat Telegram bevestigt (message_id terug).
  - >= N opeenvolgende mislukte sends -> lokaal incident notifications:delivery,
    GEEN Telegram-alert over de kapotte Telegram-verbinding zelf.
  - 0 LLM: er is hier geen codepad naar een model. 0 tokens.

Modes: run (standalone verwerking), test (synthetische cases), send-test
(één gecontroleerde transporttest, geen fake CRITICAL).
"""
import json, os, sqlite3, sys, time, urllib.error, urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

from hermes_evaluator import LEVELS, NAME, mini_yaml

LLM_FREE = True  # hard: dit module importeert/callt nooit een model
DEFAULTS = {
    "enabled": True,
    "min_severity": "warning",
    "telegram_enabled": True,
    "recovery_enabled": True,
    "cooldown_hours": {"warning_unchanged": 4, "urgent_reminder": 2, "critical_reminder": 1},
    "retry": {"base_delay_s": 60, "factor": 2, "max_delay_s": 900},
    "failure_incident_after": 3,
}
AUDIT_NAME = "notifications.jsonl"

HOME = Path(os.environ.get("HERMES_HOME", "/opt/data"))
HL = HOME / "homelab"
STATE_DB = HL / "agent_state.db"
SAMPLES_DB = HL / "samples.db"

SCHEMA = """
create table if not exists notifications(
  fingerprint text primary key,
  last_notified_at text, last_notified_severity text, last_notified_state text,
  notification_count integer default 0, telegram_message_id text,
  resolved_notified integer default 0, ever_notified integer default 0,
  pending integer default 0, pending_json text,
  retry_count integer default 0, last_error text, next_retry_at text,
  updated_at text);
create table if not exists notification_meta(name text primary key, value text);
create table if not exists pending_transitions(
  id integer primary key autoincrement,
  fingerprint text not null, ts text, event_type text, severity text,
  reason text);
"""


def now_dt():
    return datetime.now(timezone.utc)


def iso(dt):
    return dt.isoformat(timespec="seconds")


def parse_ts(s):
    try:
        d = datetime.fromisoformat(s)
        return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return None


def load_cfg(home=None):
    p = (home or HOME) / "notifications.yaml"
    raw = mini_yaml(p.read_text()).get("notifications", {}) if p.exists() else {}

    def merge(base, over):
        out = dict(base)
        for k, v in (over or {}).items():
            out[k] = merge(base[k], v) if isinstance(v, dict) and isinstance(base.get(k), dict) else v
        return out
    return merge(DEFAULTS, raw)


def load_creds(home=None):
    """TELEGRAM_BOT_TOKEN/TELEGRAM_HOME_CHANNEL uit $HERMES_HOME/.env.
    Waarden verlaten deze functie nooit via logs of audit."""
    token = chat = None
    p = (home or HOME) / ".env"
    if p.exists():
        for line in p.read_text(errors="replace").splitlines():
            if line.startswith("TELEGRAM_BOT_TOKEN="):
                token = line.split("=", 1)[1].strip() or None
            elif line.startswith("TELEGRAM_HOME_CHANNEL="):
                chat = line.split("=", 1)[1].strip() or None
    return token, chat


# ------------------------------------------------------------- transport --
def telegram_send(token, chat, text, timeout=15):
    """Directe sendMessage-call. Geeft (ok, message_id, error); het token
    komt nooit in return-waarden of exceptions terecht."""
    body = json.dumps({"chat_id": chat, "text": text,
                       "disable_web_page_preview": True}).encode()
    req = urllib.request.Request(
        f"https://api.telegram.org/bot{token}/sendMessage", data=body,
        headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.loads(r.read())
        if data.get("ok"):
            return True, str(data.get("result", {}).get("message_id") or ""), None
        return False, None, f"telegram ok=false: {data.get('description', '?')}"[:200]
    except urllib.error.HTTPError as e:
        return False, None, f"http {e.code}"[:200]
    except Exception as e:  # noqa: BLE001 — transportfouten zijn verwacht
        return False, None, f"{type(e).__name__}: {e}"[:200]


# ----------------------------------------------------------------- audit --
def audit(path, *, fingerprint, severity, state, event, attempted, delivered,
          message_id=None, error=None, retry_count=0, reason=""):
    row = {"ts": iso(now_dt()), "fingerprint": fingerprint, "severity": severity,
           "state": state, "channel": "telegram", "event": event,
           "attempted": attempted, "delivered": delivered,
           "message_id": message_id, "error": error,
           "retry_count": retry_count, "reason": reason}
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a") as f:
        f.write(json.dumps(row, ensure_ascii=False) + "\n")


# ------------------------------------------------------------ berichttekst --
TITLES = [
    ("host:memory:oom", "OOM kill gedetecteerd"),
    ("host:memory:high", "RAM usage high"),
    ("host:docker_vdisk:growth", "Docker vDisk groeit snel"),
    ("host:docker_vdisk:high", "Docker vDisk bijna vol"),
    ("host:logfs:growth", "/var/log groeit snel"),
    ("host:logfs:high", "/var/log loopt vol"),
    ("host:cache:high", "Cache-pool bijna vol"),
    ("host:vm_storage:high", "VM-storage bijna vol"),
    ("host:user_share:high", "User-share bijna vol"),
    ("host:rootfs:high", "Rootfs bijna vol"),
    ("host:temperature:package", "CPU-package temperatuur hoog"),
    ("host:temperature:core", "CPU-core temperatuur hoog"),
    ("host:docker_daemon:down", "Docker daemon down"),
    ("host:containers:unhealthy", "Unhealthy containers"),
    ("host:swap:active", "Swap actief"),
    ("host:array:stopped", "Array niet gestart"),
    ("host:array:resync", "Parity/resync actief"),
    ("dumbscope:availability", "DUMBscope onbereikbaar"),
]


def title_for(fp, dsi):
    for pref, t in TITLES:
        if fp.startswith(pref):
            return t
    if fp.startswith("pool:") and fp.endswith(":readonly"):
        return f"Pool {fp.split(':')[1]} read-only"
    if fp.startswith("disk:"):
        dev = fp.split(":")[1]
        if ":smart_failed" in fp:
            return f"SMART health FAILED ({dev})"
        if ":pending_absolute" in fp:
            return f"Pending sectors ({dev})"
        if ":growth" in fp:
            return f"SMART-teller groeit ({dev})"
    if fp.startswith("docker:") and fp.endswith(":restarts"):
        return f"Container herstart: {fp.split(':')[1]}"
    if fp.startswith("host:") and ":readonly" in fp:
        return "Filesystem read-only"
    if dsi and dsi.get("title"):
        return str(dsi["title"])[:80]
    return fp


def human_dur(dt_from, now):
    if not dt_from:
        return None
    secs = max(0, int((now - dt_from).total_seconds()))
    if secs < 3600:
        return f"{max(1, secs // 60)} min"
    return f"{secs // 3600}h {secs % 3600 // 60}m"


def fmt_gib(kb):
    return f"{kb / 1024 / 1024:.1f} GiB"


def build_text(fp, inc, dsi, ctx, event):
    """Compact, deterministic bericht. Severity komt 1-op-1 uit de evaluator."""
    sev = inc["current_severity"] if inc["state"] != "resolved" else "normal"
    icon = {"warning": "⚠️", "urgent": "🔔", "critical": "🚨"}.get(sev, "✅")
    title = title_for(fp, dsi)
    tag = {"escalation": " (escalatie)", "reminder": " (herinnering)",
           "recovery": " — opgelost", "retry": " (herhaal)"}.get(event, "")
    lines = [f"{icon} Unraid — {title}{tag}", ""]
    now = now_dt()
    lvl = LEVELS.get(inc["current_severity"], 0)
    val = inc["last_value"]
    peak = inc["peak_value"]
    if fp == "host:memory:high":
        lines.append(f"RAM: {val:.0f}% used")
        if ctx.get("mem_avail_kb"):
            lines.append(f"Available: {fmt_gib(ctx['mem_avail_kb'])}")
    if fp.startswith("disk:") and fp.endswith(":growth"):
        # monotone-counter event: huidige teller = context, delta = het event
        if val is not None:
            lines.append(f"Nieuwe delta: +{int(val or 0)}")
        if ctx.get("counter_current") is not None:
            lines.append(f"Huidige counter: {int(ctx['counter_current'])}")
        if ctx.get("since_change"):
            lines.append(f"Sinds vorige verandering: {ctx['since_change']}")
    elif fp.endswith(":growth"):
        # groei-incidenten: last_value is een groeirate in GiB/uur — nooit als
        # percentage tonen (veronderstelde '6%' was een verkeerd geformatteerde rate)
        unit = " GiB/uur"
        if val is not None:
            lines.append(f"Groeirate: {val:.2f}{unit}")
    elif "vdisk" in fp or "logfs" in fp or \
            fp.split(':high')[0].split(':')[-1] in ("cache", "vm_storage", "user_share", "rootfs"):
        lines.append(f"Gebruikt: {val:.0f}%")
        if "vdisk" in fp and ctx.get("vdisk_avail_kb"):
            lines.append(f"Vrij: {fmt_gib(ctx['vdisk_avail_kb'])}")
    elif fp.startswith("host:temperature"):
        lines.append(f"Temperatuur: {val:.0f} °C")
    elif dsi:
        lines.append(f"Severity bron: {dsi.get('severity') or sev}")
        if dsi.get("affected"):
            lines.append(f"Services: {', '.join(dsi['affected'])}")
        if dsi.get("root_cause"):
            lines.append(f"Root cause service: {dsi['root_cause']}")
    elif fp == "dumbscope:availability":
        lines.append(f"Mislukte polls: {int(val or 0)}")
    elif fp == "host:memory:oom":
        lines.append(f"OOM-teller delta: +{int(val or 0)}")
    else:
        if val is not None:
            lines.append(f"Waarde: {val}")
    if dsi is None and fp not in ("dumbscope:availability",) and not fp.startswith("docker:") \
            and not (fp.startswith("disk:") and fp.endswith(":growth")):
        if ctx.get("direction") and lvl >= 2:
            lines.append(f"Trend: {ctx['direction']}")
        if peak is not None and peak != val and lvl >= 2:
            peak_unit = " GiB/uur" if fp.endswith(":growth") else (
                "%" if fp.endswith(":high") else (" °C" if fp.startswith("host:temperature") else ""))
            peak_txt = peak if isinstance(peak, str) else round(peak, 1)
            lines.append(f"Peak: {peak_txt}{peak_unit}")
    dur = human_dur(parse_ts(inc["first_seen"]), now)
    if dur and inc["state"] != "resolved" and not (fp.startswith("disk:") and fp.endswith(":growth")):
        lines.append(f"Duur: {dur}")
    elif inc["state"] == "resolved" and dur:
        lines.append(f"Duur incident: {dur}")
    if ctx.get("load1") is not None and fp == "host:memory:high":
        lines.append(f"Load1: {ctx['load1']:.1f}")
    if ctx.get("oom_delta") and fp == "host:memory:high":
        lines.append(f"OOM nieuw: ja (+{int(ctx['oom_delta'])})")
    if inc["occurrences"] and inc["occurrences"] > 1:
        lines.append(f"Voorkomens: {inc['occurrences']}")
    # fase 4: hypotheses/context, geen causaliteits-claim
    if ctx.get("recent_changes"):
        lines.append("Recent: " + "; ".join(ctx["recent_changes"])[:220])
    if ctx.get("recurrence"):
        lines.append(str(ctx["recurrence"])[:200])
    reason = (inc["last_reason"] or "")[:160]
    if reason:
        lines.append(f"Reden: {reason}")
    lines += ["", f"Severity: {sev.upper()}", "Geen AI gebruikt."]
    return "\n".join(lines)


# --------------------------------------------------------------- beslissen --
def decide(inc, nrow, cfgn, now):
    """(event|None, reden) — puur op evaluator-state, geen drempels hier."""
    sev = inc["current_severity"] or "normal"
    lvl = LEVELS.get(sev, 0)
    state = inc["state"]
    minl = LEVELS[cfgn.get("min_severity", "warning")]
    if state == "recovering":
        return None, "recovering: geen nieuw alarm"
    if state == "resolved":
        if cfgn.get("recovery_enabled", True) and nrow and nrow["ever_notified"] \
                and not nrow["resolved_notified"]:
            return "recovery", "resolved na eerdere WARNING+-melding"
        return None, "resolved zonder eerdere melding of al bevestigd"
    if lvl < minl:
        return None, f"severity {sev} onder minimum"
    if nrow and nrow["last_notified_state"] == "resolved":
        return "new", "heropend na resolve -> direct bericht (geen cooldown)"
    if not nrow or not nrow["ever_notified"]:
        return "new", "nieuw incident"
    last_lvl = LEVELS.get(nrow["last_notified_severity"], 0)
    if last_lvl < lvl:
        return "escalation", f"escalatie {nrow['last_notified_severity']} -> {sev} (cooldown genegeerd)"
    if last_lvl > lvl:
        return None, "gedeëscaleerd: geen bericht"
    cd = cfgn.get("cooldown_hours", {})
    cd_h = {"warning": cd.get("warning_unchanged"), "urgent": cd.get("urgent_reminder"),
            "critical": cd.get("critical_reminder")}.get(sev)
    if cd_h is None:
        return None, "unchanged: geen herinnering geconfigureerd"
    last = parse_ts(nrow["last_notified_at"])
    if last and (now - last) >= timedelta(hours=float(cd_h)):
        return "reminder", f"unchanged >= {cd_h}u herinnering"
    return None, "unchanged binnen cooldown"


# ----------------------------------------------------------------- verzend --
def backoff_s(retry_count, retry_cfg):
    base = float(retry_cfg.get("base_delay_s", 60))
    factor = float(retry_cfg.get("factor", 2))
    return min(base * (factor ** max(0, retry_count - 1)),
               float(retry_cfg.get("max_delay_s", 900)))


def ensure_schema(c):
    c.executescript(SCHEMA)


def meta_get(c, name, default=None):
    r = c.execute("select value from notification_meta where name=?", (name,)).fetchone()
    return r[0] if r else default


def meta_set(c, name, value):
    c.execute("insert into notification_meta(name, value) values(?,?)"
              " on conflict(name) do update set value=excluded.value", (name, str(value)))


def set_delivery_incident(c, ok, err, cfgn, now, events):
    """Self-monitoring (§11): >= N mislukte sends achter elkaar -> lokaal
    incident, lokaal gelogd. GEEN Telegram-alert hierover (geen recursie)."""
    fp = "notifications:delivery"
    if ok:
        meta_set(c, "tg_consecutive_failures", 0)
        r = c.execute("select state from incidents where fingerprint=?", (fp,)).fetchone()
        if r and r[0] == "active":
            c.execute("update incidents set state='resolved', current_severity='normal',"
                      " last_changed=?, resolved_at=?, last_reason='telegram weer bereikbaar'"
                      " where fingerprint=?", (iso(now), iso(now), fp))
            events.append({"fingerprint": fp, "event": "self_monitor_resolved"})
        return
    n = int(meta_get(c, "tg_consecutive_failures", "0") or 0) + 1
    meta_set(c, "tg_consecutive_failures", n)
    thr = int(cfgn.get("failure_incident_after", 3))
    if n >= thr:
        r = c.execute("select state from incidents where fingerprint=?", (fp,)).fetchone()
        if r is None:
            c.execute("insert into incidents(fingerprint, source, type, state,"
                      " current_severity, previous_severity, first_seen, last_seen,"
                      " last_changed, occurrences, last_value, peak_value, last_alert_at,"
                      " last_reason) values(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                      (fp, "notifier", "telegram_delivery", "active", "warning", "normal",
                       iso(now), iso(now), iso(now), 1, n, n, iso(now),
                       f"{n} opeenvolgende Telegram-fouten: {err}"))
        elif r[0] == "active":
            c.execute("update incidents set last_value=?, last_seen=?, last_reason=?"
                      " where fingerprint=?", (n, iso(now),
                                               f"{n} opeenvolgende Telegram-fouten: {err}", fp))
        events.append({"fingerprint": fp, "event": f"self_monitor_active({n})"})


def deliver(c, *, fp, inc, nrow, event, text, cfgn, audit_path, token, chat, sender, events):
    now = now_dt()
    sev = inc["current_severity"] if inc["state"] != "resolved" else "normal"
    attempted, delivered, mid, err = 1, 0, None, None
    if not cfgn.get("telegram_enabled", True):
        err = "telegram uitgeschakeld (notifications.yaml)"
    elif not token or not chat:
        err = "geen TELEGRAM_BOT_TOKEN/TELEGRAM_HOME_CHANNEL in .env"
    else:
        ok, mid, err = sender(token, chat, text)
        delivered = 1 if ok else 0
    audit(audit_path, fingerprint=fp, severity=sev, state=inc["state"], event=event,
          attempted=attempted, delivered=delivered, message_id=mid if delivered else None,
          error=err, retry_count=(nrow["retry_count"] if nrow else 0) + (0 if delivered else 1),
          reason=inc["last_reason"] or "")
    new_retry = 0 if delivered else (nrow["retry_count"] if nrow else 0) + 1
    c.execute("insert into notifications(fingerprint, last_notified_at,"
              " last_notified_severity, last_notified_state, notification_count,"
              " telegram_message_id, resolved_notified, ever_notified, pending,"
              " pending_json, retry_count, last_error, next_retry_at, updated_at)"
              " values(?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
              " on conflict(fingerprint) do update set"
              " last_notified_at=case when excluded.ever_notified=1 then excluded.last_notified_at"
              " else notifications.last_notified_at end,"
              " last_notified_severity=case when excluded.ever_notified=1"
              " then excluded.last_notified_severity else notifications.last_notified_severity end,"
              " last_notified_state=case when excluded.ever_notified=1"
              " then excluded.last_notified_state else notifications.last_notified_state end,"
              " notification_count=notifications.notification_count+excluded.notification_count,"
              " telegram_message_id=case when excluded.ever_notified=1"
              " then excluded.telegram_message_id else notifications.telegram_message_id end,"
              " resolved_notified=excluded.resolved_notified,"
              " ever_notified=max(notifications.ever_notified, excluded.ever_notified),"
              " pending=excluded.pending, pending_json=excluded.pending_json,"
              " retry_count=excluded.retry_count, last_error=excluded.last_error,"
              " next_retry_at=excluded.next_retry_at, updated_at=excluded.updated_at",
              (fp, iso(now) if delivered else None,
               sev if delivered else None, inc["state"] if delivered else None,
               1 if delivered else 0, mid if delivered else None,
               1 if (event == "recovery" and delivered) else 0,
               1 if delivered else 0,
               0 if delivered else 1, None if delivered else text,
               new_retry, err,
               None if delivered else iso(now + timedelta(seconds=backoff_s(new_retry, cfgn.get("retry", {})))),
               iso(now)))
    set_delivery_incident(c, bool(delivered), err, cfgn, now, events)
    return bool(delivered)


def gather_context(samples_db, c, fp):
    """Relevante context uit bestaande state — geen nieuwe interpretatie."""
    ctx = {}
    try:
        s = sqlite3.connect(f"file:{samples_db}?mode=ro", uri=True, timeout=5)
        row = s.execute("select mem_avail_kb, load1, vdisk_avail_kb from samples"
                        " order by ts desc limit 1").fetchone()
        s.close()
        if row:
            ctx = {"mem_avail_kb": row[0], "load1": row[1], "vdisk_avail_kb": row[2]}
    except Exception:  # noqa: BLE001 — context is best-effort
        pass
    try:
        r = c.execute("select delta from counters where name='oom_kills'").fetchone()
        if r:
            ctx["oom_delta"] = r[0]
        if fp.startswith("disk:") and fp.endswith(":growth"):
            parts = fp.split(":")
            name = f"smart:{parts[1]}:{parts[-1].removesuffix('_growth')}"
            r = c.execute("select current_value from counters where name=?", (name,)).fetchone()
            if r and r[0] is not None:
                ctx["counter_current"] = r[0]
            t = c.execute("select value from cursors where name=?",
                          (f"{name}:last_change",)).fetchone()
            if t:
                since = human_dur(parse_ts(t[0]), now_dt())
                if since:
                    ctx["since_change"] = since
        metric = {"host:memory:high": "mem_used_pct", "host:docker_vdisk:high": "vdisk_pct",
                  "host:logfs:high": "logfs_pct", "host:cache:high": "cache_pct",
                  "host:vm_storage:high": "vm_pct", "host:user_share:high": "user_pct",
                  "host:rootfs:high": "rootfs_pct", "host:temperature:package": "package_temp_c",
                  "host:temperature:core": "core_max_temp_c"}.get(fp)
        if metric:
            ms = c.execute("select trend from metric_state where metric=?", (metric,)).fetchone()
            if ms:
                ctx["direction"] = ms[0]
    except Exception:  # noqa: BLE001
        pass
    # fase 4: change-correlation + recurrentie — deterministisch, lokaal,
    # 0 LLM. Alleen bereikt voor een daadwerkelijk te versturen bericht
    # (candidate); gezonde runs komen hier nooit.
    try:
        import hermes_changes as hc
        ccfg = hc.load_cfg()
        exclude_key = fp.split(":")[1] if fp.startswith("docker:") and \
            (":restarts" in fp or ":exited" in fp) else None
        ch = hc.correlate(c, hc.now_iso(), exclude_key=exclude_key, cfg=ccfg)
        if ch:
            ctx["recent_changes"] = ch
        rec = hc.recurrence(c, fp, label=title_for(fp, None).lower(), cfg=ccfg)
        if rec:
            ctx["recurrence"] = rec
    except Exception:  # noqa: BLE001 — context is best-effort
        pass
    return ctx


def load_nrow(c, fp):
    """Notificatie-state voor één fingerprint (of None)."""
    r = c.execute("select last_notified_at, last_notified_severity, last_notified_state,"
                  " notification_count, ever_notified, resolved_notified, pending,"
                  " retry_count, next_retry_at, pending_json from notifications"
                  " where fingerprint=?", (fp,)).fetchone()
    if not r:
        return None
    return {"last_notified_at": r[0], "last_notified_severity": r[1],
            "last_notified_state": r[2], "notification_count": r[3] or 0,
            "ever_notified": r[4] or 0, "resolved_notified": r[5] or 0,
            "pending": r[6] or 0, "retry_count": r[7] or 0, "next_retry_at": r[8],
            "pending_json": r[9]}


def load_dsi(c, fp):
    """DUMBscope-context voor een fingerprint (of None)."""
    d = c.execute("select title, severity, root_cause_service, affected_services,"
                  " occurrences from dumbscope_incidents where fingerprint=?",
                  (fp,)).fetchone()
    if not d:
        return None
    return {"title": d[0], "severity": d[1], "root_cause": d[2],
            "affected": json.loads(d[3]) if d[3] else [], "occurrences": d[4]}


STALE_PENDING_S = 24 * 3600  # oudere vastgelegde transities zijn vervallen


def run_pending_transitions(c, cfgn, now, *, samples_db_path, audit_path, token, chat,
                            sender, events, stats, notified_this_run):
    """Replay-veiligheid (fase 3-fix): transitie die de evaluator tijdens een
    sample-replay heeft vastgelegd (bijv. critical dat binnen dezelfde run al
    weer resolved raakte) hier alsnog door de policy halen. Geen eigen
    state-machine: decide()/deliver()/dedup/cooldowns zijn precies dezelfde
    paden als de state-pass hieronder; die ziet daarna verse last_notified_*-
    velden en blijft door cooldowns stil (geen dubbele berichten)."""
    rows = c.execute("select id, fingerprint, ts, event_type, severity, reason"
                     " from pending_transitions order by id").fetchall()
    for (pid, fp, ts, etype, sev, reason) in rows:
        c.execute("delete from pending_transitions where id=?", (pid,))
        if fp.startswith("notifications:"):
            continue
        ts_dt = parse_ts(ts)
        if ts_dt and (now - ts_dt).total_seconds() > STALE_PENDING_S:
            continue  # vervallen transitie (notifier lang niet gedraaid): nooit insets
        irow = c.execute("select first_seen, occurrences, last_value, peak_value,"
                         " last_reason from incidents where fingerprint=?", (fp,)).fetchone()
        if irow is None:
            stats["skipped"] += 1
            continue
        inc = {"fingerprint": fp, "state": "active", "current_severity": sev or "warning",
               "first_seen": irow[0], "occurrences": irow[1] or 1, "last_value": irow[2],
               "peak_value": irow[3], "last_reason": reason or irow[4] or ""}
        nrow = load_nrow(c, fp)
        event, why = decide(inc, nrow, cfgn, now)
        if event is None:
            stats["skipped"] += 1
            continue
        stats["candidates"] += 1
        dsi = load_dsi(c, fp)
        ctx = gather_context(samples_db_path, c, fp)
        text = build_text(fp, inc, dsi, ctx, event)
        ok = deliver(c, fp=fp, inc=inc, nrow=nrow, event=event, text=text, cfgn=cfgn,
                     audit_path=audit_path, token=token, chat=chat, sender=sender,
                     events=events)
        if ok:
            notified_this_run.add(fp)
        stats["sent" if ok else "failed"] += 1
        c.commit()


def run_notifications(cfg=None, *, home=None, state_db_path=None, samples_db_path=None,
                      sender=None):
    """Verwerk huidige incident-state -> Telegram volgens policy. Idempotent:
    alleen state-transities en cooldowns bepalen of er iets gaat."""
    home = Path(home) if home else HOME
    state_db_path = Path(state_db_path) if state_db_path else home / "homelab" / "agent_state.db"
    samples_db_path = Path(samples_db_path) if samples_db_path else home / "homelab" / "samples.db"
    audit_path = home / "homelab" / AUDIT_NAME
    cfgn = load_cfg(home)
    sender = sender or telegram_send
    stats = {"candidates": 0, "sent": 0, "skipped": 0, "failed": 0, "retried": 0}
    if not cfgn.get("enabled", True) or not state_db_path.exists():
        stats["skipped"] = 1
        return stats
    now = now_dt()
    token, chat = load_creds(home)
    events = []
    c = sqlite3.connect(state_db_path, timeout=10)
    c.execute("pragma busy_timeout=5000")
    ensure_schema(c)
    # 0) tijdens replay vastgelegde transities eerst (policy identiek aan de
    #    state-pass; daarna blijven cooldowns duplicates blokkeren)
    notified_this_run = set()
    run_pending_transitions(c, cfgn, now, samples_db_path=samples_db_path,
                            audit_path=audit_path, token=token, chat=chat,
                            sender=sender, events=events, stats=stats,
                            notified_this_run=notified_this_run)
    rows = c.execute("select fingerprint, state, current_severity, first_seen, occurrences,"
                     " last_value, peak_value, last_reason from incidents"
                     " where state in ('active','recovering','resolved')"
                     " and fingerprint not like 'notifications:%'"
                     " and (source is null or source != 'llm')"
                     " order by last_changed").fetchall()
    for (fp, state, sev, first_seen, occ, val, peak, reason) in rows:
        inc = {"fingerprint": fp, "state": state, "current_severity": sev or "normal",
               "first_seen": first_seen, "occurrences": occ or 1, "last_value": val,
               "peak_value": peak, "last_reason": reason}
        if fp in notified_this_run and inc["state"] == "resolved":
            # transitie-alert ging deze run al uit en het episode eindigde nog
            # vóór de notifier: herstelbericht zou een directe duplicaat zijn.
            # resolved_notified alsnog bevestigen (zelde semantiek als een
            # gewone recovery-delivery), zodat heropennen normaal blijft werken.
            c.execute("update notifications set resolved_notified=1,"
                      " last_notified_state='resolved', updated_at=? where fingerprint=?",
                      (iso(now), fp))
            c.commit()
            stats["skipped"] += 1
            continue
        nrow = load_nrow(c, fp)
        # 1) pending retry eerst (fail-safe: niet-afgeleverde meldingen blijven staan)
        if nrow and nrow["pending"] and nrow["next_retry_at"]:
            due = parse_ts(nrow["next_retry_at"])
            if due and due <= now:
                stats["candidates"] += 1
                stats["retried"] += 1
                text = nrow.get("pending_json") or build_text(
                    fp, inc, None, {}, "retry")  # lege pending -> herbouw (deterministisch)
                ok = deliver(c, fp=fp, inc=inc, nrow=nrow, event="retry", text=text,
                             cfgn=cfgn, audit_path=audit_path, token=token, chat=chat,
                             sender=sender, events=events)
                stats["sent" if ok else "failed"] += 1
                c.commit()
            continue
        event, why = decide(inc, nrow, cfgn, now)
        if event is None:
            stats["skipped"] += 1
            continue
        stats["candidates"] += 1
        dsi = load_dsi(c, fp)
        ctx = gather_context(samples_db_path, c, fp)
        text = build_text(fp, inc, dsi, ctx, event)
        ok = deliver(c, fp=fp, inc=inc, nrow=nrow, event=event, text=text, cfgn=cfgn,
                     audit_path=audit_path, token=token, chat=chat, sender=sender,
                     events=events)
        stats["sent" if ok else "failed"] += 1
        c.commit()
    c.commit()
    c.close()
    stats["self_monitor"] = events
    return stats


# -------------------------------------------------------- transport-test --
def send_test(home=None):
    """§15: één gecontroleerde testmelding. Geen fake CRITICAL."""
    home = Path(home) if home else HOME
    token, chat = load_creds(home)
    text = "✅ Hermes deterministic alerting test — fase 4.5\n\nDeterministisch, zonder LLM."
    ok, mid, err = telegram_send(token, chat, text) if token and chat else (False, None,
                                                                            "geen token/chat in .env")
    audit(home / "homelab" / AUDIT_NAME, fingerprint="notifications:transport_test",
          severity="normal", state="transport_test", event="transport_test",
          attempted=1, delivered=1 if ok else 0, message_id=mid if ok else None,
          error=err, reason="fase 4.5 live smoke-test")
    print(json.dumps({"ok": ok, "message_id": mid, "error": err}))
    return 0 if ok else 1


# ------------------------------------------------------------------ test --
def run_test():
    """14 synthetische cases (§14) + self-monitoring; never echt verzenden."""
    import tempfile
    results = []

    def check(name, cond, detail=""):
        results.append((name, bool(cond), detail))

    sent_log = []
    fail_mode = {"on": False}

    def fake_send(token, chat, text, timeout=15):
        sent_log.append(text)
        if fail_mode["on"]:
            return False, None, "synthetische transportfout"
        return True, f"mid{len(sent_log)}", None

    def mkdb():
        tmp = Path(tempfile.mkdtemp())
        (tmp / "homelab").mkdir(parents=True)
        (tmp / ".env").write_text("TELEGRAM_BOT_TOKEN=123456789:SYNTHETIC_TEST_TOKEN_ONLY\n"
                                  "TELEGRAM_HOME_CHANNEL=12345678\n")
        con = sqlite3.connect(tmp / "homelab" / "agent_state.db")
        con.executescript("""
        create table incidents(fingerprint text primary key, source text, type text,
          state text, current_severity text, previous_severity text, first_seen text,
          last_seen text, last_changed text, resolved_at text, occurrences integer,
          last_value real, peak_value real, last_alert_at text, suppression_until text,
          good_samples integer, last_reason text);
        create table dumbscope_incidents(fingerprint text primary key,
          source_fingerprint text, incident_id text, status text, severity text,
          title text, last_seen_ms integer, resolved_at_ms integer, occurrences integer,
          last_processed_at text, host_correlations text, summary text,
          root_cause_service text, affected_services text, evidence_json text);
        create table metric_state(metric text primary key, last_value real,
          previous_value real, last_ts text, trend text, slope real, sustained_since text,
          peak real, baseline_pending integer);
        create table counters(name text primary key, device text, previous_value real,
          current_value real, delta real, last_checked text);
        """)
        con.commit()
        ensure_schema(con)
        con.commit()
        return tmp, con

    def ins(con, fp, state, sev, source="fast", value=90.0, reason="synthetic",
            first="2026-09-17T10:00:00+00:00"):
        con.execute("insert or replace into incidents values(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (fp, source, "t", state, sev, "normal", first, first, first, None, 1,
                     value, value, first, None, 0, reason))
        con.commit()

    def run(tmp, con):
        n_before = len(sent_log)
        stats = run_notifications({"enabled": True}, home=tmp, sender=fake_send)
        return stats, sent_log[n_before:]

    # 1+2: NORMAL en NOTICE -> geen bericht
    tmp, con = mkdb()
    ins(con, "host:x:normal", "resolved", "normal")
    ins(con, "host:y:notice", "active", "notice")
    st, new = run(tmp, con)
    check("1+2: NORMAL/NOTICE -> geen bericht", not new and st["skipped"] == 2, str(st))

    # 3: nieuw WARNING -> 1 bericht
    ins(con, "host:memory:high", "active", "warning", value=92.0, reason=">=warn sustained(3)")
    st, new = run(tmp, con)
    check("3: nieuw WARNING -> 1 bericht", len(sent_log) == 1 and "RAM usage high" in sent_log[0]
          and "Severity: WARNING" in sent_log[0], str(sent_log)[:120])

    # 4: unchanged WARNING volgende poll -> 0
    st, new = run(tmp, con)
    check("4: unchanged WARNING -> 0 bericht", len(new) == 0, str(sent_log))

    # 5: WARNING -> URGENT -> escalatiebericht (cooldown genegeerd)
    con.execute("update incidents set current_severity='urgent', last_reason='>=urgent sustained'"
                " where fingerprint='host:memory:high'"); con.commit()
    st, new = run(tmp, con)
    check("5: WARNING->URGENT -> 1 escalatie", len(new) == 1 and "Severity: URGENT" in new[0],
          str(new)[:120])

    # 6: URGENT unchanged binnen cooldown -> 0
    st, new = run(tmp, con)
    check("6: URGENT unchanged binnen cooldown -> 0", len(new) == 0, str(sent_log))

    # 7: -> RECOVERING -> 0
    con.execute("update incidents set state='recovering', current_severity='warning'"
                " where fingerprint='host:memory:high'"); con.commit()
    st, new = run(tmp, con)
    check("7: RECOVERING -> 0 bericht", len(new) == 0, str(sent_log))

    # 8: RECOVERING -> RESOLVED -> 1 herstelbericht
    con.execute("update incidents set state='resolved', current_severity='normal',"
                " resolved_at='2026-09-17T12:00:00+00:00' where fingerprint='host:memory:high'")
    con.commit()
    st, new = run(tmp, con)
    check("8: RESOLVED -> 1 herstelbericht", len(new) == 1 and "opgelost" in new[0],
          str(new)[:120])
    con.close()

    # 9: resolved dat nooit gemeld was -> geen herstelbericht
    tmp, con = mkdb()
    ins(con, "host:cache:high", "resolved", "normal")
    st, new = run(tmp, con)
    check("9: resolved zonder eerdere melding -> 0", len(new) == 0, str(sent_log))
    con.close()

    # 10+11: failure -> pending; retry (na verstrijken) -> delivered
    tmp, con = mkdb()
    ins(con, "host:memory:high", "active", "warning")
    fail_mode["on"] = True
    st, new = run(tmp, con)
    row = con.execute("select pending, retry_count, last_error, ever_notified from notifications"
                      " where fingerprint='host:memory:high'").fetchone()
    check("10: Telegram failure -> pending, niet notified",
          len(new) == 1 and row == (1, 1, "synthetische transportfout", 0), str(row))
    con.execute("update notifications set next_retry_at='2026-09-17T00:00:00+00:00'"
                " where fingerprint='host:memory:high'"); con.commit()
    fail_mode["on"] = False
    st, new = run(tmp, con)
    row = con.execute("select pending, ever_notified, telegram_message_id from notifications"
                      " where fingerprint='host:memory:high'").fetchone()
    check("11: retry slaagt -> delivered",
          row is not None and row[0] == 0 and row[1] == 1 and bool(row[2]), str(row))
    con.close()

    # 12: duplicate evaluator-run -> geen duplicates
    tmp, con = mkdb()
    ins(con, "host:cache:high", "active", "critical")
    _, n1 = run(tmp, con)
    _, n2 = run(tmp, con)
    _, n3 = run(tmp, con)
    check("12: duplicate runs -> geen duplicate bericht",
          len(n1) == 1 and len(n2) == 0 and len(n3) == 0, f"{len(n1)}/{len(n2)}/{len(n3)}")
    con.close()

    # 13: DUMBscope critical -> alert met title/services
    tmp, con = mkdb()
    ins(con, "dumbscope:p1", "active", "critical", source="dumbscope")
    con.execute("insert into dumbscope_incidents(fingerprint, source_fingerprint,"
                " incident_id, status, severity, title, last_seen_ms, resolved_at_ms,"
                " occurrences, last_processed_at, host_correlations, root_cause_service,"
                " affected_services) values(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                ("dumbscope:p1", "p1", "i1", "active", "critical", "Plex dumps core",
                 1, None, 3, "t", "[]", "plex", '["plex","sonarr"]'))
    con.commit()
    st, new = run(tmp, con)
    check("13: DUMBscope critical -> alert",
          len(new) == 1 and "Plex dumps core" in new[0] and "sonarr" in new[0],
          str(new)[:140])

    # 14: host critical terwijl DUMBscope down is -> host-alert werkt
    ins(con, "dumbscope:availability", "active", "urgent", source="dumbscope", value=67.0,
        reason="67 polls mislukt")
    ins(con, "host:docker_vdisk:high", "active", "critical", value=96.0)
    n_before = len(sent_log)
    st, new = run(tmp, con)
    host_sent = any("Docker vDisk" in t for t in sent_log[n_before:])
    check("14: host critical naast DUMBscope-down -> host-alert verstuurd",
          host_sent and len(sent_log) == n_before + 2, str(len(sent_log)))
    con.close()

    # bonus §11: 3 opeenvolgende failures -> lokaal delivery-incident, geen recursieve alert
    tmp, con = mkdb()
    ins(con, "host:cache:high", "active", "warning")
    fail_mode["on"] = True
    for _ in range(3):
        con.execute("update notifications set next_retry_at='2026-09-17T00:00:00+00:00'"
                    " where fingerprint='host:cache:high'")
        con.commit()
        run(tmp, con)
    row = con.execute("select state, current_severity from incidents"
                      " where fingerprint='notifications:delivery'").fetchone()
    check("§11: 3 failures -> lokaal delivery-incident",
          row == ("active", "warning"), str(row))
    con.close()

    # ── replay-transities (fase 3-fix): pending_transitions door dezelfde policy ──
    fail_mode["on"] = False  # bonus §11 liet de fail-mode aan; hier moet bezorgd worden
    def add_pending(fp, sev, etype="new", reason="synthetic replay-transitie"):
        con.execute("insert into pending_transitions(fingerprint, ts, event_type,"
                    " severity, reason) values(?,?,?,?,?)",
                    (fp, iso(now_dt()), etype, sev, reason))
        con.commit()

    # A: normal → critical → resolved binnen één replay-run
    tmp, con = mkdb()
    ins(con, "host:memory:high", "resolved", "normal", value=97.0)
    add_pending("host:memory:high", "critical")
    st, new = run(tmp, con)
    check("A1: replay-critical -> alert bezorgd (niet gemist)",
          len(new) == 1 and "Severity: CRITICAL" in new[0], str(new)[:140])
    st, new = run(tmp, con)
    check("A2: episode eindigde binnen dezelfde run -> géén apart herstelbericht (geen duplicaat)",
          len(new) == 0, str(new))
    st, new = run(tmp, con)
    check("A3: geen duplicates", len(new) == 0, str(new))
    con.close()

    # B: warning-transitie -> 1 alert; identieke herhaling -> 0
    tmp, con = mkdb()
    ins(con, "host:memory:high", "active", "warning", value=92.0)
    add_pending("host:memory:high", "warning")
    st, new = run(tmp, con)
    check("B1: nieuwe warning-transitie -> 1 bericht",
          len(new) == 1 and "Severity: WARNING" in new[0], str(new)[:120])
    add_pending("host:memory:high", "warning")  # duplicaat binnen cooldown-periode
    st, new = run(tmp, con)
    check("B2: identieke warning binnen cooldown -> 0", len(new) == 0, str(new))
    con.close()

    # C: bestaande recovery-policy onaangetast (alert eerdere run, geen pending)
    tmp, con = mkdb()
    ins(con, "host:memory:high", "active", "critical")
    st, new = run(tmp, con)
    check("C1: critical via state-pass -> 1 bericht", len(new) == 1, str(new)[:120])
    st, new = run(tmp, con)
    check("C2: unchanged critical binnen cooldown -> 0", len(new) == 0, str(new))
    con.execute("update incidents set state='recovering', current_severity='warning'"
                " where fingerprint='host:memory:high'"); con.commit()
    st, new = run(tmp, con)
    check("C3: recovering -> 0", len(new) == 0, str(new))
    con.execute("update incidents set state='resolved', resolved_at=?"
                " where fingerprint='host:memory:high'", (iso(now_dt()),)); con.commit()
    st, new = run(tmp, con)
    check("C4: resolved -> exact 1 herstelbericht",
          len(new) == 1 and "opgelost" in new[0], str(new)[:120])
    st, new = run(tmp, con)
    check("C5: herstel bevestigd -> 0", len(new) == 0, str(new))
    con.close()

    # D: critical → resolved → critical binnen replay: dedup/reopen-gedrag
    tmp, con = mkdb()
    ins(con, "host:memory:high", "resolved", "normal", value=97.0)
    add_pending("host:memory:high", "critical", "new")
    add_pending("host:memory:high", "critical", "reopened")
    st, new = run(tmp, con)
    crit = [t for t in new if "Severity: CRITICAL" in t]
    rec = [t for t in new if "opgelost" in t]
    check("D1: dubbele critical-transitie -> precies 1 critical-alert (cooldown)",
          len(crit) == 1, f"crit={len(crit)} new={len(new)}")
    check("D2: herstelbericht onderdrukt (same-run) -> totaal 1 bericht",
          len(rec) == 0 and len(new) == 1, f"rec={len(rec)} new={len(new)}")
    st, new = run(tmp, con)
    check("D3: geen vervolgberichten", len(new) == 0, str(new))
    con.close()

    # E: stale pending (notifier lang niet gedraaid) -> nooit insets versturen
    tmp, con = mkdb()
    ins(con, "host:memory:high", "resolved", "normal", value=97.0)
    con.execute("insert into pending_transitions(fingerprint, ts, event_type, severity, reason)"
                " values('host:memory:high', ?, 'new', 'critical', 'oud')",
                ("2026-01-01T00:00:00+00:00",))
    con.commit()
    st, new = run(tmp, con)
    check("E: stale pending-transitie > 24u -> geen bericht, rij opgeruimd",
          len(new) == 0 and con.execute("select count(*) from pending_transitions").fetchone()[0] == 0,
          str(new))
    con.close()

    fails = [r for r in results if not r[1]]
    for name, okk, detail in results:
        print(f"{'PASS' if okk else 'FAIL'}  {name}" + (f"  [{detail}]" if detail and not okk else ""))
    print(f"\n{len(results) - len(fails)}/{len(results)} geslaagd")
    return 0 if not fails else 1


# ------------------------------------------------------------------- main --
def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "run"
    if mode == "test":
        sys.exit(run_test())
    if mode == "send-test":
        sys.exit(send_test())
    if mode == "run":
        print(json.dumps(run_notifications(), ensure_ascii=False, default=str))
        return
    print(f"onbekende mode: {mode}", file=sys.stderr)
    sys.exit(64)


if __name__ == "__main__":
    main()
