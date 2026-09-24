#!/usr/bin/env python3
"""hermes_infinidysk.py — deterministische per-bestand repair-loop-detectie
voor InfiniDysk/NzbWebDAV (fase 7). Uitsluitend read-only.

Bron: het bestaande InfiniDysk-hostlog, in de Hermes-container read-only
gemount (user.scripts evaluator fast/deep: /mnt/user/appdata/DUMB/log ->
/opt/dumblog). Deze module bevat uitsluitend pure functies: regelparser,
pad-normalisatie/fingerprint en cursor-beheer. State en policy staan in
hermes_evaluator.py (run_infinidysk) — zelfde splitsing als
hermes_dumbscope.py vs run_dumbscope.

Geen LLM, geen Telegram, geen remediation, geen writes buiten de
Hermes-state-db. Detectie is volledig deterministisch; een gezonde run
produceert geen events en veroorzaakt 0 LLM-calls.

Herkende regels (uit het echte log, zie AUDIT-20260921-INFINIDYSK-DECPHARR):
  repair-START (telt in het rolling window):
    "... Health check classified <pad> as failed: <reden> Starting repair."
    "... Scheduled dynamic repair for <pad>"
    "... Performing urgent dynamic repair for <pad>"
  faalrede (uitsluitend context, telt niet als start):
    "... PAR2 repair error for <pad> Reason: <reden>"
    "... PAR2 repair infeasible for <pad> Reason: <reden>"
    "... Health check classified <pad> as failed: <reden>"   (zonder start)

Fingerprint-semantiek: licht verschillende paden van dezelfde file (hoofd-
letters, categorieworTEL /content/<cat>/, dubbele slashes, kopie-suffix
" (2)" op de releasedir) krijgen dezelfde fingerprint. Een andere release- of
bestandsnaam is een ander incident.
"""
import hashlib
import re
from datetime import datetime, timezone
from pathlib import Path

_TS_RE = re.compile(r"^([A-Z][a-z]{2}) (\d{2}), (\d{4}) (\d{2}):(\d{2}):(\d{2}) - ")
MONTHS = {"Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
          "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12}
DEFAULT_TZ = "Europe/Amsterdam"  # DUMB-container schrijft lokale tijd (TZ-env)
_TZ_CACHE = {"name": None, "tz": None}


def _tz(tz_name):
    """ZoneInfo met cache; valt terug op UTC als zoneinfo/tzdata ontbreekt
    (dan is de offset verkeerd bij niet-UTC-log, maar detectie blijft werkend)."""
    tz_name = tz_name or "UTC"
    if _TZ_CACHE["name"] != tz_name:
        try:
            from zoneinfo import ZoneInfo
            tz = ZoneInfo(tz_name)
        except Exception:  # noqa: BLE001 — fallback houdt detectie werkend
            tz = timezone.utc
        _TZ_CACHE["name"] = tz_name
        _TZ_CACHE["tz"] = tz
    return _TZ_CACHE["tz"]

# repair-STARTS (rolling window)
URGENT_RE = re.compile(r"Performing urgent dynamic repair for (.+?)\s*$")
DYNAMIC_RE = re.compile(r"Scheduled dynamic repair for (.+?)\s*$")
HEALTH_START_RE = re.compile(
    r"Health check classified (.+?) as failed: (.*?) Starting repair\.\s*$")
# faalredenen (context)
RESULT_RE = re.compile(r"PAR2 repair (?:error|infeasible) for (.+?) Reason: (.+?)\s*$")
HEALTH_ONLY_RE = re.compile(r"Health check classified (.+?) as failed: (.*?)\s*$")

START_KINDS = ("health", "dynamic", "urgent")


def parse_ts(line, tz_name=DEFAULT_TZ):
    """Log-timestamp (in de lokale tijd van het DUMB-containerlog) ->
    epoch-seconden UTC. None bij onbekende regel."""
    m = _TS_RE.match(line)
    if not m:
        return None
    mon, day, year, hh, mm, ss = m.groups()
    month = MONTHS.get(mon)
    if not month:
        return None
    try:
        t = datetime(int(year), month, int(day), int(hh), int(mm), int(ss),
                     tzinfo=_tz(tz_name))
    except ValueError:
        return None
    return int(t.timestamp())


def parse_line(line, tz_name=DEFAULT_TZ):
    """Herkende regel -> dict(kind, path, reason, ts); None bij geen match.
    kind: health|dynamic|urgent (repair-start) of result (alleen faalrede)."""
    ts = parse_ts(line, tz_name)
    if ts is None:
        return None
    for kind, rx in (("urgent", URGENT_RE), ("dynamic", DYNAMIC_RE),
                     ("health", HEALTH_START_RE)):
        m = rx.search(line)
        if m:
            reason = m.group(2).strip() if kind == "health" else None
            return {"kind": kind, "path": m.group(1).strip(),
                    "reason": reason or None, "ts": ts}
    m = RESULT_RE.search(line)
    if m:
        return {"kind": "result", "path": m.group(1).strip(),
                "reason": m.group(2).strip(), "ts": ts}
    m = HEALTH_ONLY_RE.search(line)
    if m:
        return {"kind": "result", "path": m.group(1).strip(),
                "reason": m.group(2).strip(), "ts": ts}
    return None


def normalize_path(raw):
    """Semantische normalisatie: hoofletters, categorieworTEL, dubbele
    slashes en kopie-suffix ' (N)' op de releasedir worden geneutraliseerd."""
    p = re.sub(r"\s+", " ", (raw or "").strip())
    p = re.sub(r"^/content/[^/]+/", "", p)
    p = p.lower()
    p = re.sub(r"/{2,}", "/", p)
    segs = p.split("/")
    if segs:
        segs[0] = re.sub(r"\s+\(\d+\)$", "", segs[0])
    return "/".join(s for s in segs if s)


def fingerprint(norm):
    """Stabiele korte fingerprint van genormaliseerd pad."""
    return hashlib.sha1(norm.encode("utf-8")).hexdigest()[:16]


def display_name(raw):
    """Leesbare naam: <releasedir>/<bestandsnaam>, begrensd op 120 tekens."""
    p = re.sub(r"\s+", " ", (raw or "").strip())
    p = re.sub(r"^/content/[^/]+/", "", p).strip("/")
    parts = [s for s in p.split("/") if s]
    if len(parts) >= 2:
        return f"{parts[-2]}/{parts[-1]}"[:120]
    return (parts[-1][:120] if parts else "onbekend")


def tail_new_lines(path, cursor, now, initial_backlog_s=86400,
                   max_bytes=8 * 1024 * 1024, tz_name=DEFAULT_TZ):
    """Nieuwe regels sinds cursor; read-only. cursor is een dict
    {"file": pad, "offset": int} of None. Rotatie (ander bestandsnaam):
    rest van het vorige bestand eerst, daarna het nieuwe vanaf 0. Bij een
    ingekort bestand (zelfde naam) wordt vanaf 0 opnieuw gelezen; exact
    dubbele regels worden door de state-db-PK genegeerd (geen dubbele
    tellingen). Eerste waarneming (cursor None): uitsluitend regels binnen
    initial_backlog_s (begrenste backlog, geen historie-vloed). Leest per
    keer max. max_bytes vanaf het einde (steeds vanaf een regelgrens).
    Geeft (regels, nieuwe_cursor, nota)."""
    p = Path(path)
    out = []

    def read_from(fpath, offset):
        try:
            size = fpath.stat().st_size
        except OSError:
            return [], 0
        if offset > size:
            offset = 0
        start = offset
        if size - offset > max_bytes:
            start = max(0, size - max_bytes)
        lines = []
        with fpath.open("r", errors="replace") as f:
            if start:
                f.seek(start)
            if start > offset:
                f.readline()  # half ingesprongen regel overslaan
            for ln in f:
                lines.append(ln.rstrip("\n"))
            return lines, f.tell()

    prev = (cursor or {}).get("file")
    off = int((cursor or {}).get("offset", 0) or 0)
    note = ""
    if prev and prev != str(p):
        prev_lines, _ = read_from(Path(prev), off)
        out.extend(prev_lines)
        off = 0
    if not p.exists():
        return out, {"file": prev, "offset": off}, "log_bestaat_niet"
    lines, end = read_from(p, off if prev == str(p) else 0)
    if cursor is None:
        cutoff = now - int(initial_backlog_s)
        lines = [ln for ln in lines
                 if (ts := parse_ts(ln, tz_name)) is None or ts >= cutoff]
        note = "eerste_waarneming_backlog_begrensd"
    out.extend(lines)
    return out, {"file": str(p), "offset": end}, note
