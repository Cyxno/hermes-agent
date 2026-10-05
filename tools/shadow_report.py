#!/usr/bin/env python3
"""Shadow-validatierapport: v1 vs Hermes v2, noise-funnel en classificatie.

Read-only. Werkt zowel op de host (via docker exec) als in de v2-container.

Gebruik (in de hermes-v2 container, of op de host met paden gemount):
    python tools/shadow_report.py --v2-db /data/hermes.db \
        --v1-notifications /legacy/homelab/notifications.jsonl \
        --v1-events /legacy/homelab/evaluator-events.jsonl [--window-hours 24]

Output: markdown-rapport met:
- v1 alerts in het venster (per dag/severity/fingerprint)
- v2 candidates / confirmed / suppressed / transients / cancelled
- noise-funnel: raw signals -> notifications-worthy
- classificatieblok voor handmatige beoordeling
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import time
from collections import Counter
from pathlib import Path

SEV_ORDER = {"critical": 0, "urgent": 1, "warning": 2, "notice": 3}


def load_v1_notifications(path: str, since: float) -> list[dict]:
    out = []
    p = Path(path)
    if not p.exists():
        return out
    with p.open(encoding="utf-8", errors="replace") as fh:
        for line in fh:
            try:
                row = json.loads(line)
            except (ValueError, TypeError):
                continue
            ts = row.get("ts") or row.get("timestamp")
            if not ts:
                continue
            try:
                ts = float(ts)
            except (TypeError, ValueError):
                from datetime import datetime

                try:
                    ts = datetime.fromisoformat(str(ts)).timestamp()
                except ValueError:
                    continue
            if ts >= since:
                out.append({**row, "_ts": ts})
    return out


def v2_summary(db_path: str, since: float) -> dict:
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    q = lambda sql, *params: [dict(r) for r in conn.execute(sql, params)]  # noqa: E731

    incidents = q("SELECT * FROM incidents WHERE first_seen >= ?", since)
    events = q("SELECT * FROM incident_events WHERE ts >= ?", since)
    signals = q("SELECT COUNT(*) AS n, COUNT(DISTINCT category) AS cats FROM signals WHERE ts >= ?", since)
    transients = q("SELECT fingerprint, COUNT(*) AS n FROM transients WHERE ts >= ? GROUP BY fingerprint ORDER BY n DESC", since)
    notifications = q("SELECT * FROM notifications WHERE ts >= ?", since)
    audit = q("SELECT * FROM action_audit WHERE ts >= ?", since)
    ai = q("SELECT COUNT(*) AS n FROM ai_calls WHERE ts >= ?", since)

    confirmed = [i for i in incidents if i["state"] in ("CONFIRMED", "ACTIVE", "RESOLVED") and i["confirmed_at"]]
    cancelled = [e for e in events if e["reason"] and "final recheck" in str(e["reason"])]
    suppressed = [i for i in incidents if i["suppressed"]]
    roots = [i for i in incidents if (i["category"] or "").startswith(("storage_degradation", "docker_daemon_down", "project_degradation"))]
    notice_only = [i for i in confirmed if i["severity"] == "notice"]
    would_notify = [i for i in confirmed if i["severity"] in ("warning", "urgent", "critical")]

    return {
        "incidents": incidents,
        "confirmed": confirmed,
        "cancelled_events": cancelled,
        "suppressed": suppressed,
        "roots": roots,
        "notice_only": notice_only,
        "would_notify": would_notify,
        "signal_rows": signals[0]["n"] if signals else 0,
        "signal_categories": signals[0]["cats"] if signals else 0,
        "transients": transients,
        "notifications": notifications,
        "audit": audit,
        "ai_calls": ai[0]["n"] if ai else 0,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--v2-db", default="/data/hermes.db")
    ap.add_argument("--v1-notifications", default="/legacy/homelab/notifications.jsonl")
    ap.add_argument("--window-hours", type=float, default=24.0)
    args = ap.parse_args()

    now = time.time()
    since = now - args.window_hours * 3600

    v1 = load_v1_notifications(args.v1_notifications, since)
    v1_counter = Counter((r.get("fingerprint", "?"), r.get("event", "?")) for r in v1)
    v1_by_day = Counter(time.strftime("%Y-%m-%d", time.gmtime(r["_ts"])) for r in v1)

    v2 = v2_summary(args.v2_db, since)

    print(f"# Shadow-rapport (venster: {args.window_hours:.0f}u, t/m {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime(now))})")
    print()
    print("## v1 productie-notificaties")
    print(f"- totaal: {len(v1)}")
    for day, n in sorted(v1_by_day.items()):
        print(f"  - {day}: {n}")
    print("- top fingerprints:")
    for (fp, event), n in v1_counter.most_common(10):
        print(f"  - {fp} [{event}]: {n}")
    print()
    print("## v2 (shadow)")
    print(f"- raw signal-rows: {v2['signal_rows']} over {v2['signal_categories']} categorieën")
    print(f"- incidenten gezien: {len(v2['incidents'])}")
    print(f"- confirmed (debounce gehaald): {len(v2['confirmed'])}")
    print(f"-  ├── notice-only (nooit notificatie): {len(v2['notice_only'])}")
    print(f"-  └── notification-worthy: {len(v2['would_notify'])}")
    print(f"- suppressed door correlatie: {len(v2['suppressed'])}")
    print(f"- root-incidenten: {len(v2['roots'])}")
    print(f"- final-recheck cancellations: {len(v2['cancelled_events'])}")
    print(f"- transients (stil): {sum(t['n'] for t in v2['transients'])} over {len(v2['transients'])} fingerprints")
    print(f"- AI calls: {v2['ai_calls']}")
    print(f"- executor-auditregels: {len(v2['audit'])}")
    print()
    print("## Noise-funnel")
    raw = v2["signal_rows"]
    worthy = len(v2["would_notify"])
    if raw:
        print(f"- raw signals ({raw}) -> confirmed ({len(v2['confirmed'])}) -> "
              f"notification-worthy ({worthy}): reductie {100 * (1 - worthy / raw):.1f}%")
    print(f"- v1 verstuurde {len(v1)} meldingen in het venster; v2 zou er {worthy} versturen")
    print()
    print("## Classificatie (handmatig beoordelen)")
    print("| v1 fingerprint | v2 equivalent? | classificatie |")
    print("|---|---|---|")
    v2_ids = {i["id"] for i in v2["incidents"]}
    for (fp, _event), _n in v1_counter.most_common(15):
        note = "needs observation"
        if "dumbscope" in fp or "DUMB" in fp or "infinidysk" in fp:
            note = "v2 improvement (legacy-bron verwijderd; vals alarm)"
        print(f"| {fp} | {'ja: ' + fp if fp in v2_ids else 'nee'} | {note} |")
    print()
    print("## v2 candidates zonder v1-tegenhanger (mogelijke false positives)")
    for i in v2["would_notify"]:
        print(f"- {i['id']} [{i['severity']}] first_seen={time.strftime('%m-%d %H:%M', time.gmtime(i['first_seen']))}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
