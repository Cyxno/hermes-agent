"""Legacy Hermes v1 -> v2 migration (spec §47).

Read-only against v1; writes only into the v2 data dir:
- config.yaml          — non-secret v2 config derived from v1 thresholds/policy
- secrets.env          — secret VALUES from v1 .env (0600; wire into container env)
- migration-report.json— what was migrated / optional / obsolete / not migrated

Nothing is removed or modified in the legacy installation.
"""

from __future__ import annotations

import json
import os
import stat
import sys
from typing import Any

import yaml

from .log import info, warning


def _parse_env(path: str) -> dict[str, str]:
    out: dict[str, str] = {}
    if not os.path.exists(path):
        return out
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            out[key.strip()] = value.strip().strip('"').strip("'")
    return out


def _parse_simple_yaml(path: str) -> dict:
    """v1 thresholds.yaml is standard YAML; notifications.yaml likewise."""
    if not os.path.exists(path):
        return {}
    with open(path, encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    return data if isinstance(data, dict) else {}


def _read_v1_incident_stats(legacy_home: str) -> dict:
    """WAL-mode sqlite can refuse read-only opens on a read-only dir; copy first."""
    db_path = os.path.join(legacy_home, "homelab", "agent_state.db")
    if not os.path.exists(db_path):
        return {}
    import shutil
    import sqlite3
    import tempfile

    try:
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
            tmp_path = tmp.name
        shutil.copy2(db_path, tmp_path)
        conn = sqlite3.connect(tmp_path, timeout=10)
        conn.row_factory = sqlite3.Row
        rows = conn.query("SELECT category, COUNT(*) AS n FROM incidents GROUP BY category")
        total = conn.one("SELECT COUNT(*) AS n FROM incidents")
        open_n = conn.one("SELECT COUNT(*) AS n FROM incidents WHERE state != 'RESOLVED'")
        conn.close()
        os.unlink(tmp_path)
        return {
            "total": int(total["n"]) if total else 0,
            "open": int(open_n["n"]) if open_n else 0,
            "by_category": {r["category"]: int(r["n"]) for r in rows},
        }
    except Exception as exc:  # noqa: BLE001 - stats are best-effort
        warning("migrate", "v1 incident stats niet leesbaar", error=str(exc)[:160])
        return {}


def migrate_legacy(legacy_home: str, v2_config_path: str | None, dry_run: bool = False) -> dict:
    legacy_home = os.path.abspath(legacy_home)
    report: dict[str, Any] = {"legacy_home": legacy_home, "dry_run": dry_run}

    env = _parse_env(os.path.join(legacy_home, ".env"))
    thresholds = _parse_simple_yaml(os.path.join(legacy_home, "thresholds.yaml"))
    notifications = _parse_simple_yaml(os.path.join(legacy_home, "notifications.yaml"))

    # ---- secrets: copy values, keep out of config -----------------------
    secret_map = {
        "TELEGRAM_BOT_TOKEN": "TELEGRAM_BOT_TOKEN",
        "TELEGRAM_HOME_CHANNEL": "TELEGRAM_HOME_CHAT_ID",
        "OPENROUTER_API_KEY": "OPENROUTER_API_KEY",
    }
    secrets_out: dict[str, str] = {}
    for old, new in secret_map.items():
        if env.get(old):
            secrets_out[new] = env[old]
    report["secrets_found"] = sorted(secrets_out)

    # ---- desired state ---------------------------------------------------
    v1_thresholds = thresholds.get("docker_daemon", {}) or {}
    known_stopped = v1_thresholds.get("known_stopped", []) or []
    desired = {
        "managed": ["plex", "sonarr", "radarr", "immich_server", "netdata"],
        "retired": sorted(set(known_stopped) | {"DUMB", "decypharr"}),
        "optional": [],
        "ignored": [],
    }
    # never mark the agent's own infra as retired
    desired["retired"] = [e for e in desired["retired"] if e not in desired["managed"]]

    # ---- threshold mapping (v1 live keys: *_pct naming) -------------------
    mem = thresholds.get("memory", {}) or {}
    temps = thresholds.get("temperatures", {}) or {}
    storage = thresholds.get("storage", {}) or {}
    v2_thresholds: dict[str, dict] = {}
    mem_warn = mem.get("warn_pct") or mem.get("warn")
    mem_crit = mem.get("critical_pct") or mem.get("critical") or mem.get("urgent_pct")
    if mem_warn:
        v2_thresholds["host_memory_pct"] = {"warn": mem_warn, "crit": mem_crit or 95}
    pkg = temps.get("package", {}) or {}
    pkg_warn = pkg.get("warn_c") or pkg.get("warn")
    pkg_crit = pkg.get("critical_c") or pkg.get("critical")
    if pkg_warn:
        v2_thresholds["host_package_temp_c"] = {"warn": pkg_warn, "crit": pkg_crit or 98}
    st_warn = storage.get("warn_pct") or storage.get("warn")
    st_crit = storage.get("critical_pct") or storage.get("critical")
    if st_warn:
        v2_thresholds["storage_used_pct"] = {"warn": st_warn, "crit": st_crit or 88}

    # ---- notification policy ----------------------------------------------
    cooldowns = notifications.get("cooldowns", {}) or {}
    first_repeat = {
        sev: {"first": int(cooldowns.get(f"{sev}_first", fallback_first) ) * 60,
              "repeat": int(cooldowns.get(f"{sev}_repeat", fallback_repeat)) * 60}
        for sev, fallback_first, fallback_repeat in
        (("warning", 720, 1440), ("urgent", 240, 480), ("critical", 240, 720))
    }

    config_draft = {
        "mode": "shadow",  # v2 starts in shadow mode per migration policy (spec §48)
        "desired_state": desired,
        "thresholds": v2_thresholds,
        "cooldowns": first_repeat,
        "sources": {
            "beacon": {"enabled": True, "base_url": "http://192.168.1.2:8090",
                       "token": "env:BEACON_AGENT_API_TOKEN"},
            "netdata": {"enabled": True, "base_url": "http://192.168.1.2:19999"},
            "fallback": {"enabled": True, "prometheus_url": "http://192.168.1.2:9090",
                         "ssh_enabled": False},
        },
    }

    report["desired_state"] = desired
    report["thresholds_mapped"] = sorted(v2_thresholds)
    report["cooldowns_mapped"] = sorted(first_repeat)
    report["incident_history"] = _read_v1_incident_stats(legacy_home)
    report["not_migrated"] = [
        "DUMBscope state (infra verwijderd; :8091 dood)",
        "DUMB/InfiniDysk sampler-state en dumb_samples (bron weg)",
        "ArrSight/HOMELAB_SNAPSHOT_URL secrets (infra weg)",
        "monitor.db + cost-calls.jsonl (legacy v1 monitor, dormant)",
        "hermes-agent gateway sessions/kanban/skills (v2 heeft eigen Telegram-interface)",
    ]
    report["must_migrate_manually"] = [
        "Beacon AGENT_API_TOKEN activeren in de Unraid template ( zie docs/MIGRATION.md )",
        "executor SSH-key (agent-operator) koppelen als execution aangezet wordt",
    ]

    if not dry_run:
        v2_data_dir = os.path.dirname(os.path.abspath(v2_config_path or "/data/config.yaml"))
        os.makedirs(v2_data_dir, exist_ok=True)
        target_config = v2_config_path or os.path.join(v2_data_dir, "config.yaml")
        if os.path.exists(target_config):
            backup = target_config + ".pre-migrate"
            with open(backup, "w", encoding="utf-8") as fh:
                fh.write(open(target_config, encoding="utf-8").read())
            report["config_backup"] = backup
        with open(target_config, "w", encoding="utf-8") as fh:
            yaml.safe_dump(config_draft, fh, sort_keys=False)
        secrets_path = os.path.join(v2_data_dir, "secrets.env")
        if secrets_out:
            with open(secrets_path, "w", encoding="utf-8") as fh:
                for key, value in secrets_out.items():
                    fh.write(f"{key}={value}\n")
            os.chmod(secrets_path, stat.S_IRUSR | stat.S_IWUSR)
            report["secrets_env"] = secrets_path
        report["config_written"] = target_config
        info("migrate", "migratie voltooid", config=target_config)
    else:
        report["config_draft"] = config_draft
        info("migrate", "dry-run: niets weggeschreven")

    print(json.dumps({k: v for k, v in report.items() if k != "config_draft"}, indent=2, default=str))
    return report


def main_cli(argv: list[str]) -> int:  # pragma: no cover - CLI wrapper
    import argparse

    parser = argparse.ArgumentParser(prog="hermes-migrate")
    parser.add_argument("--legacy-home", required=True)
    parser.add_argument("--out", default="/data/config.yaml")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)
    migrate_legacy(args.legacy_home, args.out, dry_run=args.dry_run)
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main_cli(sys.argv[1:]))
