"""Configuration loading, defaults and validation.

Everything time/threshold related is config-driven (spec §8/§9). Secrets are never
stored in the config file: values of the form `env:NAME` are resolved from the
environment at load time.
"""

from __future__ import annotations

import copy
import os
from dataclasses import dataclass, field
from typing import Any

import yaml

from .log import warning

SEVERITIES = ("notice", "warning", "urgent", "critical")


def _severity_rank(s: str) -> int:
    return SEVERITIES.index(s) if s in SEVERITIES else -1


DEFAULTS: dict[str, Any] = {
    "mode": "normal",  # normal | shadow
    "data_dir": "/data",
    "log_level": "info",
    "bind": "127.0.0.1",
    "port": 8643,
    "sources": {
        "beacon": {
            "enabled": True,
            "base_url": "http://127.0.0.1:8090",
            "token": "env:BEACON_AGENT_API_TOKEN",
            "reconcile_docker": True,
        },
        "netdata": {
            "enabled": True,
            "base_url": "http://127.0.0.1:19999",
            "ml_chart": "",
        },
        "fallback": {
            "enabled": True,
            "prometheus_url": "http://127.0.0.1:9090",
            "ssh_enabled": False,
            "ssh_host": "",
            "ssh_key_path": "",
            "ssh_known_hosts": "",
        },
    },
    # Debounce/confirmation windows per signal category, seconds (spec §8).
    # Band-carried categories (threshold metrics) have debounce 0: their
    # confirmation window is the band `sustains` below (single source of truth).
    "debounce": {
        "container_unhealthy": 90,
        "container_exit": 45,
        "container_restart_loop": 300,
        "container_high_cpu": 420,
        "container_memory_pressure": 300,
        "container_memory_leak": 1800,
        "beacon_unavailable": 90,
        "netdata_unavailable": 300,
        "network_errors": 300,
        "filesystem_readonly": 0,
        "disk_missing": 0,
        "array_parity_fault": 0,
        "host_unreachable": 60,
        "beacon_stale": 300,
        "netdata_alarm": 300,
        "band_metric": 0,
    },
    # Sustain windows for band metrics (spec §8/§9): value must stay above warn
    # this long before the band opens (and a signal exists at all).
    "sustains": {
        "host_cpu_pct": 300,
        "host_memory_pct": 300,
        "host_load5_per_core": 300,
        "host_package_temp_c": 180,
        "host_iowait_pct": 180,
        "container_cpu_throttle_pct": 300,
        "container_mem_util_pct": 300,
        "disk_await_ms": 240,
        "storage_used_pct": 300,
        "net_errors_per_s": 300,
        "anomaly_rate": 600,
    },
    # Hysteresis: clear margin (percentage points) + good samples required to clear.
    "hysteresis": {
        "default": {"clear_margin_pp": 5, "good_samples": 2},
        "overrides": {
            "host_cpu_pct": {"clear_margin_pp": 15, "good_samples": 6},
            "container_high_cpu": {"clear_margin_pp": 15, "good_samples": 6},
        },
    },
    # Notification cooldowns in minutes: first message and repeat reminders.
    "cooldowns": {
        "warning": {"first": 720, "repeat": 1440},
        "urgent": {"first": 240, "repeat": 480},
        "critical": {"first": 240, "repeat": 720},
    },
    # Thresholds evaluated by rules (values in native units of each metric).
    "thresholds": {
        "host_memory_pct": {"warn": 90, "crit": 95},
        "host_cpu_pct": {"warn": 85, "crit": 95},
        "host_load5_per_core": {"warn": 2.0, "crit": 4.0},
        "host_package_temp_c": {"warn": 95, "crit": 98},
        "container_cpu_throttle_pct": {"warn": 25, "crit": 60},
        "container_mem_util_pct": {"warn": 90, "crit": 97},
        "disk_await_ms": {"warn": 50, "crit": 200},
        "storage_used_pct": {"warn": 80, "crit": 88},
        "net_errors_per_s": {"warn": 1, "crit": 10},
        "anomaly_rate": {"warn": 0.05, "crit": 0.25},
    },
    "transients": {"window": 21600, "threshold_default": 5},
    "correlation": {"storage_window": 600, "storage_min_entities": 3},
    "desired_state": {"managed": [], "optional": [], "retired": [], "ignored": []},
    "ai": {
        "enabled": True,
        "base_url": "https://openrouter.ai/api/v1",
        "api_key": "env:OPENROUTER_API_KEY",
        "tier1_model": "inclusionai/ling-3.0-flash",
        "tier2_model": "deepseek/deepseek-v4-flash-0731",
        "confidence_stop": 0.85,
        "max_calls_per_incident": 3,
        "max_calls_per_day": 8,
        "max_context_chars": 8000,
    },
    "executor": {
        # disabled -> no actions at all (safe default install, spec §44)
        # dry-run  -> log what would be done (spec §49)
        # guarded  -> real actions, gated by policy/approvals
        "mode": "dry-run",
        "transport": "ssh-operator",
        "ssh_host": "",
        "ssh_key_path": "",
        "ssh_known_hosts": "",
        "max_attempts_per_incident": 2,
        "approval_ttl": 600,
    },
    "telegram": {
        "enabled": True,
        "bot_token": "env:TELEGRAM_BOT_TOKEN",
        "home_chat_id": "env:TELEGRAM_HOME_CHAT_ID",
        "debug_chat_id": "",
        "allowed_usernames": [],
        "allowed_chat_ids": [],
        "min_severity": "warning",
        "notify_recovery": True,
        "daily_summary_hour": 8,
        "poll_timeout": 50,
    },
    "scheduler": {
        "fast_interval": 60,
        "reconcile_interval": 300,
        "baseline_interval": 900,
        "daily_hour": 4,
    },
    "retention": {
        "signals_days": 14,
        "transients_days": 14,
        "incidents_days": 90,
        "audit_days": 180,
    },
}


def _deep_merge(base: dict, override: dict) -> dict:
    out = copy.deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = copy.deepcopy(value)
    return out


def resolve_secret(value: Any) -> Any:
    """Resolve `env:NAME` references; empty string stays empty (feature off)."""
    if isinstance(value, str) and value.startswith("env:"):
        name = value[4:]
        resolved = os.environ.get(name, "")
        if not resolved:
            warning("config", "secret env var empty or missing", env=name)
        return resolved
    return value


# Environment overrides wired to the Unraid CA template (unraid/hermes-agent.xml).
ENV_OVERRIDES = {
    "HERMES_MODE": ("mode", str),
    "HERMES_EXECUTOR_MODE": ("executor.mode", str),
    "HERMES_LOG_LEVEL": ("log_level", str),
    "HERMES_BEACON_URL": ("sources.beacon.base_url", str),
    "HERMES_NETDATA_URL": ("sources.netdata.base_url", str),
    "HERMES_PROMETHEUS_URL": ("sources.fallback.prometheus_url", str),
    "HERMES_DATA_DIR": ("data_dir", str),
}


def _apply_env_overrides(cfg: dict) -> list[str]:
    applied = []
    for env_name, (path, caster) in ENV_OVERRIDES.items():
        raw_value = os.environ.get(env_name, "")
        if not raw_value:
            continue
        node = cfg
        parts = path.split(".")
        for part in parts[:-1]:
            node = node.setdefault(part, {})
        node[parts[-1]] = caster(raw_value)
        applied.append(path)
    allowed = os.environ.get("HERMES_TG_ALLOWED", "")
    if allowed:
        cfg.setdefault("telegram", {})["allowed_usernames"] = [
            u.strip().lstrip("@") for u in allowed.split(",") if u.strip()
        ]
    return applied


@dataclass
class Config:
    raw: dict[str, Any] = field(default_factory=dict)
    path: str | None = None

    def __post_init__(self) -> None:
        merged = _deep_merge(DEFAULTS, self.raw)
        self.raw = merged
        # resolve env-referenced secrets once
        for section, key in (
            ("sources.beacon", "token"),
            ("ai", "api_key"),
            ("telegram", "bot_token"),
            ("telegram", "home_chat_id"),
            ("telegram", "debug_chat_id"),
        ):
            node: dict[str, Any] = self.raw
            for part in section.split("."):
                node = node[part]
            node[key] = resolve_secret(node[key])

    # -- convenience accessors -------------------------------------------
    @property
    def mode(self) -> str:
        return str(self.raw["mode"])

    @property
    def shadow(self) -> bool:
        return self.mode == "shadow"

    def section(self, path: str) -> dict[str, Any]:
        node: Any = self.raw
        for part in path.split("."):
            node = node[part]
        return node

    def debounce_seconds(self, category: str) -> float:
        d = self.section("debounce")
        return float(d.get(category, 0))

    def hysteresis_for(self, metric: str) -> dict[str, int]:
        h = self.section("hysteresis")
        override = h.get("overrides", {}).get(metric, {})
        merged = dict(h["default"])
        merged.update(override)
        return merged

    def validate(self) -> list[str]:
        """Return a list of configuration problems (non-fatal warnings)."""
        problems: list[str] = []
        if self.mode not in ("normal", "shadow"):
            problems.append(f"unknown mode {self.mode!r}")
        if self.raw["executor"]["mode"] not in ("disabled", "dry-run", "guarded"):
            problems.append(f"unknown executor mode {self.raw['executor']['mode']!r}")
        if self.shadow and self.raw["executor"]["mode"] == "guarded":
            problems.append("shadow mode forces executor dry-run; guarded not allowed")
        beacon = self.raw["sources"]["beacon"]
        if beacon["enabled"] and not beacon["token"]:
            problems.append("beacon enabled but no token (Agent API will be DISABLED)")
        if self.raw["telegram"]["enabled"] and not self.raw["telegram"]["bot_token"]:
            problems.append("telegram enabled but no bot token")
        for sev in ("warning", "urgent", "critical"):
            if sev not in self.raw["cooldowns"]:
                problems.append(f"missing cooldown for severity {sev}")
        return problems


def load_config(path: str | None) -> Config:
    if not path:
        raw = {}
        _apply_env_overrides(raw)
        return Config(raw=raw)
    with open(path, encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    if not isinstance(data, dict):
        raise ValueError(f"config {path} must be a mapping")
    _apply_env_overrides(data)
    return Config(raw=data, path=path)
