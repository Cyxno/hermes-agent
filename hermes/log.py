"""Structured JSON-lines logging with a final-line secret sanitizer.

Fields used consistently across Hermes (spec §54):
    ts, level, component, incident_id, source, entity, state, action,
    runbook, ai_model, confidence, result, duration
"""

from __future__ import annotations

import json
import logging
import sys
from typing import Any

from .util import sanitize


class JsonlFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname.lower(),
            "component": record.name,
            "msg": sanitize(record.getMessage()),
        }
        for key, value in getattr(record, "fields", {}).items():
            payload[key] = sanitize(value) if isinstance(value, str) else value
        if record.exc_info and record.exc_info[0] is not None:
            payload["exc"] = sanitize(repr(record.exc_info[1]), limit=300)
        return json.dumps(payload, default=str)


def setup_logging(level: str = "info", stream: Any = None) -> None:
    root = logging.getLogger()
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    root.handlers.clear()
    handler = logging.StreamHandler(stream or sys.stdout)
    handler.setFormatter(JsonlFormatter())
    root.addHandler(handler)


def log(component: str, level: str, msg: str, **fields: Any) -> None:
    logging.getLogger(component).log(
        getattr(logging, level.upper(), logging.INFO), msg, extra={"fields": fields}
    )


def info(component: str, msg: str, **fields: Any) -> None:
    log(component, "info", msg, **fields)


def warning(component: str, msg: str, **fields: Any) -> None:
    log(component, "warning", msg, **fields)


def error(component: str, msg: str, **fields: Any) -> None:
    log(component, "error", msg, **fields)
