"""Hermes CLI: daemon, one-shot cycles, legacy migration, diagnostics."""

from __future__ import annotations

import argparse
import asyncio
import os
import sys

from . import version_info
from .config import load_config
from .log import setup_logging


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="hermes", description="Hermes v2 operations agent")
    parser.add_argument("--config", "-c", default=os.environ.get("HERMES_CONFIG", "/data/config.yaml"))
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("daemon", help="start the Hermes daemon")
    once = sub.add_parser("once", help="run one evaluation cycle and exit")
    once.add_argument("kind", choices=["fast", "reconcile", "baseline", "daily"])
    sub.add_parser("version", help="show version information")
    sub.add_parser("validate-config", help="load and validate config")
    migrate = sub.add_parser("migrate-legacy", help="import config/state from Hermes v1")
    migrate.add_argument("--legacy-home", required=True, help="path to v1 data dir (…/appdata/hermes/data)")
    migrate.add_argument("--dry-run", action="store_true")
    once_runbook = sub.add_parser("runbook", help="run a runbook for an incident (dry-run unless --execute)")
    once_runbook.add_argument("incident_id")
    once_runbook.add_argument("--execute", action="store_true",
                              help="allow real execution if policy allows (default dry-run)")

    args = parser.parse_args(argv)
    setup_logging()

    if args.command == "version":
        info = version_info()
        print(f"{info['version']} ({info['git_sha']} built {info['build_time']})")
        return 0

    if args.command == "validate-config":
        cfg = load_config(args.config)
        problems = cfg.validate()
        if problems:
            for problem in problems:
                print(f"PROBLEEM: {problem}")
            return 1
        print("config OK")
        return 0

    if args.command == "daemon":
        from .daemon import run_daemon

        asyncio.run(run_daemon(args.config))
        return 0

    if args.command == "once":
        from .daemon import HermesApp

        cfg = load_config(args.config)
        app = HermesApp(cfg)

        async def _run() -> None:
            if args.kind == "daily":
                await app._daily_maintenance()
            else:
                await app.cycle(args.kind)

        asyncio.run(_run())
        app.db.close()
        return 0

    if args.command == "runbook":
        from .daemon import HermesApp

        cfg = load_config(args.config)
        app = HermesApp(cfg)
        incident = app.engine.get(args.incident_id)
        if incident is None:
            print(f"Onbekend incident: {args.incident_id}")
            return 1
        if not args.execute:
            app.cfg.raw["executor"]["mode"] = "dry-run"
            app.policy.mode = "dry-run"

        async def _run():
            await app.wire_http()
            result = await app.runbooks.run(incident)
            print(f"outcome={result.outcome} runbook={result.runbook}")
            print(result.detail)
            await app.session.close()

        asyncio.run(_run())
        app.db.close()
        return 0

    if args.command == "migrate-legacy":
        from .migrate import migrate_legacy

        migrate_legacy(args.legacy_home, args.config, dry_run=args.dry_run)
        return 0

    parser.error(f"onbekend commando {args.command!r}")
    return 2


if __name__ == "__main__":
    sys.exit(main())
