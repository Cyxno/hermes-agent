"""Legacy migration: mapping, secret handling, classification report."""

from __future__ import annotations

import yaml


def test_migrate_legacy_dry_run(tmp_path):
    from hermes.migrate import migrate_legacy

    legacy = tmp_path / "legacy-data"
    legacy.mkdir()
    (legacy / ".env").write_text(
        "OPENROUTER_API_KEY=sk-or-test-123\n"
        "TELEGRAM_BOT_TOKEN=123456:ABCdefGhIJKlmNoPQRsTUV\n"
        "TELEGRAM_HOME_CHANNEL=424242\n"
        "HOMELAB_SNAPSHOT_URL=http://dead:8090\n"
    )
    (legacy / "thresholds.yaml").write_text(
        "memory:\n  warn: 90\n  critical: 96\n"
        "temperatures:\n  package:\n    warn: 95\n    critical: 98\n"
        "docker_daemon:\n  known_stopped: [DUMB, hermes]\n"
    )
    report = migrate_legacy(str(legacy), str(tmp_path / "out" / "config.yaml"), dry_run=True)
    assert set(report["secrets_found"]) == {
        "OPENROUTER_API_KEY", "TELEGRAM_BOT_TOKEN", "TELEGRAM_HOME_CHAT_ID"}
    assert "decypharr" in report["desired_state"]["retired"]
    assert "netdata" in report["desired_state"]["managed"]
    assert report["config_draft"]["mode"] == "shadow"
    # dry-run wrote nothing
    assert not (tmp_path / "out").exists()
    # legacy untouched
    assert (legacy / ".env").exists()


def test_migrate_legacy_writes_config_and_chmods_secrets(tmp_path):
    from hermes.migrate import migrate_legacy

    legacy = tmp_path / "legacy-data"
    legacy.mkdir()
    (legacy / ".env").write_text("TELEGRAM_BOT_TOKEN=123456:ABCdefGhIJKlmNoPQRsTUV\n")
    out = tmp_path / "out"
    report = migrate_legacy(str(legacy), str(out / "config.yaml"))
    config = yaml.safe_load((out / "config.yaml").read_text())
    assert config["mode"] == "shadow"
    # secrets live in a separate 0600 file, never in the config
    config_text = (out / "config.yaml").read_text()
    assert "ABCdefGhIJKlmNoPQRsTUV" not in config_text
    secrets = out / "secrets.env"
    assert secrets.exists()
    import stat

    mode = secrets.stat().st_mode
    assert not mode & (stat.S_IRGRP | stat.S_IROTH)
    assert report["not_migrated"]  # explicit obsolete list


def test_migrate_legacy_marks_dead_infra_obsolete(tmp_path):
    from hermes.migrate import migrate_legacy

    legacy = tmp_path / "legacy-data"
    legacy.mkdir()
    report = migrate_legacy(str(legacy), str(tmp_path / "out" / "config.yaml"), dry_run=True)
    joined = " ".join(report["not_migrated"])
    for needle in ("DUMBscope", "InfiniDysk", "ArrSight", "monitor.db"):
        assert needle in joined
