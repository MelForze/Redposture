from __future__ import annotations

import contextlib
import json
import sqlite3
from pathlib import Path

from sqlalchemy import select

from redposture_core.cli import main
from redposture_core.db.models import Finding
from redposture_core.db.services import DatabaseService
from redposture_core.db.session import session_scope


def test_regular_module_auto_initializes_db_via_env(
    monkeypatch,
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "autoinit.db"
    db_url = f"sqlite:///{db_path}"
    called: list[bool] = []

    def _fake_run_grafana_stage(args, logger) -> int:
        called.append(True)
        assert db_path.exists()
        with contextlib.closing(sqlite3.connect(db_path)) as conn:
            tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        assert "alembic_version" in tables
        assert "workspaces" in tables
        return 0

    monkeypatch.setenv("REDPOSTURE_DB_URL", db_url)
    monkeypatch.setattr("redposture_core.cli.run_grafana_stage", _fake_run_grafana_stage)

    assert main(["grafana", "-t", "127.0.0.1"]) == 0
    assert called == [True]


def test_regular_module_db_auto_init_is_fail_open(
    monkeypatch,
    tmp_path: Path,
    capsys,
) -> None:
    db_path = tmp_path / "autoinit-fail.db"
    db_url = f"sqlite:///{db_path}"
    called: list[bool] = []

    def _fake_run_grafana_stage(args, logger) -> int:
        called.append(True)
        return 0

    def _boom(db_url: str) -> None:
        raise RuntimeError("boom")

    monkeypatch.setenv("REDPOSTURE_DB_URL", db_url)
    monkeypatch.setattr("redposture_core.cli.run_grafana_stage", _fake_run_grafana_stage)
    monkeypatch.setattr("redposture_core.db.services.initialize_runtime_database", _boom)

    assert main(["grafana", "-t", "127.0.0.1", "--debug"]) == 0
    assert called == [True]
    assert "[warn] db auto-init failed: boom" in capsys.readouterr().err


def test_db_show_auto_initializes_empty_database(db_url: str, capsys) -> None:
    assert main(["db", "show", "--db-url", db_url]) == 0
    output = capsys.readouterr().out
    assert "database totals" in output
    assert "modules: shown=" in output


def test_successful_json_module_run_is_auto_ingested(monkeypatch, tmp_path: Path) -> None:
    db_path = tmp_path / "autoinit-ingest.db"
    output_path = tmp_path / "grafana.json"
    db_url = f"sqlite:///{db_path}"

    def _fake_run_grafana_stage(args, logger) -> int:
        _ = logger
        payload = [
            {
                "host": "10.0.0.10",
                "port": 3000,
                "status": "open_no_auth",
                "type": "datasources_dump",
                "datasources": [],
            }
        ]
        Path(args.output).write_text(json.dumps(payload), encoding="utf-8")
        return 0

    monkeypatch.setenv("REDPOSTURE_DB_URL", db_url)
    monkeypatch.setattr("redposture_core.cli.run_grafana_stage", _fake_run_grafana_stage)

    assert (
        main(
            [
                "grafana",
                "-t",
                "127.0.0.1",
                "--format",
                "json",
                "--output",
                str(output_path),
            ]
        )
        == 0
    )

    db_service = DatabaseService(db_url)
    try:
        with session_scope(db_service.session_factory, read_only=True) as session:
            finding = session.scalar(select(Finding).where(Finding.module_name == "grafana"))
            assert finding is not None
    finally:
        db_service.close()
