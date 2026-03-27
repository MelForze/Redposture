#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from collections import Counter
from pathlib import Path

from sqlalchemy import func, select

from redposture_core.db.models import Artifact, Finding, ModuleRun, NetworkEndpoint, RunObservation, TargetHost
from redposture_core.db.services import DatabaseService
from redposture_core.db.session import session_scope


def _run_cli(db_url: str, out_dir: Path, *args: str) -> subprocess.CompletedProcess[str]:
    name = "_".join(args).replace("/", "_").replace(" ", "_")
    log_path = out_dir / f"{name}.txt"
    command = [sys.executable, "redposture.py", *args, "--db-url", db_url]
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    log_path.write_text(result.stdout + ("\n" + result.stderr if result.stderr else ""), encoding="utf-8")
    return result


def _parse_status_file(path: Path) -> tuple[list[dict[str, str]], Counter[str]]:
    rows: list[dict[str, str]] = []
    success = Counter[str]()
    with path.open(encoding="utf-8") as fh:
        next(fh, None)
        for raw in fh:
            raw = raw.rstrip("\n")
            if not raw:
                continue
            module, label, exit_code, json_path, log_path = raw.split("\t")
            row = {
                "module": module,
                "label": label,
                "exit_code": exit_code,
                "json_path": json_path,
                "log_path": log_path,
            }
            rows.append(row)
            if exit_code == "0" and json_path not in {"", "-"}:
                success[module] += 1
    return rows, success


def _has_successful_label(rows: list[dict[str, str]], label: str) -> bool:
    return any(row["label"] == label and row["exit_code"] == "0" and row["json_path"] not in {"", "-"} for row in rows)


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify DB state after lab matrix run.")
    parser.add_argument("--db-url", required=True)
    parser.add_argument("--status-file", required=True)
    parser.add_argument("--out-dir", required=True)
    args = parser.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    db_checks_dir = out_dir / "db_checks"
    db_checks_dir.mkdir(parents=True, exist_ok=True)

    status_rows, successful_modules = _parse_status_file(Path(args.status_file))
    if not status_rows:
        raise SystemExit("matrix status file is empty")
    if not successful_modules:
        raise SystemExit("no successful module runs recorded")

    db = DatabaseService(args.db_url)
    try:
        with session_scope(db.session_factory, read_only=True) as session:
            totals = {
                "module_runs": int(session.scalar(select(func.count(ModuleRun.id))) or 0),
                "observations": int(session.scalar(select(func.count(RunObservation.id))) or 0),
                "hosts": int(session.scalar(select(func.count(TargetHost.id))) or 0),
                "endpoints": int(session.scalar(select(func.count(NetworkEndpoint.id))) or 0),
                "findings": int(session.scalar(select(func.count(Finding.id))) or 0),
                "artifacts": int(session.scalar(select(func.count(Artifact.id))) or 0),
            }
            module_counts = {
                module: int(count)
                for module, count in session.execute(
                    select(ModuleRun.module_name, func.count(ModuleRun.id)).group_by(ModuleRun.module_name)
                ).all()
            }
    finally:
        db.close()

    if totals["module_runs"] == 0 or totals["observations"] == 0:
        raise SystemExit("database did not receive module runs/observations")

    for module in successful_modules:
        if module_counts.get(module, 0) == 0:
            raise SystemExit(f"module {module!r} succeeded in matrix but has no DB module runs")

    summary_path = db_checks_dir / "summary.json"
    summary_path.write_text(
        json.dumps(
            {
                "totals": totals,
                "successful_modules": dict(successful_modules),
                "module_run_counts": module_counts,
            },
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    overview = _run_cli(args.db_url, db_checks_dir, "db", "show", "--json")
    if overview.returncode != 0:
        raise SystemExit("db show --json failed after lab run")

    for module in sorted(successful_modules):
        for command in (
            ("db", "show", module),
            ("db", "show", module, "--hosts"),
            ("db", "show", module, "--endpoints"),
            ("db", "show", module, "--findings"),
            ("db", "show", module, "--runs"),
            ("db", "show", module, "--artifacts"),
        ):
            result = _run_cli(args.db_url, db_checks_dir, *command)
            if result.returncode != 0:
                raise SystemExit(f"{' '.join(command)} failed after lab run")
            if command == ("db", "show", module):
                stdout = result.stdout.lower()
                if f"no recent {module} results" in stdout:
                    raise SystemExit(f"db show {module} returned an empty landing after successful matrix runs")

    if _has_successful_label(status_rows, "exporters_trigger"):
        trigger_text = _run_cli(args.db_url, db_checks_dir, "db", "show", "exporters", "--trigger")
        if trigger_text.returncode != 0:
            raise SystemExit("db show exporters --trigger failed after lab run")
        if "no recent exporter results" in trigger_text.stdout.lower():
            raise SystemExit("db show exporters --trigger returned an empty landing after successful trigger run")
        trigger_json = _run_cli(args.db_url, db_checks_dir, "db", "show", "exporters", "--trigger", "--json")
        if trigger_json.returncode != 0:
            raise SystemExit("db show exporters --trigger --json failed after lab run")
        payload = json.loads(trigger_json.stdout or "{}")
        if int(payload.get("shown", 0)) <= 0:
            raise SystemExit("db show exporters --trigger --json returned no rows after successful trigger run")

    search = _run_cli(args.db_url, db_checks_dir, "db", "search", "password")
    if search.returncode != 0:
        raise SystemExit("db search password failed after lab run")

    backup_path = out_dir / "redposture-backup.sqlite3"
    export_result = _run_cli(args.db_url, db_checks_dir, "db", "export", "database", "--output", str(backup_path))
    if export_result.returncode != 0 or not backup_path.exists():
        raise SystemExit("db export database failed after lab run")

    restore_db_url = f"sqlite:///{out_dir / 'restored-redposture.db'}"
    import_result = _run_cli(
        restore_db_url,
        db_checks_dir,
        "db",
        "import",
        "database",
        "--input",
        str(backup_path),
    )
    if import_result.returncode != 0:
        raise SystemExit("db import database failed on restored DB")

    restored_overview = _run_cli(restore_db_url, db_checks_dir, "db", "show", "--json")
    if restored_overview.returncode != 0:
        raise SystemExit("restored DB show failed")

    print(json.dumps({"totals": totals, "successful_modules": dict(successful_modules)}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
