"""Exclusive real Proxmox stand contract without booting its heavy image."""

from __future__ import annotations

import fcntl
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / "scripts/run_proxmox_real_qa.py"
SPEC = importlib.util.spec_from_file_location("run_proxmox_real_qa", PATH)
assert SPEC is not None and SPEC.loader is not None
qa = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = qa
SPEC.loader.exec_module(qa)


def test_current_macos_host_is_blocked_before_any_docker_work(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(qa.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(qa, "_run", lambda *_args, **_kwargs: pytest.fail("Docker must not start"))
    with pytest.raises(RuntimeError, match="Linux with /dev/kvm"):
        qa._preflight(tmp_path)


def test_foreign_running_container_blocks_proxmox(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(qa, "_docker_ids", lambda: {"own", "foreign"})
    monkeypatch.setattr(qa, "_own_container_ids", lambda: {"own"})
    with pytest.raises(RuntimeError, match="other container"):
        qa._assert_exclusive()


def test_credential_command_redacts_report_and_keeps_raw_output_private(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(qa, "_assert_exclusive", lambda: None)
    seen: list[list[str]] = []

    def run(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        seen.append(command)
        record = {"host": "127.0.0.1", "status": "token_ok", "is_proxmox": True, "nodes": ["pve"]}
        return subprocess.CompletedProcess(command, 0, json.dumps(record) + "\n", "")

    monkeypatch.setattr(qa, "_run", run)
    row = qa._qa_command("valid", ["-u", "root@pam", "-p", "lab-password"], tmp_path, "lab-password")
    assert seen and "lab-password" in seen[0]
    assert "lab-password" not in row["command"]
    assert row["is_proxmox"] is True and row["nodes_count"] == 1
    assert (tmp_path / "valid.stdout.jsonl").stat().st_mode & 0o777 == 0o600


def test_failed_start_stops_only_own_project_and_preserves_volumes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(qa, "_preflight", lambda _output: {"kvm": True})
    calls: list[tuple[str, ...]] = []

    def compose(*args: str, **_kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(args)
        return subprocess.CompletedProcess(args, 1 if args[0] == "up" else 0, "", "boot failed")

    monkeypatch.setattr(qa, "_compose", compose)
    monkeypatch.setattr(sys, "argv", [str(PATH), str(tmp_path / "report")])
    assert qa.main() == 1
    assert calls == [("up", "-d"), ("down", "--remove-orphans")]
    assert all("-v" not in call and "--volumes" not in call for call in calls)
    result = json.loads((tmp_path / "report/report.json").read_text())
    assert result["status"] == "failed"
    assert "boot failed" not in json.dumps(result)


def test_blocked_host_writes_report_without_starting_docker(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(qa.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(qa, "_compose", lambda *_args, **_kwargs: pytest.fail("Compose must not start"))
    monkeypatch.setattr(sys, "argv", [str(PATH), str(tmp_path / "report")])
    assert qa.main() == 2
    result = json.loads((tmp_path / "report/report.json").read_text())
    assert result["status"] == "blocked"
    assert os.stat(tmp_path / "report/report.json").st_mode & 0o777 == 0o600


def test_second_proxmox_run_is_blocked_by_process_lock(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    lock = tmp_path / "proxmox.lock"
    monkeypatch.setattr(qa, "LOCK", lock)
    monkeypatch.setattr(qa, "_preflight", lambda _output: pytest.fail("Preflight must not run"))
    monkeypatch.setattr(sys, "argv", [str(PATH), str(tmp_path / "report")])
    descriptor = os.open(lock, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        assert qa.main() == 2
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)
    report = json.loads((tmp_path / "report/report.json").read_text())
    assert report["status"] == "blocked"
    assert "another real Proxmox QA" in report["reason"]


def test_real_stand_scenario_orders_proofs_and_cleans_up_qa_identities(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[tuple[str, str]] = []

    def api(path: str, *, method: str = "GET", form: dict[str, str] | None = None, **_kwargs: object):
        seen.append((method, path))
        if path == "/access/ticket":
            return 200, {"data": {"ticket": "ticket", "CSRFPreventionToken": "csrf"}}
        if method == "POST" and "/token/" in path:
            return 200, {"data": {"value": "token-secret"}}
        return 200, {"data": {}}

    def command(name: str, _extra: list[str], _output: Path, _password: str):
        status = "auth_failed" if name.startswith("wrong-") else "auth_required" if name == "anonymous" else "token_ok"
        return {
            "name": name,
            "command": [],
            "duration_seconds": 0.1,
            "exit_code": 0,
            "record_count": 1,
            "status": status,
            "is_proxmox": True,
            "detection_status": "confirmed",
            "nodes_count": 1,
            "ansi_free": True,
            "record": {},
        }

    def plain(command: list[str], **_kwargs: object):
        Path(command[-1]).write_text("PROXMOX 127.0.0.1 [*] Proxmox API\n")
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(qa, "_api_request", api)
    monkeypatch.setattr(qa, "_qa_command", command)
    monkeypatch.setattr(qa, "_run", plain)
    checks: list[dict] = []
    qa._run_checks(tmp_path, "lab-password", checks)
    assert [row["name"] for row in checks] == [
        "anonymous",
        "valid-password",
        "wrong-password",
        "valid-token",
        "wrong-token",
        "limited-valid-password",
        "plain-no-color",
    ]
    assert all(row["passed"] for row in checks)
    assert len([path for method, path in seen if method == "DELETE" and "/token/" in path]) == 1
    assert (
        len([path for method, path in seen if method == "DELETE" and "/users/" in path and "/token/" not in path]) == 1
    )
