from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from scripts.run_service_version_matrix import check_record, override_services, run, run_case

ROOT = Path(__file__).resolve().parents[1]


def test_empty_licensed_manifest_cannot_report_success(tmp_path: Path) -> None:
    manifest = tmp_path / "licensed.json"
    manifest.write_text('{"cases": []}')
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/run_service_version_matrix.py"),
            str(tmp_path / "artifacts"),
            "--manifest",
            str(manifest),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 2
    assert "manifest contains no cases" in result.stderr
    assert not (tmp_path / "artifacts" / "report.json").exists()


@pytest.mark.parametrize("exit_code", [0, 7])
def test_handoff_preserves_exit_code_console_and_summary(tmp_path: Path, exit_code: int) -> None:
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    shutil.copy(ROOT / "scripts/run_qa_handoff.sh", scripts)
    runner = scripts / "run_full_local_qa.sh"
    runner.write_text(f'#!/usr/bin/env bash\necho "QA test output"\nexit {exit_code}\n', encoding="utf-8")
    runner.chmod(0o755)
    destination = tmp_path / "artifacts"
    result = subprocess.run(
        ["bash", str(scripts / "run_qa_handoff.sh"), "full", str(destination)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == exit_code
    assert "QA test output" in (destination / "console.log").read_text()
    summary = (destination / "summary.txt").read_text()
    assert f"exit_code={exit_code}" in summary
    assert "started_utc=" in summary and "finished_utc=" in summary
    assert str(destination) in summary
    assert ("last_console_lines:" in summary) is (exit_code != 0)


@pytest.mark.parametrize(
    "script,args",
    [
        ("run_qa_handoff.sh", ["versions"]),
        ("run_version_qa.sh", []),
    ],
)
def test_handoff_refuses_stale_artifacts(tmp_path: Path, script: str, args: list[str]) -> None:
    stale = tmp_path / "checkpoint.json"
    stale.write_text("old checkpoint")
    result = subprocess.run(
        ["bash", str(ROOT / "scripts" / script), *args, str(tmp_path)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 2
    assert "not empty" in result.stderr
    assert stale.read_text() == "old checkpoint"


def test_compose_override_updates_all_cluster_and_seed_images() -> None:
    config = {
        "services": {
            "server": {"image": "vendor/product:1"},
            "peer": {"image": "vendor/product:1"},
            "seed": {"image": "vendor/product:1"},
            "helper": {"image": "python:3.12.14"},
        }
    }
    result = override_services(config, {"vendor/product:": "vendor/product:2"})
    assert result == {"services": {name: {"image": "vendor/product:2"} for name in ("server", "peer", "seed")}}
    with pytest.raises(ValueError, match="matched no services"):
        override_services(config, {"missing:": "missing:2"})


@pytest.mark.parametrize("resolved", [True, False])
def test_compose_override_waits_for_ready_dependency_before_starting_worker(resolved: bool) -> None:
    config = {
        "services": {
            "core": {"image": "vendor/core:1"},
            "jobservice": {
                "image": "vendor/jobservice:1",
                "depends_on": {"core": {"condition": "service_started", "required": True}} if resolved else ["core"],
            },
        }
    }
    original = json.dumps(config)
    override = override_services(
        config, {"vendor/core:": "vendor/core:2"}, healthy_dependencies={"jobservice": ["core"]}
    )
    dependency = override["services"]["jobservice"]["depends_on"]["core"]
    assert dependency["condition"] == "service_healthy"
    assert dependency.get("required", True) is True
    assert override["services"]["core"]["image"] == "vendor/core:2"
    assert json.dumps(config) == original


@pytest.mark.parametrize("dependencies", [{"missing": ["core"]}, {"worker": ["missing"]}, {"worker": ["other"]}])
def test_compose_override_rejects_unknown_or_undeclared_startup_dependency(dependencies: dict[str, list[str]]) -> None:
    config = {"services": {"core": {}, "other": {}, "worker": {"depends_on": ["core"]}}}
    with pytest.raises(ValueError, match="unknown"):
        override_services(config, {}, healthy_dependencies=dependencies)


def _case() -> dict[str, Any]:
    return {"marker": "is_elastic", "product_key": "opensearch", "expected_version": "2.19.1"}


def _record() -> dict[str, Any]:
    return {
        "is_elastic": True,
        "cve_enumeration": {
            "status": "no_matches",
            "products": [
                {"product_key": "opensearch", "normalized_version": "2.19.1"},
            ],
        },
    }


@pytest.mark.parametrize("status", ["matched", "no_matches"])
def test_release_probe_accepts_confirmed_product_and_version(status: str) -> None:
    record = _record()
    record["cve_enumeration"]["status"] = status
    check_record(_case(), record)


@pytest.mark.parametrize("mutation", ["fingerprint", "vendor", "version", "duplicate", "catalog_error", "missing"])
def test_release_probe_rejects_false_success(mutation: str) -> None:
    record = _record()
    if mutation == "fingerprint":
        record["is_elastic"] = False
    elif mutation == "vendor":
        record["cve_enumeration"]["products"][0]["product_key"] = "elasticsearch"
    elif mutation == "version":
        record["cve_enumeration"]["products"][0]["normalized_version"] = "2.19.10"
    elif mutation == "duplicate":
        record["cve_enumeration"]["products"] *= 2
    elif mutation == "catalog_error":
        record["cve_enumeration"]["status"] = "catalog_error"
    else:
        del record["cve_enumeration"]
    with pytest.raises(AssertionError):
        check_record(_case(), record)


def test_kafka_version_probe_requires_explicit_unsupported_status() -> None:
    case = {"marker": "is_kafka", "unsupported": True}
    check_record(case, {"is_kafka": True, "cve_enumeration": {"status": "unsupported"}})
    with pytest.raises(AssertionError, match="unsupported"):
        check_record(case, {"is_kafka": True, "cve_enumeration": {"status": "no_matches"}})


def test_command_failure_and_timeout_are_logged(tmp_path: Path) -> None:
    log = tmp_path / "failure.log"
    with pytest.raises(RuntimeError, match="exit 9"):
        run([sys.executable, "-c", "print('failure detail'); raise SystemExit(9)"], log, timeout=10)
    assert "failure detail" in log.read_text()
    assert "exit=9" in log.read_text()
    with pytest.raises(subprocess.TimeoutExpired):
        run([sys.executable, "-c", "import time; time.sleep(20)"], log, timeout=1)
    assert "child process group stopped" in log.read_text()


def test_release_runner_preserves_existing_project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from scripts import run_service_version_matrix as matrix

    calls = []

    def fake_run(command: list[str], _log: Path, **_kwargs: Any) -> str:
        calls.append(command)
        if "config" in command:
            return json.dumps({"services": {"server": {"image": "vendor/product:1"}}})
        return "existing-container\n"

    monkeypatch.setattr(matrix, "run", fake_run)
    result = run_case(
        {"id": "product-2", "fixture": "example", "images": {"vendor/": "vendor/product:2"}},
        tmp_path,
        validate_only=False,
    )
    assert result["status"] == "failed"
    assert "already exists" in result["error"]
    assert not any("down" in command or "up" in command for command in calls)


def test_release_runner_cleanup_failure_fails_case(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from scripts import run_service_version_matrix as matrix

    calls = []

    def fake_run(command: list[str], _log: Path, **_kwargs: Any) -> str:
        calls.append(command)
        if "config" in command:
            return json.dumps({"services": {"server": {"image": "vendor/product:1"}}})
        if "up" in command:
            raise RuntimeError("startup failed")
        if "down" in command:
            raise RuntimeError("cleanup failed")
        return ""

    monkeypatch.setattr(matrix, "run", fake_run)
    result = run_case(
        {"id": "product-2", "fixture": "example", "images": {"vendor/": "vendor/product:2"}},
        tmp_path,
        validate_only=False,
    )
    assert result["status"] == "failed"
    assert result["error"] == "startup failed"
    assert result["cleanup_error"] == "cleanup failed"
    assert any("down" in command for command in calls)


def test_release_runner_saves_health_and_oom_evidence_before_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from scripts import run_service_version_matrix as matrix

    calls: list[list[str]] = []
    state = [{"Id": "owned-container", "State": {"OOMKilled": False, "Health": {"Status": "unhealthy"}}}]
    started = False

    def fake_run(command: list[str], _log: Path, **_kwargs: Any) -> str:
        nonlocal started
        calls.append(command)
        if "config" in command:
            return json.dumps({"services": {"server": {"image": "vendor/product:1"}}})
        if "up" in command:
            started = True
            raise RuntimeError("startup failed")
        if "ps" in command:
            return "owned-container\n" if started else ""
        if "inspect" in command:
            assert command == ["docker", "inspect", "owned-container"]
            return json.dumps(state)
        return ""

    monkeypatch.setattr(matrix, "run", fake_run)
    result = run_case(
        {"id": "product-2", "fixture": "example", "images": {"vendor/": "vendor/product:2"}},
        tmp_path,
        validate_only=False,
    )
    assert result["status"] == "failed" and result["error"] == "startup failed"
    assert json.loads((tmp_path / "product-2/container-state.json").read_text()) == state
    assert next(i for i, command in enumerate(calls) if "inspect" in command) < next(
        i for i, command in enumerate(calls) if "down" in command
    )


@pytest.mark.parametrize("affected", [True, False])
def test_release_probe_asserts_real_cve_boundary_not_only_version(affected: bool) -> None:
    case = dict(
        _case(),
        must_match=["CVE-2024-12345"] if affected else [],
        must_not_match=[] if affected else ["CVE-2024-12345"],
    )
    record = _record()
    record["cve_enumeration"]["findings"] = [{"id": "CVE-2024-12345"}] if affected else []
    check_record(case, record)
    record["cve_enumeration"]["findings"] = [] if affected else [{"id": "CVE-2024-12345"}]
    with pytest.raises(AssertionError, match="CVE boundary"):
        check_record(case, record)


@pytest.mark.parametrize("verified", [False, None, "true", 1])
def test_release_probe_never_accepts_unverified_identity(verified: Any) -> None:
    record = dict(_record(), provided_credentials_ok=verified)
    with pytest.raises(AssertionError, match="credentials"):
        check_record(dict(_case(), require_credentials=True), record)


def test_release_probe_accepts_verified_identity() -> None:
    check_record(dict(_case(), require_credentials=True), dict(_record(), provided_credentials_ok=True))


@pytest.mark.parametrize("reported", ["2023-03-20T20:16:18Z", "RELEASE.2023-03-20T20-16-18Z"])
def test_minio_release_identity_accepts_iso_and_release_tag_only_for_same_instant(reported: str) -> None:
    case = dict(_case(), product_key="minio", expected_version="RELEASE.2023-03-20T20-16-18Z")
    record = _record()
    record["cve_enumeration"]["products"] = [{"product_key": "minio", "normalized_version": reported}]
    check_record(case, record)
    record["cve_enumeration"]["products"][0]["normalized_version"] = "2023-03-20T20:16:19Z"
    with pytest.raises(AssertionError, match="expected version"):
        check_record(case, record)


@pytest.mark.parametrize(
    ("state", "restarts", "service"),
    [
        ({"Status": "dead"}, 0, "server"),
        ({"Status": "running", "OOMKilled": True}, 0, "server"),
        ({"Status": "restarting"}, 3, "server"),
        ({"Status": "exited", "ExitCode": 1}, 0, "seed"),
    ],
)
def test_release_readiness_fails_fast_on_terminal_state_or_seed_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, state: dict[str, Any], restarts: int, service: str
) -> None:
    from scripts import run_service_version_matrix as matrix

    def fake_run(command: list[str], _log: Path, **_kwargs: Any) -> str:
        if "ps" in command:
            return "owned-container"
        return json.dumps(
            [
                {
                    "Name": "/owned-container",
                    "State": state,
                    "RestartCount": restarts,
                    "Config": {"Labels": {"com.docker.compose.service": service}},
                }
            ]
        )

    monkeypatch.setattr(matrix, "run", fake_run)
    with pytest.raises(RuntimeError, match="startup failed"):
        matrix.wait_ready(["docker", "compose"], {"services": {"server": {}}}, tmp_path / "ready.log", 20)


def test_release_readiness_accepts_recovered_healthy_service(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from scripts import run_service_version_matrix as matrix

    def fake_run(command: list[str], _log: Path, **_kwargs: Any) -> str:
        if "ps" in command:
            return "owned-container"
        return json.dumps(
            [
                {
                    "Name": "/owned-container",
                    "RestartCount": 4,
                    "State": {"Status": "running", "Health": {"Status": "healthy"}},
                    "Config": {},
                }
            ]
        )

    monkeypatch.setattr(matrix, "run", fake_run)
    matrix.wait_ready(["docker", "compose"], {"services": {"server": {}}}, tmp_path / "ready.log", 20)
