"""QA startup can avoid repeated work without accepting port conflicts or Docker errors."""

from __future__ import annotations

import json
import os
import shlex
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/run_lab_matrix_sequential.sh"


def _function(name: str) -> str:
    source = SCRIPT.read_text()
    return name + "() {" + source.split(name + "() {", 1)[1].split("\n}\n", 1)[0] + "\n}\n"


def _preflight(tmp_path: Path, *, stale: bool = False, docker_error: bool = False):
    setup = r"""
set -euo pipefail
MATRIX_SERVICES=(redis postgres)
COMPOSE_PROJECT_NAME=qa-test
ROOT_DIR=/repo
OUT_DIR="$QA_TMP"
mkdir -p "$OUT_DIR/logs"
PYTHON_BIN=qa_python
compose_service() { printf '%s\n' "$*" >> "$QA_TMP/compose"; }
collect_lab_ports() { printf '5432\n6379\n'; }
qa_python() { printf '%s\n' "$*" >> "$QA_TMP/port-checks"; }
docker() {
  printf '%s\n' "$*" >> "$QA_TMP/docker"
  if [ "$DOCKER_ERROR" = 1 ]; then return 9; fi
  if [ "$1" = ps ] && [ "${2:-}" = -aq ] && [ "$STALE" = 1 ]; then
    printf 'owned-container\n'
  fi
}
"""
    return subprocess.run(
        ["bash", "-c", setup + _function("preflight_lab_environment") + "\npreflight_lab_environment"],
        env={**os.environ, "QA_TMP": str(tmp_path), "STALE": str(int(stale)), "DOCKER_ERROR": str(int(docker_error))},
        text=True,
        capture_output=True,
        timeout=5,
        check=False,
    )


def test_clean_project_avoids_unneeded_teardown_and_checks_ports_once(tmp_path):
    result = _preflight(tmp_path)
    assert result.returncode == 0, result.stderr
    assert not (tmp_path / "compose").exists()
    assert len((tmp_path / "port-checks").read_text().splitlines()) == 1
    assert (tmp_path / "logs/lab-ports.txt").read_text().splitlines() == ["5432", "6379"]


def test_existing_project_keeps_teardown_scoped_and_preserves_volumes(tmp_path):
    result = _preflight(tmp_path, stale=True)
    assert result.returncode == 0, result.stderr
    assert (tmp_path / "compose").read_text().splitlines() == ["redis down", "postgres down"]
    commands = (tmp_path / "docker").read_text()
    assert "label=com.docker.compose.project=qa-test" in commands
    assert "prune" not in commands


def test_unavailable_daemon_is_not_treated_as_free_ports(tmp_path):
    result = _preflight(tmp_path, docker_error=True)
    assert result.returncode != 0
    assert not (tmp_path / "compose").exists()
    assert not (tmp_path / "port-checks").exists()


def test_normalized_compose_config_is_reused_for_port_collection(tmp_path):
    lab = tmp_path / "lab/services/redis"
    lab.mkdir(parents=True)
    (lab / "docker-compose.yml").write_text("services: {}\n")
    logs = tmp_path / "logs"
    logs.mkdir()
    payload = {"services": {"redis": {"ports": [{"published": "16379", "target": 6379}]}}}
    (logs / "redis-compose.json").write_text(json.dumps(payload))
    setup = f"""
set -euo pipefail
OUT_DIR={shlex.quote(str(tmp_path))}
LAB_DIR="$OUT_DIR/lab"
ROOT_DIR=/repo
PYTHON_BIN={shlex.quote(sys.executable)}
qa_compose_override() {{ printf '/override\n'; }}
docker() {{ printf 'unexpected-docker\n' >&2; return 99; }}
"""
    result = subprocess.run(
        ["bash", "-c", setup + _function("compose_service") + "\ncompose_service redis config --format json"],
        text=True,
        capture_output=True,
        check=False,
        timeout=5,
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == payload


def test_port_snapshot_checks_host_bindings_not_exposed_container_ports():
    from scripts.qa_port_conflicts import find_conflicts

    containers = [
        {
            "Id": "a" * 64,
            "Name": "/user-db",
            "NetworkSettings": {
                "Ports": {
                    "5432/tcp": [{"HostIp": "127.0.0.1", "HostPort": "15432"}, {"HostIp": "::1", "HostPort": "15432"}],
                    "6379/tcp": None,
                }
            },
        },
        {
            "Id": "b" * 64,
            "Name": "/dns",
            "NetworkSettings": {
                "Ports": {
                    "53/udp": [{"HostIp": "0.0.0.0", "HostPort": "16379"}],
                }
            },
        },
    ]
    assert find_conflicts(containers, {5432, 6379}) == []
    assert find_conflicts(containers, {15432, 16379}) == [
        (15432, "a" * 12, "user-db"),
        (16379, "b" * 12, "dns"),
    ]


@pytest.mark.parametrize("payload", [{}, [None], [{"NetworkSettings": None}], [{"NetworkSettings": {"Ports": []}}]])
def test_malformed_inspect_cannot_be_reported_as_free_ports(payload):
    from scripts.qa_port_conflicts import find_conflicts

    with pytest.raises(ValueError):
        find_conflicts(payload, {5432})


def test_empty_and_nil_port_maps_do_not_create_conflicts():
    from scripts.qa_port_conflicts import find_conflicts

    assert find_conflicts([], {5432}) == []
    assert find_conflicts([{"NetworkSettings": {"Ports": None}}], {5432}) == []


@pytest.mark.parametrize("contents", ["", "0\n", "65536\n", "not-a-port\n"])
def test_invalid_requested_ports_fail_before_querying_docker(tmp_path, monkeypatch, contents):
    from scripts import qa_port_conflicts as ports

    requested = tmp_path / "ports.txt"
    requested.write_text(contents)
    snapshot = tmp_path / "inspect.json"

    def unexpected_query():
        raise AssertionError("Docker queried despite invalid port input")

    monkeypatch.setattr(ports, "inspect_running", unexpected_query)
    assert ports.main(["--ports-file", str(requested), "--snapshot", str(snapshot)]) == 2
    assert not snapshot.exists()


def test_port_query_timeout_is_a_failure(tmp_path, monkeypatch):
    from scripts import qa_port_conflicts as ports

    requested = tmp_path / "ports.txt"
    requested.write_text("5432\n")
    snapshot = tmp_path / "inspect.json"

    def timeout():
        raise subprocess.TimeoutExpired(["docker", "ps"], 30)

    monkeypatch.setattr(ports, "inspect_running", timeout)
    assert ports.main(["--ports-file", str(requested), "--snapshot", str(snapshot)]) == 2
    assert not snapshot.exists()


def test_one_malformed_compose_config_cannot_silently_reduce_checked_port_set(tmp_path):
    valid = json.dumps({"services": {"redis": {"ports": [{"published": "6379"}]}}})
    setup = f"""set -euo pipefail
MATRIX_SERVICES=(broken valid)
ROOT_DIR={shlex.quote(str(ROOT))}
PYTHON_BIN={shlex.quote(sys.executable)}
compose_service() {{
 if [ "$1" = broken ]; then printf '{{broken'; else printf '%s' {shlex.quote(valid)}; fi
}}
"""
    result = subprocess.run(
        ["bash", "-c", setup + _function("collect_lab_ports") + "\nif collect_lab_ports; then exit 0; else exit 2; fi"],
        text=True,
        capture_output=True,
        timeout=5,
        check=False,
    )
    assert result.returncode == 2


@pytest.mark.parametrize("exit_code,invalid_json", [(9, False), (0, True), (0, False)])
def test_port_probe_reports_errors_and_conflicts_without_mutations(
    tmp_path, monkeypatch, capsys, exit_code, invalid_json
):
    from scripts import qa_port_conflicts as ports

    requested = tmp_path / "ports.txt"
    requested.write_text("15432\n")
    snapshot = tmp_path / "inspect.json"
    calls = []

    def run(command, **kwargs):
        calls.append(command)
        if exit_code:
            raise subprocess.CalledProcessError(exit_code, command, stderr="daemon unavailable")
        if command[1] == "ps":
            return subprocess.CompletedProcess(command, 0, "owned-id\n", "")
        assert command == ["docker", "inspect", "owned-id"]
        output = (
            "{broken"
            if invalid_json
            else json.dumps(
                [
                    {
                        "Id": "f" * 64,
                        "Name": "/foreign-db",
                        "Config": {"Env": ["PRIVATE_USER_DATA=unrelated"]},
                        "NetworkSettings": {
                            "Ports": {"5432/tcp": [{"HostPort": "15432"}]},
                        },
                    },
                ]
            )
        )
        return subprocess.CompletedProcess(command, 0, output, "")

    monkeypatch.setattr(ports.subprocess, "run", run)
    assert ports.main(["--ports-file", str(requested), "--snapshot", str(snapshot)]) == 2
    output = capsys.readouterr().err
    assert "cannot verify" in output if exit_code or invalid_json else "port=15432" in output
    assert all(command[1] in {"ps", "inspect"} for command in calls)
    assert len(calls) == (1 if exit_code else 2)
    assert snapshot.exists() is (not exit_code and not invalid_json)
    if snapshot.exists():
        assert "Config" not in json.loads(snapshot.read_text())[0]


def test_port_probe_with_no_containers_does_not_call_inspect(tmp_path, monkeypatch, capsys):
    from scripts import qa_port_conflicts as ports

    requested = tmp_path / "ports.txt"
    requested.write_text("15432\n")
    snapshot = tmp_path / "inspect.json"
    calls = []

    def run(command, **kwargs):
        calls.append(command)
        assert command == ["docker", "ps", "-q"]
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(ports.subprocess, "run", run)
    assert ports.main(["--ports-file", str(requested), "--snapshot", str(snapshot)]) == 0
    assert len(calls) == 1
    assert json.loads(snapshot.read_text()) == []
    assert "1 host ports checked" in capsys.readouterr().out


def test_compose_snapshot_preserves_every_field_and_only_changes_container_names(tmp_path):
    config = {
        "name": "qa-test",
        "services": {
            "redis": {
                "container_name": "manual-redis",
                "image": "redis:7.4",
                "build": {"context": "/build"},
                "ports": [{"published": "15432", "target": 5432}],
                "healthcheck": {"test": ["CMD", "redis-cli", "ping"]},
            },
            "seed": {"depends_on": {"redis": {"condition": "service_healthy"}}, "volumes": ["data:/data"]},
        },
        "volumes": {"data": {}},
    }
    destination = tmp_path / "config.json"
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/qa_compose_override.py"),
            "--project",
            "qa-test",
            "--config-output",
            str(destination),
        ],
        input=json.dumps(config),
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    merged = json.loads(destination.read_text())
    assert merged["services"]["redis"]["container_name"] == "qa-test-manual-redis"
    merged["services"]["redis"]["container_name"] = "manual-redis"
    assert merged == config
    assert json.loads(result.stdout) == {"services": {"redis": {"container_name": "qa-test-manual-redis"}}}


@pytest.mark.parametrize(
    "scenario,calls,exit_code",
    [("ready", 1, 0), ("warning", 1, 0), ("starting", 2, 0), ("failed", 1, 1), ("daemon-error", 1, 1)],
)
def test_readiness_queries_compose_once_per_poll_and_keeps_health_gate(tmp_path, scenario, calls, exit_code):
    healthy = [{"Name": "/qa-api", "State": {"Status": "running", "Health": {"Status": "healthy"}}}]
    first = json.loads(json.dumps(healthy))
    if scenario == "starting":
        first[0]["State"]["Health"]["Status"] = "starting"
    elif scenario == "failed":
        first[0]["State"] = {"Status": "exited", "ExitCode": 1}
        first[0]["RestartCount"] = 3
    (tmp_path / "first.json").write_text(json.dumps(first))
    (tmp_path / "healthy.json").write_text(json.dumps(healthy))
    setup = f"""set -euo pipefail
ROOT_DIR={shlex.quote(str(ROOT))}
PYTHON_BIN={shlex.quote(sys.executable)}
QA_TMP={shlex.quote(str(tmp_path))}
OUT_DIR="$QA_TMP"
mkdir -p "$OUT_DIR/logs"
READINESS_ALLOWED_COMPLETED_SERVICES=()
compose_service() {{
 printf '%s\\n' "$*" >> "$QA_TMP/compose-calls"
 if [ {shlex.quote(scenario)} = daemon-error ]; then
   echo 'failed to connect to the docker API' >&2; return 9
 fi
 if [ {shlex.quote(scenario)} = warning ]; then echo 'Compose warning' >&2; fi
 printf 'api-container\\n'
}}
docker() {{
 if [ "$*" != 'inspect api-container' ]; then echo 'unexpected inspect argument' >&2; return 99; fi
 if [ ! -f "$QA_TMP/inspected" ]; then
  touch "$QA_TMP/inspected"; cat "$QA_TMP/first.json"
 else cat "$QA_TMP/healthy.json"; fi
}}
sleep() {{ :; }}
"""
    result = subprocess.run(
        ["bash", "-c", setup + _function("wait_healthy_service") + "\nwait_healthy_service qa-api 6"],
        text=True,
        capture_output=True,
        timeout=5,
        check=False,
    )
    assert result.returncode == exit_code, result.stdout + result.stderr
    assert len((tmp_path / "compose-calls").read_text().splitlines()) == calls
