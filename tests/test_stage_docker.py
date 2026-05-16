from __future__ import annotations

import argparse
import json
from typing import Any

import pytest

from redposture_core import stage_docker as docker_stage


class _FakeDockerClient:
    def version(self) -> dict[str, Any]:
        return {"Version": "25.0.5", "ApiVersion": "1.45", "Os": "linux"}

    def info(self) -> dict[str, Any]:
        return {"Containers": 1, "ContainersRunning": 1, "Images": 1, "OperatingSystem": "Lab Linux"}

    def containers(self) -> list[dict[str, Any]]:
        return [{"Id": "abcdef1234567890", "Names": ["/web"], "Image": "nginx", "State": "running", "Status": "Up"}]

    def images(self) -> list[dict[str, Any]]:
        return [{"Id": "sha256:abc", "RepoTags": ["nginx:latest"], "Size": 42}]

    def networks(self) -> list[dict[str, Any]]:
        return [{"Id": "net1", "Name": "bridge", "Driver": "bridge", "Scope": "local"}]

    def volumes(self) -> list[dict[str, Any]]:
        return [{"Name": "data", "Driver": "local", "Mountpoint": "/data"}]

    def system_df(self) -> dict[str, Any]:
        return {"LayersSize": 42, "Images": [{}], "Containers": [{}], "Volumes": [{}]}

    def exec_command(self, container_id: str, command: str) -> dict[str, Any]:
        return {"exec_id": "exec1", "stdout": "ok\n", "stderr": "", "exit_code": 0, "running": False}


def _args(**overrides: object) -> argparse.Namespace:
    base = {
        "targets": "127.0.0.1",
        "hosts": None,
        "port": 2375,
        "ports": None,
        "_docker_port_explicit": True,
        "timeout": 1.0,
        "workers": 1,
        "retries": 0,
        "insecure": False,
        "tls_ca": None,
        "tls_cert": None,
        "tls_key": None,
        "containers": False,
        "images": False,
        "networks": False,
        "volumes": False,
        "system": False,
        "container": None,
        "exec_cmd": None,
        "output": None,
        "output_format": "txt",
        "debug": False,
        "log": None,
    }
    base.update(overrides)
    return argparse.Namespace(**base)


def _patch_probe(monkeypatch: pytest.MonkeyPatch, *, transport: str = "plaintext") -> None:
    def fake_probe(*_args, **_kwargs):
        return _FakeDockerClient(), {"Version": "25.0.5", "ApiVersion": "1.45", "Os": "linux"}, transport, None, False

    monkeypatch.setattr(docker_stage, "_probe_docker", fake_probe)


def test_audit_docker_host_inventory_and_exec(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_probe(monkeypatch)
    record = docker_stage._audit_docker_host(
        "127.0.0.1",
        2375,
        1.0,
        0,
        show_containers=True,
        show_images=True,
        show_networks=True,
        show_volumes=True,
        show_system=True,
        container_selector="web",
        exec_cmd="id",
    )
    assert record["status"] == "open_no_auth"
    assert record["is_docker"] is True
    assert record["containers"][0]["Names"] == ["/web"]
    assert record["exec_result"]["stdout"] == "ok\n"
    assert record["capabilities"]["can_exec"] is True


def test_exec_only_does_not_render_inventory_or_unrequested_zero_counts(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_probe(monkeypatch)
    record = docker_stage._audit_docker_host(
        "127.0.0.1",
        2375,
        1.0,
        0,
        container_selector="web",
        exec_cmd="whoami",
    )
    status_line = docker_stage._format_record(record, "txt")
    assert "(images:0)" not in status_line
    assert "(networks:0)" not in status_line
    assert "(volumes:0)" not in status_line
    assert "Containers" not in "\n".join(docker_stage._format_container_lines(record, "txt"))
    non_debug = "\n".join(docker_stage._format_exec_lines(record, "txt"))
    assert "stdout=" not in non_debug
    assert "container=web" not in non_debug
    assert "\t ok" in non_debug
    debug = "\n".join(docker_stage._format_exec_lines(record, "txt", debug=True))
    assert "container=web" in debug
    assert "command=whoami" in debug
    assert "stdout=ok" in debug


def test_exec_debug_multiline_stdout_keeps_prefixes(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_probe(monkeypatch)

    class MultilineClient(_FakeDockerClient):
        def exec_command(self, container_id: str, command: str) -> dict[str, Any]:
            return {
                "exec_id": "exec1",
                "stdout": "one\ntwo\n",
                "stderr": "",
                "exit_code": 0,
                "running": False,
            }

    def fake_probe(*_args, **_kwargs):
        return MultilineClient(), {"Version": "25.0.5", "ApiVersion": "1.45", "Os": "linux"}, "plaintext", None, False

    monkeypatch.setattr(docker_stage, "_probe_docker", fake_probe)
    record = docker_stage._audit_docker_host("127.0.0.1", 2375, 1.0, 0, container_selector="web", exec_cmd="cmd")
    debug_lines = docker_stage._format_exec_lines(record, "txt", debug=True)
    assert any("stdout=one" in line for line in debug_lines)
    assert any("stdout=two" in line for line in debug_lines)
    assert not any(line == "two" for line in debug_lines)


def test_audit_docker_targets_two_pass_debug_and_output(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_probe(monkeypatch)
    lines: list[str] = []
    debug: list[str] = []
    result = docker_stage.audit_docker_targets(
        hosts=["127.0.0.1"],
        port=2375,
        timeout=1.0,
        retries=0,
        workers=1,
        show_containers=True,
        output_format="txt",
        emit_line=lines.append,
        debug_emit=debug.append,
    )
    assert result == (1, 1, 0, 0, 0)
    assert any("Docker Engine API" in line for line in lines)
    assert any("Containers" in line for line in lines)
    assert any("pass=1 detect start" in item for item in debug)
    assert any("stage2_gate=run" in item for item in debug)
    assert any("stage_timing_summary" in item for item in debug)


def test_run_docker_stage_json_output(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    _patch_probe(monkeypatch, transport="tls")
    out = tmp_path / "docker.jsonl"
    rc = docker_stage.run_docker_stage(
        _args(output=str(out), output_format="json", containers=True, port=2376, insecure=True),
        logger=object(),  # type: ignore[arg-type]
    )
    assert rc == 0
    payload = out.read_text(encoding="utf-8")
    assert '"service": "docker"' in payload
    assert '"transport_mode": "tls"' in payload


def test_run_docker_stage_validates_exec_pair(capsys) -> None:
    assert docker_stage.run_docker_stage(_args(container="web"), logger=object()) == 2  # type: ignore[arg-type]
    assert "--container and --exec-cmd" in capsys.readouterr().err


def test_run_docker_stage_validates_tls_cert_key_pair(capsys, tmp_path) -> None:
    cert = tmp_path / "client.crt"
    cert.write_text("not-a-real-cert", encoding="utf-8")
    assert docker_stage.run_docker_stage(_args(tls_cert=str(cert)), logger=object()) == 2  # type: ignore[arg-type]
    assert "--tls-cert and --tls-key" in capsys.readouterr().err


def test_format_json_record_contains_additive_fields(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_probe(monkeypatch)
    record = docker_stage._audit_docker_host_stage("127.0.0.1", 2375, 1.0, 0, show_containers=True)
    payload = json.loads(docker_stage._format_record(record, "json"))
    assert payload["is_docker"] is True
    assert "stages" in payload
    assert "stage_durations_ms" in payload


def test_auth_required_and_not_docker_branches(monkeypatch: pytest.MonkeyPatch) -> None:
    def auth_probe(*_args, **_kwargs):
        return _FakeDockerClient(), None, "tls", "docker API HTTP 403: forbidden", True

    monkeypatch.setattr(docker_stage, "_probe_docker", auth_probe)
    auth_record = docker_stage._audit_docker_host("127.0.0.1", 2376, 1.0, 0)
    assert auth_record["status"] == "auth_required"
    assert "authentication required" in docker_stage._format_record(auth_record, "txt")

    def not_docker_probe(*_args, **_kwargs):
        return None, None, None, "not Docker Engine API endpoint (status:404)", False

    monkeypatch.setattr(docker_stage, "_probe_docker", not_docker_probe)
    not_docker = docker_stage._audit_docker_host("127.0.0.1", 1234, 1.0, 0)
    assert not_docker["status"] == "not_docker"
    assert "not Docker Engine API endpoint" in docker_stage._format_record(not_docker, "txt")


def test_detail_formatters_cover_inventory_system_and_exec(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_probe(monkeypatch)
    record = docker_stage._audit_docker_host(
        "127.0.0.1",
        2375,
        1.0,
        0,
        show_containers=True,
        show_images=True,
        show_networks=True,
        show_volumes=True,
        show_system=True,
        container_selector="web",
        exec_cmd="id",
    )
    lines: list[str] = []
    for formatter in (
        docker_stage._format_container_lines,
        docker_stage._format_image_lines,
        docker_stage._format_network_lines,
        docker_stage._format_volume_lines,
        docker_stage._format_system_lines,
        docker_stage._format_exec_lines,
    ):
        lines.extend(formatter(record, "txt"))
    joined = "\n".join(lines)
    assert "Containers" in joined
    assert "Images" in joined
    assert "Networks" in joined
    assert "Volumes" in joined
    assert "System" in joined
    assert "Exec Result" in joined
