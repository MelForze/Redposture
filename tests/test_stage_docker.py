from __future__ import annotations

import argparse
import json
from typing import Any

import pytest

from redposture_core import stage_docker as docker_stage
from tests.stage_runtime_helpers import run_module_targets_for_test


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
    result = run_module_targets_for_test(
        "docker",
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
        logger=object(),
    )
    assert rc == 0
    payload = out.read_text(encoding="utf-8")
    assert '"service": "docker"' in payload
    assert '"transport_mode": "tls"' in payload


def test_run_docker_stage_validates_exec_pair(capsys) -> None:
    assert docker_stage.run_docker_stage(_args(container="web"), logger=object()) == 2
    assert "--container and --exec-cmd" in capsys.readouterr().err


def test_run_docker_stage_validates_tls_cert_key_pair(capsys, tmp_path) -> None:
    cert = tmp_path / "client.crt"
    cert.write_text("not-a-real-cert", encoding="utf-8")
    assert docker_stage.run_docker_stage(_args(tls_cert=str(cert)), logger=object()) == 2
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


def test_run_docker_stage_not_service_emits_explicit_line(monkeypatch: pytest.MonkeyPatch, capsys) -> None:
    def not_docker_probe(*_args, **_kwargs):
        return None, None, None, "not Docker Engine API endpoint (status:404)", False

    monkeypatch.setattr(docker_stage, "_probe_docker", not_docker_probe)

    rc = docker_stage.run_docker_stage(_args(port=1234, workers=1), logger=object())

    assert rc == 0
    stdout = capsys.readouterr().out
    assert "not Docker Engine API endpoint" in stdout
    assert "Docker Engine API (auth required:unknown)" not in stdout


def test_probe_docker_transport_error_branches(monkeypatch: pytest.MonkeyPatch) -> None:
    class InfoFallbackClient:
        def __init__(self, transport: str) -> None:
            self.transport = transport

        def ping(self) -> None:
            return None

        def version(self) -> dict[str, Any]:
            raise docker_stage.DockerEngineHTTPError(404, "missing")

        def info(self) -> dict[str, Any]:
            return {"ServerVersion": "26.0.0", "ApiVersion": "1.46", "OSType": "linux"}

    clients: list[str] = []

    def fake_client(_host: str, _port: int, transport: str, *_args: object, **_kwargs: object) -> InfoFallbackClient:
        clients.append(transport)
        return InfoFallbackClient(transport)

    monkeypatch.setattr(docker_stage, "_docker_client", fake_client)
    client, version, transport, error, auth_required = docker_stage._probe_docker(
        "127.0.0.1",
        2376,
        1.0,
        insecure=True,
        tls_ca=None,
        tls_cert=None,
        tls_key=None,
    )
    assert isinstance(client, InfoFallbackClient)
    assert version == {"Version": "26.0.0", "ApiVersion": "1.46", "Os": "linux"}
    assert transport == "tls"
    assert error is None
    assert auth_required is False
    assert clients == ["tls"]

    class ForbiddenClient(InfoFallbackClient):
        def ping(self) -> None:
            raise docker_stage.DockerEngineHTTPError(403, "forbidden")

    monkeypatch.setattr(docker_stage, "_docker_client", lambda *_args, **_kwargs: ForbiddenClient("plaintext"))
    client, version, transport, error, auth_required = docker_stage._probe_docker(
        "127.0.0.1",
        2375,
        1.0,
        insecure=False,
        tls_ca=None,
        tls_cert=None,
        tls_key=None,
    )
    assert isinstance(client, ForbiddenClient)
    assert version is None
    assert transport == "plaintext"
    assert "forbidden" in str(error)
    assert auth_required is True


def test_docker_small_helpers_and_probe_failure_branches(monkeypatch: pytest.MonkeyPatch) -> None:
    assert docker_stage._clip("abcdef", 3) == "abc"
    assert docker_stage._retry_delay(10) == 1.5
    assert docker_stage._transport_order(2376) == ["tls", "plaintext"]
    assert docker_stage._transport_order(2375) == ["plaintext", "tls"]
    assert docker_stage._image_count({"images": "not-list"}) == 0
    assert docker_stage._network_count({"networks": "not-list"}) == 0
    assert docker_stage._volume_count({"volumes": "not-list"}) == 0
    assert docker_stage._caps_suffix({"capabilities": {"can_list_images": True}, "images": [{}]}) == " (images:1)"

    created: list[dict[str, object]] = []

    class FakeClient:
        def __init__(self, *args: object, **kwargs: object) -> None:
            created.append({"args": args, "kwargs": kwargs})

    monkeypatch.setattr(docker_stage, "DockerEngineClient", FakeClient)
    assert docker_stage._docker_client(
        "docker.local",
        2376,
        "tls",
        2.0,
        insecure=True,
        tls_ca="ca.pem",
        tls_cert="cert.pem",
        tls_key="key.pem",
    )
    assert created[0]["args"] == ("docker.local", 2376)
    assert created[0]["kwargs"]["transport"] == "tls"
    assert created[0]["kwargs"]["ca_file"] == "ca.pem"

    class BadVersionClient:
        def __init__(self, kind: str) -> None:
            self.kind = kind

        def ping(self) -> None:
            if self.kind == "conn-auth":
                raise docker_stage.DockerEngineConnectionError("client certificate required")
            return None

        def version(self) -> dict[str, Any]:
            if self.kind == "version-500":
                raise docker_stage.DockerEngineHTTPError(500, "boom")
            if self.kind == "bad-json":
                raise ValueError("bad json")
            return {}

        def info(self) -> dict[str, Any]:
            return {}

    sequence = iter([BadVersionClient("version-500"), BadVersionClient("bad-json")])
    monkeypatch.setattr(docker_stage, "_docker_client", lambda *_args, **_kwargs: next(sequence))
    client, version, transport, error, auth_required = docker_stage._probe_docker(
        "127.0.0.1",
        2375,
        1.0,
        insecure=False,
        tls_ca=None,
        tls_cert=None,
        tls_key=None,
    )
    assert client is None
    assert version is None
    assert transport is None
    assert "bad json" in str(error)
    assert auth_required is False

    monkeypatch.setattr(docker_stage, "_docker_client", lambda *_args, **_kwargs: BadVersionClient("conn-auth"))
    client, version, transport, error, auth_required = docker_stage._probe_docker(
        "127.0.0.1",
        2375,
        1.0,
        insecure=False,
        tls_ca=None,
        tls_cert=None,
        tls_key=None,
    )
    assert isinstance(client, BadVersionClient)
    assert version is None
    assert transport == "plaintext"
    assert auth_required is True


def test_docker_inventory_error_and_empty_exec_output_branches(monkeypatch: pytest.MonkeyPatch) -> None:
    class ErrorClient(_FakeDockerClient):
        def images(self) -> list[dict[str, Any]]:
            raise docker_stage.DockerEngineError("images denied")

        def networks(self) -> list[dict[str, Any]]:
            raise docker_stage.DockerEngineError("networks denied")

        def volumes(self) -> list[dict[str, Any]]:
            raise docker_stage.DockerEngineError("volumes denied")

        def info(self) -> dict[str, Any]:
            raise docker_stage.DockerEngineError("info denied")

        def system_df(self) -> dict[str, Any]:
            raise docker_stage.DockerEngineError("df denied")

        def exec_command(self, container_id: str, command: str) -> dict[str, Any]:
            _ = (container_id, command)
            return {"stdout": "", "stderr": "", "exit_code": 0, "running": False}

    monkeypatch.setattr(
        docker_stage,
        "_probe_docker",
        lambda *_args, **_kwargs: (
            ErrorClient(),
            {"Version": "25.0.5", "ApiVersion": "1.45", "Os": "linux"},
            "plaintext",
            None,
            False,
        ),
    )
    record = docker_stage._audit_docker_host(
        "127.0.0.1",
        2375,
        1.0,
        0,
        show_images=True,
        show_networks=True,
        show_volumes=True,
        show_system=True,
        container_selector="web",
        exec_cmd="true",
    )
    assert record["capabilities"]["can_list_images"] is False
    assert record["capabilities"]["can_read_system_info"] is False
    assert "<no output>" in "\n".join(docker_stage._format_exec_lines(record, "txt"))

    missing = docker_stage._audit_docker_host(
        "127.0.0.1",
        2375,
        1.0,
        0,
        container_selector="missing",
        exec_cmd="id",
    )
    assert missing["exec_result"]["ok"] is False
    assert "container not found" in "\n".join(docker_stage._format_exec_lines(missing, "txt"))


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
