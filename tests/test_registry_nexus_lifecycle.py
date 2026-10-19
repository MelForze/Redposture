from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from redposture_core.cli_args import parse_args
from redposture_core.modules.registry import actions, stage


def test_registry_nexus_mode_detects_non_docker_nexus_before_deep_actions(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    repository_calls: list[str] = []

    def _http_request(
        _host: str,
        _port: int,
        _method: str,
        path: str,
        _timeout: float,
        *,
        headers: dict[str, str] | None = None,
        body: bytes | None = None,
    ) -> tuple[int, bytes, dict[str, str], str | None]:
        _ = (headers, body)
        assert path == "/v2/"
        return 404, b"", {}, None

    monkeypatch.setattr(actions, "_http_request", _http_request)
    monkeypatch.setattr(actions, "_fetch_gitlab_info", lambda *_args, **_kwargs: (None, "not gitlab"))
    monkeypatch.setattr(actions, "_fetch_harbor_info", lambda *_args, **_kwargs: (None, "not harbor"))
    monkeypatch.setattr(actions, "_fetch_nexus_info", lambda *_args, **_kwargs: ({"version": "3.72.0"}, None))

    def _repositories(*_args: Any, **_kwargs: Any) -> tuple[list[dict[str, Any]], None]:
        repository_calls.append("repositories")
        return ([{"name": "docker-hosted", "format": "docker", "type": "hosted", "online": True}], None)

    monkeypatch.setattr(actions, "_fetch_nexus_repository_records", _repositories)
    monkeypatch.setattr(
        actions,
        "_fetch_nexus_components",
        lambda *_args, **_kwargs: (
            [
                {
                    "name": "redposture/sample",
                    "version": "1.0",
                    "assets": [
                        {
                            "path": "v2/redposture/sample",
                            "downloadUrl": "http://127.0.0.1:15004/repository/docker-hosted/sample",
                            "checksum": {"sha256": "abc"},
                        }
                    ],
                }
            ],
            None,
        ),
    )

    output_path = tmp_path / "registry-nexus.jsonl"
    args = parse_args(
        [
            "nexus",
            "-t",
            "127.0.0.1",
            "--port",
            "15004",
            "--assets",
            "--format",
            "json",
            "--output",
            str(output_path),
        ]
    )

    rc = stage.run_nexus_stage(args, logger=SimpleNamespace(log=lambda *_args, **_kwargs: None))

    assert rc == 0
    assert repository_calls == ["repositories"]
    payloads = [json.loads(line) for line in output_path.read_text(encoding="utf-8").splitlines()]
    assert len(payloads) == 1
    record = payloads[0]
    assert record["is_registry"] is True
    assert record["is_nexus"] is True
    assert record["status"] == "open_no_auth"
    assert record["probe_status"] == 404
    assert record["nexus_info"] == {"version": "3.72.0"}
    assert record["nexus_repository_count"] == 1
    assert record["nexus_repository_details"] is None  # --assets does not request repository inventory.
    assert record["nexus_assets"][0]["checksums"] == {"sha256": "abc"}


@pytest.mark.parametrize("flag", ["--show-manifest", "--show-metadata"])
def test_nexus_rest_port_inspects_docker_component(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, flag: str) -> None:
    requested: list[str] = []
    manifest = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        "config": {"digest": "sha256:config", "size": 128},
        "layers": [{"digest": "sha256:layer", "size": 42}],
    }
    config = {
        "config": {
            "Env": ["API_TOKEN=example"],
            "Cmd": ["run"],
            "Labels": {"owner": "qa"},
            "ExposedPorts": {"8080/tcp": {}},
        },
        "history": [{"created_by": "RUN prepare"}],
    }

    def request(_host: str, _port: int, method: str, path: str, _timeout: float, **_kwargs: Any):
        assert method == "GET"
        requested.append(path)
        if path == "/v2/":
            return 404, b"", {}, None
        if path == "/repository/docker-hosted/v2/redposture/demo-api/manifests/1.0.0":
            return 200, json.dumps(manifest).encode(), {}, None
        if path == "/repository/docker-hosted/v2/redposture/demo-api/blobs/sha256:config":
            return 200, json.dumps(config).encode(), {}, None
        raise AssertionError(path)

    monkeypatch.setattr(actions, "_http_request", request)
    monkeypatch.setattr(actions, "_fetch_gitlab_info", lambda *_a, **_k: (None, "not gitlab"))
    monkeypatch.setattr(actions, "_fetch_harbor_info", lambda *_a, **_k: (None, "not harbor"))
    monkeypatch.setattr(actions, "_fetch_nexus_info", lambda *_a, **_k: ({"version": "3.72.0"}, None))
    monkeypatch.setattr(
        actions,
        "_fetch_nexus_repository_records",
        lambda *_a, **_k: ([{"name": "docker-hosted", "format": "docker", "type": "hosted"}], None),
    )
    monkeypatch.setattr(
        actions,
        "_fetch_nexus_components",
        lambda *_a, **_k: ([{"name": "redposture/demo-api", "version": "1.0.0"}], None),
    )
    output = tmp_path / "nexus.jsonl"
    args = ["nexus", "-t", "127.0.0.1:15004", flag, "--format", "json", "-o", str(output)]
    if flag == "--show-metadata":
        args[3:3] = ["--repository", "docker-hosted/redposture/demo-api", "--tag", "1.0.0"]
    rc = stage.run_nexus_stage(parse_args(args), logger=SimpleNamespace(log=lambda *_a, **_k: None))
    assert rc == 0
    records = [json.loads(line) for line in output.read_text().splitlines()]
    assert len(records) == 1
    record = records[0]
    inspected = record["metadata_result"] if flag == "--show-metadata" else record["inspections"][0]
    assert inspected["image"] == "docker-hosted/redposture/demo-api:1.0.0"
    assert inspected["env"] == ["API_TOKEN=example"]
    assert inspected["labels"] == ["owner=qa"]
    assert inspected["cmd"] == ["run"]
    assert inspected["exposed_ports"] == ["8080/tcp"]
    assert inspected["history"] == ["RUN prepare"]
    assert inspected["suspicious"] == ["API_TOKEN=example"]
    assert requested.count("/repository/docker-hosted/v2/redposture/demo-api/manifests/1.0.0") == 1
    assert "\x1b[" not in output.read_text()

    text_output = tmp_path / "nexus.txt"
    text_args = ["nexus", "-t", "127.0.0.1:15004", flag, "--no-color", "-o", str(text_output)]
    if flag == "--show-metadata":
        text_args[3:3] = ["--repository", "docker-hosted/redposture/demo-api", "--tag", "1.0.0"]
    assert stage.run_nexus_stage(parse_args(text_args), logger=SimpleNamespace(log=lambda *_a, **_k: None)) == 0
    content = text_output.read_text()
    assert "API_TOKEN=example" in content
    assert "Possible Secret Indicators" in content
    assert "\x1b[" not in content


def test_nexus_rest_multiarch_manifest_follows_same_repository_prefix(monkeypatch: pytest.MonkeyPatch) -> None:
    paths: list[str] = []

    def request(_host: str, _port: int, _method: str, path: str, _timeout: float, **_kwargs: Any):
        paths.append(path)
        if path.endswith("/manifests/latest"):
            return (
                200,
                json.dumps(
                    {
                        "mediaType": "application/vnd.oci.image.index.v1+json",
                        "manifests": [{"digest": "sha256:child", "platform": {"architecture": "amd64", "os": "linux"}}],
                    }
                ).encode(),
                {},
                None,
            )
        if path.endswith("/manifests/sha256:child"):
            return (
                200,
                json.dumps({"schemaVersion": 2, "layers": [], "config": {"digest": "sha256:config"}}).encode(),
                {},
                None,
            )
        if path.endswith("/blobs/sha256:config"):
            return 200, json.dumps({"config": {"Env": ["MODE=qa"]}}).encode(), {}, None
        raise AssertionError(path)

    monkeypatch.setattr(actions, "_http_request", request)
    result = actions._inspect_nexus_rest_image(
        "127.0.0.1", 15004, "docker-hosted/redposture/demo-api", "latest", 5.0, headers={}
    )
    assert result["env"] == ["MODE=qa"]
    assert len(paths) == 3
    assert all(path.startswith("/repository/docker-hosted/v2/redposture/demo-api/") for path in paths)


@pytest.mark.parametrize("repository", ["demo-api", "../demo-api", "docker-hosted/../demo-api"])
def test_nexus_rest_rejects_ambiguous_storage_path(repository: str) -> None:
    result = actions._inspect_nexus_rest_image("h", 8081, repository, "latest", 1.0, headers={})
    assert result["error"] == "Nexus image must be <storage>/<image>:<tag>"
