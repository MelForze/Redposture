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
            "registry",
            "-t",
            "127.0.0.1",
            "--port",
            "15004",
            "--nexus",
            "--assets",
            "--format",
            "json",
            "--output",
            str(output_path),
        ]
    )

    rc = stage.run_registry_stage(args, logger=SimpleNamespace(log=lambda *_args, **_kwargs: None))

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
    assert record["nexus_repository_details"][0]["name"] == "docker-hosted"
    assert record["nexus_assets"][0]["checksums"] == {"sha256": "abc"}
