"""Broken inventory must remain partial, with completed sections preserved."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from redposture_core.clients.docker_engine import DockerEngineClient, DockerEngineError, DockerHTTPResponse
from redposture_core.modules.docker import actions
from scripts.performance_readonly import docker_reply


@pytest.mark.parametrize(
    "method,payload",
    [
        ("containers", b"{}"),
        ("images", b"{}"),
        ("networks", b"{}"),
        ("volumes", b"[]"),
        ("system_df", b"[]"),
        ("containers", b'["not-an-object"]'),
        ("volumes", b'{"Volumes":["not-an-object"]}'),
        ("system_df", b'{"Images":"not-an-array"}'),
        ("system_df", b"{}"),
        ("images", b"{"),
        ("containers", b"null"),
    ],
)
def test_invalid_shape_or_json_is_a_client_error(monkeypatch, method, payload):
    monkeypatch.setattr(DockerEngineClient, "request", lambda *a, **k: DockerHTTPResponse(200, "OK", {}, payload))
    client = DockerEngineClient("qa.invalid", 2375)
    with pytest.raises(DockerEngineError, match="invalid.*response"):
        getattr(client, method)()


@pytest.mark.parametrize("payload", [b"{}", b"{", b'["not-an-object"]'])
def test_bad_image_inventory_keeps_previously_read_containers_and_reports_partial(monkeypatch, payload):
    calls = []

    def request(self, method, path, **kwargs):
        calls.append((method, path))
        raw = docker_reply(method, path, access="open")
        head, body = raw.split(b"\r\n\r\n", 1)
        if path == "/images/json":
            body = payload
        return DockerHTTPResponse(int(head.split(b" ", 2)[1]), "OK", {}, body)

    monkeypatch.setattr(DockerEngineClient, "request", request)
    result = actions._audit_docker_host(
        "qa.invalid", 2375, 1, 0, show_containers=True, show_images=True, show_networks=True
    )
    assert result["is_docker"] is True and result["auth_required"] is False
    assert len(result["containers"]) == 3 and len(result["networks"]) == 2
    assert result["images"] == [] and result["capabilities"]["can_list_images"] is False
    assert result["partial"] is True and result["data_complete"] is False
    assert "invalid" in result["partial_errors"]["images"] and "images_error" in result
    assert calls.count(("GET", "/images/json")) == 1


@pytest.mark.parametrize(
    "method,payload",
    [
        ("containers", []),
        ("images", []),
        ("networks", []),
        ("volumes", {"Volumes": [], "Warnings": None}),
        ("volumes", {"Volumes": None, "Warnings": None}),
        ("system_df", {"LayersSize": 0, "Images": None, "Containers": [], "Volumes": []}),
    ],
)
def test_valid_empty_resources_are_not_confused_with_corrupt_responses(monkeypatch, method, payload):
    monkeypatch.setattr(
        DockerEngineClient, "request", lambda *a, **k: DockerHTTPResponse(200, "OK", {}, json.dumps(payload).encode())
    )
    client = DockerEngineClient("qa.invalid", 2375)
    assert getattr(client, method)() == (payload if method == "system_df" else [])


@pytest.mark.parametrize("output_format", ["txt", "json"])
def test_public_cli_keeps_completed_inventory_and_clean_partial_output(tmp_path, output_format):
    from scripts.performance_http_fixtures import response
    from scripts.performance_http_server import AsyncHttpFixture

    calls = []

    def router(method, path, headers, body, host):
        calls.append((method, path))
        return response(200, "{") if path == "/images/json" else docker_reply(method, path, access="open")

    peer = AsyncHttpFixture(router)
    peer.start()
    path = tmp_path / ("output." + output_format)
    try:
        result = subprocess.run(
            [
                sys.executable,
                "redposture.py",
                "docker",
                "-t",
                f"http://127.0.0.1:{peer.port}",
                "--containers",
                "--images",
                "--networks",
                "--no-color",
                "--timeout",
                "1",
                "--retries",
                "0",
                "-f",
                output_format,
                "-o",
                str(path),
            ],
            cwd=Path(__file__).resolve().parents[1],
            capture_output=True,
            text=True,
            timeout=20,
        )
    finally:
        peer.close()
    assert result.returncode == 0, result.stderr
    saved = path.read_text()
    assert "\x1b" not in saved + result.stdout
    if output_format == "json":
        record = json.loads(saved)
        assert record["partial"] is True and record["data_complete"] is False
        assert len(record["containers"]) == 3 and len(record["networks"]) == 2 and record["images"] == []
        assert record["capabilities"]["can_list_images"] is False
    else:
        assert "billing/api:2026.11" in saved and "billing-frontend" in saved
        assert "partial images failed err=invalid /images/json response:" in saved
    assert calls.count(("GET", "/images/json")) == 1 and not peer.errors and peer.stats["active"] == 0


def test_new_partial_diagnostic_keeps_airflow_baseline_colors():
    from redposture_core.modules.airflow.render import _render_colored_airflow_line

    class Recorder:
        def __init__(self):
            self.calls = []

        def _paint(self, text, color, stream):
            self.calls.append((text, color))
            return text

        def plain(self, *args, **kwargs):
            pass

    message = (
        "127.0.0.1\t2375\t [!] partial images failed err=invalid /images/json response: expected an array of objects"
    )
    docker, airflow = Recorder(), Recorder()
    assert actions._render_colored_docker_line(docker, "DOCKER\t" + message)
    assert _render_colored_airflow_line(airflow, "AIRFLOW\t" + message)

    def without_tag(recorder):
        # Airflow pads columns before rendering; compare color assignments
        # without treating that existing tab/space layout difference as color.
        return [(" ".join(text.split()), color) for text, color in recorder.calls if text not in {"DOCKER", "AIRFLOW"}]

    assert without_tag(docker) == without_tag(airflow)
    assert ("[!]", "true_red") in docker.calls
