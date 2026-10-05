"""Regressions for protected APIs, anonymous Proxmox, and OCI Basic checks."""

from __future__ import annotations

import base64
from types import SimpleNamespace
from typing import Any

import pytest

from redposture_core.audit_models import AuditRecord
from redposture_core.cli_args import parse_args
from redposture_core.modules.grafana import actions as grafana
from redposture_core.modules.proxmox import actions as proxmox
from redposture_core.modules.proxmox import stage as proxmox_stage
from redposture_core.modules.registry import actions as registry
from redposture_core.modules.registry import stage as registry_stage
from redposture_core.stage_runtime import AuditCredentialRun


@pytest.mark.parametrize(
    ("api_status", "body", "expected"),
    [(401, "{}", True), (403, "{}", True), (200, "[]", False), (200, "{}", None)],
)
def test_grafana_public_health_does_not_determine_auth(
    monkeypatch: pytest.MonkeyPatch, api_status: int, body: str, expected: bool | None
) -> None:
    monkeypatch.setattr(grafana, "_http_request", lambda *_args, **_kwargs: (api_status, body, {}))
    assert (
        grafana._infer_grafana_auth_required("grafana.example", 443, 1.0, health_status=200, health_api_ok=True)
        is expected
    )


def test_grafana_service_line_contains_detected_or_unknown_version() -> None:
    record = {"host": "h", "port": 443, "auth_required": True, "server_version": "11.2.0"}
    assert grafana._format_detect_record(record, "txt").endswith(
        "Grafana Service (auth required:True) (version:11.2.0)"
    )
    assert grafana._format_detect_record({**record, "server_version": None}, "txt").endswith("(version:unknown)")


def test_grafana_service_line_color_and_saved_formats_are_ansi_free() -> None:
    class ConsoleStub:
        def __init__(self) -> None:
            self.paint_calls: list[tuple[str, str]] = []

        def _paint(self, value: str, color: str, _stream: Any) -> str:
            self.paint_calls.append((value, color))
            return value

        def plain(self, _value: str) -> None:
            pass

    record = {"host": "h", "port": 443, "auth_required": True, "server_version": "11.2.0"}
    line = grafana._format_detect_record(record, "txt")
    console = ConsoleStub()
    assert grafana._render_colored_grafana_line(console, line)
    assert ("auth required:True", "bright_green") in console.paint_calls
    assert any("version:11.2.0" in value and color == "white" for value, color in console.paint_calls)
    assert "\x1b[" not in line
    assert "\x1b[" not in grafana._format_detect_record(record, "json")


def _proxmox_ctx() -> SimpleNamespace:
    return SimpleNamespace(
        host="proxy.example",
        port=3128,
        target=SimpleNamespace(scheme="http"),
        args=parse_args(["proxmox", "-t", "http://proxy.example:3128"]),
        credential=AuditCredentialRun(source="anonymous"),
        lifecycle_state=None,
        debug_emit=None,
    )


def test_proxmox_proxy_501_is_not_a_confirmed_service(monkeypatch: pytest.MonkeyPatch) -> None:
    assert proxmox._looks_like_proxmox_response(501, b"", {"Server": "pve-api-daemon/3.0"}) is False
    monkeypatch.setattr(
        proxmox,
        "_proxmox_request",
        lambda *_args, **_kwargs: (501, b"proxy error", {"Server": "pve-api-daemon/3.0"}, None),
    )
    record = proxmox_stage._proxmox_detect(_proxmox_ctx())
    assert record.extra["is_proxmox"] is False


def test_proxmox_anonymous_401_does_not_create_token_or_password_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    def fake_request(_host: str, _port: int, path: str, *_args: Any, **_kwargs: Any):
        calls.append(path)
        return 401, b'{"data":null}', {"Server": "pve-api-daemon/3.0"}, None

    monkeypatch.setattr(proxmox, "_proxmox_request", fake_request)
    ctx = _proxmox_ctx()
    detected = proxmox_stage._proxmox_detect(ctx)
    assert detected.extra["is_proxmox"] is True
    assert detected.status == "auth_required"
    authenticated = proxmox_stage._proxmox_auth(ctx, detected)
    assert authenticated.status == "auth_required"
    assert proxmox._format_record(authenticated.to_dict(), "txt") == ""
    assert calls == ["/access"]


def test_docker_registry_defcreds_probe_without_challenge_is_verified(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fingerprint_headers = {"docker-distribution-api-version": "registry/2.0"}
    accepted = base64.b64encode(b"registry:registry").decode()
    calls: list[dict[str, str]] = []

    def fake_request(_host: str, _port: int, _method: str, path: str, _timeout: float, *, headers=None):
        if path != "/v2/":
            return 404, b"", {}, None
        auth = dict(headers or {})
        calls.append(auth)
        if auth.get("Authorization") == f"Basic {accepted}":
            return 200, b"{}", fingerprint_headers, None
        return 401, b'{"errors":[{"code":"UNAUTHORIZED"}]}', fingerprint_headers, None

    monkeypatch.setattr(registry, "_http_request", fake_request)
    monkeypatch.setattr(registry, "_fetch_nexus_info", lambda *_args, **_kwargs: (None, "not nexus"))
    monkeypatch.setattr(registry, "_fetch_harbor_info", lambda *_args, **_kwargs: (None, "not harbor"))
    args = parse_args(["docker-registry", "-t", "http://registry.example:5000", "--defcreds"])
    spec = registry_stage.build_registry_spec(args, product="docker-registry")
    state = registry.RegistryLifecycleState()
    ctx = SimpleNamespace(
        host="registry.example",
        port=5000,
        target=SimpleNamespace(scheme="http", host="registry.example", port=5000, path=""),
        args=args,
        lifecycle_state=state,
        credential=AuditCredentialRun(username="registry", password="registry", source="default"),
    )
    detected = spec.detect(ctx) if spec.detect is not None else None
    assert isinstance(detected, AuditRecord)
    assert detected.extra["credential_verification_status"] == "available"
    assert detected.auth_required is True
    assert spec.auth is not None
    verified = spec.auth(ctx, detected)
    assert verified.extra["provided_credentials_ok"] is True
    assert any(call.get("Authorization") == f"Basic {accepted}" for call in calls)
