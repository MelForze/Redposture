"""Keycloak fingerprint, token and output regressions through the real HTTP client."""

from __future__ import annotations

import json
import re
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import pytest
from hypothesis import given
from hypothesis import strategies as st

from redposture_core.cli import main
from redposture_core.clients.http_api import HttpResponse
from redposture_core.cve import enumerate_record, load_catalog
from redposture_core.modules.keycloak.actions import _get_public, _oidc_response, _realm_response, _realms
from redposture_core.modules.keycloak.render import _render_colored_keycloak_line


class _KeycloakHandler(BaseHTTPRequestHandler):
    prefix = ""
    fake = False
    calls: list[tuple[str, str]] = []

    def log_message(self, *_args: Any) -> None:
        pass

    def do_GET(self) -> None:
        path = urlsplit(self.path).path
        type(self).calls.append((path, self.headers.get("Authorization", "")))
        root = f"http://127.0.0.1:{self.server.server_port}{self.prefix}"
        authorized = self.headers.get("Authorization") == "Bearer valid-token"
        payload: Any = {"error": "not found"}
        code = 404
        if path == f"{self.prefix}/realms/master":
            code = 200
            payload = {
                "realm": "master",
                "public_key": "A" * 128,
                "token-service": f"{root}/realms/master/protocol/openid-connect",
                "account-service": f"{root}/realms/master/account",
            }
            if self.fake:
                payload = {"realm": "master", "version": "26.3.4"}
        elif path == f"{self.prefix}/realms/master/.well-known/openid-configuration":
            code = 200
            issuer = f"{root}/realms/master"
            payload = {
                "issuer": issuer,
                "jwks_uri": issuer + "/protocol/openid-connect/certs",
                "token_endpoint": issuer + "/protocol/openid-connect/token",
                "authorization_endpoint": issuer + "/protocol/openid-connect/auth",
            }
        elif path == f"{self.prefix}/realms/master/protocol/openid-connect/certs":
            code = 200
            payload = {"keys": []}
        elif path == f"{self.prefix}/realms/master/protocol/openid-connect/userinfo":
            code = 200 if authorized else 401
            payload = {"sub": "test-user"} if authorized else {"error": "unauthorized"}
        elif path == f"{self.prefix}/admin/serverinfo":
            code = 200 if authorized else 401
            payload = {"systemInfo": {"version": "26.3.4"}} if authorized else {"error": "unauthorized"}
        elif path == f"{self.prefix}/admin/realms":
            code = 200 if authorized else 401
            payload = [{"realm": "master"}] if authorized else {"error": "unauthorized"}
        elif path == f"{self.prefix}/admin/realms/master/clients":
            code = 200 if authorized else 401
            payload = [{"clientId": "sample-app"}] if authorized else {"error": "unauthorized"}
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture
def keycloak_server() -> Iterator[tuple[str, type[_KeycloakHandler]]]:
    class Handler(_KeycloakHandler):
        calls: list[tuple[str, str]] = []

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", Handler
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _records(text: str) -> list[dict[str, Any]]:
    return [value for line in text.splitlines() if line.startswith("{") if isinstance(value := json.loads(line), dict)]


def test_confirmed_realm_and_token_enumeration(
    keycloak_server: tuple[str, type[_KeycloakHandler]], capsys: pytest.CaptureFixture[str]
) -> None:
    url, handler = keycloak_server
    assert (
        main(
            [
                "keycloak",
                "-t",
                url,
                "--token",
                "valid-token",
                "--show-realms",
                "--show-clients",
                "--enum-cve",
                "--no-color",
            ]
        )
        == 0
    )
    output = capsys.readouterr().out
    assert "Keycloak (auth required:True) (realm:master) (version:26.3.4)" in output
    assert "Bearer token accepted" in output
    assert "Realm Name=master" in output
    assert "Client Name=master/sample-app" in output
    assert "CVE's Enumeration" in output
    assert "CVE-2026-11800 potentially affected" in output
    assert output.index("Bearer token accepted") < output.index("CVE's Enumeration")
    assert "\x1b[" not in output
    assert all(method.startswith("/") for method, _ in handler.calls)
    assert not any(
        secret == "Bearer valid-token" and path.startswith("/realms/master/.well-known")
        for path, secret in handler.calls
    )


def test_anonymous_detection_json_and_no_admin_enumeration(
    keycloak_server: tuple[str, type[_KeycloakHandler]], capsys: pytest.CaptureFixture[str]
) -> None:
    url, handler = keycloak_server
    assert main(["keycloak", "-t", url, "--show-realms", "--enum-cve", "-f", "json", "--no-color"]) == 0
    data = _records(capsys.readouterr().out)[0]
    assert data["detection_status"] == "confirmed"
    assert data["auth_required"] is True
    assert data["version"] is None
    assert data["cve_enumeration"]["status"] == "version_unknown"
    assert data.get("visible_realms") is None
    assert not any(secret for _path, secret in handler.calls)


def test_prefix_and_foreign_provider_never_claimed(
    keycloak_server: tuple[str, type[_KeycloakHandler]], capsys: pytest.CaptureFixture[str]
) -> None:
    url, handler = keycloak_server
    handler.prefix = "/auth"
    assert main(["keycloak", "-t", url + "/auth", "--no-color"]) == 0
    assert "Keycloak (auth required:True)" in capsys.readouterr().out
    handler.fake = True
    handler.calls.clear()
    assert main(["keycloak", "-t", url + "/auth", "--token", "valid-token", "-f", "json", "--no-color"]) == 0
    data = _records(capsys.readouterr().out)[0]
    assert data["detection_status"] == "probable"
    assert data["is_keycloak"] is False
    assert not any(path.startswith("/auth/admin/") for path, _ in handler.calls)


def test_token_file_is_redacted_in_json(
    keycloak_server: tuple[str, type[_KeycloakHandler]],
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    url, _ = keycloak_server
    token_file = tmp_path / "token"
    token_file.write_text("valid-token\n")
    assert main(["keycloak", "-t", url, "--token-file", str(token_file), "-f", "json", "--no-color"]) == 0
    output = capsys.readouterr().out
    assert "valid-token" not in output
    assert _records(output)[0]["provided_credentials_ok"] is True


def test_invalid_token_does_not_unlock_admin_or_low_privilege_cve(
    keycloak_server: tuple[str, type[_KeycloakHandler]], capsys: pytest.CaptureFixture[str]
) -> None:
    url, _ = keycloak_server
    assert main(["keycloak", "-t", url, "--token", "bad-token", "--show-clients", "--enum-cve", "--no-color"]) == 0
    output = capsys.readouterr().out
    assert "Bearer token rejected" in output
    assert "Clients Enumeration" not in output
    assert "CVE-2026-11800" not in output


def test_keycloak_cve_requires_verified_access_and_respects_fixed_boundary() -> None:
    catalog = load_catalog()
    payload = {"is_keycloak": True, "version": "26.6.3", "auth_required": True}
    unauthenticated = enumerate_record("keycloak", payload, catalog=catalog, confirmed=True)
    authenticated = enumerate_record("keycloak", payload, catalog=catalog, confirmed=True, credentials_provided=True)
    fixed = enumerate_record(
        "keycloak", {**payload, "version": "26.6.4"}, catalog=catalog, confirmed=True, credentials_provided=True
    )
    assert not unauthenticated["findings"]
    assert [finding["id"] for finding in authenticated["findings"]] == ["CVE-2026-11800"]
    assert not fixed["findings"]


def test_keycloak_output_colors_follow_airflow_baseline() -> None:
    class ConsoleStub:
        def __init__(self) -> None:
            self.lines: list[str] = []

        def _paint(self, value: str, color: str, _stream: Any) -> str:
            return f"<{color}>{value}</{color}>"

        def plain(self, value: str) -> None:
            self.lines.append(value)

    console = ConsoleStub()
    lines = (
        "KEYCLOAK\th\t8080\t [*] Realms Enumeration (realms:1)",
        "KEYCLOAK\th\t8080\t [+] Realm Name=master",
        "KEYCLOAK\th\t8080\t [+] Bearer token accepted",
        "KEYCLOAK\th\t8080\t [*] Clients Enumeration (clients:0)",
        "KEYCLOAK\th\t8080\t [*] CVE's Enumeration",
        "KEYCLOAK\th\t8080\t [!] CVE-2026-11800 potentially affected (HIGH 8.1) Keycloak auth bypass",
    )
    for line in lines:
        assert _render_colored_keycloak_line(console, line)
    assert "<true_red>realms:1</true_red>" in console.lines[0]
    assert "<orange>Realm Name=master</orange>" in console.lines[1]
    assert "<true_red>Bearer token accepted</true_red>" in console.lines[2]
    assert "<bright_green>clients:0</bright_green>" in console.lines[3]
    assert "<white>CVE's Enumeration</white>" in console.lines[4]
    assert "<orange>CVE-2026-11800 potentially affected" in console.lines[5]


def test_public_redirect_keeps_endpoint_and_never_follows_idp() -> None:
    class ClientStub:
        def __init__(self, destination: str) -> None:
            self.destination = destination
            self.urls: list[str] = []

        def get(self, url: str, *, headers: dict[str, str]) -> HttpResponse:
            self.urls.append(url)
            assert "Authorization" not in headers
            if len(self.urls) == 1:
                return HttpResponse(302, b"", {"Location": self.destination}, final_url=url)
            return HttpResponse(200, b"{}", {}, final_url=url)

    source = "http://id.example:8080/realms/master"
    accepted = ClientStub("https://id.example:8443/edge/realms/master")
    assert _get_public(accepted, source).status == 200  # type: ignore[arg-type]
    assert accepted.urls == [source, accepted.destination]
    rejected = ClientStub("https://idp.example/login")
    assert _get_public(rejected, source).status == 302  # type: ignore[arg-type]
    assert rejected.urls == [source]


def test_realm_candidates_are_bounded_and_infer_url_realm() -> None:
    args = type("Args", (), {"realm": None, "enum_realms": True})()
    realms = _realms(args, "/prefix/auth/realms/custom/protocol/openid-connect")
    assert realms[0] == "custom"
    assert "master" in realms
    assert len(realms) <= 12


@given(
    st.recursive(
        st.none() | st.booleans() | st.integers() | st.text(max_size=60),
        lambda child: st.lists(child, max_size=3) | st.dictionaries(st.text(max_size=20), child, max_size=3),
        max_leaves=10,
    )
)
def test_generic_json_never_passes_realm_fingerprint(value: Any) -> None:
    if isinstance(value, dict) and _realm_response(value, "master"):
        assert all(key in value for key in ("realm", "public_key", "token-service", "account-service"))
    else:
        assert not _realm_response(value if isinstance(value, dict) else None, "master")
    if isinstance(value, dict) and _oidc_response(value, "master"):
        assert all(key in value for key in ("issuer", "jwks_uri", "token_endpoint", "authorization_endpoint"))


def test_output_tsv_has_no_ansi(
    keycloak_server: tuple[str, type[_KeycloakHandler]], tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    url, _ = keycloak_server
    output = tmp_path / "result.txt"
    assert main(["keycloak", "-t", url, "-o", str(output), "--no-color"]) == 0
    text = output.read_text()
    assert "\x1b[" not in text
    assert re.match(r"^KEYCLOAK\t127\.0\.0\.1\t\d+\t \[\*\] Keycloak", text)
    assert "\x1b[" not in capsys.readouterr().out
