"""Keycloak fingerprint, token and output regressions through the real HTTP client."""

from __future__ import annotations

import json
import re
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from urllib.parse import urlsplit

import pytest
from hypothesis import given
from hypothesis import strategies as st

from redposture_core.cli import main
from redposture_core.clients.http_api import HttpResponse
from redposture_core.cve import enumerate_record, load_catalog
from redposture_core.modules.keycloak.actions import (
    _client_settings,
    _endpoint_values,
    _get_public,
    _oidc_response,
    _realm_response,
    _realm_settings,
    _realms,
)
from redposture_core.modules.keycloak.policy import validate_args
from redposture_core.modules.keycloak.render import _render_colored_keycloak_line


@pytest.mark.parametrize(
    ("token_file_text", "token", "realms", "expected_error"),
    [
        ("", None, [], "--token-file is empty"),
        (None, "first\nsecond", [], "token contains a line break"),
        (None, "token", ["invalid/realm"], "--realm requires"),
        (None, "token", ["realm"] * 13, "--realm requires"),
    ],
)
def test_keycloak_rejects_invalid_auth_and_realm_inputs(
    tmp_path: Path,
    token_file_text: str | None,
    token: str | None,
    realms: list[str],
    expected_error: str,
) -> None:
    class ConsoleStub:
        def __init__(self) -> None:
            self.errors: list[str] = []

        def error(self, message: str) -> None:
            self.errors.append(message)

    token_file = None
    if token_file_text is not None:
        token_file = tmp_path / "token"
        token_file.write_text(token_file_text, encoding="utf-8")
    args = SimpleNamespace(token=token, token_file=token_file, realm=realms)
    console = ConsoleStub()
    assert validate_args(args, console) == 2
    assert any(expected_error in message for message in console.errors)


def test_keycloak_reports_unreadable_token_file(tmp_path: Path) -> None:
    errors: list[str] = []
    args = SimpleNamespace(token=None, token_file=tmp_path / "missing-token", realm=[])
    console = SimpleNamespace(error=errors.append)
    assert validate_args(args, console) == 2
    assert errors and errors[0].startswith("cannot read --token-file:")


class _KeycloakHandler(BaseHTTPRequestHandler):
    prefix = ""
    fake = False
    rich = False
    deny_partner_settings = False
    deny_partner_clients = False
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
        public_realms = ("master", "corp", "partners") if self.rich else ("master",)
        if path in {f"{self.prefix}/realms/{realm}" for realm in public_realms}:
            realm = path.rsplit("/", 1)[-1]
            code = 200
            payload = {
                "realm": realm,
                "public_key": "A" * 128,
                "token-service": f"{root}/realms/{realm}/protocol/openid-connect",
                "account-service": f"{root}/realms/{realm}/account",
            }
            if self.fake:
                payload = {"realm": "master", "version": "26.3.4"}
        elif path in {f"{self.prefix}/realms/{realm}/.well-known/openid-configuration" for realm in public_realms}:
            code = 200
            realm = path.split("/realms/", 1)[1].split("/", 1)[0]
            issuer = f"{root}/realms/{realm}"
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
            payload = [{"realm": realm} for realm in public_realms] if authorized else {"error": "unauthorized"}
        elif path == f"{self.prefix}/admin/realms/master/clients":
            code = 200 if authorized else 401
            payload = [{"clientId": "sample-app"}] if authorized else {"error": "unauthorized"}
        elif self.rich and path in {
            f"{self.prefix}/admin/realms/corp/clients",
            f"{self.prefix}/admin/realms/partners/clients",
        }:
            realm = path.split("/admin/realms/", 1)[1].split("/", 1)[0]
            code = 200 if authorized else 401
            if realm == "partners" and self.deny_partner_clients:
                code = 403
            payload = (
                [
                    {
                        "clientId": "legacy-reports",
                        "publicClient": True,
                        "directAccessGrantsEnabled": True,
                        "implicitFlowEnabled": True,
                        "redirectUris": ["https://reports.example.test/*"],
                        "webOrigins": ["*"],
                        "secret": "never-print-this-secret",
                    }
                ]
                if code == 200 and realm == "corp"
                else [
                    {
                        "clientId": "partner-portal",
                        "publicClient": True,
                        "directAccessGrantsEnabled": False,
                        "implicitFlowEnabled": False,
                        "redirectUris": ["https://partner.example.test/callback"],
                        "webOrigins": ["https://partner.example.test"],
                    }
                ]
                if code == 200
                else {"error": "forbidden"}
            )
        elif self.rich and path in {f"{self.prefix}/admin/realms/{realm}" for realm in public_realms}:
            realm = path.rsplit("/", 1)[-1]
            code = 200 if authorized else 401
            if realm == "partners" and self.deny_partner_settings:
                code = 403
            payload = (
                {
                    "realm": realm,
                    "bruteForceProtected": realm != "partners",
                    "registrationAllowed": realm == "partners",
                    "sslRequired": "external",
                    "passwordPolicy": "length(12) and digits(1)" if realm == "corp" else "",
                }
                if code == 200
                else {"error": "forbidden"}
            )
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


def test_keycloak_settings_colors_follow_airflow_baseline() -> None:
    class ConsoleStub:
        def __init__(self) -> None:
            self.lines: list[str] = []

        def _paint(self, value: str, color: str, _stream: Any) -> str:
            return f"<{color}>{value}</{color}>"

        def plain(self, value: str) -> None:
            self.lines.append(value)

    console = ConsoleStub()
    lines = (
        "KEYCLOAK\th\t8080\t [*] Public Realms Enumeration (realms:3)",
        "KEYCLOAK\th\t8080\t [+] Realm Name=corp (brute-force protected:True) "
        "(registration allowed:False) (SSL required:external) "
        '(password policy:"length(12) and digits(1)")',
        "KEYCLOAK\th\t8080\t [+] Realm Name=partners (brute-force protected:False) "
        "(registration allowed:True) (SSL required:none) (password policy:none)",
        "KEYCLOAK\th\t8080\t [+] Client Name=corp/legacy-reports (type:public) "
        "(direct grants:True) (implicit:True) (redirect URIs:1) (web origins:1)",
        'KEYCLOAK\th\t8080\t [+] Client Web Origin="*" (client:corp/legacy-reports)',
        "KEYCLOAK\th\t8080\t [*] Realm Settings Name=partners (access:denied)",
        "KEYCLOAK\th\t8080\t [+] Client Name=corp/service (type:unknown) "
        "(direct grants:unknown) (implicit:unknown) (redirect URIs:unknown) (web origins:0)",
    )
    for line in lines:
        assert _render_colored_keycloak_line(console, line)
    assert "<white>Public Realms Enumeration" in console.lines[0]
    assert "<true_red>realms:3</true_red>" in console.lines[0]
    assert "<orange>Realm Name=corp</orange>" in console.lines[1]
    assert "<bright_green>brute-force protected:True</bright_green>" in console.lines[1]
    assert "<bright_green>registration allowed:False</bright_green>" in console.lines[1]
    assert '<orange>password policy:"length(12) and digits(1)"</orange>' in console.lines[1]
    assert "<orange>SSL required:external</orange>" in console.lines[1]
    assert "<true_red>brute-force protected:False</true_red>" in console.lines[2]
    assert "<true_red>registration allowed:True</true_red>" in console.lines[2]
    assert "<true_red>direct grants:True</true_red>" in console.lines[3]
    assert "<orange>type:public</orange>" in console.lines[3]
    assert "<true_red>redirect URIs:1</true_red>" in console.lines[3]
    assert '<orange>Client Web Origin="*" (client:corp/legacy-reports)</orange>' in console.lines[4]
    assert "<bright_green>access:denied</bright_green>" in console.lines[5]
    assert "<orange>direct grants:unknown</orange>" in console.lines[6]
    assert "<bright_green>web origins:0</bright_green>" in console.lines[6]


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
    assert _get_public(accepted, source).status == 200
    assert accepted.urls == [source, accepted.destination]
    rejected = ClientStub("https://idp.example/login")
    assert _get_public(rejected, source).status == 302
    assert rejected.urls == [source]


def test_realm_candidates_are_bounded_and_infer_url_realm() -> None:
    args = type("Args", (), {"realm": None, "enum_realms": True})()
    realms = _realms(args, "/prefix/auth/realms/custom/protocol/openid-connect")
    assert realms[0] == "custom"
    assert "master" in realms
    assert {"corp", "partners", "development", "uat", "identity"}.issubset(realms)
    assert 20 < len(realms) <= 32
    assert len(realms) == len(set(realms))


def test_enumerates_public_realms_and_authenticated_settings(
    keycloak_server: tuple[str, type[_KeycloakHandler]], capsys: pytest.CaptureFixture[str]
) -> None:
    url, handler = keycloak_server
    handler.rich = True
    args = [
        "keycloak",
        "-t",
        url,
        "--realm",
        "corp",
        "--realm",
        "partners",
        "--token",
        "valid-token",
        "--enum-realms",
        "--show-realms",
        "--show-clients",
        "--no-color",
    ]
    assert main([*args, "-f", "json"]) == 0
    data = _records(capsys.readouterr().out)[0]
    assert data["public_realms"] == ["corp", "master", "partners"]
    assert data["visible_realms"] == ["corp", "master", "partners"]
    assert data["realm_settings"][0] == {
        "realm": "corp",
        "brute_force_protected": True,
        "registration_allowed": False,
        "ssl_required": "external",
        "password_policy": "length(12) and digits(1)",
    }
    legacy = next(item for item in data["client_settings"] if item["client_id"] == "legacy-reports")
    assert legacy["type"] == "public"
    assert legacy["direct_access_grants"] is True
    assert legacy["implicit_flow"] is True
    assert legacy["redirect_uris"] == ["https://reports.example.test/*"]
    assert legacy["web_origins"] == ["*"]
    assert "never-print-this-secret" not in json.dumps(data)
    assert all(not auth for path, auth in handler.calls if path.startswith("/realms/") and "userinfo" not in path)

    assert main(args) == 0
    output = capsys.readouterr().out
    assert "Public Realms Enumeration (realms:3)" in output
    assert "Realm Name=corp (brute-force protected:True) (registration allowed:False)" in output
    assert "Client Name=corp/legacy-reports (type:public) (direct grants:True) (implicit:True)" in output
    assert 'Client Redirect URI="https://reports.example.test/*"' in output
    assert 'Client Web Origin="*"' in output
    assert "never-print-this-secret" not in output
    assert "\x1b[" not in output


def test_restricted_settings_remain_denied_not_false(
    keycloak_server: tuple[str, type[_KeycloakHandler]], capsys: pytest.CaptureFixture[str]
) -> None:
    url, handler = keycloak_server
    handler.rich = True
    handler.deny_partner_settings = True
    handler.deny_partner_clients = True
    args = ["keycloak", "-t", url, "--token", "valid-token", "--show-realms", "--show-clients", "--realm", "partners"]
    assert main([*args, "-f", "json", "--no-color"]) == 0
    data = _records(capsys.readouterr().out)[0]
    assert data["realm_settings_access"]["partners"] == "denied"
    assert "partners" not in {item["realm"] for item in data["realm_settings"]}
    assert data["clients_access"]["partners"] == "denied"
    assert data.get("client_settings", []) == [] or all(item["realm"] != "partners" for item in data["client_settings"])
    assert main([*args, "--no-color"]) == 0
    output = capsys.readouterr().out
    assert "Realm Settings Name=partners (access:denied)" in output
    assert "Clients Name=partners (access:denied)" in output
    assert "Realm Name=partners (brute-force protected:False)" not in output


def test_malformed_admin_settings_do_not_become_safe_values() -> None:
    realm = _realm_settings(
        {"realm": "corp", "bruteForceProtected": "false", "registrationAllowed": 0, "sslRequired": "maybe"}, "corp"
    )
    assert realm == {
        "realm": "corp",
        "brute_force_protected": None,
        "registration_allowed": None,
        "ssl_required": None,
        "password_policy": None,
    }
    assert _realm_settings({"realm": "other", "bruteForceProtected": True}, "corp") is None
    client = _client_settings(
        {
            "clientId": "portal",
            "publicClient": "true",
            "directAccessGrantsEnabled": 1,
            "implicitFlowEnabled": "false",
            "redirectUris": "*",
            "webOrigins": None,
        },
        "corp",
    )
    assert client is not None
    assert client["type"] == "unknown"
    assert client["direct_access_grants"] is None
    assert client["implicit_flow"] is None
    assert client["redirect_uri_count"] is None
    assert client["web_origin_count"] is None
    assert _endpoint_values([1, "https://example.test"]) == ([], None, False)


@given(st.lists(st.text(max_size=600), max_size=80))
def test_client_endpoint_inventory_is_bounded(values: list[str]) -> None:
    selected, count, truncated = _endpoint_values(values)
    assert count == len(values)
    assert len(selected) <= 20
    assert all(len(item) <= 512 for item in selected)
    assert truncated == (len(values) > 20 or any(len(item) > 512 for item in values[:20]))


def test_enriched_inventory_files_are_ansi_free(
    keycloak_server: tuple[str, type[_KeycloakHandler]], tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    url, handler = keycloak_server
    handler.rich = True
    args = [
        "keycloak",
        "-t",
        url,
        "--token",
        "valid-token",
        "--enum-realms",
        "--show-realms",
        "--show-clients",
    ]
    txt_path = tmp_path / "inventory.txt"
    assert main([*args, "-o", str(txt_path), "--no-color"]) == 0
    assert "\x1b[" not in capsys.readouterr().out
    text = txt_path.read_text()
    assert "\x1b[" not in text
    assert "Client Name=corp/legacy-reports" in text
    assert "never-print-this-secret" not in text
    assert all(len(line.split("\t", 3)) == 4 for line in text.splitlines() if line.startswith("KEYCLOAK\t"))
    json_path = tmp_path / "inventory.json"
    assert main([*args, "-f", "json", "-o", str(json_path), "--no-color"]) == 0
    assert "\x1b[" not in capsys.readouterr().out
    payload = json_path.read_text()
    assert "\x1b[" not in payload
    assert "never-print-this-secret" not in payload
    assert _records(payload)[0]["public_realms"] == ["corp", "master", "partners"]


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
