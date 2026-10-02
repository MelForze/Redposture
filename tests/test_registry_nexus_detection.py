"""Regressions for Nexus status fingerprints, release builds and auth inference."""

from __future__ import annotations

import base64
import json
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from redposture_core.cli_args import parse_args
from redposture_core.modules.registry import actions, stage
from redposture_core.stage_runtime import AuditCommandRunner


@pytest.mark.parametrize("raw", ["3.72.0", "3.72.0-04", "3.73.0-12", " 3.68.1-02 "])
def test_nexus_numeric_build_is_not_a_prerelease(raw: str) -> None:
    expected = raw.strip().split("-")[0]
    assert actions._nexus_release_version(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [None, True, 3.72, {}, [], "3", "3.72", "3.72.0-rc1", "3.72.0+build", "v3.72.0", "٣.٧٢.٠", "3.72.0\x00"],
)
def test_nexus_incomplete_or_ambiguous_versions_are_not_guessed(raw: Any) -> None:
    assert actions._nexus_release_version(raw) is None


@pytest.mark.parametrize(
    "headers,payload",
    [
        ({}, {}),
        ({}, {"version": "3.72.0", "edition": "OSS"}),
        ({}, {"version": "3.72.0", "name": "Nexus Repository"}),
        ({}, {"productName": "Nexus Repository", "version": "3.72"}),
        ({"Server": "nginx"}, {"version": "3.72.0"}),
        ({"Server": "NotNexus/3.72.0"}, {}),
        ({"Server": "proxy mentions Nexus/3.72.0"}, {}),
        ({"WWW-Authenticate": 'Basic realm="private"'}, {}),
        ({"WWW-Authenticate": 'Bearer realm="Nexus Repository"'}, {}),
    ],
)
def test_nexus_rejects_generic_responses(headers: dict[str, str], payload: dict[str, Any]) -> None:
    assert actions._nexus_status_info(headers, payload) is None


@pytest.mark.parametrize("header", ["Server", "server", "SERVER"])
def test_nexus_empty_status_uses_vendor_server_version(header: str) -> None:
    assert actions._nexus_status_info({header: "Nexus/3.72.0-04 (OSS)"}, {}) == {
        "version": "3.72.0",
        "raw_version": "3.72.0-04",
        "version_source": "server_header",
    }


@pytest.mark.parametrize("key", ["product", "productName", "applicationName"])
def test_nexus_product_body_is_independent_evidence(key: str) -> None:
    info = actions._nexus_status_info({}, {key: "Sonatype Nexus Repository", "release": "3.73.0-12"})
    assert info is not None
    assert info["version"] == "3.73.0"
    assert info["raw_version"] == "3.73.0-12"
    assert info["version_source"] == "status_body"


def test_nexus_conflicting_versions_keep_product_but_suppress_cve_version() -> None:
    info = actions._nexus_status_info({"server": "Nexus/3.72.0-04 (OSS)"}, {"version": "3.73.0"})
    assert info is not None
    assert "version" not in info
    assert info["version_error"] == "conflicting Nexus version evidence"


@pytest.mark.parametrize("headers", [{}, {"server": "Nexus/3.72.0-04 (OSS)"}])
def test_nexus_checks_both_body_version_fields_for_conflicts(headers: dict[str, str]) -> None:
    info = actions._nexus_status_info(
        headers, {"productName": "Nexus Repository", "version": "3.72.0", "release": "3.73.0"}
    )
    assert info is not None and "version" not in info and "release" not in info
    assert info["version_error"] == "conflicting Nexus version evidence"


@pytest.mark.parametrize("server", ["Nexus", "Nexus/3.72", "Nexus/unknown", "Sonatype Nexus Repository Manager"])
def test_nexus_product_without_exact_version_remains_version_unknown(server: str) -> None:
    info = actions._nexus_status_info({"server": server}, {})
    assert info == {}


@given(st.text(max_size=512), st.text(max_size=512))
def test_nexus_generic_version_and_name_never_confirm_product(version: str, name: str) -> None:
    assert actions._nexus_status_info({}, {"version": version, "name": name, "edition": "OSS"}) is None


@given(st.integers(0, 999999), st.integers(0, 999999), st.integers(0, 999999), st.integers(0, 999999))
def test_nexus_server_release_build_preserves_exact_semantic_version(a: int, b: int, c: int, build: int) -> None:
    version = f"{a}.{b}.{c}"
    info = actions._nexus_status_info({"server": f"Nexus/{version}-{build} (OSS)"}, {})
    assert info is not None and info["version"] == version


@contextmanager
def _status_service(
    status: int,
    body: bytes,
    headers: dict[str, str],
    *,
    accept_credentials: bool = False,
    authenticated_headers: dict[str, str] | None = None,
) -> Iterator[tuple[int, list[tuple[str, str, str | None]]]]:
    requests: list[tuple[str, str, str | None]] = []
    valid_auth = "Basic " + base64.b64encode(b"observer:correct").decode()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            auth = self.headers.get("Authorization")
            requests.append(("GET", self.path, auth))
            code, response, extra = 404, b"", {}
            if self.path == "/service/rest/v1/status":
                code, response, extra = status, body, headers
                if accept_credentials and auth == valid_auth:
                    code, response = 200, b""
                    extra = authenticated_headers if authenticated_headers is not None else headers
            elif self.path == "/service/rest/v1/repositories":
                code, response = 200, b"[]"
            elif self.path == "/service/rest/v1/security/users":
                code, response = (200, b'[{"userId":"observer"}]') if auth == valid_auth else (401, b"")
            self.send_response_only(code)
            for key, value in extra.items():
                self.send_header(key, value)
            self.send_header("Content-Length", str(len(response)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(response)

        def log_message(self, *_args: Any) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        yield server.server_port, requests
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)
        assert not worker.is_alive()


def _audit(port: int, *extra: str) -> list[str]:
    args = parse_args(["nexus", "-t", f"http://127.0.0.1:{port}", "--enum-cve", "--no-color", *extra])
    lines: list[str] = []
    AuditCommandRunner(
        args=args, spec=stage.build_registry_spec(args, product="nexus"), emit_line=lines.append
    ).run_plan(stage.build_registry_plan(args, product="nexus"))
    return lines


def _record(port: int, *extra: str) -> dict[str, Any]:
    records = [json.loads(line) for line in _audit(port, "--format", "json", *extra)]
    targets = [record for record in records if record.get("type") != "summary"]
    assert len(targets) == 1
    return targets[0]


@pytest.mark.parametrize(
    "status,body,headers",
    [
        (200, b"", {}),
        (200, b'{"version":"3.72.0","edition":"OSS"}', {}),
        (200, b"<html>Nexus login</html>", {}),
        (401, b"login", {"WWW-Authenticate": 'Basic realm="private"'}),
        (403, b"SSO authentication required", {}),
    ],
)
def test_foreign_status_never_starts_credentials_data_or_cves(
    status: int, body: bytes, headers: dict[str, str]
) -> None:
    with _status_service(status, body, headers) as (port, requests):
        record = _record(port, "-u", "observer", "-p", "wrong", "--assets")
        lines = _audit(port, "-u", "observer", "-p", "wrong", "--assets")
    assert record["is_registry"] is False
    assert record.get("is_nexus") is not True
    assert record["cve_enumeration"]["findings"] == []
    assert not any("CVE's Enumeration" in line or "potentially affected" in line for line in lines)
    assert not any("Nexus Repository" in line or "observer:wrong" in line for line in lines)
    assert record["error"] == "requested nexus fingerprint not confirmed"
    assert all(method == "GET" and auth is None for method, _path, auth in requests)
    assert not any(path.startswith("/service/rest/v1/repositories") for _method, path, _auth in requests)


def test_empty_real_nexus_status_enriches_json_and_emits_cve_in_order() -> None:
    with _status_service(200, b"", {"Server": "Nexus/3.72.0-04 (OSS)"}) as (port, requests):
        record = _record(port)
        lines = _audit(port)
    assert record["is_nexus"] is True
    assert record["nexus_info"]["version"] == "3.72.0"
    assert record["nexus_info"]["raw_version"] == "3.72.0-04"
    assert record["cve_enumeration"]["status"] == "matched"
    assert any(item["id"] == "CVE-2026-3199" for item in record["cve_enumeration"]["findings"])
    service = next(i for i, line in enumerate(lines) if "[*] Nexus Repository (auth required:" in line)
    heading = next(i for i, line in enumerate(lines) if "CVE's Enumeration" in line)
    finding = next(i for i, line in enumerate(lines) if "CVE-2026-3199 potentially affected" in line)
    assert service < heading < finding
    assert sum("CVE's Enumeration" in line for line in lines) == 1
    assert all(method == "GET" for method, _path, _auth in requests)


@pytest.mark.parametrize("status", [401, 403])
@pytest.mark.parametrize("password", ["wrong", "correct"])
def test_authenticated_nexus_version_does_not_turn_rejection_into_valid_credentials(status: int, password: str) -> None:
    with _status_service(status, b"Unauthorized", {"Server": "Nexus/3.72.0-04 (OSS)"}, accept_credentials=True) as (
        port,
        requests,
    ):
        record = _record(port, "-u", "observer", "-p", password)
    assert record["is_nexus"] is True
    assert record["auth_required"] is True
    assert record["nexus_info"]["version"] == "3.72.0"
    assert record["provided_credentials_ok"] is (password == "correct")
    assert record["status"] == ("valid_credentials" if password == "correct" else "auth_required")
    findings = record["cve_enumeration"]["findings"]
    assert all(item["privileges_required"] != "L" for item in findings) or password == "correct"
    assert any(item["id"] == "CVE-2026-3199" for item in findings) is (password == "correct")
    assert all(method == "GET" for method, _path, _auth in requests)


def test_nexus_basic_realm_confirms_product_but_does_not_invent_version() -> None:
    with _status_service(401, b"", {"WWW-Authenticate": 'Basic realm="Sonatype Nexus Repository Manager"'}) as (
        port,
        _requests,
    ):
        record = _record(port)
        lines = _audit(port)
    assert record["is_nexus"] is True and record["auth_required"] is True
    assert record["cve_enumeration"]["status"] == "version_unknown"
    assert not any("CVE's Enumeration" in line for line in lines)


def test_nexus_version_revealed_after_auth_stays_on_single_service_line() -> None:
    with _status_service(
        401,
        b"Unauthorized",
        {"WWW-Authenticate": 'Basic realm="Sonatype Nexus Repository Manager"'},
        accept_credentials=True,
        authenticated_headers={"Server": "Nexus/3.72.0-04 (OSS)"},
    ) as (port, _requests):
        lines = _audit(port, "-u", "observer", "-p", "correct")
    service_lines = [line for line in lines if "[*] Nexus Repository (auth required:" in line]
    assert len(service_lines) == 1
    assert service_lines[0].endswith("(version:3.72.0)")
    assert lines.index(service_lines[0]) < next(i for i, line in enumerate(lines) if "[+] observer:correct" in line)
