"""Existing Keycloak secrets are read by GET; no generation or role changes."""

from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

import pytest

from redposture_core.modules.keycloak import discover
from tests.test_docker_discover import Pool
from tests.test_keycloak_module import keycloak_server as keycloak_server


@pytest.fixture
def context():
    Pool.calls = []
    Pool.routes = {
        "/admin/realms": (200, [{"realm": "qa"}]),
        "/admin/realms/qa": (200, {"realm": "qa", "smtpServer": {"password": "inactive-smtp!42"}}),
        "/admin/realms/qa/components": (200, [{"config": {"bindCredential": ["inactive-ldap!42"]}}]),
        "/admin/realms/qa/identity-provider/instances": (
            200,
            [{"alias": "qa", "config": {"clientSecret": "**********", "tokenUrl": "https://identity.invalid/token"}}],
        ),
        "/admin/realms/qa/clients": (
            200,
            [{"id": "c1", "clientId": "qa", "publicClient": False}, {"id": "public", "publicClient": True}],
        ),
        "/admin/realms/qa/clients/c1/client-secret": (200, {"type": "secret", "value": "inactive-client!42"}),
    }
    return SimpleNamespace(
        host="qa.invalid",
        port=8080,
        credential=SimpleNamespace(token=None),
        lifecycle_state=SimpleNamespace(http=Pool()),
        args=SimpleNamespace(timeout=1, discover_time=30, realm=[], _keycloak_token="login-only-token"),
    )


def run(ctx):
    return discover.discover(
        ctx,
        {
            "status": "valid_credentials",
            "provided_credentials_ok": True,
            "api_endpoint": "http://qa.invalid",
            "detected_realm": "qa",
        },
    )


def test_all_visible_sources_no_masked_values_or_public_client_secret(context):
    report = run(context)
    assert report["status"] == "complete"
    assert {str(f["value"]) for f in report["findings"]} == {
        "inactive-smtp!42",
        "inactive-ldap!42",
        "inactive-client!42",
    }
    assert "/admin/realms/qa/clients/public/client-secret" not in Pool.calls
    assert all(row["complete"] and row["read"] for row in report["sources"])


def test_explicit_realm_does_not_download_other_realms(context):
    context.args.realm = ["qa"]
    report = run(context)
    assert report["status"] == "complete"
    assert "/admin/realms" not in Pool.calls


def test_denied_client_secret_is_partial_and_preserves_other_sources(context):
    Pool.routes["/admin/realms/qa/clients/c1/client-secret"] = (403, {"value": "not-readable-error"})
    report = run(context)
    assert report["status"] == "partial"
    assert {str(f["value"]) for f in report["findings"]} == {"inactive-smtp!42", "inactive-ldap!42"}
    assert next(s for s in report["sources"] if s["id"] == "keycloak.client_credentials")["denied"] == 1


def test_ordinary_realm_token_no_admin_access_is_unavailable(context):
    context.args.realm = ["qa"]
    Pool.routes = {path: (403, {"error": "denied"}) for path in Pool.routes}
    report = run(context)
    assert report["status"] == "unavailable" and not report["findings"]


@pytest.mark.parametrize("repeat", [False, True])
def test_client_pagination_and_repeat_guard(context, monkeypatch, repeat):
    monkeypatch.setattr(discover, "_PAGE_SIZE", 2)
    original = context.lifecycle_state.http.request_stream
    offsets = []

    def request(method, url, **kwargs):
        if urlsplit(url).path == "/admin/realms/qa/clients":
            first = int(parse_qs(urlsplit(url).query)["first"][0])
            offsets.append(first)
            Pool.routes["/admin/realms/qa/clients"] = (
                200,
                [{"id": "c1"}, {"id": "public", "publicClient": True}] if not first or repeat else [],
            )
        return original(method, url, **kwargs)

    context.lifecycle_state.http.request_stream = request
    report = run(context)
    assert offsets == [0, 2]
    assert report["status"] == ("partial" if repeat else "complete")
    assert Pool.calls.count("/admin/realms/qa/clients/c1/client-secret") == 1


def test_paginated_client_findings_keep_the_physical_page(context, monkeypatch):
    monkeypatch.setattr(discover, "_PAGE_SIZE", 1)
    original = context.lifecycle_state.http.request_stream

    def request(method, url, **kwargs):
        if urlsplit(url).path == "/admin/realms/qa/clients":
            first = int(parse_qs(urlsplit(url).query)["first"][0])
            Pool.routes["/admin/realms/qa/clients"] = (
                200,
                [{"id": f"c{first}", "publicClient": True, "attributes": {"password": f"page-{first}-secret!42"}}]
                if first < 2
                else [],
            )
        return original(method, url, **kwargs)

    context.lifecycle_state.http.request_stream = request
    report = run(context)
    assert report["status"] == "complete"
    for offset in range(2):
        finding = next(f for f in report["findings"] if str(f["value"]) == f"page-{offset}-secret!42")
        assert f"/clients?first={offset}&max=1" in finding["object_path"]


@pytest.mark.parametrize("token", ["valid-token", "invalid-token"])
def test_discover_full_cli_auth_and_ansi_free_files(keycloak_server, tmp_path, monkeypatch, token):
    import json

    from redposture_core.cli import main

    url, handler = keycloak_server
    original = handler.do_GET
    documents = {
        "/admin/realms/master": {"realm": "master", "smtpServer": {"password": "inactive-cli-smtp!42"}},
        "/admin/realms/master/clients": [{"id": "c1", "publicClient": False}],
        "/admin/realms/master/clients/c1/client-secret": {"type": "secret", "value": "inactive-cli-client!42"},
        "/admin/realms/master/components": [],
        "/admin/realms/master/identity-provider/instances": [],
    }

    def get(self):
        path = urlsplit(self.path).path
        if path not in documents:
            return original(self)
        accepted = self.headers.get("Authorization") == "Bearer valid-token"
        raw = json.dumps(documents[path] if accepted else {"error": "unauthorized"}).encode()
        self.send_response(200 if accepted else 401)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    monkeypatch.setattr(handler, "do_GET", get)
    arguments = [
        "keycloak",
        "-t",
        url,
        "--token",
        token,
        "--realm",
        "master",
        "--discover",
        "--discover-time",
        "30",
        "--no-color",
    ]
    for format in ("json", "txt"):
        output = tmp_path / ("result." + format)
        assert main([*arguments, "--format", format, "-o", str(output)]) == 0
        raw = output.read_text()
        assert "\x1b" not in raw and token not in raw
        if format == "json":
            loaded = json.loads(raw)
            report = (loaded[0] if isinstance(loaded, list) else loaded)["content_discovery"]
            assert report["status"] == ("complete" if token == "valid-token" else "unavailable")
            assert {str(f["value"]) for f in report["findings"]} == (
                {"inactive-cli-smtp!42", "inactive-cli-client!42"} if token == "valid-token" else set()
            )
        elif token == "valid-token":
            assert 'Value="inactive-cli-smtp!42"' in raw and 'Value="inactive-cli-client!42"' in raw
