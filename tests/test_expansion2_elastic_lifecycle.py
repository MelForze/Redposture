"""Lifecycle selection, authenticated metadata and vendor-specific user evidence."""

from __future__ import annotations

import gzip
import json
import zlib
from types import SimpleNamespace
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest

from redposture_core.modules.elastic import actions
from redposture_core.stage_runtime import AuditCredentialRun


def context(*, token: str | None = None, anonymous: bool = False) -> SimpleNamespace:
    return SimpleNamespace(
        host="127.0.0.1",
        port=9200,
        target=SimpleNamespace(scheme="http"),
        args=SimpleNamespace(timeout=1.0, retries=0, proxy="test-proxy", debug=False, ca_file=None),
        lifecycle_state=actions.ElasticLifecycleState(),
        credential=AuditCredentialRun(
            username=None if token or anonymous else "auditor",
            password=None if token or anonymous else "valid-password",
            token=token,
            source="anonymous" if anonymous else "provided",
        ),
    )


def detected(**updates: Any) -> dict[str, Any]:
    return {
        "host": "127.0.0.1",
        "port": 9200,
        "status": "auth_required",
        "is_elastic": True,
        "auth_required": True,
        "scheme": "http",
        "insecure_effective": False,
        "server_version": None,
        "vendor": "elasticsearch",
        **updates,
    }


def options(*enabled: str) -> dict[str, bool]:
    return {
        name: name in enabled for name in ("show_endpoints", "show_plugins", "show_cluster", "show_users", "discover")
    }


def http(value: Any, status: int = 200) -> tuple[int, bytes, dict[str, str], None]:
    return status, json.dumps(value).encode(), {}, None


@pytest.mark.parametrize(
    "encoding", ["gzip", "gzip-prefix", "gzip-wrapped", "deflate", "raw-deflate", "deflate-wrapped", "bom"]
)
def test_detection_recovers_identity_and_version_from_encoded_root(
    monkeypatch: pytest.MonkeyPatch,
    encoding: str,
) -> None:
    raw = json.dumps(
        {
            "name": "node-a",
            "cluster_name": "qa",
            "version": {"number": "8.17.3", "build_flavor": "default"},
            "tagline": "You Know, for Search",
        }
    ).encode()
    headers = {}
    if encoding == "bom":
        payload = b"\xef\xbb\xbf" + raw
    elif encoding.startswith("gzip"):
        payload = gzip.compress(b"gateway preface\n" + raw if encoding.endswith("wrapped") else raw)
        if encoding != "gzip-prefix":
            headers["Content-Encoding"] = "gzip"
    else:
        compressed = zlib.compress(b"gateway preface\n" + raw if encoding.endswith("wrapped") else raw)
        payload = compressed[2:-4] if encoding == "raw-deflate" else compressed
        headers["Content-Encoding"] = "deflate"
    requests = []

    def request(host: str, port: int, path: str, timeout: float, **kwargs: Any) -> Any:
        requests.append(path)
        return 200, payload, headers.copy(), None

    monkeypatch.setattr(actions, "_elastic_request", request)
    result = actions.detect_elastic(context(), {})
    assert result["is_elastic"] is True and result["server_version"] == "8.17.3"
    assert result["auth_required"] is False
    assert requests == ["/"]


@pytest.mark.parametrize("root_fault", ["truncated-gzip", "bad-deflate", "empty"])
def test_unreadable_root_does_not_mask_independent_node_identity(
    monkeypatch: pytest.MonkeyPatch,
    root_fault: str,
) -> None:
    payload, headers = {
        "truncated-gzip": (b"\x1f\x8bbroken", {"Content-Encoding": "gzip"}),
        "bad-deflate": (b"not-deflate", {"Content-Encoding": "deflate"}),
        "empty": (b"", {}),
    }[root_fault]

    def request(host: str, port: int, path: str, timeout: float, **kwargs: Any) -> Any:
        if path.startswith("/_nodes"):
            return http({"nodes": {"node-a": {"version": "8.17.3"}}})
        if path == "/_cluster/health":
            return http({"cluster_name": "qa", "status": "green"})
        return 200, payload, headers.copy(), None

    monkeypatch.setattr(actions, "_elastic_request", request)
    monkeypatch.setattr(actions, "_can_probe_direct_async", lambda *_args: False)
    result = actions.detect_elastic(context(), {})
    assert result["is_elastic"] is True and result["server_version"] == "8.17.3"
    assert "nodes_version_shape" in result["detect_signals"]


@pytest.mark.parametrize("node_fault", ["transport", "denied", "server", "invalid_json", "missing_version", "success"])
def test_verified_identity_survives_authenticated_version_resolution_failure(
    monkeypatch: pytest.MonkeyPatch,
    node_fault: str,
) -> None:
    paths = []

    def request(host: str, port: int, path: str, timeout: float, **kwargs: Any) -> Any:
        paths.append(path)
        assert "Basic " in kwargs["headers"]["Authorization"]
        if path == "/_security/_authenticate":
            return http({"username": "auditor", "roles": ["monitoring_user"], "enabled": True})
        if path == "/":
            return http({"error": {"type": "security_exception", "reason": "root denied"}}, 403)
        assert path.startswith("/_nodes")
        return {
            "transport": (0, b"", {}, "connection reset"),
            "denied": http({}, 403),
            "server": http({}, 503),
            "invalid_json": (200, b"broken", {}, None),
            "missing_version": http({"nodes": {"n": {"name": "node-a"}}}),
            "success": http({"nodes": {"n": {"version": "8.17.3"}}}),
        }[node_fault]

    monkeypatch.setattr(actions, "_elastic_request", request)
    result = actions.authenticate_elastic(context(), detected(), {})
    assert result["auth_valid"] is True and result["identity_verified"] is True
    assert result["status"] == "valid_credentials" and result["error"] is None
    assert len(paths) == 3
    if node_fault == "success":
        assert result["server_version"] == "8.17.3"
        assert result["server_version_source"] == "authenticated"
    else:
        assert result["server_version"] is None
        assert (
            result["server_version_error"]
            == {
                "transport": "connection reset",
                "denied": "Access Denied",
                "server": "nodes status=503",
                "invalid_json": "version unavailable",
                "missing_version": "version unavailable",
            }[node_fault]
        )


@pytest.mark.parametrize("root_fault", ["transport", "server"])
def test_authenticated_root_metadata_failure_stops_version_probe_without_rejecting_credentials(
    monkeypatch: pytest.MonkeyPatch,
    root_fault: str,
) -> None:
    paths = []

    def request(host: str, port: int, path: str, timeout: float, **kwargs: Any) -> Any:
        paths.append(path)
        if path == "/_security/_authenticate":
            return http({"username": "auditor"})
        assert path == "/"
        return (0, b"", {}, "root timeout") if root_fault == "transport" else http({}, 503)

    monkeypatch.setattr(actions, "_elastic_request", request)
    result = actions.authenticate_elastic(context(), detected(), {})
    assert result["credential_accepted"] is True and result["error"] is None
    assert result["server_version_error"] == ("root timeout" if root_fault == "transport" else "status=503")
    assert paths == ["/_security/_authenticate", "/"]


@pytest.mark.parametrize("vendor", ["elasticsearch", "opensearch"])
def test_user_collection_preserves_disabled_state_and_merges_vendor_role_lists(
    monkeypatch: pytest.MonkeyPatch,
    vendor: str,
) -> None:
    paths = []
    users = {
        "zeta": {"roles": ["reader"], "enabled": False, "full_name": "Disabled account"},
        "alpha": {
            "roles": ["reader", "reader"],
            "backend_roles": ["ops", "reader"],
            "opendistro_security_roles": ["monitor"],
            "disabled": False,
            "description": "Operations",
        },
    }

    def request(host: str, port: int, path: str, timeout: float, **kwargs: Any) -> Any:
        paths.append(path)
        return http(users)

    monkeypatch.setattr(actions, "_elastic_request", request)
    result = actions.collect_elastic_data(
        context(anonymous=True), detected(status="open_no_auth", vendor=vendor), options("show_users")
    )
    assert len(paths) == 1
    assert result["users"] == [
        {
            "username": "alpha",
            "roles": ["ops", "reader", "monitor"] if vendor == "opensearch" else ["reader"],
            "enabled": True,
            "full_name": "Operations",
        },
        {"username": "zeta", "roles": ["reader"], "enabled": False, "full_name": "Disabled account"},
    ]
    assert result["error"] is None


@pytest.mark.parametrize("action", ["show_endpoints", "show_plugins", "show_cluster", "show_users"])
def test_action_selection_only_requests_selected_surface_and_keeps_existing_auth_error(
    monkeypatch: pytest.MonkeyPatch,
    action: str,
) -> None:
    paths = []

    def request(host: str, port: int, path: str, timeout: float, **kwargs: Any) -> Any:
        paths.append(path)
        assert "Authorization" not in kwargs["headers"]
        return http({"error": {"type": "security_exception", "reason": "forbidden"}}, 403)

    monkeypatch.setattr(actions, "_elastic_request", request)
    result = actions.collect_elastic_data(
        context(),
        detected(status="invalid_credentials_anonymous", auth_required=False, error="credential diagnostic"),
        options(action),
    )
    assert paths
    if action == "show_endpoints":
        assert "/_cat?help" in paths and "/_cat/" in paths
        assert not any(
            path.startswith(("/_nodes", "/_cluster/settings", "/_security/user", "/_search")) for path in paths
        )
        assert result["cat_endpoints"] == []
    elif action == "show_plugins":
        assert paths == ["/_cat/plugins?format=json"]
    elif action == "show_cluster":
        assert len(paths) == 2 and paths[0] == "/_cluster/health"
        assert urlsplit(paths[1]).path == "/_cluster/settings"
        assert parse_qs(urlsplit(paths[1]).query) == {"flat_settings": ["true"], "include_defaults": ["true"]}
    else:
        assert paths == ["/_security/user"]
    assert result["error"] == "credential diagnostic; Access Denied"
    assert result["status"] == "invalid_credentials_anonymous"


@pytest.mark.parametrize("failure", ["transport", "http"])
def test_endpoint_discovery_reports_first_transport_or_http_failure_without_inventing_available_endpoints(
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
) -> None:
    def request(host: str, port: int, path: str, timeout: float, **kwargs: Any) -> Any:
        return (0, b"", {}, "connection reset") if failure == "transport" else http({}, 503)

    monkeypatch.setattr(actions, "_elastic_request", request)
    result = actions.collect_elastic_data(
        context(anonymous=True), detected(status="open_no_auth"), options("show_endpoints")
    )
    assert result["cat_endpoints"] == []
    assert result["endpoints_error"] == ("connection reset" if failure == "transport" else "/_cat?help status=503")
    assert result["endpoint_diagnostics"]
    assert all(item["status"] == (0 if failure == "transport" else 503) for item in result["endpoint_diagnostics"])


@pytest.mark.parametrize("recover", [True, False])
def test_detection_retries_transient_confirmation_failures_with_a_bounded_budget(
    monkeypatch: pytest.MonkeyPatch,
    recover: bool,
) -> None:
    counts: dict[str, int] = {}

    def request(host: str, port: int, path: str, timeout: float, **kwargs: Any) -> Any:
        counts[path] = counts.get(path, 0) + 1
        if path == "/":
            return http({})
        if recover and counts[path] == 2 and path.startswith("/_nodes"):
            return http({"nodes": {"n": {"version": "8.17.3"}}})
        return 0, b"", {}, "read timed out"

    monkeypatch.setattr(actions, "_elastic_request", request)
    monkeypatch.setattr(actions, "_can_probe_direct_async", lambda *_args: False)
    ctx = context()
    ctx.args.retries = 1
    result = actions.detect_elastic(ctx, {})
    assert result["is_elastic"] is recover
    assert max(counts.values()) == 2
    assert counts["/"] == 1
    trace = result["detect_probe_trace"]
    node_trace = [item for item in trace if item["path"].startswith("/_nodes")]
    assert len(node_trace) == 2
    assert node_trace[0]["status"] == 0
    assert node_trace[1]["status"] == (200 if recover else 0)


@pytest.mark.parametrize("root_status", [0, 401, 503])
def test_unavailable_identity_endpoints_keep_root_fallback_transport_or_rejection_explicit(
    monkeypatch: pytest.MonkeyPatch,
    root_status: int,
) -> None:
    paths = []

    def request(host: str, port: int, path: str, timeout: float, **kwargs: Any) -> Any:
        paths.append(path)
        if path == "/":
            return (0, b"", {}, "root timed out") if root_status == 0 else http({"error": "root rejected"}, root_status)
        return http(
            {
                "error": {
                    "type": "illegal_argument_exception",
                    "reason": f"no handler found for uri [{path}] and method [GET]",
                }
            },
            404,
        )

    monkeypatch.setattr(actions, "_elastic_request", request)
    result = actions.authenticate_elastic(context(), detected(vendor="compatible"), {})
    assert paths[-1] == "/" and len(paths) == 3
    assert result["auth_valid"] is (False if root_status == 401 else None)
    assert result["identity_verified"] is False
    assert result["auth_probe_endpoint"] == "/"
    assert result["auth_probe_http_status"] == root_status
    if root_status == 0:
        assert result["verification_capability"] == "transport_error"
        assert result["auth_error_detail"]["type"] == "auth_fallback_transport_error"
    elif root_status == 401:
        assert result["verification_capability"] == "root_access_control"
        assert result["auth_error_detail"]["fallback"] is True
    else:
        assert result["credential_accepted"] is False
        assert result["auth_error_detail"]["type"] == "authentication_unverified"
