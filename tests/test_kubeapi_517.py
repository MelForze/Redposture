from __future__ import annotations

import argparse
import base64
from types import SimpleNamespace
from typing import Any

import pytest

from redposture_core.clients import tls_cache
from redposture_core.modules.kubeapi import actions as kube
from redposture_core.modules.kubeapi import http_session


def _options(**overrides: Any) -> dict[str, Any]:
    values = {
        "namespace_filters": [],
        "show_namespaces": False,
        "show_pods": False,
        "show_secrets": False,
        "exec_pod": None,
        "exec_command": None,
    }
    values.update(overrides)
    return values


def _ctx(*, retries: int = 0, credential: Any = None) -> SimpleNamespace:
    return SimpleNamespace(
        host="kube.local",
        port=6443,
        target=SimpleNamespace(scheme="https"),
        args=argparse.Namespace(
            timeout=1.0,
            retries=retries,
            https=True,
            insecure=True,
            ca_file=None,
            tls_ca=None,
            _proxy_config=None,
        ),
        credential=credential or SimpleNamespace(token=None, username=None, password=None),
        lifecycle_state=kube.KubeApiLifecycleState(),
    )


def _status(code: int) -> dict[str, Any]:
    return {
        "kind": "Status",
        "apiVersion": "v1",
        "status": "Failure",
        "reason": "Unauthorized" if code == 401 else "Forbidden",
        "code": code,
    }


def test_ssl_context_cache_separates_modes_and_custom_ca(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    created: list[tuple[str, str | None]] = []

    monkeypatch.setattr(
        tls_cache.ssl,
        "create_default_context",
        lambda *, cafile=None: created.append(("verified", cafile)) or object(),
    )
    monkeypatch.setattr(
        tls_cache.ssl,
        "_create_unverified_context",
        lambda: created.append(("insecure", None)) or object(),
    )
    ca_file = tmp_path / "ca.pem"
    ca_file.write_text("test-ca", encoding="utf-8")
    http_session.clear_transport_caches()

    assert http_session.shared_ssl_context(insecure=False, ca_file=None) is http_session.shared_ssl_context(
        insecure=False, ca_file=None
    )
    assert http_session.shared_ssl_context(insecure=True, ca_file=None) is http_session.shared_ssl_context(
        insecure=True, ca_file=None
    )
    http_session.shared_ssl_context(insecure=False, ca_file=str(ca_file))

    assert created == [("verified", None), ("insecure", None), ("verified", str(ca_file.resolve()))]
    http_session.clear_transport_caches()


def test_direct_session_reuses_connection_and_reopens_after_truncation(monkeypatch: pytest.MonkeyPatch) -> None:
    connections: list[Any] = []
    responses = [(b"one", False), (b"oversized", False), (b"three", False)]

    class Response:
        status = 200

        def __init__(self, payload: bytes, will_close: bool) -> None:
            self.payload = payload
            self.will_close = will_close

        def read(self, size: int) -> bytes:
            return self.payload[:size]

        def getheaders(self) -> list[tuple[str, str]]:
            return []

        def close(self) -> None:
            return None

    class Connection:
        def __init__(self, *_args: Any, **_kwargs: Any) -> None:
            self.timeout = 1.0
            self.requests: list[str] = []
            self.closed = False
            connections.append(self)

        def request(self, _method: str, path: str, **_kwargs: Any) -> None:
            self.requests.append(path)

        def getresponse(self) -> Response:
            payload, will_close = responses.pop(0)
            return Response(payload, will_close)

        def close(self) -> None:
            self.closed = True

    monkeypatch.setattr(http_session.http.client, "HTTPConnection", Connection)
    session = http_session.KubeApiHttpSession(
        "kube.local", 6443, use_https=False, timeout=1.0, insecure=False, ca_file=None
    )

    assert session.request("GET", "http://kube.local:6443/version").body == b"one"
    assert session.request("GET", "http://kube.local:6443/api", response_size_cap=3).truncated is True
    assert session.request("GET", "http://kube.local:6443/api/v1/namespaces").body == b"three"

    assert len(connections) == 2
    assert connections[0].requests == ["/version", "/api"]
    assert connections[0].closed is True
    assert connections[1].requests == ["/api/v1/namespaces"]


@pytest.mark.parametrize(
    ("namespace_access", "namespace_status", "expected_access", "expected_auth", "expected_status"),
    [
        (True, 200, "open", False, "open_no_auth"),
        (False, 403, "limited", False, "anonymous_limited"),
        (False, 401, "disabled", True, "auth_required"),
        (None, 0, "unknown", None, "detected"),
    ],
)
def test_anonymous_access_classification(
    monkeypatch: pytest.MonkeyPatch,
    namespace_access: bool | None,
    namespace_status: int,
    expected_access: str,
    expected_auth: bool | None,
    expected_status: str,
) -> None:
    ctx = _ctx()
    monkeypatch.setattr(
        kube,
        "_lifecycle_get_json_with_retries",
        lambda *_args, **_kwargs: (200, {"major": "1", "minor": "31", "gitVersion": "v1.31.2"}, {}, None),
    )
    monkeypatch.setattr(
        kube,
        "_probe_namespace_access",
        lambda *_args, **_kwargs: (
            namespace_access,
            namespace_status,
            "network failed" if namespace_status == 0 else None,
        ),
    )

    record = kube.detect_kubeapi(ctx, _options())

    assert record["anonymous_access"] == expected_access
    assert record["auth_required"] is expected_auth
    assert record["status"] == expected_status


def test_mixed_auth_statuses_confirm_kubeapi_without_namespace_probe(monkeypatch: pytest.MonkeyPatch) -> None:
    ctx = _ctx()
    calls: list[str] = []

    def request(_ctx: Any, _state: Any, path: str, **_kwargs: Any):
        calls.append(path)
        code = 401 if path == "/version" else 403
        return code, _status(code), {}, None

    monkeypatch.setattr(kube, "_lifecycle_get_json_with_retries", request)
    monkeypatch.setattr(kube, "_probe_namespace_access", lambda *_args, **_kwargs: pytest.fail("duplicate probe"))

    record = kube.detect_kubeapi(ctx, _options())

    assert calls == ["/version", "/api"]
    assert record["is_kubeapi"] is True
    assert record["anonymous_access"] == "limited"


def test_api_is_checked_after_version_oversize(monkeypatch: pytest.MonkeyPatch) -> None:
    ctx = _ctx()
    calls: list[str] = []

    def request(_ctx: Any, _state: Any, path: str, **_kwargs: Any):
        calls.append(path)
        if path == "/version":
            return 200, None, {}, "response exceeds 262144 byte limit"
        return 200, {"kind": "APIVersions", "apiVersion": "v1", "versions": ["v1"]}, {}, None

    monkeypatch.setattr(kube, "_lifecycle_get_json_with_retries", request)
    monkeypatch.setattr(kube, "_probe_namespace_access", lambda *_args, **_kwargs: (True, 200, None))

    record = kube.detect_kubeapi(ctx, _options())

    assert calls == ["/version", "/api"]
    assert record["is_kubeapi"] is True


@pytest.mark.parametrize(
    ("status", "payload", "error", "expected"),
    [
        (
            201,
            {
                "apiVersion": "authentication.k8s.io/v1",
                "kind": "SelfSubjectReview",
                "status": {"userInfo": {"username": "system:serviceaccount:default:scanner"}},
            },
            None,
            True,
        ),
        (
            200,
            {
                "apiVersion": "authentication.k8s.io/v1",
                "kind": "SelfSubjectReview",
                "status": {"userInfo": {"username": "system:anonymous"}},
            },
            None,
            False,
        ),
        (401, _status(401), None, False),
        (403, _status(403), None, None),
        (404, {}, None, None),
        (200, {"kind": "Other"}, None, None),
        (0, None, "connection timeout", None),
    ],
)
def test_self_subject_review_verdicts(
    monkeypatch: pytest.MonkeyPatch,
    status: int,
    payload: Any,
    error: str | None,
    expected: bool | None,
) -> None:
    ctx = _ctx(credential=SimpleNamespace(token="token", username=None, password=None))
    monkeypatch.setattr(
        kube,
        "_lifecycle_request_json_with_retries",
        lambda *_args, **_kwargs: (status, payload, {}, error),
    )

    valid, _identity, _reason = kube._verify_self_subject_review(ctx, ctx.lifecycle_state, "token")

    assert valid is expected


def test_bearer_403_never_becomes_valid_when_verification_is_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    ctx = _ctx(credential=SimpleNamespace(token="token", username=None, password=None))
    ctx.lifecycle_state.anonymous_access = "limited"
    ctx.lifecycle_state.anonymous_namespace_status = 403
    monkeypatch.setattr(kube, "_probe_namespace_access", lambda *_args, **_kwargs: (False, 403, "Forbidden"))
    monkeypatch.setattr(kube, "_verify_self_subject_review", lambda *_args, **_kwargs: (None, None, "unavailable"))

    record = kube.authenticate_kubeapi(ctx, {"status": "anonymous_limited"}, _options())

    assert record["auth_valid"] is None
    assert record["status"] == "auth_unverified_anonymous"
    assert kube._status_summary_line(record).startswith("[!] token auth verification unavailable")


def test_retry_policy_retries_transport_only(monkeypatch: pytest.MonkeyPatch) -> None:
    responses = iter([(0, None, {}, "connection reset"), (0, None, {}, "connection reset"), (200, {}, {}, None)])
    calls: list[int] = []
    sleeps: list[float] = []
    monkeypatch.setattr(kube, "_api_get_json", lambda *_args, **_kwargs: (calls.append(1), next(responses))[1])
    monkeypatch.setattr(kube.time, "sleep", sleeps.append)

    result = kube._api_request_json_with_retries(
        "kube.local",
        6443,
        "GET",
        "/version",
        1.0,
        retries=2,
        use_https=True,
        insecure=True,
        ca_file=None,
    )

    assert result[0] == 200
    assert len(calls) == 3
    assert sleeps == [kube._retry_delay(0), kube._retry_delay(1)]

    calls.clear()
    monkeypatch.setattr(
        kube,
        "_api_get_json",
        lambda *_args, **_kwargs: (calls.append(1), (200, None, {}, "response exceeds 10 byte limit"))[1],
    )
    kube._api_request_json_with_retries(
        "kube.local",
        6443,
        "GET",
        "/version",
        1.0,
        retries=3,
        use_https=True,
        insecure=True,
        ca_file=None,
    )
    assert len(calls) == 1


def test_repeated_continue_token_stops_pagination(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []

    def request(_host: str, _port: int, path: str, _timeout: float, **_kwargs: Any):
        calls.append(path)
        return 200, {"items": [], "metadata": {"continue": "same"}}, {}, None

    monkeypatch.setattr(kube, "_api_get_json", request)
    result = kube._kube_list_items(
        "kube.local",
        6443,
        "/api/v1/pods",
        1.0,
        use_https=True,
        insecure=True,
        ca_file=None,
    )

    assert len(calls) == 2
    assert result.access_confirmed is True
    assert result.complete is False
    assert result.error == "partial: pagination continue token repeated"


@pytest.mark.parametrize("resource", ["pods", "secrets"])
def test_late_page_failure_preserves_list_capability(monkeypatch: pytest.MonkeyPatch, resource: str) -> None:
    responses = iter(
        [
            kube.KubeListResult([], 200, None, True, True),
            kube.KubeListResult(None, 403, "forbidden", False, False),
        ]
    )
    monkeypatch.setattr(kube, "_kube_list_items", lambda *_args, **_kwargs: next(responses))
    function = kube._list_pods if resource == "pods" else kube._list_secrets

    result = function(
        "kube.local",
        6443,
        1.0,
        use_https=True,
        insecure=True,
        ca_file=None,
        namespaces=["one", "two"],
    )

    assert result.items == []
    assert result.access_confirmed is True
    assert result.complete is False
    assert "forbidden" in str(result.error)


def test_secret_decode_is_strict_and_escapes_terminal_controls() -> None:
    assert kube._decode_secret_data_value("Zm9v%%%") == "<invalid-base64>"
    raw = b"line1\r\n\t\\line2\x01"
    rendered = kube._decode_secret_data_value(base64.b64encode(raw).decode("ascii"))
    assert rendered == "line1\\r\\n\\t\\\\line2\\u0001"
    assert all(character not in rendered for character in "\r\n\t\x01")


def test_lifecycle_passes_parsed_proxy_to_shared_client(monkeypatch: pytest.MonkeyPatch) -> None:
    proxy = object()
    state = kube.KubeApiLifecycleState(proxy=proxy, use_https=True, insecure=True, ca_file="ca.pem")
    captured: list[dict[str, Any]] = []
    client = object()

    monkeypatch.setattr(
        kube,
        "HttpSessionPool",
        lambda **kwargs: (captured.append(kwargs), client)[1],
    )

    assert state.http_client(response_size_cap=1234) is client
    assert captured == [{"timeout": 5.0, "insecure": True, "ca_file": "ca.pem", "proxy": proxy}]


def test_collect_preserves_partial_capability_and_cumulative_elapsed(monkeypatch: pytest.MonkeyPatch) -> None:
    state = kube.KubeApiLifecycleState(
        use_https=True,
        insecure=True,
        anonymous_access="open",
        anonymous_namespaces=[],
        access_namespaces=[],
        started_at=10.0,
    )
    ctx = _ctx()
    ctx.lifecycle_state = state
    monotonic_values = iter([15.0])
    monkeypatch.setattr(kube.time, "monotonic", lambda: next(monotonic_values))
    monkeypatch.setattr(
        kube,
        "_list_pods",
        lambda *_args, **_kwargs: kube.KubeResourceResult(
            [{"namespace": "default", "name": "pod"}],
            "partial: connection reset",
            True,
            False,
        ),
    )

    record = kube.collect_kubeapi_data(
        ctx,
        {"status": "open_no_auth", "can_list_namespaces": True},
        _options(show_pods=True),
    )

    assert record["can_list_pods"] is True
    assert record["pods_partial"] is True
    assert record["elapsed_ms"] == 5000


def test_exec_retries_setup_but_never_retries_after_send(monkeypatch: pytest.MonkeyPatch) -> None:
    setup_calls: list[int] = []
    sleeps: list[float] = []

    def fail_setup(*_args: Any, **_kwargs: Any):
        setup_calls.append(1)
        raise OSError("connection refused")

    monkeypatch.setattr(kube.socket, "create_connection", fail_setup)
    monkeypatch.setattr(kube.time, "sleep", sleeps.append)
    failed = kube._kube_exec_ws(
        "kube.local",
        6443,
        "default",
        "pod",
        "id",
        1.0,
        use_https=False,
        insecure=False,
        ca_file=None,
        retries=2,
    )
    assert len(setup_calls) == 3
    assert len(sleeps) == 2
    assert "connection refused" in failed["error"]

    class SendFailure:
        def settimeout(self, _timeout: float) -> None:
            return None

        def sendall(self, _payload: bytes) -> None:
            raise OSError("send failed")

        def close(self) -> None:
            return None

    setup_calls.clear()
    monkeypatch.setattr(
        kube.socket,
        "create_connection",
        lambda *_args, **_kwargs: (setup_calls.append(1), SendFailure())[1],
    )
    sent = kube._kube_exec_ws(
        "kube.local",
        6443,
        "default",
        "pod",
        "id",
        1.0,
        use_https=False,
        insecure=False,
        ca_file=None,
        retries=4,
    )
    assert len(setup_calls) == 1
    assert "retry suppressed after exec upgrade request send began" in sent["error"]


def test_legacy_adapter_matches_lifecycle_status(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        kube,
        "_api_get_json",
        lambda _host, _port, path, _timeout, **_kwargs: (
            200,
            {"major": "1", "minor": "31", "gitVersion": "v1.31.0"}
            if path == "/version"
            else {"kind": "APIVersions", "apiVersion": "v1", "versions": ["v1"]},
            {},
            None,
        ),
    )
    monkeypatch.setattr(kube, "_list_namespaces", lambda *_args, **_kwargs: (None, 403, "Forbidden"))

    legacy = kube._audit_kubeapi_host(
        "kube.local",
        6443,
        1.0,
        0,
        use_https=True,
        insecure=True,
        ca_file=None,
        token=None,
        username=None,
        password=None,
        show_namespaces=False,
        show_pods=False,
        show_secrets=False,
        namespace_filters=[],
        exec_pod=None,
        exec_command=None,
    )
    lifecycle = kube.detect_kubeapi(_ctx(), _options())

    assert legacy["status"] == lifecycle["status"] == "anonymous_limited"
    assert legacy["anonymous_access"] == lifecycle["anonymous_access"] == "limited"
