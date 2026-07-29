from __future__ import annotations

import http.client
import ssl
import threading
from types import SimpleNamespace
from typing import Any

import pytest

from redposture_core.modules.elastic import http_session as session_module
from redposture_core.modules.elastic.http_session import ElasticHttpSession


class _FakeResponse:
    def __init__(
        self,
        body: bytes = b"ok",
        *,
        status: int = 200,
        headers: list[tuple[str, str]] | None = None,
        will_close: bool = False,
    ) -> None:
        self.body = body
        self.status = status
        self.headers = headers or [("Content-Type", "application/json")]
        self.will_close = will_close
        self.closed = False

    def read(self, size: int = -1) -> bytes:
        return self.body if size < 0 else self.body[:size]

    def getheaders(self) -> list[tuple[str, str]]:
        return self.headers

    def close(self) -> None:
        self.closed = True


class _FakeConnection:
    def __init__(self, outcomes: list[_FakeResponse | BaseException]) -> None:
        self.outcomes = list(outcomes)
        self.requests: list[tuple[str, str, bytes | None, dict[str, str]]] = []
        self.closed = False

    def request(
        self,
        method: str,
        path: str,
        body: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.requests.append((method, path, body, dict(headers or {})))

    def getresponse(self) -> _FakeResponse:
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    def close(self) -> None:
        self.closed = True


def test_session_reuses_http_connection_and_normalizes_response(monkeypatch: pytest.MonkeyPatch) -> None:
    connection = _FakeConnection(
        [
            _FakeResponse(b'{"one":1}', headers=[("X-Elastic-Product", "Elasticsearch")]),
            _FakeResponse(b'{"two":2}', status=404),
        ]
    )
    created: list[tuple[str, int, float]] = []

    def _factory(host: str, port: int, *, timeout: float) -> _FakeConnection:
        created.append((host, port, timeout))
        return connection

    monkeypatch.setattr(session_module.http.client, "HTTPConnection", _factory)
    client = ElasticHttpSession("elastic.local", 9200, timeout=1.25)

    first = client.request("http", "GET", "/", {"Accept": "application/json"})
    second = client.request("http", "get", "_cluster/health")

    assert created == [("elastic.local", 9200, 1.25)]
    assert first.status == 200
    assert first.headers == {"X-Elastic-Product": "Elasticsearch"}
    assert second.status == 404
    assert second.error is None
    assert connection.requests[0][3]["Host"] == "elastic.local:9200"
    assert connection.requests[0][3]["Connection"] == "keep-alive"
    assert connection.requests[1][1] == "/_cluster/health"
    assert client.connected_scheme == "http"


def test_response_cap_marks_truncated_and_discards_connection(monkeypatch: pytest.MonkeyPatch) -> None:
    first = _FakeConnection([_FakeResponse(b"abcdef")])
    second = _FakeConnection([_FakeResponse(b"next")])
    connections = [first, second]
    monkeypatch.setattr(
        session_module.http.client,
        "HTTPConnection",
        lambda *_args, **_kwargs: connections.pop(0),
    )
    client = ElasticHttpSession("127.0.0.1", 9200, response_cap=3)

    response = client.request("http", "GET", "/")
    following = client.request("http", "GET", "/next")

    assert response.body == b"abc"
    assert response.truncated is True
    assert first.closed is True
    assert following.body == b"nex"
    assert second.closed is True


def test_ipv6_authority_and_request_body(monkeypatch: pytest.MonkeyPatch) -> None:
    connection = _FakeConnection([_FakeResponse()])
    monkeypatch.setattr(session_module.http.client, "HTTPConnection", lambda *_args, **_kwargs: connection)
    client = ElasticHttpSession("[2001:db8::5]", 9200)

    response = client.request("http", "POST", "/_search", data='{"size":0}')

    assert response.status == 200
    _method, _path, body, headers = connection.requests[0]
    assert body == b'{"size":0}'
    assert headers["Host"] == "[2001:db8::5]:9200"
    assert headers["Content-Length"] == "10"


def test_switching_scheme_closes_old_connection_and_reuses_ssl_context(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plain = _FakeConnection([_FakeResponse()])
    first_tls_connection = _FakeConnection([_FakeResponse()])
    second_tls_connection = _FakeConnection([_FakeResponse()])
    tls_connections = [first_tls_connection, second_tls_connection]
    contexts: list[ssl.SSLContext] = []
    monkeypatch.setattr(session_module.http.client, "HTTPConnection", lambda *_args, **_kwargs: plain)

    def _https_factory(
        _host: str,
        _port: int,
        *,
        timeout: float,
        context: ssl.SSLContext,
    ) -> _FakeConnection:
        assert timeout == 1.0
        contexts.append(context)
        return tls_connections.pop(0)

    monkeypatch.setattr(session_module.http.client, "HTTPSConnection", _https_factory)
    client = ElasticHttpSession("::1", 443, insecure=True)

    client.request("http", "GET", "/")
    first_tls = client.request("https", "GET", "/")
    client.close_connection()
    second_tls = client.request("https", "GET", "/_nodes")

    assert plain.closed is True
    assert first_tls.status == second_tls.status == 200
    assert len(contexts) == 2
    assert contexts[0] is contexts[1]
    assert contexts[0].verify_mode == ssl.CERT_NONE
    assert first_tls_connection.requests[0][3]["Host"] == "[::1]"


def test_stale_reused_connection_reconnects_once_for_get(monkeypatch: pytest.MonkeyPatch) -> None:
    stale = _FakeConnection([_FakeResponse(), http.client.RemoteDisconnected("stale keep-alive")])
    replacement = _FakeConnection([_FakeResponse(b"recovered")])
    connections = [stale, replacement]
    created: list[_FakeConnection] = []

    def _factory(*_args: Any, **_kwargs: Any) -> _FakeConnection:
        connection = connections.pop(0)
        created.append(connection)
        return connection

    monkeypatch.setattr(session_module.http.client, "HTTPConnection", _factory)
    client = ElasticHttpSession("127.0.0.1", 9200)

    assert client.request("http", "GET", "/").status == 200
    response = client.request("http", "GET", "/_cluster/health")

    assert response.body == b"recovered"
    assert response.error is None
    assert created == [stale, replacement]
    assert stale.closed is True


def test_stale_connection_reconnects_for_read_only_search_post(monkeypatch: pytest.MonkeyPatch) -> None:
    stale = _FakeConnection([_FakeResponse(), BrokenPipeError("closed")])
    replacement = _FakeConnection([_FakeResponse(b"search-result")])
    connections = [stale, replacement]

    def _factory(*_args: Any, **_kwargs: Any) -> _FakeConnection:
        return connections.pop(0)

    monkeypatch.setattr(session_module.http.client, "HTTPConnection", _factory)
    client = ElasticHttpSession("127.0.0.1", 9200)
    client.request("http", "GET", "/")

    response = client.request("http", "POST", "/logs-*/_search?track_total_hits=true", data=b"{}")

    assert response.body == b"search-result"
    assert response.error is None
    assert len(stale.requests) == 2
    assert len(replacement.requests) == 1


def test_stale_connection_is_not_retried_for_mutating_post(monkeypatch: pytest.MonkeyPatch) -> None:
    connection = _FakeConnection([_FakeResponse(), BrokenPipeError("closed")])
    created = 0

    def _factory(*_args: Any, **_kwargs: Any) -> _FakeConnection:
        nonlocal created
        created += 1
        return connection

    monkeypatch.setattr(session_module.http.client, "HTTPConnection", _factory)
    client = ElasticHttpSession("127.0.0.1", 9200)
    client.request("http", "GET", "/")

    response = client.request("http", "POST", "/_bulk", data=b"{}\n")

    assert response.status == 0
    assert response.error == "closed"
    assert created == 1


def test_initial_failure_is_not_a_stale_keep_alive_retry(monkeypatch: pytest.MonkeyPatch) -> None:
    connection = _FakeConnection([ConnectionResetError("refused")])
    created = 0

    def _factory(*_args: Any, **_kwargs: Any) -> _FakeConnection:
        nonlocal created
        created += 1
        return connection

    monkeypatch.setattr(session_module.http.client, "HTTPConnection", _factory)
    response = ElasticHttpSession("127.0.0.1", 9200).request("http", "GET", "/")

    assert response.status == 0
    assert response.error == "refused"
    assert created == 1


def test_invalid_inputs_are_normalized_without_opening_connection(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        session_module.http.client,
        "HTTPConnection",
        lambda *_args, **_kwargs: pytest.fail("connection must not be opened"),
    )
    client = ElasticHttpSession("127.0.0.1", 9200)

    assert "unsupported" in str(client.request("ftp", "GET", "/").error)
    assert "path" in str(client.request("http", "GET", "/\r\nInjected: 1").error)
    assert "header" in str(client.request("http", "GET", "/", {"X-Test": "ok\nbad"}).error)


def test_session_is_thread_confined(monkeypatch: pytest.MonkeyPatch) -> None:
    connection = _FakeConnection([_FakeResponse()])
    monkeypatch.setattr(session_module.http.client, "HTTPConnection", lambda *_args, **_kwargs: connection)
    client = ElasticHttpSession("127.0.0.1", 9200)
    assert client.request("http", "GET", "/").status == 200
    errors: list[BaseException] = []

    def _cross_thread_request() -> None:
        try:
            client.request("http", "GET", "/other")
        except BaseException as exc:
            errors.append(exc)

    worker = threading.Thread(target=_cross_thread_request)
    worker.start()
    worker.join()

    assert len(errors) == 1
    assert isinstance(errors[0], RuntimeError)
    assert "across threads" in str(errors[0])
    assert len(connection.requests) == 1


def test_terminal_close_is_allowed_from_supervisor_thread(monkeypatch: pytest.MonkeyPatch) -> None:
    connection = _FakeConnection([_FakeResponse()])
    monkeypatch.setattr(session_module.http.client, "HTTPConnection", lambda *_args, **_kwargs: connection)
    client = ElasticHttpSession("127.0.0.1", 9200)
    assert client.request("http", "GET", "/").status == 200
    errors: list[BaseException] = []

    def _cross_thread_close() -> None:
        try:
            client.close()
        except BaseException as exc:
            errors.append(exc)

    supervisor = threading.Thread(target=_cross_thread_close)
    supervisor.start()
    supervisor.join()

    assert errors == []
    assert connection.closed is True
    assert client.closed is True
    with pytest.raises(RuntimeError, match="closed"):
        client.request("http", "GET", "/closed")


def test_close_connection_is_reusable_and_close_is_terminal(monkeypatch: pytest.MonkeyPatch) -> None:
    first = _FakeConnection([_FakeResponse()])
    second = _FakeConnection([_FakeResponse()])
    connections = [first, second]
    monkeypatch.setattr(
        session_module.http.client,
        "HTTPConnection",
        lambda *_args, **_kwargs: connections.pop(0),
    )
    client = ElasticHttpSession("127.0.0.1", 9200)
    client.request("http", "GET", "/")

    client.close_connection()
    assert first.closed is True
    assert client.connected_scheme is None
    assert client.request("http", "GET", "/again").status == 200
    client.close()
    client.close()

    assert second.closed is True
    assert client.closed is True
    with pytest.raises(RuntimeError, match="closed"):
        client.request("http", "GET", "/closed")


def test_context_manager_closes_connection(monkeypatch: pytest.MonkeyPatch) -> None:
    connection = _FakeConnection([_FakeResponse(will_close=False)])
    monkeypatch.setattr(session_module.http.client, "HTTPConnection", lambda *_args, **_kwargs: connection)

    with ElasticHttpSession("127.0.0.1", 9200) as client:
        assert client.request("http", "HEAD", "/").status == 200

    assert connection.closed is True
    assert client.closed is True


@pytest.mark.parametrize(
    ("host", "port"),
    [
        ("", 9200),
        ("bad\nhost", 9200),
        ("localhost", 0),
        ("localhost", 65536),
    ],
)
def test_constructor_rejects_invalid_target(host: str, port: int) -> None:
    with pytest.raises(ValueError):
        ElasticHttpSession(host, port)


def test_lifecycle_session_enables_verification_when_ca_file_is_present(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from redposture_core.modules.elastic import actions

    captured: dict[str, Any] = {}
    sentinel = object()

    def _session_factory(host: str, port: int, **kwargs: Any) -> object:
        captured.update({"host": host, "port": port, **kwargs})
        return sentinel

    monkeypatch.setattr(actions, "ElasticHttpSession", _session_factory)
    ctx = SimpleNamespace(
        host="2001:db8::10",
        port=9243,
        args=SimpleNamespace(proxy=None, timeout=2.0, ca_file="/tmp/lab-ca.pem"),
    )

    session = actions._make_lifecycle_session(ctx)

    assert session is sentinel
    assert captured == {
        "host": "2001:db8::10",
        "port": 9243,
        "timeout": 2.0,
        "insecure": False,
        "ca_file": "/tmp/lab-ca.pem",
    }


def test_https_fallback_with_ca_reports_certificate_verification_enabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from redposture_core.modules.elastic import actions

    calls: list[tuple[bool, bool, str | None]] = []

    def _request(
        _host: str,
        _port: int,
        _path: str,
        _timeout: float,
        *,
        use_https: bool,
        insecure: bool,
        ca_file: str | None,
        **_kwargs: Any,
    ) -> tuple[int, bytes, dict[str, str], str | None]:
        calls.append((use_https, insecure, ca_file))
        if not use_https:
            return 0, b"", {}, "remote end closed connection during protocol negotiation"
        return 200, b'{"tagline":"You Know, for Search"}', {}, None

    monkeypatch.setattr(actions, "_elastic_request", _request)

    result = actions._request_with_tls_fallback(
        "2001:db8::10",
        9243,
        "/",
        1.0,
        ca_file="/tmp/lab-ca.pem",
        preferred_scheme="http",
    )

    assert calls == [
        (False, False, None),
        (True, False, "/tmp/lab-ca.pem"),
    ]
    assert result[0] == 200
    assert result[4] == "https"
    assert result[5] is False
