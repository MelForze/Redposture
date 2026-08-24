from __future__ import annotations

import threading
import time
import zlib
from types import SimpleNamespace
from typing import Any

import pytest

from redposture_core.cli import parse_args
from redposture_core.clients import http_session, tls_cache
from redposture_core.clients import kafka as kafka_client
from redposture_core.clients.http_api import HttpResponse
from redposture_core.clients.http_session import HttpSessionPool
from redposture_core.modules.gitlab import actions as gitlab_actions
from redposture_core.modules.grafana import actions as grafana_actions
from redposture_core.modules.kafka import actions as kafka_actions
from redposture_core.modules.kubeapi import http_session as kube_http_session
from redposture_core.modules.qdrant import actions as qdrant_actions
from redposture_core.modules.registry import actions as registry_actions
from redposture_core.network_proxy import ProxyConfig
from redposture_core.scheduler import SharedNestedScheduler
from redposture_core.transport_contract import MODULE_TRANSPORT_STRATEGY


class _Response:
    reason = "OK"

    def __init__(
        self,
        payload: bytes = b"{}",
        *,
        status: int = 200,
        will_close: bool = False,
        headers: list[tuple[str, str]] | None = None,
    ) -> None:
        self.payload = payload
        self.status = status
        self.will_close = will_close
        self.headers = headers or []

    def read(self, size: int) -> bytes:
        return self.payload[:size]

    def getheaders(self) -> list[tuple[str, str]]:
        return list(self.headers)

    def close(self) -> None:
        return None


def test_shared_tls_cache_is_bounded_and_separates_configuration(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    created: list[Any] = []

    class _Context:
        check_hostname = True

        def load_cert_chain(self, certfile: str, keyfile: str | None = None) -> None:
            self.identity = (certfile, keyfile)

        def set_alpn_protocols(self, protocols: list[str]) -> None:
            self.alpn = tuple(protocols)

    monkeypatch.setattr(
        tls_cache.ssl, "create_default_context", lambda **_kwargs: created.append(_Context()) or created[-1]
    )
    monkeypatch.setattr(
        tls_cache.ssl,
        "_create_unverified_context",
        lambda: created.append(_Context()) or created[-1],
    )
    ca = tmp_path / "ca.pem"
    cert = tmp_path / "client.pem"
    key = tmp_path / "client.key"
    for path in (ca, cert, key):
        path.write_text("fixture", encoding="utf-8")

    secure = tls_cache.shared_client_ssl_context(insecure=False, ca_file=str(ca))
    assert secure is tls_cache.shared_client_ssl_context(insecure=False, ca_file=str(ca))
    assert secure is not tls_cache.shared_client_ssl_context(insecure=True)
    assert secure is not tls_cache.shared_client_ssl_context(
        insecure=False,
        ca_file=str(ca),
        cert_file=str(cert),
        key_file=str(key),
    )
    for index in range(70):
        tls_cache.shared_client_ssl_context(insecure=True, alpn=(f"test-{index}",))
    assert tls_cache.tls_context_cache_stats()["size"] == 64


def test_shared_tls_cache_coalesces_concurrent_cold_misses(monkeypatch: pytest.MonkeyPatch) -> None:
    created: list[Any] = []
    barrier = threading.Barrier(24)

    class _Context:
        check_hostname = True

    def _create() -> _Context:
        # Make the old check-build-publish race deterministic: without
        # single-flight construction every worker enters this slow path.
        time.sleep(0.01)
        context = _Context()
        created.append(context)
        return context

    monkeypatch.setattr(tls_cache.ssl, "_create_unverified_context", _create)
    contexts: list[Any] = []

    def _worker() -> None:
        barrier.wait()
        contexts.append(tls_cache.shared_client_ssl_context(insecure=True))

    threads = [threading.Thread(target=_worker) for _ in range(barrier.parties)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert len(created) == 1
    assert len({id(context) for context in contexts}) == 1
    assert tls_cache.tls_context_cache_stats() == {"size": 1, "hits": 23, "misses": 1}


def test_http_pool_reuses_connection_and_keeps_identity_headers_separate(monkeypatch: pytest.MonkeyPatch) -> None:
    connections: list[Any] = []

    class _Connection:
        def __init__(self, *_args: Any, **_kwargs: Any) -> None:
            self.timeout = 1.0
            self.requests: list[dict[str, str]] = []
            self.closed = False
            connections.append(self)

        def request(self, _method: str, _path: str, *, body: bytes | None, headers: dict[str, str]) -> None:
            _ = body
            self.requests.append(dict(headers))

        def getresponse(self) -> _Response:
            return _Response()

        def close(self) -> None:
            self.closed = True

    monkeypatch.setattr(http_session.http.client, "HTTPConnection", _Connection)
    pool = HttpSessionPool(timeout=1.0)
    pool.request("GET", "http://127.0.0.1:8080/one", headers={"Authorization": "Bearer one"})
    pool.request("GET", "http://127.0.0.1:8080/two", headers={"Authorization": "Bearer two"})
    assert len(connections) == 1
    assert [request["Authorization"] for request in connections[0].requests] == ["Bearer one", "Bearer two"]
    assert pool.stats() == {"connections": 1, "reused": 1, "requests": 2, "retries": 0}
    pool.close()
    assert connections[0].closed is True


def test_http_pool_reopens_stale_and_truncated_connections(monkeypatch: pytest.MonkeyPatch) -> None:
    connections: list[Any] = []
    outcomes: list[Any] = [http_session.http.client.RemoteDisconnected("stale"), _Response(b"ok"), _Response(b"large")]

    class _Connection:
        def __init__(self, *_args: Any, **_kwargs: Any) -> None:
            self.timeout = 1.0
            self.closed = False
            connections.append(self)

        def request(self, *_args: Any, **_kwargs: Any) -> None:
            return None

        def getresponse(self) -> _Response:
            outcome = outcomes.pop(0)
            if isinstance(outcome, BaseException):
                raise outcome
            return outcome

        def close(self) -> None:
            self.closed = True

    monkeypatch.setattr(http_session.http.client, "HTTPConnection", _Connection)
    pool = HttpSessionPool(timeout=1.0, retries=1)
    assert pool.request("GET", "http://127.0.0.1:8080/").body == b"ok"
    truncated = pool.request("GET", "http://127.0.0.1:8080/large", response_size_cap=2)
    assert truncated.truncated is True
    assert len(connections) == 2
    assert pool.stats()["retries"] == 1
    pool.close()


def test_http_pool_never_replays_post_after_redirect(monkeypatch: pytest.MonkeyPatch) -> None:
    requests: list[str] = []

    class _Connection:
        def __init__(self, *_args: Any, **_kwargs: Any) -> None:
            self.timeout = 1.0

        def request(self, method: str, _path: str, **_kwargs: Any) -> None:
            requests.append(method)

        def getresponse(self) -> _Response:
            return _Response(status=307, headers=[("Location", "/again")])

        def close(self) -> None:
            return None

    monkeypatch.setattr(http_session.http.client, "HTTPConnection", _Connection)
    response = HttpSessionPool(timeout=1.0).request("POST", "http://127.0.0.1:8080/action", body=b"{}")
    assert response.error == "redirect suppressed after non-replay-safe request"
    assert requests == ["POST"]


def test_http_pool_follows_bounded_same_origin_redirect(monkeypatch: pytest.MonkeyPatch) -> None:
    paths: list[str] = []
    responses = [_Response(status=302, headers=[("Location", "/next")]), _Response(b"done")]

    class _Connection:
        def __init__(self, *_args: Any, **_kwargs: Any) -> None:
            self.timeout = 1.0

        def request(self, _method: str, path: str, **_kwargs: Any) -> None:
            paths.append(path)

        def getresponse(self) -> _Response:
            return responses.pop(0)

        def close(self) -> None:
            return None

    monkeypatch.setattr(http_session.http.client, "HTTPConnection", _Connection)
    response = HttpSessionPool(timeout=1.0).request("GET", "http://127.0.0.1:8080/start")
    assert response.body == b"done"
    assert response.final_url == "http://127.0.0.1:8080/next"
    assert response.redirect_history == ("http://127.0.0.1:8080/start",)
    assert paths == ["/start", "/next"]


def test_layered_tls_socket_adapter_flushes_reads_and_closes() -> None:
    class _Outer:
        def __init__(self) -> None:
            self.sent: list[bytes] = []
            self.timeout: float | None = None
            self.closed = False

        def sendall(self, payload: bytes) -> None:
            self.sent.append(payload)

        def recv(self, size: int) -> bytes:
            return b"r" * min(size, 2)

        def settimeout(self, timeout: float | None) -> None:
            self.timeout = timeout

        def close(self) -> None:
            self.closed = True

    class _TlsObject:
        def do_handshake(self) -> None:
            return None

        def write(self, payload: memoryview) -> int:
            return len(payload)

        def read(self, size: int) -> bytes:
            return b"x" * min(size, 2)

    class _Context:
        def wrap_bio(self, *_args: Any, **_kwargs: Any) -> _TlsObject:
            return _TlsObject()

    outer = _Outer()
    layered = http_session._LayeredTlsSocket(outer, _Context(), "target")
    layered.sendall(b"request")
    assert layered.recv(3) == b"xx"
    raw = http_session._LayeredTlsRaw(layered)
    buffer = bytearray(4)
    assert raw.readinto(buffer) == 2
    assert raw.readable() is True
    assert layered.makefile("rb") is not None
    with pytest.raises(ValueError, match="read makefiles"):
        layered.makefile("wb")
    layered.settimeout(2.0)
    layered.close()
    layered.close()
    assert outer.timeout == 2.0
    assert outer.closed is True


def test_http_pool_passes_parsed_proxy_to_reusable_tunnel(monkeypatch: pytest.MonkeyPatch) -> None:
    tunnels: list[tuple[ProxyConfig, tuple[str, int]]] = []

    class _Tunnel:
        def settimeout(self, _timeout: float) -> None:
            return None

        def close(self) -> None:
            return None

    class _Connection:
        def __init__(self, *_args: Any, **_kwargs: Any) -> None:
            self.timeout = 1.0
            self.sock: Any = None

        def request(self, *_args: Any, **_kwargs: Any) -> None:
            return None

        def getresponse(self) -> _Response:
            return _Response()

        def close(self) -> None:
            return None

    proxy = ProxyConfig("socks5", "proxy", 1080, None, None, "socks5://proxy:1080")
    monkeypatch.setattr(
        http_session,
        "open_connection_via_proxy",
        lambda config, destination, **_kwargs: tunnels.append((config, destination)) or _Tunnel(),
    )
    monkeypatch.setattr(http_session.http.client, "HTTPConnection", _Connection)
    pool = HttpSessionPool(timeout=1.0, proxy=proxy)
    assert pool.request("GET", "http://service.internal:8080/").status == 200
    assert tunnels == [(proxy, ("service.internal", 8080))]
    pool.close()


def test_kube_direct_session_reuses_connection_and_blocks_cross_origin(monkeypatch: pytest.MonkeyPatch) -> None:
    connections: list[Any] = []
    responses = [
        _Response(status=302, headers=[("Location", "/api")]),
        _Response(b'{"versions":["v1"]}'),
        _Response(status=302, headers=[("Location", "https://elsewhere.invalid/api")]),
    ]

    class _Connection:
        def __init__(self, *_args: Any, **_kwargs: Any) -> None:
            self.timeout = 1.0
            self.sock = None
            self.closed = False
            connections.append(self)

        def request(self, *_args: Any, **_kwargs: Any) -> None:
            return None

        def getresponse(self) -> _Response:
            return responses.pop(0)

        def close(self) -> None:
            self.closed = True

    monkeypatch.setattr(kube_http_session.http.client, "HTTPConnection", _Connection)
    session = kube_http_session.KubeApiHttpSession(
        "127.0.0.1", 8080, use_https=False, timeout=1.0, insecure=False, ca_file=None
    )
    response = session.request("GET", "http://127.0.0.1:8080/version")
    assert response.status == 200
    blocked = session.request("GET", "http://127.0.0.1:8080/redirect")
    assert blocked.error and blocked.error.startswith("cross-origin redirect blocked")
    assert len(connections) == 1
    assert session.stats()["reused"] == 2
    session.close()
    assert connections[0].closed is True


def test_shared_nested_scheduler_enforces_one_command_budget() -> None:
    scheduler = SharedNestedScheduler(max_workers=3)
    active = 0
    peak = 0
    lock = threading.Lock()

    def worker(value: int) -> int:
        nonlocal active, peak
        with lock:
            active += 1
            peak = max(peak, active)
        time.sleep(0.005)
        with lock:
            active -= 1
        return value * 2

    assert scheduler.map_ordered(range(18), worker) == [value * 2 for value in range(18)]
    scheduler.close()
    assert peak == 3


@pytest.mark.parametrize(
    "factory",
    [
        grafana_actions.grafana_lifecycle_state_factory,
        gitlab_actions.gitlab_lifecycle_state_factory,
        qdrant_actions.qdrant_lifecycle_state_factory,
        registry_actions.registry_lifecycle_state_factory,
    ],
)
def test_module_retry_budget_has_one_owner(factory: Any) -> None:
    ctx = SimpleNamespace(
        args=SimpleNamespace(timeout=0.1, retries=3, _proxy_config=None),
        target=None,
    )
    state = factory(ctx)
    assert state.http is not None
    assert state.http.default_retries == 0
    state.close()


def test_grafana_retries_are_linear_not_squared(monkeypatch: pytest.MonkeyPatch) -> None:
    ctx = SimpleNamespace(
        host="127.0.0.1",
        port=3000,
        args=SimpleNamespace(timeout=0.1, retries=3, _proxy_config=None),
        target=None,
    )
    state = grafana_actions.grafana_lifecycle_state_factory(ctx)
    ctx.lifecycle_state = state
    calls: list[str] = []

    def _failed_request(_method: str, url: str, **_kwargs: Any) -> HttpResponse:
        calls.append(url)
        return HttpResponse(status=0, body=b"", headers={}, error="connection refused")

    assert state.http is not None
    monkeypatch.setattr(state.http, "request", _failed_request)
    monkeypatch.setattr(grafana_actions.time, "sleep", lambda _delay: None)
    record = grafana_actions.detect_grafana(ctx, {"show_datasources": False, "check_urls": []})

    # Four command attempts, each with exactly one HTTP and one HTTPS probe.
    # A second transport-level retry loop would inflate this to 32 calls.
    assert len(calls) == 8
    assert record["status"] == "fail"
    state.close()


@pytest.mark.parametrize(
    ("module", "default_workers"),
    [
        ("clickhouse", 50),
        ("consul", 50),
        ("docker", 50),
        ("elastic", 50),
        ("etcd", 50),
        ("gitlab", 50),
        ("grafana", 50),
        ("grpc", 50),
        ("kafka", 50),
        ("kubeapi", 12),
        ("mongodb", 50),
        ("oracle", 50),
        ("postgres", 50),
        ("proxmox", 50),
        ("qdrant", 50),
        ("redis", 50),
        ("registry", 50),
        ("zookeeper", 50),
    ],
)
def test_module_worker_defaults_and_explicit_override(module: str, default_workers: int) -> None:
    assert parse_args([module, "-t", "127.0.0.1"]).workers == default_workers
    assert parse_args([module, "-t", "127.0.0.1", "-w", "73"]).workers == 73


def test_transport_contract_is_exhaustive_and_uses_known_strategies() -> None:
    expected = {
        "clickhouse",
        "consul",
        "docker",
        "elastic",
        "etcd",
        "exporters",
        "gitlab",
        "grafana",
        "grpc",
        "kafka",
        "kubeapi",
        "mongodb",
        "oracle",
        "postgres",
        "proxmox",
        "qdrant",
        "redis",
        "registry",
        "zookeeper",
    }
    assert set(MODULE_TRANSPORT_STRATEGY) == expected
    assert set(MODULE_TRANSPORT_STRATEGY.values()) <= {
        "reusable_lifecycle",
        "identity_session",
        "existing_pool",
    }


def test_kafka_limits_are_part_of_the_public_transport_contract() -> None:
    assert kafka_client.KAFKA_MAX_DECOMPRESSED_BYTES == 16 * 1024 * 1024
    assert kafka_client.KAFKA_MAX_COMPRESSION_DEPTH == 4
    assert kafka_client.KAFKA_MAX_PARSE_STEPS == 100_000
    reader = kafka_client._KafkaReader(b"")
    with pytest.raises(ValueError, match="parse budget"):
        kafka_client._parse_record_entries(reader, 0, kafka_client.KAFKA_MAX_PARSE_STEPS + 1, 1)
    compressor = zlib.compressobj(wbits=16 + zlib.MAX_WBITS)
    bomb = compressor.compress(b"x" * (kafka_client.KAFKA_MAX_DECOMPRESSED_BYTES + 1)) + compressor.flush()
    with pytest.raises(kafka_client.KafkaCompressionError, match="exceeds 16 MiB"):
        kafka_client._decompress_kafka_records(1, bomb)


def test_kafka_session_reuses_socket_and_correlation_ids(monkeypatch: pytest.MonkeyPatch) -> None:
    class _Socket:
        closed = False

        def close(self) -> None:
            self.closed = True

    sock = _Socket()
    monkeypatch.setattr(kafka_client, "_open_kafka_socket_configured", lambda *_a, **_k: (sock, "plaintext"))
    monkeypatch.setattr(
        kafka_client,
        "_probe_apiversions",
        lambda _sock, correlation: kafka_client.KafkaApiVersionsResult(True, 0, None, {3: (0, 9)}),
    )
    correlations: list[int] = []

    def _metadata(_sock: Any, correlation: int, *, topics: list[str] | None = None):
        correlations.append(correlation)
        return {"topic_map": {"events": 1}, "auth_required": False}, None

    monkeypatch.setattr(kafka_client, "_fetch_metadata", _metadata)
    session = kafka_client.KafkaSession.open("broker", 9092, 1.0)
    assert session.detect().ok is True
    metadata, error = session.fetch_metadata()
    assert error is None
    assert metadata is not None and metadata["api_versions"] == {3: (0, 9)}
    assert correlations == [2]
    session.close()
    assert sock.closed is True


def test_kafka_leader_pool_is_bounded_reuses_and_isolates_identities(monkeypatch: pytest.MonkeyPatch) -> None:
    sessions: list[Any] = []

    class _Session:
        def __init__(self, identity: tuple[str | None, str | None]) -> None:
            self.identity = identity
            self.closed = False

        def bootstrap(self, **_kwargs: Any) -> tuple[bool, None]:
            return True, None

        def close(self) -> None:
            self.closed = True

    def _open(*_args: Any, username: str | None = None, password: str | None = None, **_kwargs: Any) -> _Session:
        session = _Session((username, password))
        sessions.append(session)
        return session

    monkeypatch.setattr(kafka_client.KafkaSession, "open", _open)
    pool = kafka_client.KafkaLeaderPool(max_sessions=1)
    first, error = pool.get_or_open(
        "leader",
        9092,
        1.0,
        username="one",
        password="secret",
        use_tls=False,
        tls_config=None,
        sasl_first=False,
        known_kafka=True,
    )
    assert error is None
    reused, error = pool.get_or_open(
        "leader",
        9092,
        1.0,
        username="one",
        password="secret",
        use_tls=False,
        tls_config=None,
        sasl_first=False,
        known_kafka=True,
    )
    assert reused is first and error is None
    second, error = pool.get_or_open(
        "leader",
        9092,
        1.0,
        username="two",
        password="secret",
        use_tls=False,
        tls_config=None,
        sasl_first=False,
        known_kafka=True,
    )
    assert second is not first and error is None
    assert sessions[0].closed is True
    assert pool.stats() == {"connections": 2, "reused": 1, "requests": 0, "retries": 0}
    pool.close()
    assert sessions[1].closed is True


def test_kafka_lifecycle_retains_first_valid_identity_and_closes_others(monkeypatch: pytest.MonkeyPatch) -> None:
    sessions: list[Any] = []

    class _Session:
        transport_mode = "plaintext"

        def __init__(self, identity: tuple[str | None, str | None]) -> None:
            self.identity = identity
            self.closed = False

        def bootstrap(self, **_kwargs: Any) -> tuple[bool, None]:
            return True, None

        def fetch_metadata(self, **_kwargs: Any) -> tuple[dict[str, Any], None]:
            return {"topic_map": {}, "auth_required": False}, None

        def close(self) -> None:
            self.closed = True

    def _open(*_args: Any, username: str | None = None, password: str | None = None, **_kwargs: Any) -> _Session:
        session = _Session((username, password))
        sessions.append(session)
        return session

    monkeypatch.setattr(kafka_actions.KafkaSession, "open", _open)
    state = kafka_actions.KafkaLifecycleState(is_kafka=True, auth_required=True, transport_mode="plaintext")
    detect_record = {"is_kafka": True, "status": "auth_required", "auth_required": True}
    for username in ("first", "second"):
        ctx = SimpleNamespace(
            host="broker",
            port=9092,
            args=SimpleNamespace(timeout=1.0, retries=0),
            credential=SimpleNamespace(username=username, password="secret", source="provided"),
            lifecycle_state=state,
        )
        result = kafka_actions.authenticate_kafka(ctx, detect_record, {})
        assert result["provided_credentials_ok"] is True
    assert state.authenticated_session is sessions[0]
    assert sessions[0].closed is False
    assert sessions[1].closed is True
    state.close()
    assert sessions[0].closed is True
