from __future__ import annotations

import errno
import ssl
import struct
import subprocess
import sys
import threading
from pathlib import Path

import pytest

import redposture_core.clients.zookeeper as zk


def test_parallel_znode_enumeration_success_truncation_and_progress(monkeypatch: pytest.MonkeyPatch) -> None:
    tree = {
        "/": ["app", "zookeeper"],
        "/app": ["config", "secret"],
        "/app/config": [],
        "/app/secret": [],
        "/zookeeper": [],
    }

    class FakeClient:
        def __init__(self, host: str, port: int, timeout: float) -> None:
            self.host = host
            self.port = port
            self.timeout = timeout
            self.closed = False

        def connect(self) -> None:
            return None

        def auth_digest(self, username: str, password: str):
            assert (username, password) == ("user", "pass")
            return True, None

        def get_children2(self, parent: str):
            stat = {"data_length": len(parent), "num_children": len(tree.get(parent, []))}
            return list(tree[parent]), zk._ZK_ERR_OK, stat

        def close(self) -> None:
            self.closed = True

    events: list[dict[str, object]] = []
    monkeypatch.setattr(zk, "_ZkClient", FakeClient)

    nodes, total, truncated, meta, error = zk._enumerate_znodes_parallel(
        host="zk.internal",
        port=2181,
        timeout=1.0,
        max_znodes=5,
        progress_hook=events.append,
        progress_interval_s=0.000001,
        enum_workers=2,
        auth_username="user",
        auth_password="pass",
    )

    assert error is None
    assert total == 4
    assert truncated is False
    assert nodes == ["/app", "/zookeeper", "/app/config", "/app/secret"]
    assert "/zookeeper" in nodes
    assert meta["/app"]["children"] == 2
    assert events[-1]["event"] == "enumerate_done"


def test_serial_enumeration_hard_caps_wide_page_and_traversal() -> None:
    calls: list[str] = []

    class WideClient:
        def get_children2(self, parent: str):
            calls.append(parent)
            if parent == "/":
                return [f"node-{index:03d}" for index in range(100)], zk._ZK_ERR_OK, {}
            return ["nested"], zk._ZK_ERR_OK, {}

    nodes, total, truncated, _meta, error = zk._enumerate_znodes(
        WideClient(),
        max_znodes=3,
        enum_workers=1,
    )

    assert nodes == ["/node-000", "/node-001"]
    assert total == 2
    assert truncated is True
    assert calls == ["/", "/node-000", "/node-001"]
    assert error is None


def test_enumeration_preserves_root_noauth_as_coverage_evidence(monkeypatch: pytest.MonkeyPatch) -> None:
    class RootDeniedClient:
        def __init__(self, *_args, **_kwargs) -> None:
            self.host = "zk.internal"
            self.port = 2181
            self.timeout = 1.0

        def connect(self) -> None:
            return

        def get_children2(self, parent: str):
            assert parent == "/"
            return None, zk._ZK_ERR_NOAUTH, None

        def close(self) -> None:
            return

    serial = zk._enumerate_znodes(RootDeniedClient(), max_znodes=10, enum_workers=1)
    assert serial[3]["/"]["error"] == "Access Denied"

    monkeypatch.setattr(zk, "_ZkClient", RootDeniedClient)
    parallel = zk._enumerate_znodes_parallel(
        host="zk.internal",
        port=2181,
        timeout=1.0,
        max_znodes=10,
        enum_workers=2,
    )
    assert parallel[3]["/"]["error"] == "Access Denied"


def test_parallel_enumeration_hard_caps_wide_page_and_queued_work(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []
    calls_lock = threading.Lock()

    class WideClient:
        def __init__(self, *_args, **_kwargs) -> None:
            return None

        def connect(self) -> None:
            return None

        def get_children2(self, parent: str):
            with calls_lock:
                calls.append(parent)
            if parent == "/":
                return [f"node-{index:03d}" for index in range(100)], zk._ZK_ERR_OK, {}
            return ["nested"], zk._ZK_ERR_OK, {}

        def close(self) -> None:
            return None

    monkeypatch.setattr(zk, "_ZkClient", WideClient)
    nodes, total, truncated, _meta, error = zk._enumerate_znodes_parallel(
        host="zk.internal",
        port=2181,
        timeout=1.0,
        max_znodes=3,
        enum_workers=3,
    )

    assert nodes == ["/node-000", "/node-001"]
    assert total == 2
    assert truncated is True
    assert sorted(calls) == ["/", "/node-000", "/node-001"]
    assert error is None


def test_connect_response_parser_rejects_ambiguous_or_trailing_records() -> None:
    base = (
        struct.pack(">i", 0) + struct.pack(">i", 1000) + struct.pack(">q", 1) + struct.pack(">i", 16) + (b"\x00" * 16)
    )
    zk._parse_connect_response(base)
    zk._parse_connect_response(base + b"\x00")
    zk._parse_connect_response(base + b"\x01")

    malformed = (
        base[:4] + struct.pack(">i", 0) + base[8:],
        struct.pack(">i", 1) + base[4:],
        base[:8] + struct.pack(">q", 0) + base[16:],
        base[:16] + struct.pack(">i", 15) + (b"\x00" * 15),
        base + b"\x02",
        base + b"\x00\x00",
    )
    for payload in malformed:
        with pytest.raises(ValueError):
            zk._parse_connect_response(payload)


def test_zkclient_rejects_incomplete_or_trailing_root_payloads(monkeypatch: pytest.MonkeyPatch) -> None:
    client = zk._ZkClient("zk.internal", 2181, 1.0)
    stat = struct.pack(">qqqqiiiqiiq", 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 10)
    children = struct.pack(">i", 0)

    monkeypatch.setattr(client, "_request", lambda *_a, **_k: (zk._ZK_ERR_OK, children))
    with pytest.raises(ValueError, match="stat payload"):
        client.get_children2("/")

    monkeypatch.setattr(client, "_request", lambda *_a, **_k: (zk._ZK_ERR_OK, children + stat + b"junk"))
    with pytest.raises(ValueError, match="trailing"):
        client.get_children2("/")

    mismatched_stat = struct.pack(">qqqqiiiqiiq", 1, 2, 3, 4, 5, 6, 7, 8, 9, 1, 10)
    monkeypatch.setattr(client, "_request", lambda *_a, **_k: (zk._ZK_ERR_OK, children + mismatched_stat))
    with pytest.raises(ValueError, match="count mismatch"):
        client.get_children2("/")

    negative_stat = struct.pack(">qqqqiiiqiiq", 1, 2, 3, 4, 5, 6, 7, 8, -1, 0, 10)
    monkeypatch.setattr(client, "_request", lambda *_a, **_k: (zk._ZK_ERR_OK, children + negative_stat))
    with pytest.raises(ValueError, match="stat counters"):
        client.get_children2("/")

    monkeypatch.setattr(client, "_request", lambda *_a, **_k: (zk._ZK_ERR_OK, struct.pack(">i", -1) + stat))
    with pytest.raises(ValueError, match="null.*children vector"):
        client.get_children2("/")

    monkeypatch.setattr(client, "_request", lambda *_a, **_k: (zk._ZK_ERR_NOAUTH, b"junk"))
    with pytest.raises(ValueError, match="error payload"):
        client.get_children2("/")

    empty_buffer = struct.pack(">i", 0)
    monkeypatch.setattr(client, "_request", lambda *_a, **_k: (zk._ZK_ERR_OK, empty_buffer))
    with pytest.raises(ValueError, match="stat payload"):
        client.get_data("/")

    monkeypatch.setattr(client, "_request", lambda *_a, **_k: (zk._ZK_ERR_OK, empty_buffer + stat + b"junk"))
    with pytest.raises(ValueError, match="trailing"):
        client.get_data("/")


@pytest.mark.parametrize(
    "name_payload",
    (
        struct.pack(">i", 0),
        struct.pack(">i", -1),
        struct.pack(">i", 3) + b"a/b",
        struct.pack(">i", 1) + b"\x00",
        struct.pack(">i", 2) + b"..",
        struct.pack(">i", 2) + b"\xc3(",
    ),
)
def test_children_vector_rejects_invalid_names(name_payload: bytes) -> None:
    with pytest.raises(ValueError, match="child|UTF-8"):
        zk._parse_children_vector(struct.pack(">i", 1) + name_payload)


def test_children_vector_and_buffers_enforce_exact_negative_sentinels_and_bounds() -> None:
    assert zk._parse_children_vector(struct.pack(">i", -1)) == (None, 4)
    with pytest.raises(ValueError, match="vector count"):
        zk._parse_children_vector(struct.pack(">i", -2))
    with pytest.raises(ValueError, match="truncated.*vector"):
        zk._parse_children_vector(struct.pack(">i", 100))
    with pytest.raises(ValueError, match="string length"):
        zk._decode_zk_string(struct.pack(">i", -2))
    with pytest.raises(ValueError, match="buffer length"):
        zk._decode_zk_buffer(struct.pack(">i", -2))


@pytest.mark.parametrize(
    "failure",
    (
        TimeoutError("auth timed out"),
        ConnectionResetError("connection reset by peer"),
        ValueError("malformed auth response"),
    ),
)
def test_auth_digest_propagates_transport_and_malformed_response_failures(
    monkeypatch: pytest.MonkeyPatch,
    failure: BaseException,
) -> None:
    client = zk._ZkClient("zk.internal", 2181, 1.0)

    def fail_request(*_args: object, **_kwargs: object) -> tuple[int, bytes]:
        raise failure

    monkeypatch.setattr(client, "_request_with_xid", fail_request)

    with pytest.raises(type(failure), match=str(failure)):
        client.auth_digest("admin", "secret")


def test_auto_transport_request_budget_and_security_downgrade_guards(monkeypatch: pytest.MonkeyPatch) -> None:
    cases: tuple[tuple[zk.ZkTransportConfig, BaseException], ...] = (
        (
            zk.ZkTransportConfig(mode="auto", ca_file="ca.pem"),
            ssl.SSLCertVerificationError(1, "certificate verify failed"),
        ),
        (
            zk.ZkTransportConfig(mode="auto", cert_file="client.pem", key_file="client.key"),
            ssl.SSLError(1, "tlsv13 alert certificate required"),
        ),
        (
            zk.ZkTransportConfig(mode="auto", ca_file="missing.pem"),
            FileNotFoundError(errno.ENOENT, "missing CA"),
        ),
    )
    for config, failure in cases:
        client = zk._ZkClient("keeper", 9181, 1.0, transport_config=config)
        attempts: list[str] = []

        def fail(
            mode: str,
            *,
            _failure: BaseException = failure,
            _attempts: list[str] = attempts,
        ) -> None:
            _attempts.append(mode)
            raise _failure

        monkeypatch.setattr(client, "_connect_once", fail)
        with pytest.raises(type(failure)):
            client.connect()
        assert attempts == ["tls"]

    mismatch = zk._ZkClient(
        "keeper",
        9181,
        1.0,
        transport_config=zk.ZkTransportConfig(mode="auto", insecure=True),
    )
    mismatch_attempts: list[str] = []

    def mismatch_then_plaintext(mode: str) -> None:
        mismatch_attempts.append(mode)
        if mode == "tls":
            raise ssl.SSLError(1, "wrong version number")

    monkeypatch.setattr(mismatch, "_connect_once", mismatch_then_plaintext)
    mismatch.connect()
    assert mismatch_attempts == ["tls", "plaintext"]
    assert mismatch.selected_transport == "plaintext"

    unreachable = zk._ZkClient("keeper", 9181, 1.0, transport_config=zk.ZkTransportConfig(mode="auto"))
    unreachable_attempts: list[str] = []

    def no_route(mode: str) -> None:
        unreachable_attempts.append(mode)
        raise OSError(errno.EHOSTUNREACH, "no route to host")

    monkeypatch.setattr(unreachable, "_connect_once", no_route)
    with pytest.raises(OSError):
        unreachable.connect()
    assert unreachable_attempts == ["plaintext"]


def test_auto_transport_uses_one_fallback_after_tls_protocol_payload_mismatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    attempts: list[str] = []

    class FakeSocket:
        def sendall(self, _data: bytes) -> None:
            return None

        def close(self) -> None:
            return None

    def open_socket(
        _host: str,
        _port: int,
        _timeout: float,
        *,
        transport: str,
        config: zk.ZkTransportConfig,
    ) -> FakeSocket:
        assert config.insecure is True
        attempts.append(transport)
        return FakeSocket()

    monkeypatch.setattr(zk, "_open_zk_socket", open_socket)
    monkeypatch.setattr(zk, "_recv_frame", lambda _sock: b"\x00")
    client = zk._ZkClient(
        "keeper",
        9181,
        1.0,
        transport_config=zk.ZkTransportConfig(mode="auto", insecure=True),
    )

    with pytest.raises(ConnectionError, match="transport auto-detection failed"):
        client.connect()

    assert attempts == ["tls", "plaintext"]


@pytest.mark.parametrize(
    "failure",
    (
        ConnectionError("unexpected EOF"),
        TimeoutError("response timed out"),
        OSError("connection reset after handshake"),
    ),
)
def test_auto_transport_uses_one_fallback_after_tls_connect_response_io_failure(
    monkeypatch: pytest.MonkeyPatch,
    failure: BaseException,
) -> None:
    attempts: list[str] = []

    class FakeSocket:
        def sendall(self, _data: bytes) -> None:
            return None

        def close(self) -> None:
            return None

    def open_socket(
        _host: str,
        _port: int,
        _timeout: float,
        *,
        transport: str,
        config: zk.ZkTransportConfig,
    ) -> FakeSocket:
        assert config.ca_file == "ca.pem"
        attempts.append(transport)
        return FakeSocket()

    def fail_response(_sock: FakeSocket) -> bytes:
        raise failure

    monkeypatch.setattr(zk, "_open_zk_socket", open_socket)
    monkeypatch.setattr(zk, "_recv_frame", fail_response)
    client = zk._ZkClient(
        "keeper",
        9181,
        1.0,
        transport_config=zk.ZkTransportConfig(mode="auto", ca_file="ca.pem"),
    )

    with pytest.raises(ConnectionError, match="transport auto-detection failed"):
        client.connect()

    assert attempts == ["tls", "plaintext"]


def test_auto_transport_does_not_downgrade_delayed_mtls_alert_wrapped_by_connect_exchange(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    attempts: list[str] = []
    security_failure = ssl.SSLError(1, "tlsv13 alert certificate required")

    class FakeSocket:
        def sendall(self, _data: bytes) -> None:
            return None

        def close(self) -> None:
            return None

    def open_socket(
        _host: str,
        _port: int,
        _timeout: float,
        *,
        transport: str,
        config: zk.ZkTransportConfig,
    ) -> FakeSocket:
        assert (config.cert_file, config.key_file) == ("client.pem", "client.key")
        attempts.append(transport)
        return FakeSocket()

    def reject_connect_response(_sock: FakeSocket) -> bytes:
        raise security_failure

    monkeypatch.setattr(zk, "_open_zk_socket", open_socket)
    monkeypatch.setattr(zk, "_recv_frame", reject_connect_response)
    client = zk._ZkClient(
        "keeper",
        9181,
        1.0,
        transport_config=zk.ZkTransportConfig(
            mode="auto",
            cert_file="client.pem",
            key_file="client.key",
        ),
    )

    with pytest.raises(zk._ZkProtocolPayloadError) as caught:
        client.connect()

    assert attempts == ["tls"]
    assert caught.value.transport == "tls"
    assert caught.value.__cause__ is security_failure


@pytest.mark.parametrize(
    "failure",
    (
        ConnectionError("unexpected EOF"),
        ConnectionResetError("connection reset by peer"),
        TimeoutError("root response timed out"),
        ValueError("malformed ZooKeeper root payload"),
    ),
)
def test_auto_transport_selection_waits_for_decoded_root_and_falls_back_once(
    monkeypatch: pytest.MonkeyPatch,
    failure: BaseException,
) -> None:
    client = zk._ZkClient(
        "keeper",
        9181,
        1.0,
        transport_config=zk.ZkTransportConfig(mode="auto"),
    )
    attempts: list[str] = []
    root_attempts: list[str] = []
    active_transport = ""

    def connect_once(transport: str) -> None:
        nonlocal active_transport
        active_transport = transport
        attempts.append(transport)

    def get_root(path: str):
        assert path == "/"
        root_attempts.append(active_transport)
        if active_transport == "plaintext":
            raise failure
        return ["keeper"], zk._ZK_ERR_OK, {"data_length": 0, "num_children": 1}

    monkeypatch.setattr(client, "_connect_once", connect_once)
    monkeypatch.setattr(client, "get_children2", get_root)

    root = client.connect_and_get_root()

    assert root == (["keeper"], zk._ZK_ERR_OK, {"data_length": 0, "num_children": 1})
    assert attempts == ["plaintext", "tls"]
    assert root_attempts == ["plaintext", "tls"]
    assert client.selected_transport == "tls"


def test_auto_transport_verified_tls_root_eof_may_fall_back_but_certificate_error_may_not(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = zk._ZkClient(
        "keeper",
        9181,
        1.0,
        transport_config=zk.ZkTransportConfig(mode="auto", ca_file="ca.pem"),
    )
    attempts: list[str] = []
    active_transport = ""

    def connect_once(transport: str) -> None:
        nonlocal active_transport
        active_transport = transport
        attempts.append(transport)

    def get_root(_path: str):
        if active_transport == "tls":
            raise ConnectionError("unexpected EOF")
        return [], zk._ZK_ERR_OK, {"data_length": 0, "num_children": 0}

    monkeypatch.setattr(client, "_connect_once", connect_once)
    monkeypatch.setattr(client, "get_children2", get_root)

    assert client.connect_and_get_root()[1] == zk._ZK_ERR_OK
    assert attempts == ["tls", "plaintext"]
    assert client.selected_transport == "plaintext"

    certificate_failure = zk._ZkClient(
        "keeper",
        9181,
        1.0,
        transport_config=zk.ZkTransportConfig(mode="auto", ca_file="ca.pem"),
    )
    security_attempts: list[str] = []

    def reject_certificate(transport: str) -> None:
        security_attempts.append(transport)
        raise ssl.SSLCertVerificationError(1, "certificate verify failed")

    monkeypatch.setattr(certificate_failure, "_connect_once", reject_certificate)
    with pytest.raises(ssl.SSLCertVerificationError):
        certificate_failure.connect_and_get_root()
    assert security_attempts == ["tls"]
    assert certificate_failure.selected_transport is None

    unreachable = zk._ZkClient(
        "keeper",
        9181,
        1.0,
        transport_config=zk.ZkTransportConfig(mode="auto"),
    )
    permanent_attempts: list[str] = []

    def no_route(transport: str) -> None:
        permanent_attempts.append(transport)
        raise OSError(errno.EHOSTUNREACH, "no route to host")

    monkeypatch.setattr(unreachable, "_connect_once", no_route)
    monkeypatch.setattr(
        unreachable,
        "get_children2",
        lambda _path: pytest.fail("root must not be requested after a permanent connect failure"),
    )
    with pytest.raises(OSError):
        unreachable.connect_and_get_root()
    assert permanent_attempts == ["plaintext"]
    assert unreachable.selected_transport is None


def test_parallel_znode_enumeration_worker_auth_and_result_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    class AuthFailClient:
        def __init__(self, *_args) -> None:
            return None

        def connect(self) -> None:
            return None

        def auth_digest(self, _username: str, _password: str):
            return False, "bad digest"

        def close(self) -> None:
            return None

    monkeypatch.setattr(zk, "_ZkClient", AuthFailClient)
    _nodes, _total, _truncated, _meta, error = zk._enumerate_znodes_parallel(
        host="zk.internal",
        port=2181,
        timeout=1.0,
        max_znodes=10,
        enum_workers=1,
        auth_username="user",
        auth_password="bad",
    )
    assert error == "worker init failed: bad digest"

    class ErrorClient:
        def __init__(self, *_args) -> None:
            return None

        def connect(self) -> None:
            return None

        def get_children2(self, _parent: str):
            raise TimeoutError("slow")

        def close(self) -> None:
            return None

    monkeypatch.setattr(zk, "_ZkClient", ErrorClient)
    _nodes, _total, _truncated, _meta, error = zk._enumerate_znodes_parallel(
        host="zk.internal",
        port=2181,
        timeout=1.0,
        max_znodes=10,
        enum_workers=1,
    )
    assert "getChildren failed for /" in str(error)


def test_parallel_znode_enumeration_non_ok_statuses(monkeypatch: pytest.MonkeyPatch) -> None:
    responses = {
        "/": (["missing", "denied", "bad"], zk._ZK_ERR_OK, {"data_length": 1}),
        "/missing": ([], zk._ZK_ERR_NONODE, {}),
        "/denied": ([], zk._ZK_ERR_NOAUTH, {}),
        "/bad": ([], -7, {}),
    }

    class StatusClient:
        def __init__(self, *_args) -> None:
            return None

        def connect(self) -> None:
            return None

        def get_children2(self, parent: str):
            return responses[parent]

        def close(self) -> None:
            return None

    monkeypatch.setattr(zk, "_ZkClient", StatusClient)

    nodes, total, truncated, meta, error = zk._enumerate_znodes_parallel(
        host="zk.internal",
        port=2181,
        timeout=1.0,
        max_znodes=10,
        enum_workers=1,
    )

    assert nodes == ["/missing", "/denied", "/bad"]
    assert total == 3
    assert truncated is False
    assert meta["/missing"]["error"] == "not found"
    assert meta["/denied"]["error"] == "Access Denied"
    assert error == "getChildren failed for /bad: OPERATIONTIMEOUT"


def test_parallel_znode_enumeration_unexpected_worker_error_cancels_without_hanging(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    blocked_worker_started = threading.Event()
    release_blocked_worker = threading.Event()

    class UnexpectedErrorClient:
        def __init__(self, *_args) -> None:
            return None

        def connect(self) -> None:
            return None

        def get_children2(self, parent: str):
            if parent == "/":
                return ["blocked", "boom"], zk._ZK_ERR_OK, {}
            if parent == "/blocked":
                blocked_worker_started.set()
                release_blocked_worker.wait(timeout=5.0)
                return [], zk._ZK_ERR_OK, {}
            assert parent == "/boom"
            assert blocked_worker_started.wait(timeout=1.0)
            raise RuntimeError("unexpected worker crash")

        def close(self) -> None:
            return None

    monkeypatch.setattr(zk, "_ZkClient", UnexpectedErrorClient)
    results: list[tuple[list[str], int, bool, dict[str, dict[str, object]], str | None]] = []

    def _enumerate() -> None:
        results.append(
            zk._enumerate_znodes_parallel(
                host="zk.internal",
                port=2181,
                timeout=1.0,
                max_znodes=10,
                enum_workers=2,
            )
        )

    enumeration_thread = threading.Thread(target=_enumerate, daemon=True)
    enumeration_thread.start()
    try:
        enumeration_thread.join(timeout=2.0)
        assert not enumeration_thread.is_alive(), "parallel enumeration did not stop after a fatal worker error"
    finally:
        release_blocked_worker.set()
        enumeration_thread.join(timeout=0.5)

    assert results
    nodes, total, truncated, _meta, error = results[0]
    assert nodes == ["/blocked", "/boom"]
    assert total == 2
    assert truncated is False
    assert error == "getChildren failed for /boom: unexpected worker crash"


def test_parallel_znode_enumeration_cancellation_closes_blocked_worker_client(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    blocked_worker_started = threading.Event()
    blocked_worker_released_by_close = threading.Event()

    class CancelAwareClient:
        def __init__(self, *_args, **_kwargs) -> None:
            self.blocked = False

        def connect(self) -> None:
            return None

        def get_children2(self, parent: str):
            if parent == "/":
                return ["blocked", "boom"], zk._ZK_ERR_OK, {}
            if parent == "/blocked":
                self.blocked = True
                blocked_worker_started.set()
                assert blocked_worker_released_by_close.wait(timeout=2.0)
                return [], zk._ZK_ERR_OK, {}
            assert parent == "/boom"
            assert blocked_worker_started.wait(timeout=1.0)
            raise RuntimeError("unexpected worker crash")

        def close(self) -> None:
            if self.blocked:
                blocked_worker_released_by_close.set()

    monkeypatch.setattr(zk, "_ZkClient", CancelAwareClient)

    _nodes, _total, _truncated, _meta, error = zk._enumerate_znodes_parallel(
        host="zk.internal",
        port=2181,
        timeout=1.0,
        max_znodes=10,
        enum_workers=2,
    )

    assert error == "getChildren failed for /boom: unexpected worker crash"
    assert blocked_worker_released_by_close.is_set()


def test_parallel_znode_enumeration_unexpected_worker_error_subprocess_deadline() -> None:
    repository_root = Path(__file__).resolve().parents[1]
    script = """
import redposture_core.clients.zookeeper as zk

class UnexpectedErrorClient:
    def __init__(self, *_args):
        pass

    def connect(self):
        pass

    def get_children2(self, parent):
        if parent == "/":
            return ["boom"], zk._ZK_ERR_OK, {}
        raise RuntimeError("unexpected worker crash")

    def close(self):
        pass

zk._ZkClient = UnexpectedErrorClient
result = zk._enumerate_znodes_parallel(
    host="zk.internal",
    port=2181,
    timeout=1.0,
    max_znodes=10,
    enum_workers=2,
)
assert result[1] == 1, result
assert result[-1] == "getChildren failed for /boom: unexpected worker crash", result
"""
    completed = subprocess.run(
        [sys.executable, "-c", script],
        cwd=repository_root,
        capture_output=True,
        text=True,
        timeout=2.0,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr or completed.stdout
