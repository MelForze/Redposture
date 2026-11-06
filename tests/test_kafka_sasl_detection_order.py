"""Read-only SASL proof precedes Metadata; no password is submitted by detect."""

import struct
from types import SimpleNamespace

import pytest

from redposture_core.clients import kafka
from redposture_core.modules.kafka import actions


def reply(correlation, code, mechanisms):
    return struct.pack(">ihi", correlation, code, len(mechanisms)) + b"".join(
        struct.pack(">h", len(m.encode())) + m.encode() for m in mechanisms
    )


@pytest.mark.parametrize(
    "code,mechanisms,expected",
    [
        (0, ["PLAIN"], True),
        (33, ["SCRAM-SHA-256"], True),
        (34, [], False),
        (0, [], None),
        (34, ["PLAIN"], None),
        (35, [], None),
    ],
)
def test_probe_sasl_decision_requires_full_correlated_mechanisms(monkeypatch, code, mechanisms, expected):
    requests = []

    def send(sock, **options):
        requests.append(options)
        return reply(options["correlation_id"], code, mechanisms)

    monkeypatch.setattr(kafka, "_send_kafka_request", send)
    session = kafka.KafkaSession(
        sock=SimpleNamespace(),
        transport_mode="plaintext",
        identity=(None, None),
        correlation_id=9,
        api_versions={17: (0, 1)},
    )
    assert session.probe_sasl() is expected
    assert session.correlation_id == 10
    assert len(requests) == 1 and requests[0]["api_key"] == 17
    assert requests[0]["body"] == b"\0\5PLAIN"


@pytest.mark.parametrize("damage", ["correlation", "truncated", "trailing"])
def test_damaged_handshake_never_confirms_auth(monkeypatch, damage):
    data = reply(1 if damage != "correlation" else 99, 0, ["PLAIN"])
    data = data[:-1] if damage == "truncated" else data + b"x" if damage == "trailing" else data
    monkeypatch.setattr(kafka, "_send_kafka_request", lambda *args, **kw: data)
    session = kafka.KafkaSession(
        sock=SimpleNamespace(), transport_mode="plaintext", identity=(None, None), api_versions={17: (0, 1)}
    )
    assert session.probe_sasl() is None


@pytest.mark.parametrize("required", [True, False, None])
def test_lifecycle_does_not_send_metadata_before_sasl_probe(monkeypatch, required):
    calls = []

    class Session:
        transport_mode = "plaintext"
        closed = False

        def detect(self):
            calls.append("versions")
            return kafka.KafkaApiVersionsResult(True, 0, None, {17: (0, 1), 3: (0, 12)})

        def probe_sasl(self):
            calls.append("handshake")
            return required

        def fetch_metadata(self, **kw):
            calls.append("metadata")
            return {"auth_required": False, "topic_map": {}}, None

        def close(self):
            self.closed = True

    session = Session()
    monkeypatch.setattr(actions, "KafkaSession", SimpleNamespace(open=lambda *args, **kwargs: session))
    from redposture_core.cli_args import parse_args
    from redposture_core.stage_runtime import AuditCredentialRun, AuditHookContext

    ctx = AuditHookContext(
        args=parse_args(["kafka", "-t", "127.0.0.1", "--retries", "0"]),
        logger=None,
        host="127.0.0.1",
        port=9092,
        credential=AuditCredentialRun(source="anonymous"),
    )
    state = actions.KafkaLifecycleState(requested_use_tls=False)
    record = actions._kafka_lifecycle_detection_record(ctx, state)
    assert calls == (["versions", "handshake"] if required is True else ["versions", "handshake", "metadata"])
    assert record["is_kafka"] is True
    assert record["auth_required"] is (required is True)
    assert state.connections_opened == 1
    if required is True:
        assert state.sasl_first and session.closed and state.anonymous_session is None


@pytest.mark.parametrize("sasl", [False, True])
def test_real_framing_sync_native_parity_without_metadata_on_sasl(monkeypatch, sasl):
    import asyncio
    import socketserver
    import threading

    from redposture_core.cli_args import parse_args
    from redposture_core.modules.kafka import stage
    from redposture_core.stage_runtime import AuditCredentialRun, AuditHookContext

    calls = []
    errors = []

    class Peer(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.settimeout(2)
            requests = []
            calls.append(requests)

            def exact(n):
                data = b""
                while len(data) < n:
                    chunk = self.request.recv(n - len(data))
                    if not chunk:
                        raise EOFError()
                    data += chunk
                return data

            try:
                for _ in range(2 if sasl else 3):
                    size = struct.unpack(">i", exact(4))[0]
                    request = exact(size)
                    key, version, corr = struct.unpack(">hhi", request[:8])
                    requests.append(key)
                    if key == 18:
                        response = struct.pack(">ihi", corr, 0, 3) + b"".join(
                            struct.pack(">hhh", k, 0, 1) for k in (3, 17, 18)
                        )
                    elif key == 17:
                        response = reply(corr, 0 if sasl else 34, ["PLAIN"] if sasl else [])
                    elif key == 3 and not sasl:
                        response = struct.pack(">iii", corr, 0, 0)
                    else:
                        raise AssertionError(key)
                    data = struct.pack(">i", len(response)) + response
                    # Split both framing and body to exercise partial reads.
                    self.request.sendall(data[:3])
                    self.request.sendall(data[3:])
            except BaseException as exc:
                errors.append(repr(exc))

    class Server(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = True

    with Server(("127.0.0.1", 0), Peer) as server:
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        thread.start()
        try:
            args = parse_args(["kafka", "-t", f"127.0.0.1:{server.server_address[1]}", "--retries", "0"])
            spec = stage.build_kafka_spec(args)
            factory, close = spec.lifecycle_state_factory, spec.lifecycle_state_close
            sync_detect, native_detect = spec.detect, spec.detect_async
            assert factory is not None and close is not None
            assert sync_detect is not None and native_detect is not None
            records = []
            for native in (False, True):
                ctx = AuditHookContext(
                    args=args,
                    logger=None,
                    host="127.0.0.1",
                    port=server.server_address[1],
                    credential=AuditCredentialRun(source="anonymous"),
                )
                state = factory(ctx)
                from dataclasses import replace

                ctx = replace(ctx, lifecycle_state=state)
                try:
                    if native:

                        async def run(context=ctx):
                            monkeypatch.setattr(
                                asyncio.get_running_loop(),
                                "run_in_executor",
                                lambda *a, **k: pytest.fail("detect used an executor"),
                            )
                            return await native_detect(context, None)

                        record = asyncio.run(run())
                    else:
                        record = sync_detect(ctx)
                    records.append(record)
                    assert state.connections_opened == 1
                    assert record.extra["is_kafka"] is True
                    assert record.auth_required is sasl
                finally:
                    close(state)
            assert [(r.status, r.auth_required, r.extra.get("auth_flow")) for r in records] == [
                ("auth_required", True, "sasl_handshake") if sasl else ("open_no_auth", False, None)
            ] * 2
        finally:
            server.shutdown()
            thread.join(2)
    assert errors == []
    assert calls == [[18, 17] if sasl else [18, 17, 3]] * 2


def test_optional_handshake_failure_reopens_for_original_metadata(monkeypatch):
    from redposture_core.cli_args import parse_args
    from redposture_core.stage_runtime import AuditCredentialRun, AuditHookContext

    calls = []

    class Session:
        transport_mode = "plaintext"
        closed = False
        correlation_id = 1
        sock = object()
        api_versions = {}

        def detect(self):
            calls.append("versions")
            return kafka.KafkaApiVersionsResult(True, 0, None, {17: (0, 1), 3: (0, 12)})

        def probe_sasl(self):
            calls.append("handshake")
            raise ConnectionError("peer closed optional handshake")

        def fetch_metadata(self, **kw):
            calls.append("metadata")
            return {"auth_required": False, "topic_map": {}}, None

        def close(self):
            self.closed = True

    sessions = []

    def opened(*args, **kwargs):
        session = Session()
        sessions.append(session)
        return session

    monkeypatch.setattr(actions, "KafkaSession", SimpleNamespace(open=opened))
    monkeypatch.setattr(actions, "_sasl_handshake_plain", lambda *args: (False, 2, "legacy probe unavailable"))
    ctx = AuditHookContext(
        args=parse_args(["kafka", "-t", "127.0.0.1", "--retries", "0"]),
        logger=None,
        host="127.0.0.1",
        port=9092,
        credential=AuditCredentialRun(source="anonymous"),
    )
    state = actions.KafkaLifecycleState(requested_use_tls=False)
    try:
        record = actions._kafka_lifecycle_detection_record(ctx, state)
        assert record["is_kafka"] is True and record["auth_required"] is False
        assert calls == ["versions", "handshake", "metadata"]
        assert len(sessions) == 2 and sessions[0].closed
    finally:
        state.close()


@pytest.mark.parametrize("versions", [{}, {17: (2, 2)}, {17: (0, 0)}])
def test_handshake_version_negotiation_preserves_legacy_path(monkeypatch, versions):
    calls = []

    def send(sock, **options):
        calls.append(options["api_version"])
        return reply(options["correlation_id"], 0, ["PLAIN"])

    monkeypatch.setattr(kafka, "_send_kafka_request", send)
    session = kafka.KafkaSession(
        sock=SimpleNamespace(), transport_mode="plaintext", identity=(None, None), api_versions=versions
    )
    expected = True if versions == {17: (0, 0)} else None
    assert session.probe_sasl() is expected
    assert calls == ([0] if expected else [])


@pytest.mark.parametrize("count", [-1, 2**31 - 1, 5000000])
def test_impossible_sasl_array_count_is_rejected_before_allocation(monkeypatch, count):
    monkeypatch.setattr(kafka, "_send_kafka_request", lambda *args, **kwargs: struct.pack(">ihi", 1, 0, count))
    session = kafka.KafkaSession(
        sock=SimpleNamespace(), transport_mode="plaintext", identity=(None, None), api_versions={17: (0, 1)}
    )
    assert session.probe_sasl() is None


@pytest.mark.parametrize("flow,auth_first", [(None, False), ("sasl_fallback", True), ("sasl_handshake", False)])
def test_detect_wrapper_keeps_legacy_auth_first_separate_from_normal_handshake(monkeypatch, flow, auth_first):
    """New probe success must not select the legacy pre-ApiVersions auth flow."""
    from redposture_core.cli_args import parse_args
    from redposture_core.stage_runtime import AuditCredentialRun, AuditHookContext

    bootstrap = []

    def detected(ctx, state):
        # Simulate stale intermediate state: the wrapper must normalize it
        # using the actual flow, not inherit a flag from a previous attempt.
        state.sasl_first = not auth_first
        return {
            "host": ctx.host,
            "port": ctx.port,
            "is_kafka": True,
            "status": "auth_required",
            "auth_required": True,
            "transport_mode": "plaintext",
            "auth_flow": flow,
        }

    class Session:
        transport_mode = "plaintext"

        def bootstrap(self, **kwargs):
            bootstrap.append(kwargs)
            return True, None

        def fetch_metadata(self, **kwargs):
            return {"auth_required": False, "topic_map": {}}, None

        def close(self):
            pass

    monkeypatch.setattr(actions, "_kafka_lifecycle_detection_record", detected)
    monkeypatch.setattr(actions.KafkaSession, "open", lambda *args, **kwargs: Session())
    state = actions.KafkaLifecycleState()
    ctx = AuditHookContext(
        args=parse_args(["kafka", "-t", "127.0.0.1:9092", "--retries", "0"]),
        logger=None,
        host="127.0.0.1",
        port=9092,
        credential=AuditCredentialRun(username="qa", password="pass", source="provided"),
        lifecycle_state=state,
    )
    try:
        record = actions.detect_kafka(ctx, {"max_messages": 10})
        assert state.sasl_first is auth_first
        authenticated = actions.authenticate_kafka(ctx, record, {})
        assert authenticated["provided_credentials_ok"] is True
        assert bootstrap == [{"known_kafka": True, "sasl_first": auth_first}]
    finally:
        state.close()
