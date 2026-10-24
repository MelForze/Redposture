"""SDK and framed-listener faults must preserve evidence and release owned IO."""

import asyncio
import ssl
import struct
from types import SimpleNamespace

import pytest
from bson import BSON
from pymongo.errors import OperationFailure, ProtocolError, ServerSelectionTimeoutError

from redposture_core import stage_spray
from redposture_core.clients import async_mongodb_detect as mongo
from redposture_core.clients import async_oracle_detect as oracle
from redposture_core.clients.async_http_detect import AsyncHttpFallback
from redposture_core.modules.mongodb import async_detect as mongo_detect
from redposture_core.modules.oracle import async_detect as oracle_detect

HELLO = {"ok": 1, "minWireVersion": 0, "maxWireVersion": 17, "isWritablePrimary": True}


class StreamReader:
    def __init__(self, data=b"", *, terminal=None, fragment=3):
        self.data = bytearray(data)
        self.terminal = terminal
        self.fragment = fragment

    async def read(self, count):
        if self.data:
            size = min(count, self.fragment, len(self.data))
            chunk = bytes(self.data[:size])
            del self.data[:size]
            return chunk
        if self.terminal is not None:
            raise self.terminal
        return b""


class StreamWriter:
    def __init__(self):
        self.sent = []
        self.closed = False
        self.aborted = False
        self.transport = SimpleNamespace(abort=self.abort)

    def write(self, data):
        self.sent.append(data)

    async def drain(self):
        pass

    def close(self):
        self.closed = True

    async def wait_closed(self):
        pass

    def abort(self):
        self.aborted = True


def install_stream(monkeypatch, reader, writer):
    calls = []

    async def connect(*args, **kwargs):
        calls.append((args, kwargs))
        return reader, writer

    monkeypatch.setattr(asyncio, "open_connection", connect)
    return calls


def oracle_probe(**options):
    return oracle.connect_probe(
        "127.0.0.1",
        1521,
        **{
            "timeout": 0.5,
            "protocol": "tcp",
            "service": "XE",
            "sid": None,
            "wallet": None,
            "ssl_server_dn": None,
            "insecure": True,
            **options,
        },
    )


@pytest.mark.parametrize("backend", ["mongodb", "oracle"])
def test_optional_sdk_dependency_failure_requests_legacy(monkeypatch, backend):
    if backend == "mongodb":

        def missing():
            raise mongo.helpers.MongoDependencyError("PyMongo is unavailable")

        monkeypatch.setattr(mongo.helpers, "_load_pymongo", missing)
        with pytest.raises(AsyncHttpFallback, match="PyMongo is unavailable"):
            mongo.open_client("127.0.0.1", 27017, timeout=0.5, auth_db="admin")
    else:

        def missing():
            raise oracle.helpers.OracleDependencyError("Oracle driver is unavailable")

        monkeypatch.setattr(oracle.helpers, "_load_oracledb", missing)
        with pytest.raises(AsyncHttpFallback, match="Oracle driver is unavailable"):
            asyncio.run(oracle_probe())


@pytest.mark.parametrize(
    "driver",
    [
        SimpleNamespace(),
        SimpleNamespace(connect_async=True, is_thin_mode=lambda: True),
        SimpleNamespace(connect_async=lambda: None),
        SimpleNamespace(connect_async=lambda: None, is_thin_mode=lambda: False),
    ],
)
def test_oracle_never_calls_an_unsupported_sync_or_thick_factory(monkeypatch, driver):
    monkeypatch.setattr(oracle.helpers, "_load_oracledb", lambda: driver)
    with pytest.raises(AsyncHttpFallback, match="Thin mode"):
        asyncio.run(oracle_probe())


@pytest.mark.parametrize("host", ["db.example.invalid", "fe80::1%en0"])
def test_sdk_and_descriptor_dns_fallback_precedes_any_factory_or_socket(monkeypatch, host):
    def forbidden(*args, **kwargs):
        pytest.fail("unsupported DNS target must not start SDK or socket IO")

    monkeypatch.setattr(mongo.helpers, "_load_pymongo", forbidden)
    monkeypatch.setattr(oracle.helpers, "_load_oracledb", forbidden)
    monkeypatch.setattr(asyncio, "open_connection", forbidden)
    with pytest.raises(AsyncHttpFallback):
        mongo.open_client(host, 27017, timeout=0.5, auth_db="admin")
    with pytest.raises(AsyncHttpFallback):
        asyncio.run(
            oracle.connect_probe(
                host,
                1521,
                timeout=0.5,
                protocol="tcp",
                service="XE",
                sid=None,
                wallet=None,
                ssl_server_dn=None,
                insecure=True,
            )
        )
    with pytest.raises(AsyncHttpFallback):
        asyncio.run(oracle.service_fingerprint(host, 1521, service="XE"))


def test_mongo_factory_preserves_original_uri_tls_timeouts_and_closes_sdk(monkeypatch):
    constructed = []
    closed = []

    class Driver:
        def __init__(self, uri, **kwargs):
            constructed.append((uri, kwargs))

        async def close(self):
            closed.append(self)

    monkeypatch.setattr(mongo.helpers, "_load_pymongo", lambda: SimpleNamespace(AsyncMongoClient=Driver))
    client = mongo.open_client(
        "::1",
        27017,
        timeout=0.25,
        auth_db="admin",
        tls=True,
        tls_ca="ca.pem",
        tls_cert_key="client.pem",
        tls_insecure=True,
    )
    uri, options = constructed[0]
    assert uri.startswith("mongodb://[::1]:27017/")
    assert "directConnection=true" in uri
    assert options == {
        "serverSelectionTimeoutMS": 250,
        "connectTimeoutMS": 250,
        "socketTimeoutMS": 250,
        "appname": "redposture",
        "tls": True,
        "tlsCAFile": "ca.pem",
        "tlsCertificateKeyFile": "client.pem",
        "tlsAllowInvalidCertificates": True,
        "tlsAllowInvalidHostnames": True,
    }
    asyncio.run(client.close())
    assert closed == [client.client]


@pytest.mark.parametrize("result,message", [(None, "document"), ([HELLO], "document"), ({"ok": 1}, "MongoDB-like")])
def test_mongo_rejects_foreign_acknowledgements(result, message):
    class Driver:
        def __getitem__(self, name):
            assert name == "admin"
            return self

        async def command(self, command):
            assert command == "hello"
            return result

    with pytest.raises(mongo.helpers.MongoNotMongoError, match=message):
        asyncio.run(mongo.AsyncMongoDetectClient(Driver()).hello())


@pytest.mark.parametrize("topology", [None, SimpleNamespace(server_descriptions=None), "protocol", "transport"])
def test_mongo_selection_retains_protocol_or_transport_cause(topology):
    original = ServerSelectionTimeoutError("selection deadline")
    if topology in ("protocol", "transport"):
        nested = ProtocolError("foreign wire opcode") if topology == "protocol" else OSError("network down")
        topology = SimpleNamespace(
            server_descriptions=lambda: {
                "unresolved": SimpleNamespace(error=None),
                "numeric": SimpleNamespace(error=nested),
            }
        )
    else:
        nested = None

    class Driver:
        topology_description = topology

        def __getitem__(self, name):
            return self

        async def command(self, command):
            raise original

    if isinstance(nested, ProtocolError):
        with pytest.raises(mongo.helpers.MongoClientError, match="foreign wire opcode") as caught:
            asyncio.run(mongo.AsyncMongoDetectClient(Driver()).hello())
        assert caught.value.__cause__ is original
    else:
        with pytest.raises(ServerSelectionTimeoutError) as selection_error:
            asyncio.run(mongo.AsyncMongoDetectClient(Driver()).hello())
        assert selection_error.value is original


def test_mongo_permission_error_does_not_retry_deprecated_handshake():
    calls = []
    denied = OperationFailure("not authorized", code=13)

    class Driver:
        def __getitem__(self, name):
            return self

        async def command(self, command):
            calls.append(command)
            raise denied

    with pytest.raises(OperationFailure) as caught:
        asyncio.run(mongo.AsyncMongoDetectClient(Driver()).hello())
    assert caught.value is denied
    assert calls == ["hello"]


@pytest.mark.parametrize("info,expected", [(None, {}), ({"version": "7.0.1"}, {"version": "7.0.1"})])
@pytest.mark.parametrize("estimate", [3, ValueError("estimate unavailable"), AsyncHttpFallback("DNS redirect")])
def test_mongo_metadata_and_count_fallback_preserve_operation_boundaries(info, expected, estimate):
    calls = []

    class Driver:
        def __getitem__(self, name):
            calls.append(("select", name))
            return self

        async def server_info(self):
            return info

        async def list_database_names(self):
            return ["app", 42]

        async def list_collection_names(self):
            return ["events", 7]

        async def estimated_document_count(self):
            calls.append("estimated")
            if isinstance(estimate, Exception):
                raise estimate
            return estimate

        async def count_documents(self, query):
            calls.append(("exact", query))
            return 9

    async def run():
        client = mongo.AsyncMongoDetectClient(Driver())
        assert await client.server_info() == expected
        assert await client.list_database_names() == ["app", "42"]
        assert await client.list_collection_names("app") == ["events", "7"]
        if isinstance(estimate, AsyncHttpFallback):
            with pytest.raises(AsyncHttpFallback, match="DNS redirect"):
                await client.count_documents("app", "events")
        else:
            assert await client.count_documents("app", "events") == (9 if isinstance(estimate, Exception) else 3)

    asyncio.run(run())
    assert calls[:4] == [("select", "app"), ("select", "app"), ("select", "events"), "estimated"]
    assert calls[4:] == ([("exact", {})] if isinstance(estimate, ValueError) else [])


def mongo_reply(payload):
    return struct.pack("<iiii", 16 + len(payload), 7, 1, 1) + payload


@pytest.mark.parametrize(
    "reply,expected",
    [
        (struct.pack("<iiii", 35, 7, 1, 1), None),
        (struct.pack("<iiii", 1024 * 1024 + 1, 7, 1, 1), None),
        (mongo_reply(struct.pack("<iqii", 0, 0, 0, 0)), None),
        (mongo_reply(struct.pack("<iqii", 0, 0, 0, 1)), None),
        (mongo_reply(struct.pack("<iqii", 0, 0, 0, 1) + struct.pack("<i", 4)), None),
        (mongo_reply(struct.pack("<iqii", 0, 0, 0, 1) + struct.pack("<i", 999)), None),
        (mongo_reply(struct.pack("<iqii", 0, 0, 0, 1) + b"\x05\x00\x00\x00\xff"), None),
        (mongo_reply(struct.pack("<iqii", 0, 0, 0, 1) + BSON.encode({"ok": 1})), None),
        (mongo_reply(struct.pack("<iqii", 0, 0, 0, 1) + BSON.encode(HELLO)), HELLO),
    ],
)
def test_legacy_mongo_requires_bounded_correlated_complete_bson(monkeypatch, reply, expected):
    writer = StreamWriter()
    install_stream(monkeypatch, StreamReader(reply), writer)
    assert asyncio.run(mongo.probe_legacy_hello("127.0.0.1", 27017, timeout=0.5)) == expected
    assert writer.closed and not writer.aborted
    request = writer.sent[0]
    assert struct.unpack("<iiii", request[:16]) == (len(request), 1, 0, 2004)
    assert request.endswith(BSON.encode({"isMaster": 1}))


def test_legacy_mongo_eof_is_transport_failure_and_releases_writer(monkeypatch):
    writer = StreamWriter()
    install_stream(monkeypatch, StreamReader(b"short"), writer)
    with pytest.raises(ConnectionError, match="truncated MongoDB reply"):
        asyncio.run(mongo.probe_legacy_hello("127.0.0.1", 27017, timeout=0.5))
    assert writer.closed


@pytest.mark.parametrize("insecure", [False, True])
def test_legacy_mongo_tls_keeps_ca_client_certificate_and_hostname_policy(monkeypatch, insecure):
    loaded = []
    context = SimpleNamespace(check_hostname=True, verify_mode=ssl.CERT_REQUIRED, load_cert_chain=loaded.append)
    ca_files = []

    def ssl_context(*, cafile):
        ca_files.append(cafile)
        return context

    monkeypatch.setattr(mongo.ssl, "create_default_context", ssl_context)
    writer = StreamWriter()
    calls = install_stream(monkeypatch, StreamReader(mongo_reply(struct.pack("<iqii", 0, 0, 0, 0))), writer)
    assert (
        asyncio.run(
            mongo.probe_legacy_hello(
                "127.0.0.1",
                27017,
                timeout=0.5,
                tls=True,
                tls_ca_file="ca.pem",
                tls_certificate_key_file="client.pem",
                tls_insecure=insecure,
            )
        )
        is None
    )
    assert ca_files == ["ca.pem"] and loaded == ["client.pem"]
    assert calls == [(("127.0.0.1", 27017), {"ssl": context, "server_hostname": "127.0.0.1"})]
    assert context.check_hostname is (not insecure)
    assert context.verify_mode == (ssl.CERT_NONE if insecure else ssl.CERT_REQUIRED)
    assert writer.closed


def test_legacy_mongo_tls_setup_failure_never_opens_a_plaintext_socket(monkeypatch):
    failure = ssl.SSLError("invalid client key")

    def load_certificate(path):
        assert path == "client.pem"
        raise failure

    monkeypatch.setattr(
        mongo.ssl, "create_default_context", lambda **kwargs: SimpleNamespace(load_cert_chain=load_certificate)
    )
    monkeypatch.setattr(asyncio, "open_connection", lambda *args, **kwargs: pytest.fail("TLS setup failed"))
    with pytest.raises(ssl.SSLError) as caught:
        asyncio.run(
            mongo.probe_legacy_hello("127.0.0.1", 27017, timeout=0.5, tls=True, tls_certificate_key_file="client.pem")
        )
    assert caught.value is failure


@pytest.mark.parametrize("backend", ["mongo", "oracle"])
def test_cancelled_stream_handshake_aborts_owned_writer(monkeypatch, backend):
    async def run():
        entered = asyncio.Event()
        writer = StreamWriter()

        async def stalled_drain():
            entered.set()
            await asyncio.Event().wait()

        monkeypatch.setattr(writer, "drain", stalled_drain)
        install_stream(monkeypatch, StreamReader(), writer)
        operation = (
            mongo.probe_legacy_hello("127.0.0.1", 27017, timeout=20)
            if backend == "mongo"
            else oracle.listener_command("127.0.0.1", 1521, "status", timeout=20)
        )
        task = asyncio.create_task(operation)
        await asyncio.wait_for(entered.wait(), 0.5)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, 0.5)
        assert writer.closed and writer.aborted

    asyncio.run(run())


def tns_reply(text):
    payload = text.encode("ascii")
    return struct.pack(">HHBBH", 8 + len(payload), 0, 4, 0, 0) + payload


@pytest.mark.parametrize("terminal", [None, TimeoutError()])
def test_oracle_listener_accumulates_fragmented_evidence_and_preserves_tcps(monkeypatch, terminal):
    writer = StreamWriter()
    replies = tns_reply("TNS-01169 (SECURITY=ON)") + tns_reply("TNS-12528 (SERVICE_NAME=XE)")
    calls = install_stream(monkeypatch, StreamReader(replies, terminal=terminal), writer)
    policies = []
    context = object()

    def ssl_context(*, insecure):
        policies.append(insecure)
        return context

    monkeypatch.setattr(oracle.helpers, "shared_client_ssl_context", ssl_context)
    result = asyncio.run(
        oracle.listener_command("127.0.0.1", 1521, "STA-TUS!", timeout=0.5, protocol="TCPS", insecure=False)
    )
    assert result["ok"] is True and result["error"] is None
    assert result["command"] == "status" and result["protocol"] == "tcps"
    assert len(result["packets"]) == 2
    assert result["listener_password_protected"] is True and result["listener_restricted"] is True
    assert "TNS-01169" in result["text"] and "TNS-12528" in result["text"]
    assert result["fields"]["SERVICE_NAME"] == ["XE"]
    assert policies == [False]
    assert calls == [
        (
            ("127.0.0.1", 1521),
            {
                "ssl": context,
                "server_hostname": "127.0.0.1",
                "ssl_handshake_timeout": 0.5,
            },
        )
    ]
    assert b"(COMMAND=status)" in writer.sent[0]
    assert writer.closed and not writer.aborted


@pytest.mark.parametrize(
    "reply,error",
    [
        (b"", "no listener response"),
        (b"short", "no listener response"),
        (struct.pack(">HHBBH", 10, 0, 4, 0, 0) + b"x", "truncated TNS packet body"),
        (struct.pack(">HHBBH", 7, 0, 4, 0, 0), "invalid TNS packet length"),
    ],
)
def test_oracle_listener_never_confirms_eof_or_malformed_frame(monkeypatch, reply, error):
    writer = StreamWriter()
    install_stream(monkeypatch, StreamReader(reply), writer)
    result = asyncio.run(oracle.listener_command("127.0.0.1", 1521, "!"))
    assert result["ok"] is False and result["packets"] == []
    assert result["command"] == "status" and result["error"] == error
    assert writer.closed


@pytest.mark.parametrize(
    "text,protected",
    [
        ("TNSLSNR (VERSION=23)", False),
        ("(ERR=1169)", True),
        ("(LISTENER=PASSWORD)", True),
        ("(SECURITY=PASSWORD)", True),
        ("(PASSWORD=unknown)", False),
    ],
)
def test_oracle_listener_password_policy_requires_listener_specific_evidence(monkeypatch, text, protected):
    writer = StreamWriter()
    install_stream(monkeypatch, StreamReader(tns_reply(text)), writer)
    result = asyncio.run(oracle.listener_command("127.0.0.1", 1521, "status"))
    assert result["ok"] is True and result["listener_password_protected"] is protected
    assert result["listener_restricted"] is False
    assert writer.closed


def test_oracle_listener_preserves_wrapped_resolver_fallback_and_closes_stream(monkeypatch):
    fallback = AsyncHttpFallback("hostname redirect needs legacy")
    writer = StreamWriter()

    async def drain():
        raise OSError("transport wrapper") from fallback

    monkeypatch.setattr(writer, "drain", drain)
    install_stream(monkeypatch, StreamReader(), writer)
    with pytest.raises(AsyncHttpFallback) as caught:
        asyncio.run(oracle.listener_command("127.0.0.1", 1521, "status"))
    assert caught.value is fallback
    assert writer.closed


@pytest.mark.parametrize(
    "failure,error",
    [
        (TimeoutError(), "connection timeout"),
        (ConnectionRefusedError("connection refused"), "connection refused (listener is not available)"),
    ],
)
def test_oracle_connection_failures_keep_original_normalized_evidence(monkeypatch, failure, error):
    async def connect(*args, **kwargs):
        raise failure

    monkeypatch.setattr(asyncio, "open_connection", connect)
    result = asyncio.run(oracle.listener_command("127.0.0.1", 1521, "services"))
    assert result["ok"] is False and result["error"] == error
    assert result["packets"] == [] and result["text"] == ""


@pytest.mark.parametrize(
    "text,exception,message",
    [
        ("ORA-28000", oracle.helpers.OracleAccountLockedError, "account locked"),
        ("ORA-28001", oracle.helpers.OracleAccountExpiredError, "account expired"),
        ("ORA-01017", oracle.helpers.OracleAuthError, "invalid credentials"),
        ("ORA-12514", oracle.helpers.OracleServiceError, "listener does not know service"),
        ("ORA-12528", oracle.helpers.OracleServiceError, "listener restricted/blocking new connections"),
        ("DPY-4011", oracle.helpers.OracleClientError, "database or network closed the connection"),
    ],
)
def test_oracle_sdk_faults_keep_typed_original_evidence(monkeypatch, text, exception, message):
    failure = RuntimeError(text)

    async def connect(**kwargs):
        raise failure

    monkeypatch.setattr(
        oracle.helpers, "_load_oracledb", lambda: SimpleNamespace(is_thin_mode=lambda: True, connect_async=connect)
    )
    with pytest.raises(exception) as caught:
        asyncio.run(oracle_probe())
    assert type(caught.value) is exception
    assert str(caught.value) == message and caught.value.__cause__ is failure


def test_oracle_sdk_returns_original_session_for_target_owner_to_close(monkeypatch):
    calls = []
    closed = []
    session = SimpleNamespace()

    async def close():
        closed.append(session)

    session.close = close

    async def connect(**kwargs):
        calls.append(kwargs)
        return session

    monkeypatch.setattr(
        oracle.helpers, "_load_oracledb", lambda: SimpleNamespace(is_thin_mode=lambda: True, connect_async=connect)
    )

    async def run():
        assert (
            await oracle_probe(
                protocol="tcps", service=None, sid="ORCLCDB", wallet="wallet", ssl_server_dn="CN=db", insecure=False
            )
            is session
        )
        assert closed == []
        await session.close()
        rows = await oracle_detect.probe_targets(
            "127.0.0.1",
            1521,
            0.5,
            protocol_candidates=["tcp"],
            target_candidates=[{"service": "XE", "sid": None}],
            wallet=None,
            ssl_server_dn=None,
            insecure=True,
        )
        assert len(rows) == 1 and rows[0]["status"] == "accepted"

    asyncio.run(run())
    assert closed == [session, session]
    first = calls[0]
    assert "(SID=ORCLCDB)" in first["dsn"] and "(PROTOCOL=tcps)" in first["dsn"]
    assert first["config_dir"] == "wallet" and first["wallet_location"] == "wallet"
    assert first["ssl_server_cert_dn"] == "CN=db" and first["ssl_server_dn_match"] is True
    assert first["user"] == "REDPOSTURE_PROBE" and first["tcp_connect_timeout"] == 0.5


@pytest.mark.parametrize("phase", ["cancel", "fallback"])
def test_mongo_detector_always_awaits_sdk_close_before_propagating(monkeypatch, phase):
    async def run():
        entered = asyncio.Event()
        closed = []
        fallback = AsyncHttpFallback("replica hostname requires legacy")

        class Driver:
            def __getitem__(self, name):
                return self

            async def command(self, command):
                entered.set()
                if phase == "fallback":
                    raise fallback
                await asyncio.Event().wait()

            async def close(self):
                await asyncio.sleep(0)
                closed.append(self)

        driver = Driver()
        monkeypatch.setattr(mongo_detect, "open_client", lambda *args, **kwargs: mongo.AsyncMongoDetectClient(driver))
        ctx = SimpleNamespace(
            host="127.0.0.1",
            port=27017,
            args=SimpleNamespace(timeout=1, retries=0),
            lifecycle_state=None,
            debug_emit=None,
        )
        task = asyncio.create_task(mongo_detect.detect(ctx, None))
        await asyncio.wait_for(entered.wait(), 0.5)
        if phase == "cancel":
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await asyncio.wait_for(task, 0.5)
        else:
            with pytest.raises(AsyncHttpFallback) as caught:
                await task
            assert caught.value is fallback
        assert closed == [driver]

    asyncio.run(run())


@pytest.mark.parametrize("hook", ["preflight", "fingerprint_steps", "listener", "fingerprint"])
def test_oracle_spray_declines_overridden_sync_transport_seams(monkeypatch, hook):
    def custom(*args, **kwargs):
        pytest.fail("async interpreter must not execute an unknown synchronous hook")

    async def status(*args, **kwargs):
        return {"ok": False}

    monkeypatch.setattr(oracle, "listener_command", status)
    if hook == "preflight":
        monkeypatch.setattr(stage_spray, "_oracle_spray_preflight", custom)
    elif hook == "fingerprint_steps":
        monkeypatch.setattr(oracle.helpers, "_tns_service_fingerprint_steps", custom)
    elif hook == "listener":
        monkeypatch.setattr(oracle.helpers, "tns_listener_command", custom)
    else:
        monkeypatch.setattr(oracle.helpers, "tns_service_fingerprint", custom)
    with pytest.raises(AsyncHttpFallback, match="override"):
        if hook == "fingerprint_steps":
            asyncio.run(oracle.service_fingerprint("127.0.0.1", 1521, service="XE"))
        else:
            asyncio.run(
                oracle.spray_preflight("127.0.0.1", 1521, SimpleNamespace(protocol="tcp", service="XE", timeout=0.5))
            )
