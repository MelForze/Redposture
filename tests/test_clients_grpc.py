from __future__ import annotations

import socket
import ssl

import pytest
from google.protobuf import descriptor_pb2

from redposture_core.clients import grpc as grpc_client
from redposture_core.clients.tls_cache import clear_tls_context_cache
from redposture_core.proto import grpc_health_pb2, grpc_reflection_pb2


def _grpc_ok_call(messages: list[bytes] | None = None) -> dict[str, object]:
    return {
        "grpc_status": 0,
        "grpc_message": "",
        "messages": messages or [],
        "is_grpc": True,
        "transport_ok": True,
        "http_status": 200,
        "error": None,
    }


def test_grpc_frame_codec_handles_roundtrip_and_malformed_frames() -> None:
    first = grpc_client._encode_grpc_frame(b"one")
    second = grpc_client._encode_grpc_frame(b"two")

    messages, error = grpc_client._decode_grpc_frames(first + second)
    assert messages == [b"one", b"two"]
    assert error is None

    messages, error = grpc_client._decode_grpc_frames(first[:-1])
    assert messages == []
    assert error == "truncated gRPC frame"

    compressed = b"\x01" + (3).to_bytes(4, "big") + b"bad"
    messages, error = grpc_client._decode_grpc_frames(compressed)
    assert messages == []
    assert error == "compressed gRPC payload is not supported"

    messages, error = grpc_client._decode_grpc_frames(b"abcd")
    assert messages == []
    assert error == "trailing bytes after gRPC frames"


def test_auth_metadata_status_and_http1_helpers() -> None:
    assert grpc_client._grpc_status_name(None) == "-"
    assert grpc_client._grpc_status_name(123) == "CODE_123"
    assert grpc_client._build_auth_header(token="tok", username="u", password="p") == "Bearer tok"
    assert grpc_client._build_auth_header(token=None, username="u", password="") == "Basic dTo="
    assert grpc_client._build_auth_header(token=None, username="u", password=None) is None
    assert grpc_client._metadata_value({"grpc-status": "1"}, {"grpc-status": "0"}, "Grpc-Status") == "0"
    assert grpc_client._http2_headers_to_map([(b"X-Test", b"1"), ("Y-Test", "2")]) == {
        "x-test": "1",
        "y-test": "2",
    }

    status, headers, body, error = grpc_client._parse_http1_response(
        b"HTTP/1.1 204 No Content\r\nX-Test: yes\r\n\r\nbody"
    )
    assert status == 204
    assert headers == {"x-test": "yes"}
    assert body == b"body"
    assert error is None

    status, headers, body, error = grpc_client._parse_http1_response(b"HTTP/1.1 200 OK\r\nNo terminator")
    assert status is None
    assert headers == {}
    assert body.startswith(b"HTTP/1.1")
    assert error == "truncated HTTP response"


def test_open_socket_tls_failure_paths(monkeypatch) -> None:
    class BaseSocket:
        def __init__(self) -> None:
            self.closed = False
            self.timeout: float | None = None

        def settimeout(self, timeout: float) -> None:
            self.timeout = timeout

        def close(self) -> None:
            self.closed = True

    base = BaseSocket()
    monkeypatch.setattr(socket, "create_connection", lambda *_a, **_k: base)
    assert grpc_client._open_grpc_socket("host", 50051, 1.0, use_tls=False) is base
    assert base.timeout == 1.0

    class BadContext:
        check_hostname = True
        verify_mode = ssl.CERT_REQUIRED

        def set_alpn_protocols(self, _protocols) -> None:
            return None

        def wrap_socket(self, _sock, server_hostname: str):  # noqa: ANN001
            raise ssl.SSLError(f"bad tls {server_hostname}")

    base = BaseSocket()
    monkeypatch.setattr(socket, "create_connection", lambda *_a, **_k: base)
    monkeypatch.setattr(ssl, "_create_unverified_context", lambda: BadContext())
    with pytest.raises(ssl.SSLError):
        grpc_client._open_grpc_socket("host", 50051, 1.0, use_tls=True)
    assert base.closed is True

    class WrappedSocket(BaseSocket):
        def selected_alpn_protocol(self) -> str:
            return "http/1.1"

    wrapped = WrappedSocket()

    class MismatchContext(BadContext):
        def wrap_socket(self, _sock, server_hostname: str):  # noqa: ANN001
            return wrapped

    base = BaseSocket()
    monkeypatch.setattr(socket, "create_connection", lambda *_a, **_k: base)
    clear_tls_context_cache()
    monkeypatch.setattr(ssl, "_create_unverified_context", lambda: MismatchContext())
    with pytest.raises(OSError, match="alpn negotiation"):
        grpc_client._open_grpc_socket("host", 50051, 1.0, use_tls=True)
    assert wrapped.closed is True

    class HttpContext(BadContext):
        def wrap_socket(self, _sock, server_hostname: str):  # noqa: ANN001
            raise OSError("wrap failed")

    base = BaseSocket()
    monkeypatch.setattr(socket, "create_connection", lambda *_a, **_k: base)
    clear_tls_context_cache()
    monkeypatch.setattr(ssl, "_create_unverified_context", lambda: HttpContext())
    with pytest.raises(OSError, match="wrap failed"):
        grpc_client._open_http_socket("host", 443, 1.0, use_tls=True)
    assert base.closed is True


def test_grpc_web_frame_codec_extracts_messages_trailers_and_errors() -> None:
    message = b"payload"
    trailer_text = b"grpc-status: 0\r\ngrpc-message: OK\r\n"
    body = (
        b"\x00"
        + len(message).to_bytes(4, "big")
        + message
        + b"\x80"
        + len(trailer_text).to_bytes(4, "big")
        + trailer_text
    )

    messages, trailers, error = grpc_client._decode_grpc_web_frames(body)
    assert messages == [message]
    assert trailers == {"grpc-status": "0", "grpc-message": "OK"}
    assert error is None

    messages, trailers, error = grpc_client._decode_grpc_web_frames(body[:-2])
    assert messages == [message]
    assert trailers == {}
    assert error == "truncated gRPC-Web frame"

    messages, trailers, error = grpc_client._decode_grpc_web_frames(b"\x02" + (1).to_bytes(4, "big") + b"x")
    assert messages == []
    assert trailers == {}
    assert error == "unsupported gRPC-Web frame type 2"


def test_health_payload_and_result_parsing(monkeypatch) -> None:
    request = grpc_health_pb2.HealthCheckRequest()
    request.ParseFromString(grpc_client._grpc_health_payload("grpc.health.v1.Health"))
    assert request.service == "grpc.health.v1.Health"

    response = grpc_health_pb2.HealthCheckResponse(status=grpc_health_pb2.HealthCheckResponse.SERVING)
    assert grpc_client._parse_health_message(response.SerializeToString()) == "SERVING"
    assert grpc_client._parse_health_message(b"not-protobuf") is None

    def fake_call(*_args, **_kwargs):
        return _grpc_ok_call([response.SerializeToString()])

    monkeypatch.setattr(grpc_client, "_grpc_call", fake_call)
    result = grpc_client._health_check_call(
        "127.0.0.1",
        50051,
        timeout=1.0,
        use_tls=False,
        authorization=None,
        service_name="grpc.health.v1.Health",
    )

    assert result["grpc_status_name"] == "OK"
    assert result["serving_status"] == "SERVING"
    assert result["health_supported"] is True

    monkeypatch.setattr(
        grpc_client, "_grpc_call", lambda *_a, **_k: {"grpc_status": 12, "messages": [], "is_grpc": True}
    )
    assert (
        grpc_client._health_check_call("127.0.0.1", 50051, timeout=1.0, use_tls=False, authorization=None)[
            "health_supported"
        ]
        is False
    )

    monkeypatch.setattr(
        grpc_client, "_grpc_call", lambda *_a, **_k: {"grpc_status": 16, "messages": [], "is_grpc": True}
    )
    assert (
        grpc_client._health_check_call("127.0.0.1", 50051, timeout=1.0, use_tls=False, authorization=None)[
            "health_supported"
        ]
        is None
    )


def test_grpc_web_health_status_branches(monkeypatch) -> None:
    monkeypatch.setattr(
        grpc_client,
        "_grpc_web_call",
        lambda *_a, **_k: {"grpc_status": 12, "messages": [], "is_grpc": True, "error": "unimplemented"},
    )
    assert (
        grpc_client._grpc_web_health_check_call("127.0.0.1", 8080, timeout=1.0, use_tls=False, authorization=None)[
            "health_supported"
        ]
        is False
    )

    monkeypatch.setattr(
        grpc_client,
        "_grpc_web_call",
        lambda *_a, **_k: {"grpc_status": 7, "messages": [], "is_grpc": True, "error": "denied"},
    )
    assert (
        grpc_client._grpc_web_health_check_call("127.0.0.1", 8080, timeout=1.0, use_tls=False, authorization=None)[
            "health_supported"
        ]
        is None
    )

    monkeypatch.setattr(
        grpc_client,
        "_grpc_web_call",
        lambda *_a, **_k: {"grpc_status": None, "messages": [], "is_grpc": False, "error": "no grpc"},
    )
    result = grpc_client._grpc_web_health_check_call("127.0.0.1", 8080, timeout=1.0, use_tls=False, authorization=None)
    assert result["health_supported"] is None
    assert result["error"] == "no grpc"


def test_reflection_list_and_descriptor_fetch(monkeypatch) -> None:
    list_response = grpc_reflection_pb2.ServerReflectionResponse(
        list_services_response=grpc_reflection_pb2.ListServiceResponse(
            service=[
                grpc_reflection_pb2.ServiceResponse(name="demo.Greeter"),
                grpc_reflection_pb2.ServiceResponse(name="grpc.health.v1.Health"),
                grpc_reflection_pb2.ServiceResponse(name="demo.Greeter"),
            ]
        )
    )
    fd_response = grpc_reflection_pb2.ServerReflectionResponse(
        file_descriptor_response=grpc_reflection_pb2.FileDescriptorResponse(
            file_descriptor_proto=[grpc_health_pb2.DESCRIPTOR.serialized_pb]
        )
    )
    seen_paths: list[str] = []

    def fake_call(*_args, **kwargs):
        seen_paths.append(kwargs["path"])
        payload = kwargs["payload"]
        request = grpc_reflection_pb2.ServerReflectionRequest()
        request.ParseFromString(payload)
        if request.HasField("list_services"):
            return _grpc_ok_call([list_response.SerializeToString()])
        if request.HasField("file_containing_symbol"):
            assert request.file_containing_symbol == "grpc.health.v1.Health"
            return _grpc_ok_call([fd_response.SerializeToString()])
        raise AssertionError("unexpected reflection request")

    monkeypatch.setattr(grpc_client, "_grpc_call", fake_call)

    list_result = grpc_client._reflection_list_services_call(
        "127.0.0.1", 50051, timeout=1.0, use_tls=False, authorization=None
    )
    descriptor_result = grpc_client._reflection_file_descriptors_call(
        "127.0.0.1",
        50051,
        timeout=1.0,
        use_tls=False,
        authorization=None,
        symbol="grpc.health.v1.Health",
    )

    assert list_result["reflection_enabled"] is True
    assert list_result["reflection_version"] == "v1"
    assert list_result["services"] == ["demo.Greeter", "grpc.health.v1.Health"]
    assert descriptor_result["descriptor_bytes"] == [grpc_health_pb2.DESCRIPTOR.serialized_pb]
    assert descriptor_result["reflection_version"] == "v1"
    assert seen_paths == [
        "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo",
        "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo",
    ]


def test_reflection_v1alpha_fallback_is_cached_for_session(monkeypatch) -> None:
    list_response = grpc_reflection_pb2.ServerReflectionResponse(
        list_services_response=grpc_reflection_pb2.ListServiceResponse(
            service=[grpc_reflection_pb2.ServiceResponse(name="demo.Greeter")]
        )
    )
    descriptor_response = grpc_reflection_pb2.ServerReflectionResponse(
        file_descriptor_response=grpc_reflection_pb2.FileDescriptorResponse(
            file_descriptor_proto=[grpc_health_pb2.DESCRIPTOR.serialized_pb]
        )
    )
    seen_paths: list[str] = []

    def fake_call(*_args, **kwargs):
        path = str(kwargs["path"])
        seen_paths.append(path)
        if ".v1.ServerReflection" in path:
            return {**_grpc_ok_call(), "grpc_status": 12}
        request = grpc_reflection_pb2.ServerReflectionRequest()
        request.ParseFromString(kwargs["payload"])
        if request.HasField("list_services"):
            return _grpc_ok_call([list_response.SerializeToString()])
        return _grpc_ok_call([descriptor_response.SerializeToString()])

    monkeypatch.setattr(grpc_client, "_grpc_call", fake_call)
    session = grpc_client._GrpcH2Session("127.0.0.1", 50051, timeout=1.0, use_tls=False)

    listed = grpc_client._reflection_list_services_call(
        "127.0.0.1", 50051, timeout=1.0, use_tls=False, authorization=None, session=session
    )
    described = grpc_client._reflection_file_descriptors_call(
        "127.0.0.1",
        50051,
        timeout=1.0,
        use_tls=False,
        authorization=None,
        symbol="demo.Greeter",
        session=session,
    )

    assert listed["reflection_version"] == "v1alpha"
    assert described["reflection_version"] == "v1alpha"
    assert seen_paths == [
        "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo",
        "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo",
        "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo",
    ]


def test_reflection_v1alpha_fallback_accepts_plain_http_404(monkeypatch) -> None:
    seen_paths: list[str] = []

    def fake_call(*_args, **kwargs):
        path = str(kwargs["path"])
        seen_paths.append(path)
        if ".v1.ServerReflection" in path:
            return {
                **_grpc_ok_call(),
                "grpc_status": None,
                "http_status": 404,
                "is_grpc": False,
            }
        return _grpc_ok_call()

    monkeypatch.setattr(grpc_client, "_grpc_call", fake_call)
    session = grpc_client._GrpcH2Session("127.0.0.1", 50051, timeout=1.0, use_tls=False)

    listed = grpc_client._reflection_list_services_call(
        "127.0.0.1", 50051, timeout=1.0, use_tls=False, authorization=None, session=session
    )
    described = grpc_client._reflection_file_descriptors_call(
        "127.0.0.1",
        50051,
        timeout=1.0,
        use_tls=False,
        authorization=None,
        symbol="demo.Greeter",
        session=session,
    )

    assert listed["reflection_version"] == "v1alpha"
    assert described["reflection_version"] == "v1alpha"
    assert seen_paths == [
        "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo",
        "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo",
        "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo",
    ]


def test_reflection_error_and_invalid_message_branches(monkeypatch) -> None:
    error_response = grpc_reflection_pb2.ServerReflectionResponse(
        error_response=grpc_reflection_pb2.ErrorResponse(error_code=5, error_message="missing")
    )

    def fake_list_call(*_args, **_kwargs):
        return _grpc_ok_call([b"not-protobuf", error_response.SerializeToString(), "not-bytes"])

    monkeypatch.setattr(grpc_client, "_grpc_call", fake_list_call)
    list_result = grpc_client._reflection_list_services_call(
        "127.0.0.1", 50051, timeout=1.0, use_tls=False, authorization=None
    )
    assert list_result["services"] == []
    assert list_result["error"] == "5:missing"

    def fake_descriptor_call(*_args, **_kwargs):
        return _grpc_ok_call([b"not-protobuf", error_response.SerializeToString(), "not-bytes"])

    monkeypatch.setattr(grpc_client, "_grpc_call", fake_descriptor_call)
    descriptor_result = grpc_client._reflection_file_descriptors_call(
        "127.0.0.1",
        50051,
        timeout=1.0,
        use_tls=False,
        authorization=None,
        symbol="missing.Service",
    )
    assert descriptor_result["descriptor_bytes"] == []
    assert descriptor_result["error"] == "5:missing"


def test_reflection_capability_probe_does_not_request_service_list(monkeypatch) -> None:
    error_response = grpc_reflection_pb2.ServerReflectionResponse(
        error_response=grpc_reflection_pb2.ErrorResponse(error_code=5, error_message="missing")
    )
    requests: list[grpc_reflection_pb2.ServerReflectionRequest] = []

    def fake_call(*_args, **kwargs):
        request = grpc_reflection_pb2.ServerReflectionRequest()
        request.ParseFromString(kwargs["payload"])
        requests.append(request)
        return _grpc_ok_call([error_response.SerializeToString()])

    monkeypatch.setattr(grpc_client, "_grpc_call", fake_call)

    result = grpc_client._reflection_capability_call(
        "127.0.0.1",
        50051,
        timeout=1.0,
        use_tls=False,
        authorization=None,
    )

    assert result["reflection_enabled"] is True
    assert result["embedded_error_code"] == 5
    assert len(requests) == 1
    assert requests[0].HasField("file_containing_symbol")
    assert not requests[0].HasField("list_services")


@pytest.mark.parametrize(("grpc_status", "expected"), [(12, False), (16, None)])
def test_reflection_capability_probe_classifies_outer_status(monkeypatch, grpc_status, expected) -> None:
    monkeypatch.setattr(
        grpc_client,
        "_grpc_call",
        lambda *_args, **_kwargs: {
            "grpc_status": grpc_status,
            "grpc_message": "",
            "messages": [],
            "is_grpc": True,
            "transport_ok": True,
            "http_status": 200,
            "error": None,
        },
    )

    result = grpc_client._reflection_capability_call(
        "127.0.0.1",
        50051,
        timeout=1.0,
        use_tls=False,
        authorization=None,
    )

    assert result["reflection_enabled"] is expected


def test_descriptor_pool_invoke_and_openapi_generation(monkeypatch) -> None:
    descriptor_bytes = [grpc_health_pb2.DESCRIPTOR.serialized_pb]
    pool, errors = grpc_client._descriptor_bytes_to_pool(descriptor_bytes)
    assert errors == []
    assert pool.FindMessageTypeByName("grpc.health.v1.HealthCheckRequest").full_name == (
        "grpc.health.v1.HealthCheckRequest"
    )

    response = grpc_health_pb2.HealthCheckResponse(status=grpc_health_pb2.HealthCheckResponse.SERVING)
    seen: dict[str, object] = {}

    def fake_call(*_args, **kwargs):
        seen.update(kwargs)
        request = grpc_health_pb2.HealthCheckRequest()
        request.ParseFromString(kwargs["payload"])
        assert request.service == "grpc.health.v1.Health"
        return _grpc_ok_call([response.SerializeToString()])

    monkeypatch.setattr(grpc_client, "_grpc_call", fake_call)
    invoke_result = grpc_client._invoke_unary_method(
        "127.0.0.1",
        50051,
        timeout=1.0,
        use_tls=False,
        protocol_flavor="grpc",
        authorization="Bearer token",
        metadata=[("x-test", "1")],
        descriptor_bytes=descriptor_bytes,
        invoke_path="/grpc.health.v1.Health/Check",
        request_json={"service": "grpc.health.v1.Health"},
    )

    assert invoke_result["status"] == "ok"
    assert invoke_result["response"] == {"status": "SERVING"}
    assert invoke_result["request"] == {"service": "grpc.health.v1.Health"}
    assert invoke_result["metadata"] == [{"key": "x-test", "value": "1"}]
    assert seen["authorization"] == "Bearer token"
    assert seen["metadata"] == [("x-test", "1")]

    streaming_result = grpc_client._invoke_unary_method(
        "127.0.0.1",
        50051,
        timeout=1.0,
        use_tls=False,
        protocol_flavor="grpc",
        authorization=None,
        metadata=[],
        descriptor_bytes=descriptor_bytes,
        invoke_path="/grpc.health.v1.Health/Watch",
        request_json={},
    )
    assert streaming_result["status"] == "unsupported"
    assert streaming_result["error"] == "unsupported streaming method"

    openapi = grpc_client._generate_openapi_document(descriptor_bytes)
    operation = openapi["paths"]["/grpc.health.v1.Health/Check"]["post"]
    assert operation["x-grpc-service"] == "grpc.health.v1.Health"
    assert operation["x-grpc-method"] == "Check"
    assert operation["x-grpc-streaming"] == {"client": False, "server": False}


def test_descriptor_helpers_dedup_protoset_and_error_normalization(tmp_path, monkeypatch) -> None:
    fd = descriptor_pb2.FileDescriptorProto()
    fd.ParseFromString(grpc_health_pb2.DESCRIPTOR.serialized_pb)
    descriptor_set = descriptor_pb2.FileDescriptorSet(file=[fd, fd])
    protoset = tmp_path / "health.protoset"
    protoset.write_bytes(descriptor_set.SerializeToString())

    loaded = grpc_client._descriptor_bytes_from_protoset(str(protoset))
    assert loaded == [fd.SerializeToString(), fd.SerializeToString()]
    assert grpc_client._dedup_descriptor_bytes(loaded) == [fd.SerializeToString()]

    def boom(*_args, **_kwargs):
        raise TimeoutError("timed out")

    monkeypatch.setattr(grpc_client, "_open_grpc_socket", boom)
    result = grpc_client._grpc_call(
        "127.0.0.1",
        50051,
        path="/grpc.health.v1.Health/Check",
        payload=b"",
        timeout=0.1,
        use_tls=False,
        authorization=None,
    )

    assert result["transport_ok"] is False
    assert result["error"] == "connection timeout"

    assert grpc_client._dedup_descriptor_bytes([b"", b"invalid"]) == []

    monkeypatch.setattr(
        grpc_client, "_compile_proto_files", lambda files, paths: [grpc_health_pb2.DESCRIPTOR.serialized_pb]
    )
    loaded = grpc_client._load_explicit_descriptor_bytes(["health.proto"], ["."], [str(protoset)])
    assert loaded == [fd.SerializeToString()]


def test_grpc_http2_call_success_path_with_fake_h2(monkeypatch) -> None:
    class FakeResponseReceived:
        def __init__(self) -> None:
            self.headers = [(b":status", b"200"), (b"content-type", b"application/grpc")]

    class FakeTrailersReceived:
        def __init__(self) -> None:
            self.headers = [(b"grpc-status", b"0"), (b"grpc-message", b"OK")]

    class FakeDataReceived:
        def __init__(self) -> None:
            self.data = grpc_client._encode_grpc_frame(b"response")
            self.flow_controlled_length = len(self.data)
            self.stream_id = 1

    class FakeStreamEnded:
        pass

    class FakeH2Connection:
        def __init__(self) -> None:
            self.sent_headers = []
            self.sent_data = []

        def initiate_connection(self) -> None:
            return None

        def data_to_send(self) -> bytes:
            return b""

        def get_next_available_stream_id(self) -> int:
            return 1

        def send_headers(self, stream_id, headers, end_stream=False):  # noqa: ANN001
            self.sent_headers.append((stream_id, headers, end_stream))

        def send_data(self, stream_id, data, end_stream=False):  # noqa: ANN001
            self.sent_data.append((stream_id, data, end_stream))

        def receive_data(self, _chunk: bytes):  # noqa: ANN001
            return [FakeResponseReceived(), FakeDataReceived(), FakeTrailersReceived(), FakeStreamEnded()]

        def acknowledge_received_data(self, *_args) -> None:  # noqa: ANN002
            return None

    class FakeSocket:
        def __init__(self) -> None:
            self.recv_calls = 0
            self.sent = []
            self.closed = False

        def sendall(self, data: bytes) -> None:
            self.sent.append(data)

        def recv(self, _size: int) -> bytes:
            self.recv_calls += 1
            return b"server-bytes" if self.recv_calls == 1 else b""

        def close(self) -> None:
            self.closed = True

    fake_sock = FakeSocket()
    monkeypatch.setattr(grpc_client, "H2Connection", FakeH2Connection)
    monkeypatch.setattr(grpc_client, "ResponseReceived", FakeResponseReceived)
    monkeypatch.setattr(grpc_client, "TrailersReceived", FakeTrailersReceived)
    monkeypatch.setattr(grpc_client, "DataReceived", FakeDataReceived)
    monkeypatch.setattr(grpc_client, "StreamEnded", FakeStreamEnded)
    monkeypatch.setattr(grpc_client, "_open_grpc_socket", lambda *_a, **_k: fake_sock)

    result = grpc_client._grpc_call(
        "127.0.0.1",
        50051,
        path="/demo.Service/Call",
        payload=b"request",
        timeout=1.0,
        use_tls=False,
        authorization="Bearer token",
        metadata=[("x-meta", "1")],
    )

    assert result["transport_ok"] is True
    assert result["is_grpc"] is True
    assert result["http_status"] == 200
    assert result["grpc_status"] == 0
    assert result["messages"] == [b"response"]
    assert fake_sock.closed is True


def test_grpc_http2_session_reuses_socket_streams_and_brackets_ipv6(monkeypatch) -> None:
    class FakeResponseReceived:
        def __init__(self, stream_id: int) -> None:
            self.stream_id = stream_id
            self.headers = [(b":status", b"200"), (b"content-type", b"application/grpc")]

    class FakeTrailersReceived:
        def __init__(self, stream_id: int) -> None:
            self.stream_id = stream_id
            self.headers = [(b"grpc-status", b"0")]

    class FakeDataReceived:
        def __init__(self, stream_id: int) -> None:
            self.stream_id = stream_id
            self.data = grpc_client._encode_grpc_frame(f"response-{stream_id}".encode())
            self.flow_controlled_length = len(self.data)

    class FakeStreamEnded:
        def __init__(self, stream_id: int) -> None:
            self.stream_id = stream_id

    class FakeH2Connection:
        instances: list[FakeH2Connection] = []

        def __init__(self) -> None:
            self.next_stream_id = 1
            self.current_stream_id = 0
            self.sent_headers: list[tuple[int, list[tuple[str, str]], bool]] = []
            self.initiated = 0
            self.closed = 0
            self.__class__.instances.append(self)

        def initiate_connection(self) -> None:
            self.initiated += 1

        def close_connection(self) -> None:
            self.closed += 1

        def data_to_send(self) -> bytes:
            return b""

        def get_next_available_stream_id(self) -> int:
            stream_id = self.next_stream_id
            self.next_stream_id += 2
            return stream_id

        def send_headers(self, stream_id, headers, end_stream=False):  # noqa: ANN001
            self.current_stream_id = stream_id
            self.sent_headers.append((stream_id, headers, end_stream))

        def send_data(self, _stream_id, _data, end_stream=False):  # noqa: ANN001
            assert end_stream is True

        def receive_data(self, _chunk: bytes):  # noqa: ANN001
            stream_id = self.current_stream_id
            return [
                FakeResponseReceived(stream_id),
                FakeDataReceived(stream_id),
                FakeTrailersReceived(stream_id),
                FakeStreamEnded(stream_id),
            ]

        def acknowledge_received_data(self, *_args) -> None:  # noqa: ANN002
            return None

    class FakeSocket:
        def __init__(self) -> None:
            self.closed = False
            self.timeouts: list[float] = []

        def settimeout(self, timeout: float) -> None:
            self.timeouts.append(timeout)

        def sendall(self, _data: bytes) -> None:
            return None

        def recv(self, _size: int) -> bytes:
            return b"server-bytes"

        def close(self) -> None:
            self.closed = True

    fake_sock = FakeSocket()
    open_calls: list[tuple[str, int]] = []

    def fake_open(host: str, port: int, *_args, **_kwargs):
        open_calls.append((host, port))
        return fake_sock

    monkeypatch.setattr(grpc_client, "H2Connection", FakeH2Connection)
    monkeypatch.setattr(grpc_client, "ResponseReceived", FakeResponseReceived)
    monkeypatch.setattr(grpc_client, "TrailersReceived", FakeTrailersReceived)
    monkeypatch.setattr(grpc_client, "DataReceived", FakeDataReceived)
    monkeypatch.setattr(grpc_client, "StreamEnded", FakeStreamEnded)
    monkeypatch.setattr(grpc_client, "_open_grpc_socket", fake_open)

    with grpc_client._GrpcH2Session("2001:db8::1", 50051, timeout=1.0, use_tls=False) as session:
        first = grpc_client._grpc_call(
            "2001:db8::1",
            50051,
            path="/demo.Service/First",
            payload=b"one",
            timeout=1.0,
            use_tls=False,
            authorization=None,
            session=session,
        )
        second = grpc_client._grpc_call(
            "2001:db8::1",
            50051,
            path="/demo.Service/Second",
            payload=b"two",
            timeout=2.0,
            use_tls=False,
            authorization=None,
            session=session,
        )
        assert fake_sock.closed is False

    connection = FakeH2Connection.instances[0]
    assert first["messages"] == [b"response-1"]
    assert second["messages"] == [b"response-3"]
    assert open_calls == [("2001:db8::1", 50051)]
    assert connection.initiated == 1
    assert [item[0] for item in connection.sent_headers] == [1, 3]
    assert [(":authority", "[2001:db8::1]:50051")] == [
        header for header in connection.sent_headers[0][1] if header[0] == ":authority"
    ]
    assert fake_sock.timeouts == [2.0]
    assert fake_sock.closed is True


def test_grpc_web_call_success_and_helpers(monkeypatch, tmp_path) -> None:
    trailer = b"grpc-status: 0\r\ngrpc-message: OK\r\n"
    body = b"\x00" + (3).to_bytes(4, "big") + b"abc" + b"\x80" + len(trailer).to_bytes(4, "big") + trailer
    response = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: application/grpc-web+proto\r\n" + f"Content-Length: {len(body)}\r\n\r\n".encode("ascii") + body
    )

    class FakeSocket:
        def __init__(self) -> None:
            self.sent = b""
            self.done = False
            self.closed = False

        def sendall(self, data: bytes) -> None:
            self.sent += data

        def recv(self, _size: int) -> bytes:
            if self.done:
                return b""
            self.done = True
            return response

        def close(self) -> None:
            self.closed = True

    fake_sock = FakeSocket()
    monkeypatch.setattr(grpc_client, "_open_http_socket", lambda *_a, **_k: fake_sock)
    result = grpc_client._grpc_web_call(
        "127.0.0.1",
        8080,
        path="/grpc.health.v1.Health/Check",
        payload=b"",
        timeout=1.0,
        use_tls=False,
        authorization=None,
        metadata=[("x-test", "1")],
    )

    assert result["is_grpc_web"] is True
    assert result["grpc_status"] == 0
    assert result["messages"] == [b"abc"]
    assert b"X-Grpc-Web: 1" in fake_sock.sent
    assert fake_sock.closed is True

    data_file = tmp_path / "payload.json"
    data_file.write_text('{"service":"demo"}', encoding="utf-8")
    assert grpc_client._parse_json_payload_source("@" + str(data_file)) == {"service": "demo"}
    assert grpc_client._parse_json_payload_source(None) == {}
    assert grpc_client._parse_metadata_items(["x-token=abc"]) == [("x-token", "abc")]
    assert grpc_client._parse_metadata_items(["trace-bin=YWJjZA"]) == [("trace-bin", "YWJjZA==")]
    assert grpc_client._normalize_metadata([("trace-bin", b"raw\x00")]) == [("trace-bin", "cmF3AA==")]
    assert grpc_client._split_grpc_method_path("/pkg.Service/Method") == ("pkg.Service", "Method")
    with pytest.raises(ValueError, match="JSON object"):
        grpc_client._parse_json_payload_source("[1]")
    with pytest.raises(ValueError, match="key=value"):
        grpc_client._parse_metadata_items(["broken"])
    with pytest.raises(ValueError, match="invalid metadata key"):
        grpc_client._parse_metadata_items(["bad key=value"])
    with pytest.raises(ValueError, match="pseudo headers"):
        grpc_client._parse_metadata_items([":path=/x"])
    with pytest.raises(ValueError, match="reserved header"):
        grpc_client._parse_metadata_items(["authorization=Bearer x"])
    with pytest.raises(ValueError, match="CR or LF"):
        grpc_client._parse_metadata_items(["x-token=line1\r\nInjected: yes"])
    with pytest.raises(ValueError, match="CR or LF"):
        grpc_client._parse_metadata_items(["x-token\r=value"])
    with pytest.raises(ValueError, match="printable ASCII"):
        grpc_client._parse_metadata_items(["x-token=\x00"])
    with pytest.raises(ValueError, match="valid base64"):
        grpc_client._parse_metadata_items(["trace-bin=not%base64"])
    with pytest.raises(ValueError, match="cannot contain bytes"):
        grpc_client._normalize_metadata([("x-token", b"raw")])
    with pytest.raises(ValueError, match="/package.Service/Method"):
        grpc_client._split_grpc_method_path("pkg.Service/Method")
    written = grpc_client._write_openapi_document(
        str(tmp_path / "openapi.json"), [grpc_health_pb2.DESCRIPTOR.serialized_pb]
    )
    assert written >= 1


def test_grpc_call_revalidates_metadata_before_opening_socket(monkeypatch) -> None:
    def unexpected_open(*_args, **_kwargs):
        raise AssertionError("invalid metadata must be rejected before network I/O")

    monkeypatch.setattr(grpc_client, "_open_grpc_socket", unexpected_open)
    result = grpc_client._grpc_call(
        "127.0.0.1",
        50051,
        path="/demo.Service/Call",
        payload=b"",
        timeout=1.0,
        use_tls=False,
        authorization=None,
        metadata=[("x-token", "safe\nInjected: yes")],
    )

    assert result["transport_ok"] is False
    assert result["error"] == "gRPC metadata values cannot contain CR or LF"


@pytest.mark.parametrize("use_grpc_web", [False, True])
def test_grpc_calls_reject_unsafe_authorization_before_network_io(monkeypatch, use_grpc_web: bool) -> None:
    def unexpected_open(*_args, **_kwargs):
        raise AssertionError("invalid authorization metadata must be rejected before network I/O")

    result: grpc_client._GrpcWebCallResult | grpc_client._GrpcCallResult
    if use_grpc_web:
        monkeypatch.setattr(grpc_client, "_open_http_socket", unexpected_open)
        result = grpc_client._grpc_web_call(
            "127.0.0.1",
            8080,
            path="/demo.Service/Call",
            payload=b"",
            timeout=1.0,
            use_tls=False,
            authorization="Bearer safe\r\nInjected: yes",
        )
    else:
        monkeypatch.setattr(grpc_client, "_open_grpc_socket", unexpected_open)
        result = grpc_client._grpc_call(
            "127.0.0.1",
            50051,
            path="/demo.Service/Call",
            payload=b"",
            timeout=1.0,
            use_tls=False,
            authorization="Bearer safe\r\nInjected: yes",
        )

    assert result["transport_ok"] is False
    assert result["error"] == "gRPC authorization metadata cannot contain CR or LF"


def test_grpc_error_parsing_and_stream_reset_branches(monkeypatch) -> None:
    assert grpc_client._friendly_error_text("[Errno 61] Connection refused").startswith("connection refused")
    assert grpc_client._friendly_error_from_exception(TimeoutError("timed out")) == "connection timeout"

    status, headers, body, error = grpc_client._parse_http1_response(b"HTTP/1.1 nope\r\nX-Test: yes\r\n\r\nbody")
    assert status is None
    assert headers == {"x-test": "yes"}
    assert body == b"body"
    assert error is None

    messages, trailers, error = grpc_client._decode_grpc_web_frames(b"abcd")
    assert messages == []
    assert trailers == {}
    assert error == "trailing bytes after gRPC-Web frames"

    class FakeResponseReceived:
        headers = [(b":status", b"not-int"), (b"content-type", b"text/plain")]

    class FakeTrailersReceived:
        headers = [(b"grpc-status", b"not-int"), (b"grpc-message", b"bad status")]

    class FakeStreamReset:
        error_code = 8

    class FakeH2Connection:
        def initiate_connection(self) -> None:
            return None

        def data_to_send(self) -> bytes:
            return b""

        def get_next_available_stream_id(self) -> int:
            return 1

        def send_headers(self, *_args, **_kwargs) -> None:
            return None

        def send_data(self, *_args, **_kwargs) -> None:
            return None

        def receive_data(self, _chunk: bytes):  # noqa: ANN001
            return [FakeResponseReceived(), FakeTrailersReceived(), FakeStreamReset()]

    class FakeSocket:
        def __init__(self) -> None:
            self.calls = 0
            self.closed = False

        def sendall(self, _data: bytes) -> None:
            return None

        def recv(self, _size: int) -> bytes:
            self.calls += 1
            return b"server-bytes" if self.calls == 1 else b""

        def close(self) -> None:
            self.closed = True

    fake_sock = FakeSocket()
    monkeypatch.setattr(grpc_client, "H2Connection", FakeH2Connection)
    monkeypatch.setattr(grpc_client, "ResponseReceived", FakeResponseReceived)
    monkeypatch.setattr(grpc_client, "TrailersReceived", FakeTrailersReceived)
    monkeypatch.setattr(grpc_client, "StreamReset", FakeStreamReset)
    monkeypatch.setattr(grpc_client, "_open_grpc_socket", lambda *_a, **_k: fake_sock)

    result = grpc_client._grpc_call(
        "127.0.0.1",
        50051,
        path="/demo.Service/Call",
        payload=b"",
        timeout=1.0,
        use_tls=False,
        authorization=None,
    )

    assert result["http_status"] is None
    assert result["grpc_status"] is None
    assert result["error"] == "stream reset by peer (code=8)"
    assert fake_sock.closed is True


def test_grpc_web_error_and_invoke_branches(monkeypatch) -> None:
    class FakeSocket:
        def __init__(self, response: bytes) -> None:
            self.response = response
            self.done = False
            self.closed = False

        def sendall(self, _data: bytes) -> None:
            return None

        def recv(self, _size: int) -> bytes:
            if self.done:
                return b""
            self.done = True
            return self.response

        def close(self) -> None:
            self.closed = True

    truncated_sock = FakeSocket(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n")
    monkeypatch.setattr(grpc_client, "_open_http_socket", lambda *_a, **_k: truncated_sock)
    truncated = grpc_client._grpc_web_call(
        "127.0.0.1",
        8080,
        path="/demo.Service/Call",
        payload=b"",
        timeout=1.0,
        use_tls=False,
        authorization=None,
    )
    assert truncated["error"] == "truncated HTTP response"
    assert truncated["is_grpc_web"] is False

    bad_status_body = b"\x00" + (0).to_bytes(4, "big")
    bad_status_response = (
        b"HTTP/1.1 200 OK\r\nContent-Type: application/grpc-web+proto\r\nGrpc-Status: bad\r\n\r\n" + bad_status_body
    )
    monkeypatch.setattr(grpc_client, "_open_http_socket", lambda *_a, **_k: FakeSocket(bad_status_response))
    bad_status = grpc_client._grpc_web_call(
        "127.0.0.1",
        8080,
        path="/demo.Service/Call",
        payload=b"",
        timeout=1.0,
        use_tls=False,
        authorization="Bearer token",
    )
    assert bad_status["grpc_status"] is None
    assert bad_status["is_grpc_web"] is True

    response = grpc_health_pb2.HealthCheckResponse(status=grpc_health_pb2.HealthCheckResponse.SERVING)
    monkeypatch.setattr(
        grpc_client,
        "_grpc_web_call",
        lambda *_a, **_k: {
            "grpc_status": 0,
            "grpc_message": "",
            "messages": [response.SerializeToString()],
            "error": None,
        },
    )
    invoked = grpc_client._invoke_unary_method(
        "127.0.0.1",
        8080,
        timeout=1.0,
        use_tls=False,
        protocol_flavor="grpc-web",
        authorization=None,
        metadata=[],
        descriptor_bytes=[grpc_health_pb2.DESCRIPTOR.serialized_pb],
        invoke_path="/grpc.health.v1.Health/Check",
        request_json={},
    )
    assert invoked["status"] == "ok"
    assert invoked["response"] == {"status": "SERVING"}

    monkeypatch.setattr(
        grpc_client,
        "_grpc_call",
        lambda *_a, **_k: {"grpc_status": 5, "grpc_message": "missing", "messages": [], "error": None},
    )
    grpc_error = grpc_client._invoke_unary_method(
        "127.0.0.1",
        50051,
        timeout=1.0,
        use_tls=False,
        protocol_flavor="grpc",
        authorization=None,
        metadata=[],
        descriptor_bytes=[grpc_health_pb2.DESCRIPTOR.serialized_pb],
        invoke_path="/grpc.health.v1.Health/Check",
        request_json={},
    )
    assert grpc_error["status"] == "grpc_error"
    assert grpc_error["error"] == "missing"

    invalid = grpc_client._invoke_unary_method(
        "127.0.0.1",
        50051,
        timeout=1.0,
        use_tls=False,
        protocol_flavor="grpc",
        authorization=None,
        metadata=[],
        descriptor_bytes=[],
        invoke_path="/missing.Service/Call",
        request_json={},
    )
    assert invalid["status"] == "error"
    assert "missing.Service" in str(invalid["error"])


def test_grpc_h2_chunks_large_request_at_frame_and_flow_control_limits(monkeypatch: pytest.MonkeyPatch) -> None:
    class _FakeConnection:
        max_outbound_frame_size = 1024

        def __init__(self) -> None:
            self.window = 4096
            self.sent_data: list[tuple[bytes, bool]] = []
            self.window_updates = 0

        def get_next_available_stream_id(self) -> int:
            return 1

        def send_headers(self, *_args, **_kwargs) -> None:
            return None

        def local_flow_control_window(self, _stream_id: int) -> int:
            return self.window

        def send_data(self, _stream_id: int, data: bytes, *, end_stream: bool) -> None:
            assert len(data) <= self.max_outbound_frame_size
            assert len(data) <= self.window
            self.sent_data.append((bytes(data), end_stream))
            self.window -= len(data)

        def data_to_send(self) -> bytes:
            return b"pending"

        def receive_data(self, data: bytes):
            if data == b"window":
                self.window = 4096
                self.window_updates += 1
                return []
            event = grpc_client.StreamEnded(stream_id=1)
            return [event]

        def acknowledge_received_data(self, *_args) -> None:
            return None

    class _FakeSocket:
        def __init__(self, conn: _FakeConnection) -> None:
            self.conn = conn
            self.sent: list[bytes] = []

        def settimeout(self, _timeout: float) -> None:
            return None

        def sendall(self, data: bytes) -> None:
            self.sent.append(bytes(data))

        def recv(self, _size: int) -> bytes:
            return b"window" if self.conn.window == 0 else b"end"

        def close(self) -> None:
            return None

    conn = _FakeConnection()
    sock = _FakeSocket(conn)
    session = grpc_client._GrpcH2Session("127.0.0.1", 50051, timeout=1.0, use_tls=False)
    monkeypatch.setattr(session, "_ensure_connection", lambda _timeout: (sock, conn))
    payload = b"x" * 70_000
    session.call(path="/demo.Service/Call", payload=payload, authorization=None)
    framed = grpc_client._encode_grpc_frame(payload)
    assert b"".join(chunk for chunk, _end in conn.sent_data) == framed
    assert max(len(chunk) for chunk, _end in conn.sent_data) <= 1024
    assert conn.sent_data[-1][1] is True
    assert conn.window_updates > 0


def test_grpc_web_decodes_chunked_http_body(monkeypatch: pytest.MonkeyPatch) -> None:
    message_frame = b"\x00" + (3).to_bytes(4, "big") + b"abc"
    trailer = b"grpc-status: 0\r\n"
    trailer_frame = b"\x80" + len(trailer).to_bytes(4, "big") + trailer
    grpc_body = message_frame + trailer_frame
    chunks = b"".join(
        f"{len(part):x};test=yes\r\n".encode() + part + b"\r\n" for part in (grpc_body[:7], grpc_body[7:])
    )
    raw_response = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: application/grpc-web+proto\r\n"
        b"Transfer-Encoding: chunked\r\n\r\n" + chunks + b"0\r\nX-Trailer: ignored\r\n\r\n"
    )

    class _FakeSocket:
        def __init__(self) -> None:
            self.response = raw_response

        def sendall(self, _data: bytes) -> None:
            return None

        def recv(self, _size: int) -> bytes:
            response, self.response = self.response, b""
            return response

        def close(self) -> None:
            return None

    monkeypatch.setattr(grpc_client, "_open_http_socket", lambda *_a, **_k: _FakeSocket())
    result = grpc_client._grpc_web_call(
        "127.0.0.1",
        8080,
        path="/demo.Service/Call",
        payload=b"",
        timeout=1.0,
        use_tls=False,
        authorization=None,
    )
    assert result["messages"] == [b"abc"]
    assert result["grpc_status"] == 0
    assert result["error"] is None


def test_grpc_tls_context_loads_ca_and_client_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: dict[str, object] = {}

    class _FakeContext:
        check_hostname = True
        verify_mode = grpc_client.ssl.CERT_REQUIRED

        def load_cert_chain(self, *, certfile: str, keyfile: str) -> None:
            calls["cert_chain"] = (certfile, keyfile)

        def set_alpn_protocols(self, protocols: list[str]) -> None:
            calls["alpn"] = protocols

    def _fake_default_context(*, cafile: str | None = None):
        calls["cafile"] = cafile
        return _FakeContext()

    monkeypatch.setattr(grpc_client.ssl, "create_default_context", _fake_default_context)
    context = grpc_client._grpc_ssl_context(
        grpc_client.GrpcTlsConfig(ca_file="ca.pem", cert_file="client.pem", key_file="client.key"),
        alpn_h2=True,
    )
    assert context is not None
    assert calls == {
        "cafile": "ca.pem",
        "cert_chain": ("client.pem", "client.key"),
        "alpn": ["h2"],
    }


def test_grpc_tls_server_name_override_reaches_native_and_web_sockets(monkeypatch: pytest.MonkeyPatch) -> None:
    server_names: list[str] = []

    class _FakeSocket:
        def settimeout(self, _timeout: float) -> None:
            return None

        def selected_alpn_protocol(self) -> str:
            return "h2"

        def close(self) -> None:
            return None

    class _FakeContext:
        def wrap_socket(self, sock: _FakeSocket, *, server_hostname: str) -> _FakeSocket:
            server_names.append(server_hostname)
            return sock

    monkeypatch.setattr(grpc_client.socket, "create_connection", lambda *_a, **_k: _FakeSocket())
    monkeypatch.setattr(grpc_client, "_grpc_ssl_context", lambda *_a, **_k: _FakeContext())
    tls_config = grpc_client.GrpcTlsConfig(server_name="grpc.service.internal")

    grpc_client._open_grpc_socket("192.0.2.10", 50051, 1.0, use_tls=True, tls_config=tls_config)
    grpc_client._open_http_socket("192.0.2.10", 8443, 1.0, use_tls=True, tls_config=tls_config)

    assert server_names == ["grpc.service.internal", "grpc.service.internal"]


@pytest.mark.parametrize("framing", ["content-length", "chunked"])
def test_grpc_web_stops_reading_when_http_body_is_complete(
    monkeypatch: pytest.MonkeyPatch,
    framing: str,
) -> None:
    trailer = b"grpc-status: 0\r\n"
    grpc_body = b"\x00" + (3).to_bytes(4, "big") + b"abc" + b"\x80" + len(trailer).to_bytes(4, "big") + trailer
    if framing == "content-length":
        raw_response = (
            b"HTTP/1.1 200 OK\r\nContent-Type: application/grpc-web+proto\r\n"
            + f"Content-Length: {len(grpc_body)}\r\n\r\n".encode("ascii")
            + grpc_body
        )
    else:
        raw_response = (
            b"HTTP/1.1 200 OK\r\nContent-Type: application/grpc-web+proto\r\n"
            b"Transfer-Encoding: chunked\r\n\r\n"
            + f"{len(grpc_body):x}\r\n".encode("ascii")
            + grpc_body
            + b"\r\n0\r\n\r\n"
        )

    class _KeepAliveSocket:
        recv_calls = 0

        def sendall(self, _data: bytes) -> None:
            return None

        def recv(self, _size: int) -> bytes:
            self.recv_calls += 1
            if self.recv_calls > 1:
                raise TimeoutError("reader incorrectly waited for EOF")
            return raw_response

        def close(self) -> None:
            return None

    fake_socket = _KeepAliveSocket()
    monkeypatch.setattr(grpc_client, "_open_http_socket", lambda *_a, **_k: fake_socket)
    result = grpc_client._grpc_web_call(
        "127.0.0.1",
        8080,
        path="/demo.Service/Call",
        payload=b"",
        timeout=1.0,
        use_tls=False,
        authorization=None,
    )

    assert fake_socket.recv_calls == 1
    assert result["messages"] == [b"abc"]
    assert result["grpc_status"] == 0
    assert result["error"] is None
