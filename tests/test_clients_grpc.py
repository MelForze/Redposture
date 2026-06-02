from __future__ import annotations

from google.protobuf import descriptor_pb2

from redposture_core.clients import grpc as grpc_client
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
    assert list_result["services"] == ["demo.Greeter", "grpc.health.v1.Health"]
    assert descriptor_result["descriptor_bytes"] == [grpc_health_pb2.DESCRIPTOR.serialized_pb]
    assert seen_paths == [
        "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo",
        "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo",
    ]


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


def test_grpc_http2_call_success_path_with_fake_h2(monkeypatch) -> None:  # type: ignore[no-untyped-def]
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


def test_grpc_web_call_success_and_helpers(monkeypatch, tmp_path) -> None:  # type: ignore[no-untyped-def]
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
    assert grpc_client._split_grpc_method_path("/pkg.Service/Method") == ("pkg.Service", "Method")
    written = grpc_client._write_openapi_document(
        str(tmp_path / "openapi.json"), [grpc_health_pb2.DESCRIPTOR.serialized_pb]
    )
    assert written >= 1
