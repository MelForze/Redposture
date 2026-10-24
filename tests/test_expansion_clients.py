"""gRPC client validation, framing, session cleanup, and partial evidence."""

from __future__ import annotations

from typing import Any
from unittest.mock import Mock

import pytest

from redposture_core.clients import grpc
from redposture_core.proto import grpc_health_pb2, grpc_reflection_pb2


@pytest.mark.parametrize(
    ("key", "value", "message"),
    [
        ("\rname", "x", "keys cannot contain CR or LF"),
        (" ", "x", "keys cannot be empty"),
        (":path", "x", "pseudo headers"),
        ("bad/key", "x", "invalid gRPC metadata key"),
        ("te", "x", "reserved header"),
        ("binary-bin", "é", "base64 encoded ASCII"),
        ("binary-bin", "\nAA", "cannot contain CR or LF"),
        ("binary-bin", "A", "valid base64"),
        ("binary-bin", "@@", "valid base64"),
        ("text", b"raw", "cannot contain bytes"),
        ("text", "\nvalue", "cannot contain CR or LF"),
        ("text", "é", "printable ASCII"),
        ("text", "\x00", "printable ASCII"),
    ],
)
def test_grpc_metadata_rejects_unserializable_or_protocol_control_values(key: str, value: Any, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        grpc._normalize_metadata([(key, value)])


@pytest.mark.parametrize("authorization", ["\x00", "é", "abc\nInjected: header"])
def test_grpc_authorization_rejects_non_printable_header_values(authorization: str) -> None:
    with pytest.raises(ValueError, match="metadata"):
        grpc._normalize_authorization(authorization)


def test_grpc_metadata_preserves_duplicate_keys_and_canonicalizes_binary_values() -> None:
    assert grpc._normalize_metadata(
        [(" X-ID ", "one"), ("x-id", "two"), ("trace-bin", "YQ"), ("trace-bin", b"\xff")]
    ) == [("x-id", "one"), ("x-id", "two"), ("trace-bin", "YQ=="), ("trace-bin", "/w==")]
    assert grpc._normalize_metadata([("authorization", "Bearer t")], reject_reserved=False) == [
        ("authorization", "Bearer t")
    ]
    assert grpc._grpc_authority("[::1]", 443) == "[::1]:443"


@pytest.mark.parametrize(
    ("suffix", "message"),
    [
        (b"\0\0\0\0\x04x", "truncated gRPC frame"),
        (b"\x01\0\0\0\x01x", "compressed gRPC payload is not supported"),
        (b"x", "trailing bytes after gRPC frames"),
    ],
)
def test_grpc_frame_failure_retains_previous_complete_messages(suffix: bytes, message: str) -> None:
    assert grpc._decode_grpc_frames(grpc._encode_grpc_frame(b"retained") + suffix) == ([b"retained"], message)


@pytest.mark.parametrize(
    ("payload", "message"),
    [
        (b"f", "incomplete chunk size"),
        (b"z\r\n", "invalid chunk size"),
        (b"2\r\nx", "truncated chunk"),
        (b"2\r\nokNO", "truncated chunk"),
        (b"0\r\nX-Trailer: value", "incomplete trailers"),
    ],
)
def test_grpc_http_chunk_decoder_rejects_malformed_complete_response(payload: bytes, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        grpc._decode_http1_chunked_body(payload)


@pytest.mark.parametrize(
    ("body", "complete"),
    [
        (b"", False),
        (b"z\r\n", True),
        (b"-1\r\n", True),
        (b"0\r\n", False),
        (b"0\r\n\r\n", True),
        (b"0\r\nX: y\r\n", False),
        (b"0\r\nX: y\r\n\r\n", True),
        (b"2\r\nx", False),
        (b"2\r\nokNO", True),
    ],
)
def test_grpc_chunk_completion_distinguishes_waiting_from_terminal_malformed_input(body: bytes, complete: bool) -> None:
    assert grpc._chunked_http_body_complete(body) is complete


@pytest.mark.parametrize("length", ["bad", "-1"])
def test_grpc_http_content_length_failure_is_terminal_and_explicit(length: str) -> None:
    raw = f"HTTP/1.1 200 OK\r\nContent-Length: {length}\r\n\r\nx".encode()
    assert grpc._http1_response_complete(raw) is True
    status, headers, body, error = grpc._parse_http1_response(raw)
    assert status == 200 and body == b"" and error == "malformed HTTP response: invalid Content-Length"
    assert headers == {"content-length": length}


@pytest.mark.parametrize("status", ["bad", "200"])
def test_grpc_call_finish_preserves_decoded_rows_and_trailer_error_precedence(status: str) -> None:
    result = grpc._new_grpc_call_result("h", 1, "/call", False)
    result["error"] = "earlier transport failure"
    grpc._finish_grpc_call_result(
        result,
        {":status": status, "grpc-status": "0", "grpc-message": "header"},
        {"grpc-status": "invalid", "grpc-message": "trailer"},
        grpc._encode_grpc_frame(b"retained") + b"x",
    )
    assert result["http_status"] == (None if status == "bad" else 200)
    assert result["grpc_status"] is None and result["grpc_message"] == "trailer"
    assert result["error"] == "earlier transport failure" and result["messages"] == [b"retained"]


@pytest.mark.parametrize("opener", [grpc._open_grpc_socket, grpc._open_http_socket])
@pytest.mark.parametrize("failure", ["wrap", "settimeout"])
def test_grpc_tls_setup_closes_the_socket_which_owns_failed_stage(
    monkeypatch: pytest.MonkeyPatch, opener: Any, failure: str
) -> None:
    raw, wrapped, context = Mock(), Mock(), Mock()
    wrapped.selected_alpn_protocol.return_value = "h2"
    context.wrap_socket.side_effect = OSError("TLS wrap failed") if failure == "wrap" else None
    context.wrap_socket.return_value = wrapped
    if failure == "settimeout":
        wrapped.settimeout.side_effect = OSError("timeout config failed")
    monkeypatch.setattr(grpc.socket, "create_connection", Mock(return_value=raw))
    monkeypatch.setattr(grpc, "_grpc_ssl_context", Mock(return_value=context))
    with pytest.raises(OSError, match="failed"):
        opener("target", 443, 1, use_tls=True, tls_config=grpc.GrpcTlsConfig(server_name="certificate.example"))
    context.wrap_socket.assert_called_once_with(raw, server_hostname="certificate.example")
    (raw if failure == "wrap" else wrapped).close.assert_called_once()


def test_grpc_alpn_mismatch_closes_wrapped_socket(monkeypatch: pytest.MonkeyPatch) -> None:
    raw, wrapped, context = Mock(), Mock(), Mock()
    context.wrap_socket.return_value = wrapped
    wrapped.selected_alpn_protocol.return_value = "http/1.1"
    monkeypatch.setattr(grpc.socket, "create_connection", Mock(return_value=raw))
    monkeypatch.setattr(grpc, "_grpc_ssl_context", Mock(return_value=context))
    with pytest.raises(OSError, match="expected h2"):
        grpc._open_grpc_socket("target", 443, 1, use_tls=True)
    wrapped.close.assert_called_once()


@pytest.mark.parametrize("opener", [grpc._open_grpc_socket, grpc._open_http_socket])
def test_grpc_tls_context_failure_closes_already_opened_tcp_socket(
    monkeypatch: pytest.MonkeyPatch, opener: Any
) -> None:
    raw = Mock()
    monkeypatch.setattr(grpc.socket, "create_connection", Mock(return_value=raw))
    monkeypatch.setattr(grpc, "_grpc_ssl_context", Mock(side_effect=ValueError("invalid client cert")))
    with pytest.raises(ValueError, match="invalid client cert"):
        opener("target", 443, 1, use_tls=True)
    raw.close.assert_called_once()


def test_grpc_session_failed_preface_closes_socket_and_can_open_fresh_connection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    failed, healthy = Mock(), Mock()
    failed.sendall.side_effect = OSError("preface interrupted")
    opening = Mock(side_effect=[failed, healthy])
    monkeypatch.setattr(grpc, "_open_grpc_socket", opening)
    conn = Mock()
    conn.data_to_send.return_value = b"preface"
    monkeypatch.setattr(grpc, "H2Connection", Mock(return_value=conn))
    client = grpc._GrpcH2Session("target", 443, timeout=1, use_tls=True)
    with pytest.raises(OSError, match="preface interrupted"):
        client._ensure_connection(1)
    failed.close.assert_called_once()
    assert client._sock is None and client._conn is None
    assert client._ensure_connection(2) == (healthy, conn)
    assert client._ensure_connection(3) == (healthy, conn)
    healthy.settimeout.assert_called_once_with(3)
    conn.close_connection.side_effect = OSError("peer closed")
    healthy.close.side_effect = OSError("already closed")
    client.close()
    client.close()
    assert client._sock is None and client._conn is None
    healthy.close.assert_called_once()
    with pytest.raises(OSError, match="session is closed"):
        client._ensure_connection(1)


@pytest.mark.parametrize("code", [7, 12, 16])
def test_reflection_embedded_error_overrides_outer_success_and_skips_malformed_messages(
    monkeypatch: pytest.MonkeyPatch, code: int
) -> None:
    response = grpc_reflection_pb2.ServerReflectionResponse()
    response.error_response.error_code = code
    response.error_response.error_message = "endpoint denied"
    call = grpc._GrpcCallResult(grpc_status=0, messages=[None, b"\xff", response.SerializeToString()], error=None)
    monkeypatch.setattr(grpc, "_reflection_call_with_fallback", Mock(return_value=(call, "v1")))
    for function in (grpc._reflection_list_services_call, grpc._reflection_capability_call):
        result = function("h", 1, timeout=1, use_tls=False, authorization=None)
        assert result["reflection_enabled"] is (False if code == 12 else None)
        assert result["embedded_error_code"] == code
        assert result["error"] == f"{code}:endpoint denied"


def test_health_unknown_enum_is_retained_as_numeric_value() -> None:
    response = grpc_health_pb2.HealthCheckResponse()
    response.status = 42
    assert grpc._parse_health_message(response.SerializeToString()) == "42"
    assert grpc._parse_health_message(b"") is None
    assert grpc._parse_health_message(b"\xff") is None


@pytest.mark.parametrize("informational", [100, 103])
def test_grpc_web_accepts_final_response_after_informational_headers(
    monkeypatch: pytest.MonkeyPatch, informational: int
) -> None:
    trailers = b"grpc-status: 0\r\n"
    body = b"\x80" + len(trailers).to_bytes(4, "big") + trailers
    raw = (
        f"HTTP/1.1 {informational} Informational\r\n\r\nHTTP/1.1 200 OK\r\nContent-Type: application/grpc-web+proto\r\nContent-Length: {len(body)}\r\n\r\n".encode()
        + body
    )
    sock = Mock()
    sock.recv.side_effect = [raw, b""]
    monkeypatch.setattr(grpc, "_open_http_socket", Mock(return_value=sock))
    result = grpc._grpc_web_call("target", 443, path="/call", payload=b"", timeout=1, use_tls=True, authorization=None)
    sock.close.assert_called_once()
    assert result["http_status"] == 200
    assert result["is_grpc_web"] is True and result["grpc_status"] == 0 and result["error"] is None
