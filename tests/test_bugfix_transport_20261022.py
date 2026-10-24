"""Boundary regressions for confirmed transport, discovery and credential bugs."""

from __future__ import annotations

import socket
from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from redposture_core import stage_spray
from redposture_core.cli_args import parse_args
from redposture_core.clients import grpc, http_api, http_session
from redposture_core.exporters import discovery_logic


@pytest.mark.parametrize(
    ("size_token", "data"),
    [
        (b"", b""),
        (b"+0", b""),
        (b"-0", b""),
        (b"+1", b"x"),
        (b"0x1", b"x"),
        (b"0X1", b"x"),
        (b"1_0", b"x" * 16),
        (b" 1", b"x"),
        (b"\t1", b"x"),
        (b"1 ", b"x"),
        (b"1\t", b"x"),
        (b"\v1", b"x"),
    ],
)
def test_complete_chunk_sizes_require_nonempty_hex_digits(size_token: bytes, data: bytes) -> None:
    wire = size_token + b"\r\n" + (data + b"\r\n0\r\n" if data else b"") + b"\r\n"
    with pytest.raises(ValueError, match="malformed chunked body: invalid chunk size"):
        http_api._decode_chunked_body(wire)


@pytest.mark.parametrize("size_token", [b"", b"+0", b"-0", b"0x1", b"1_0", b" 1", b"1 "])
def test_partial_chunks_stop_before_invalid_size_and_keep_preceding_payload(size_token: bytes) -> None:
    wire = b"2\r\nok\r\n" + size_token + b"\r\nx\r\n0\r\n\r\n"
    assert http_api._decode_chunked_body(wire, allow_partial=True) == b"ok"


@pytest.mark.parametrize("header", [b"a", b"A", b"000a", b'a;name="value"', b"A \t; name=value"])
def test_chunk_sizes_accept_hex_case_leading_zeros_and_extensions(header: bytes) -> None:
    wire = header + b"\r\n0123456789\r\n00;done=yes\r\nX-Trailer: yes\r\n\r\n"
    assert http_api._decode_chunked_body(wire) == b"0123456789"
    assert http_api._decode_chunked_body(wire, allow_partial=True) == b"0123456789"


@pytest.mark.parametrize("trailers", [b"\r\n", b"X-One: yes\r\nX-Two: yes\r\n\r\n"])
def test_complete_chunk_framing_rejects_every_truncated_prefix(trailers: bytes) -> None:
    wire = b"2;name=value\r\nok\r\n0\r\n" + trailers
    assert http_api._decode_chunked_body(wire) == b"ok"
    for end in range(len(wire)):
        with pytest.raises(ValueError, match="malformed chunked body"):
            http_api._decode_chunked_body(wire[:end])


@pytest.mark.parametrize("suffix", [b"0\r\n\r\n", b"X\r\n0\r\n\r\n", b"\rX0\r\n\r\n"])
def test_complete_chunks_require_exact_data_delimiter(suffix: bytes) -> None:
    with pytest.raises(ValueError, match="malformed chunked body"):
        http_api._decode_chunked_body(b"2\r\nok" + suffix)


def test_cap_limited_chunks_keep_available_payload_without_complete_trailers() -> None:
    assert http_api._decode_chunked_body(b"4\r\nab", allow_partial=True) == b"ab"
    assert http_api._decode_chunked_body(b"2\r\nok\r\n0\r\nX: y", allow_partial=True) == b"ok"


@pytest.mark.parametrize("opener", [grpc._open_grpc_socket, grpc._open_http_socket])
def test_grpc_context_setup_failure_closes_real_socket(
    monkeypatch: pytest.MonkeyPatch, opener: Callable[..., socket.socket]
) -> None:
    raw, peer = socket.socketpair()
    try:
        monkeypatch.setattr(grpc.socket, "create_connection", lambda *_args, **_kwargs: raw)
        monkeypatch.setattr(grpc, "_grpc_ssl_context", Mock(side_effect=ValueError("bad certificate")))
        with pytest.raises(ValueError, match="bad certificate"):
            opener("target", 443, 1, use_tls=True)
        assert raw.fileno() == -1
        assert peer.recv(1) == b""
    finally:
        raw.close()
        peer.close()


def test_grpc_web_skips_fragmented_informational_chain_before_final_body(monkeypatch: pytest.MonkeyPatch) -> None:
    body = b"\x80\x00\x00\x00\x10grpc-status: 0\r\n"
    prefix = b"HTTP/1.1 100 Continue\r\nContent-Length: 0\r\n\r\nHTTP/1.1 103 Early Hints\r\n\r\n"
    final = b"HTTP/1.1 200 OK\r\nContent-Type: application/grpc-web+proto\r\nContent-Length: 21\r\n\r\n" + body
    wire = prefix + final
    for end in range(1, len(wire)):
        sock = Mock()
        # A reader must stop after the final body, even when EOF never arrives.
        sock.recv.side_effect = [wire[:end], wire[end:], TimeoutError("waited past final response")]
        monkeypatch.setattr(grpc, "_open_http_socket", Mock(return_value=sock))
        result = grpc._grpc_web_call(
            "target", 443, path="/call", payload=b"", timeout=1, use_tls=True, authorization=None
        )
        assert result["http_status"] == 200, end
        assert result["is_grpc_web"] and result["grpc_status"] == 0 and result["error"] is None, end


def test_grpc_informational_without_final_response_is_incomplete() -> None:
    raw = b"HTTP/1.1 100 Continue\r\nContent-Length: 0\r\n\r\n"
    assert grpc._http1_response_complete(raw) is False
    status, _headers, _body, error = grpc._parse_http1_response(raw)
    assert status is None and error == "truncated HTTP response"


def test_grpc_switching_protocols_is_terminal_not_an_informational_prefix() -> None:
    raw = b"HTTP/1.1 101 Switching Protocols\r\nContent-Length: 0\r\n\r\nHTTP/1.1 200 OK\r\n\r\n"
    assert grpc._parse_http1_response(raw)[0] == 101


@pytest.mark.parametrize(("method", "attempts"), [("GET", 3), ("POST", 1)])
def test_pool_acquisition_timeout_obeys_safe_retry_policy(
    monkeypatch: pytest.MonkeyPatch, method: str, attempts: int
) -> None:
    acquisition = Mock(side_effect=TimeoutError("proxy timed out"))
    monkeypatch.setattr(http_session, "open_connection_via_proxy", acquisition)
    monkeypatch.setattr(http_session.time, "sleep", lambda _delay: None)
    pool = http_session.HttpSessionPool(timeout=1, retries=2, proxy=Mock())
    try:
        result = pool.request(method, "http://target/")
        assert result.status == 0 and result.error and "timed out" in result.error
        assert acquisition.call_count == attempts
        assert pool.stats()["retries"] == attempts - 1
        assert pool.stats()["connections"] == 0
    finally:
        pool.close()


@pytest.mark.parametrize(
    ("score", "fingerprint", "confirmed"), [(25, "", False), (49, "", False), (50, "", True), (25, "build", True)]
)
def test_single_weak_exporter_respects_confidence_or_fingerprint(score: int, fingerprint: str, confirmed: bool) -> None:
    candidate = {"name": "exporter", "score": score, "strong_count": 0}
    result, _source, _reason = discovery_logic.resolve_best_exporter_candidate(
        host="target",
        port=9100,
        candidates=[candidate],
        exporters_by_name={"exporter": {"fingerprint_vars": ["build"]}},
        timeout=1,
        retries=0,
        fetch_fingerprint_bodies_fn=lambda *_: (fingerprint, ""),
    )
    assert (result is not None) is confirmed


def test_spray_cli_empty_password_matches_empty_password_file(tmp_path: Path) -> None:
    users = tmp_path / "users"
    users.write_text("qa\nother\n")
    passwords = tmp_path / "passwords"
    passwords.write_text("\n")
    argv = ["spray", "-t", "localhost", "--modules", "airflow", "-u", f"@{users}"]
    literal = stage_spray.load_candidates(parse_args([*argv, "-p", ""]))
    from_file = stage_spray.load_candidates(parse_args([*argv, "-p", f"@{passwords}"]))
    expected = [stage_spray.Candidate("pair", "qa", ""), stage_spray.Candidate("pair", "other", "")]
    assert list(literal) == list(from_file) == expected
    assert [literal[index] for index in range(len(literal))] == expected


@pytest.mark.parametrize(("users", "passwords"), [("qa", None), (None, ""), (None, "secret"), ("", "secret")])
def test_spray_missing_partner_still_rejected(users: str | None, passwords: str | None) -> None:
    with pytest.raises(ValueError, match="supplied together"):
        stage_spray.load_candidates(SimpleNamespace(users=users, passwords=passwords, pairs=None, tokens=None))
