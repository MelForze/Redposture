from __future__ import annotations

import struct

import pytest

from redposture_core.clients.zookeeper import _ZK_OP_SASL, _ZkClient
from redposture_core.clients.zookeeper_sasl import DigestMd5Client


def test_digest_md5_challenge_and_server_proof(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("redposture_core.clients.zookeeper_sasl.secrets.token_hex", lambda _n: "0123456789abcdef")
    client = DigestMd5Client("zk", "zookeeper")
    response = client.response(b'realm="zk",nonce="server123",qop="auth,auth-int",algorithm=md5-sess,charset=utf-8')
    assert b'username="zk"' in response
    assert b'digest-uri="zookeeper/zk-sasl-md5"' in response
    assert b"response=" in response
    assert client.expected_rspauth is not None
    client.verify_server(b"rspauth=" + client.expected_rspauth)
    with pytest.raises(ValueError, match="server proof mismatch"):
        client.verify_server(b"rspauth=00000000000000000000000000000000")


@pytest.mark.parametrize(
    "challenge",
    [b"", b'nonce="x",qop="auth-int"', b'nonce="x",nonce="y"', b'nonce="x",charset=latin-1'],
)
def test_digest_md5_rejects_unusable_challenge(challenge: bytes) -> None:
    with pytest.raises(ValueError):
        DigestMd5Client("u", "p").response(challenge)


def test_sasl_wire_exchange_is_bounded_and_checks_rspauth(monkeypatch: pytest.MonkeyPatch) -> None:
    requests: list[tuple[int, bytes]] = []
    client = _ZkClient("127.0.0.1", 2181, 1.0)

    def fake_request(opcode: int, payload: bytes) -> tuple[int, bytes]:
        requests.append((opcode, payload))
        if len(requests) == 1:
            challenge = b'nonce="server123",qop="auth",algorithm=md5-sess,charset=utf-8'
            return 0, struct.pack(">i", len(challenge)) + challenge
        # A malformed server proof must fail even if the wire header says OK.
        proof = b"rspauth=00000000000000000000000000000000"
        return 0, struct.pack(">i", len(proof)) + proof

    monkeypatch.setattr(client, "_request", fake_request)
    with pytest.raises(ValueError, match="server proof mismatch"):
        client.auth_sasl_digest("zk", "zookeeper")
    assert len(requests) == 2
    assert all(opcode == _ZK_OP_SASL for opcode, _payload in requests)
    assert requests[0][1] == b"\x00\x00\x00\x00"


def test_sasl_explicit_server_rejection_is_not_transport_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _ZkClient("127.0.0.1", 2181, 1.0)
    calls = 0

    def fake_request(_opcode: int, _payload: bytes) -> tuple[int, bytes]:
        nonlocal calls
        calls += 1
        if calls == 1:
            challenge = b'nonce="server123",qop="auth",algorithm=md5-sess,charset=utf-8'
            return 0, struct.pack(">i", len(challenge)) + challenge
        return -124, b""

    monkeypatch.setattr(client, "_request", fake_request)
    assert client.auth_sasl_digest("zk", "wrong") == (
        False,
        "authentication failed: SESSIONCLOSEDREQUIRESASLAUTH",
    )


def test_sasl_mechanism_not_offered_does_not_reject_password(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _ZkClient("127.0.0.1", 2181, 1.0)
    monkeypatch.setattr(client, "_request", lambda _opcode, _payload: (-124, b""))
    assert client.auth_sasl_digest("zk", "unknown") == (
        False,
        "SASL negotiation unavailable: SESSIONCLOSEDREQUIRESASLAUTH",
    )
