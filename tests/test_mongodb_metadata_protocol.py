"""Independent SCRAM peer verifies client proof; framing/fault tests observe IO."""

from __future__ import annotations

import base64
import hashlib
import hmac
import struct
from typing import Any

import pytest
from bson import BSON, Binary, Int64
from pymongo.errors import OperationFailure

from redposture_core.clients.mongodb import MongoClientError
from redposture_core.clients.mongodb_metadata import MongoMetadataClient, MongoMetadataFallback, _saslprep


class Peer:
    def __init__(self, *, user="reader", password="pencil", mechanism="SCRAM-SHA-256", fault=None, empty_finish=False):
        self.user, self.password, self.mechanism = user, password, mechanism
        self.fault, self.empty_finish = fault, empty_finish
        self.commands: list[dict[str, Any]] = []
        self.incoming = bytearray()
        self.closed = 0
        self.bare = self.server_first = b""
        self.nonce = b""
        self.verified = False
        self.timeouts: list[float] = []

    def settimeout(self, value):
        self.timeouts.append(value)

    def sendall(self, packet):
        size, ident, _, opcode = struct.unpack("<iiii", packet[:16])
        assert size == len(packet) and opcode == 2013 and packet[16:21] == b"\0" * 5
        doc = BSON(packet[21:]).decode()
        self.commands.append(doc)
        response = self.reply(doc)
        body = (
            struct.pack(
                "<I",
                1
                if self.fault == "checksum"
                else 2
                if self.fault == "exhaust"
                else 4
                if self.fault == "required_flag"
                else 1 << 30
                if self.fault == "optional_flag"
                else 0,
            )
            + b"\0"
            + BSON.encode(response)
        )
        head = struct.pack(
            "<iiii",
            len(body) + 16,
            100,
            ident + 1 if self.fault == "response_id" else ident,
            1 if self.fault == "opcode" else 2013,
        )
        if self.fault == "length":
            head = struct.pack("<iiii", 500 * 1024 * 1024, 100, ident, 2013)
        self.incoming.extend(head + body)

    def recv(self, count):
        if self.fault == "eof":
            return b""
        if self.fault == "timeout":
            raise TimeoutError("timed out")
        count = min(count, 7)
        data = bytes(self.incoming[:count])
        del self.incoming[:count]
        return data

    def close(self):
        self.closed += 1

    def reply(self, doc):
        if "isMaster" in doc:
            assert doc["saslSupportedMechs"] == "admin." + self.user
            return {
                "ok": 1,
                "minWireVersion": 0,
                "maxWireVersion": 7 if self.fault == "old_wire" else 21,
                "ismaster": True,
                "saslSupportedMechs": ["future-unknown", self.mechanism],
            }
        if "saslStart" in doc:
            assert doc["$db"] == "admin" and doc["mechanism"] == self.mechanism
            if self.fault == "rejected":
                return {"ok": 0, "code": 18, "errmsg": "Authentication failed"}
            self.bare = bytes(doc["payload"])[3:]
            expected = self.user.replace("=", "=3D").replace(",", "=2C").encode()
            assert self.bare.startswith(b"n=" + expected + b",r=")
            self.nonce = self.bare.split(b",r=", 1)[1] + b"-independent-server-nonce"
            self.server_first = b"r=" + self.nonce + b",s=" + base64.b64encode(b"qa-password-salt") + b",i=4096"
            if self.fault == "first_extension":
                self.server_first += b",x=optional"
            if self.fault == "nonce":
                self.server_first = self.server_first.replace(self.nonce, b"another-client")
            if self.fault == "iterations":
                self.server_first = self.server_first.replace(b"i=4096", b"i=2")
            if self.fault == "iteration_text":
                self.server_first = self.server_first.replace(b"i=4096", b"i=no")
            if self.fault == "salt":
                self.server_first = self.server_first.replace(base64.b64encode(b"qa-password-salt"), b"not-base64!")
            if self.fault == "duplicate":
                self.server_first += b",i=4096"
            if self.fault == "mandatory":
                self.server_first = b"m=extension," + self.server_first
            if self.fault == "missing":
                self.server_first = b"r=" + self.nonce
            return {
                "ok": 1,
                "conversationId": True if self.fault == "conversation" else Int64(73) if self.fault == "int64" else 73,
                "done": self.fault == "early_done",
                "payload": Binary(self.server_first),
            }
        if "saslContinue" in doc:
            assert doc["conversationId"] == 73
            if not doc["payload"]:
                assert self.empty_finish and self.verified
                return {"ok": 1, "conversationId": 73, "done": self.fault != "incomplete", "payload": Binary(b"")}
            binding, nonce, proof = bytes(doc["payload"]).split(b",")
            assert binding == b"c=biws" and nonce == b"r=" + self.nonce
            algo = "sha256" if self.mechanism == "SCRAM-SHA-256" else "sha1"
            secret = (
                self.password.encode()
                if algo == "sha256"
                else hashlib.md5((self.user + ":mongo:" + self.password).encode(), usedforsecurity=False)
                .hexdigest()
                .encode()
            )
            salted = hashlib.pbkdf2_hmac(algo, secret, b"qa-password-salt", 4096)
            key = hmac.new(salted, b"Client Key", algo).digest()
            msg = b",".join([self.bare, self.server_first, binding + b"," + nonce])
            stored = hashlib.new(algo, key).digest()
            sig = hmac.new(stored, msg, algo).digest()
            expected = bytes(x ^ y for x, y in zip(key, sig, strict=True))
            if base64.b64decode(proof.split(b"=", 1)[1]) != expected:
                return {"ok": 0, "code": 18, "errmsg": "Authentication failed"}
            self.verified = True
            server = hmac.new(hmac.new(salted, b"Server Key", algo).digest(), msg, algo).digest()
            return {
                "ok": 1,
                "conversationId": 74 if self.fault == "changed_conversation" else 73,
                "done": not self.empty_finish,
                "payload": Binary(
                    (b"v=" + base64.b64encode(server) + (b",x=optional" if self.fault == "final_extension" else b""))
                    if self.fault != "server_signature"
                    else b"v=wrong"
                ),
            }
        assert self.verified
        if "connectionStatus" in doc:
            return {"ok": 1, "authInfo": {"authenticatedUsers": [{"user": self.user, "db": "admin"}]}}
        if "buildInfo" in doc:
            return {"ok": 1, "version": "7.0.43"}
        if "listCollections" in doc:
            return {
                "ok": 1,
                "cursor": {
                    "id": 0,
                    "ns": doc["$db"] + ".$cmd.listCollections",
                    "firstBatch": [{"name": "events"}, {"name": "archive"}],
                },
            }
        if "listDatabases" in doc:
            return {"ok": 1, "databases": [{"name": "admin"}, {"name": "analytics"}]}
        raise AssertionError(doc)


def connect(monkeypatch, peer, *, user=None, password="pencil"):
    monkeypatch.setattr("socket.create_connection", lambda address, timeout: peer)
    return MongoMetadataClient(
        "qa.local", 27017, username=user or peer.user, password=password, auth_db="admin", timeout=0.5
    )


@pytest.mark.parametrize("mechanism", ["SCRAM-SHA-256", "SCRAM-SHA-1"])
@pytest.mark.parametrize("empty_finish", [False, True])
def test_full_scram_proof_metadata_and_cleanup_without_monitors(monkeypatch, mechanism, empty_finish):
    peer = Peer(mechanism=mechanism, empty_finish=empty_finish)
    client = connect(monkeypatch, peer)
    assert peer.verified and client.list_database_names() == ["admin", "analytics"]
    assert client.server_info()["version"] == "7.0.43"
    assert client.run_command("admin", {"connectionStatus": 1})["authInfo"]["authenticatedUsers"] == [
        {"user": "reader", "db": "admin"}
    ]
    assert all(0 < t <= 0.5 for t in peer.timeouts)
    client.close()
    client.close()
    assert peer.closed == 1
    with pytest.raises(MongoClientError, match="closed"):
        client.hello()
    assert sum("saslStart" in doc for doc in peer.commands) == 1


@pytest.mark.parametrize(
    "fault",
    [
        "nonce",
        "iterations",
        "iteration_text",
        "salt",
        "duplicate",
        "mandatory",
        "missing",
        "conversation",
        "early_done",
        "changed_conversation",
        "server_signature",
    ],
)
def test_malformed_or_unverified_scram_never_yields_a_client_or_replays_auth(monkeypatch, fault):
    peer = Peer(fault=fault)
    with pytest.raises(MongoClientError, match="protocol error"):
        connect(monkeypatch, peer)
    assert peer.closed == 1 and sum("saslStart" in doc for doc in peer.commands) == 1


@pytest.mark.parametrize("fault", ["response_id", "opcode", "length", "checksum", "exhaust", "required_flag"])
def test_invalid_frames_close_without_sending_credentials(monkeypatch, fault):
    peer = Peer(fault=fault)
    with pytest.raises(MongoClientError, match="protocol error"):
        connect(monkeypatch, peer)
    assert peer.closed == 1 and len(peer.commands) == 1


@pytest.mark.parametrize("fault", ["eof", "timeout"])
def test_network_fault_is_not_a_credential_rejection(monkeypatch, fault):
    peer = Peer(fault=fault)
    with pytest.raises((ConnectionError, TimeoutError)):
        connect(monkeypatch, peer)
    assert peer.closed == 1


def test_unknown_optional_frame_flags_and_unknown_mechanism_are_ignored(monkeypatch):
    peer = Peer(fault="optional_flag")
    client = connect(monkeypatch, peer)
    assert peer.verified
    client.close()


@pytest.mark.parametrize("fault,password", [("rejected", "pencil"), (None, "wrong")])
def test_only_explicit_server_auth_error_is_rejected(monkeypatch, fault, password):
    peer = Peer(fault=fault)
    with pytest.raises(OperationFailure) as error:
        connect(monkeypatch, peer, password=password)
    assert error.value.code == 18 and peer.closed == 1


def test_legacy_handshake_defers_before_any_sasl_conversation(monkeypatch):
    peer = Peer(fault="old_wire")
    with pytest.raises(MongoMetadataFallback):
        connect(monkeypatch, peer)
    assert len(peer.commands) == 1 and peer.closed == 1


@pytest.mark.parametrize(
    "user,password,stored", [("IX", "I\u00adX", "IX"), ("\u2168", "\u2163", "IV"), ("a,b=c", "pencil", "pencil")]
)
def test_mongodb_username_escape_and_sha256_password_prep_are_distinct(monkeypatch, user, password, stored):
    peer = Peer(user=user, password=stored)
    client = connect(monkeypatch, peer, password=password)
    assert peer.verified
    client.close()


@pytest.mark.parametrize("password", ["bad\0pass", "\u0221", "a\u05d0", "\u05d0a\u05d0"])
def test_invalid_saslprep_password_fails_before_sasl_start(monkeypatch, password):
    peer = Peer()
    with pytest.raises(ValueError, match="SASLprep"):
        connect(monkeypatch, peer, password=password)
    assert peer.closed == 1 and len(peer.commands) == 1


def test_native_metadata_route_does_not_execute_arbitrary_commands(monkeypatch):
    peer = Peer()
    client = connect(monkeypatch, peer)
    try:
        with pytest.raises(MongoClientError, match="data operations"):
            client.run_command("admin", {"dropDatabase": 1})
        assert all("dropDatabase" not in d for d in peer.commands)
    finally:
        client.close()


@pytest.mark.parametrize(
    "value,expected", [("user\u00a0pass", "user pass"), ("I\u00adX", "IX"), ("\u05d0\u05d1", "\u05d0\u05d1")]
)
def test_saslprep_mapping_and_bidirectional_valid_cases(value, expected):
    assert _saslprep(value) == expected


@pytest.mark.parametrize("fault", ["first_extension", "final_extension", "int64"])
def test_optional_scram_extensions_and_bson_int64_conversation_ids_preserve_valid_auth(monkeypatch, fault):
    peer = Peer(fault=fault)
    client = connect(monkeypatch, peer)
    assert peer.verified
    client.close()


def test_slow_fragments_do_not_restart_the_reply_deadline(monkeypatch):
    from types import SimpleNamespace

    from redposture_core.clients import mongodb_metadata as wire

    peer = Peer()
    clock = [0.0]
    original = peer.recv

    def delayed(count):
        result = original(count)
        clock[0] += 0.11
        return result

    monkeypatch.setattr(peer, "recv", delayed)
    monkeypatch.setattr(wire, "time", SimpleNamespace(monotonic=lambda: clock[0]))
    with pytest.raises(TimeoutError, match="connection timeout"):
        connect(monkeypatch, peer)
    assert peer.closed == 1 and len(peer.commands) == 1


def test_completed_scram_does_not_bypass_the_existing_connection_status_identity_guard(monkeypatch):
    from redposture_core.modules.mongodb import actions

    peer = Peer()
    original = peer.reply

    def another_identity(doc):
        if "connectionStatus" in doc:
            return {"ok": 1, "authInfo": {"authenticatedUsers": [{"user": "someone-else", "db": "admin"}]}}
        return original(doc)

    monkeypatch.setattr(peer, "reply", another_identity)
    monkeypatch.setattr("socket.create_connection", lambda address, timeout: peer)
    selected, attempts = actions._try_credentials(
        "127.0.0.1",
        27017,
        0.5,
        auth_db="admin",
        credential_candidates=[{"username": "reader", "password": "pencil", "default": True}],
        metadata_only=True,
    )
    assert peer.verified and selected is None and len(attempts) == 1
    assert attempts[0]["credential_state"] == "unverified" and attempts[0]["ok"] is False
    assert peer.closed == 1


def test_ipv6_brackets_are_removed_only_for_the_socket_address(monkeypatch):
    peer = Peer()
    addresses = []

    def create(address, timeout):
        addresses.append((address, timeout))
        return peer

    monkeypatch.setattr("socket.create_connection", create)
    client = MongoMetadataClient("[::1]", 27017, username="reader", password="pencil", auth_db="admin", timeout=0.5)
    assert addresses == [(("::1", 27017), 0.5)] and peer.verified
    client.close()


def test_collection_cursor_pages_are_complete_and_counting_does_not_return_a_catalogue(monkeypatch):
    peer = Peer()
    original = peer.reply

    def pages(doc):
        if "listCollections" in doc:
            assert doc["cursor"] == {"batchSize": 128}
            return {
                "ok": 1,
                "cursor": {"id": 901, "ns": "analytics.$cmd.listCollections", "firstBatch": [{"name": "a"}]},
            }
        if "getMore" in doc:
            assert doc["getMore"] == 901 and doc["collection"] == "$cmd.listCollections" and doc["$db"] == "analytics"
            assert doc["batchSize"] == 128
            return {
                "ok": 1,
                "cursor": {
                    "id": 0,
                    "ns": "analytics.$cmd.listCollections",
                    "nextBatch": [{"name": "b"}, {"name": "c"}],
                },
            }
        return original(doc)

    monkeypatch.setattr(peer, "reply", pages)
    client = connect(monkeypatch, peer)
    assert client.count_collection_names("analytics") == 3
    assert sum("listCollections" in d for d in peer.commands) == sum("getMore" in d for d in peer.commands) == 1
    assert not any("killCursors" in d for d in peer.commands)
    client.close()


@pytest.mark.parametrize("failure", ["network", "shutdown", "permission"])
def test_initial_catalogue_read_retries_once_but_permissions_do_not(monkeypatch, failure):
    peers = [Peer(), Peer()]
    first = peers[0]
    original = first.reply

    def failing(doc):
        if "listDatabases" in doc:
            if failure == "network":
                raise ConnectionError("connection reset")
            return {"ok": 0, "code": 91 if failure == "shutdown" else 13, "errmsg": "denied"}
        return original(doc)

    monkeypatch.setattr(first, "reply", failing)
    sockets = iter(peers)
    monkeypatch.setattr("socket.create_connection", lambda address, timeout: next(sockets))
    client = MongoMetadataClient("127.0.0.1", 27017, username="reader", password="pencil", auth_db="admin", timeout=0.5)
    if failure == "permission":
        with pytest.raises(OperationFailure) as exc:
            client.list_database_names()
        assert exc.value.code == 13 and not peers[1].commands
    else:
        assert client.list_database_names() == ["admin", "analytics"] and first.closed == 1
        assert sum("listDatabases" in d for p in peers for d in p.commands) == 2
    client.close()


def test_enumeration_does_not_retry_a_second_failure(monkeypatch):
    peers = [Peer(), Peer()]
    for peer in peers:
        original = peer.reply

        def failure(doc, _original=original):
            if "listDatabases" in doc:
                return {"ok": 0, "code": 91, "errmsg": "shutting down"}
            return _original(doc)

        monkeypatch.setattr(peer, "reply", failure)
    sockets = iter(peers)
    monkeypatch.setattr("socket.create_connection", lambda address, timeout: next(sockets))
    client = MongoMetadataClient("127.0.0.1", 27017, username="reader", password="pencil", auth_db="admin", timeout=0.5)
    with pytest.raises(OperationFailure) as exc:
        client.list_database_names()
    assert exc.value.code == 91 and all(p.closed == 1 for p in peers)
    assert sum("listDatabases" in d for p in peers for d in p.commands) == 2
    client.close()


@pytest.mark.parametrize("failure", ["network", "duplicate", "namespace", "empty_repeat"])
def test_cursor_failure_is_not_a_complete_count_and_getmore_is_not_replayed(monkeypatch, failure):
    peer = Peer()
    original = peer.reply

    def pages(doc):
        if "listCollections" in doc:
            return {
                "ok": 1,
                "cursor": {
                    "id": 901,
                    "ns": "analytics.$cmd.listCollections",
                    "firstBatch": [] if failure == "empty_repeat" else [{"name": "a"}],
                },
            }
        if "getMore" in doc:
            if failure == "network":
                raise ConnectionError("connection reset")
            return {
                "ok": 1,
                "cursor": {
                    "id": 999 if failure == "namespace" else 901,
                    "ns": "another.$cmd.listCollections"
                    if failure == "namespace"
                    else "analytics.$cmd.listCollections",
                    "nextBatch": [] if failure == "empty_repeat" else [{"name": "a"}],
                },
            }
        if "killCursors" in doc:
            assert doc["cursors"] == [901]
            return {"ok": 1, "cursorsKilled": [901]}
        return original(doc)

    monkeypatch.setattr(peer, "reply", pages)
    cleanup = Peer()
    cleanup_original = cleanup.reply

    def kill(doc):
        if "killCursors" in doc:
            return {"ok": 1, "cursorsKilled": [901]}
        return cleanup_original(doc)

    monkeypatch.setattr(cleanup, "reply", kill)
    sockets = iter([peer, cleanup])
    monkeypatch.setattr("socket.create_connection", lambda address, timeout: next(sockets))
    client = MongoMetadataClient("127.0.0.1", 27017, username="reader", password="pencil", auth_db="admin", timeout=0.5)
    with pytest.raises((MongoClientError, ConnectionError)):
        client.count_collection_names("analytics")
    assert sum("getMore" in d for p in [peer, cleanup] for d in p.commands) == 1
    assert sum("killCursors" in d for p in [peer, cleanup] for d in p.commands) == 1
    client.close()


def test_large_metadata_count_spills_dedup_and_removes_the_temporary_database(monkeypatch):
    import tempfile
    from pathlib import Path

    peer = Peer()
    original = peer.reply
    names = [f"collection-{i:05d}-" + "x" * 100 for i in range(1000)]

    def pages(doc):
        if "listCollections" in doc:
            return {
                "ok": 1,
                "cursor": {"id": 0, "ns": "analytics.$cmd.listCollections", "firstBatch": [{"name": n} for n in names]},
            }
        return original(doc)

    monkeypatch.setattr(peer, "reply", pages)
    before = set(Path(tempfile.gettempdir()).glob("redposture-discover-*"))
    client = connect(monkeypatch, peer)
    assert client.count_collection_names("analytics") == 1000
    assert set(Path(tempfile.gettempdir()).glob("redposture-discover-*")) == before
    client.close()
