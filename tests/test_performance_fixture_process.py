"""A separate fixture interpreter must preserve wire proof and owned cleanup."""

from __future__ import annotations

import http.client
import ipaddress
import socket
import struct

import pytest

from scripts.performance_fixture_process import ProcessHttpFixture
from scripts.profile_module_performance import BASE_IP
from tests.test_performance_native_fixtures import Wire, mongo_request, resp


def test_fixture_process_consumes_wire_identity_and_closes_server_and_child():
    index = int(ipaddress.IPv4Address("127.0.0.1")) - BASE_IP
    fixture = ProcessHttpFixture(
        "vault", {index: "positive"}, 0, False, bind_host="127.0.0.1", mode="credentials", auth_case="valid"
    )
    client = http.client.HTTPConnection("127.0.0.1", fixture.port, timeout=2)
    try:
        client.request("GET", "/v1/auth/token/lookup-self", headers={"X-Vault-Token": "profile-valid-token"})
        reply = client.getresponse()
        assert reply.status == 200 and b"profile-valid-token" in reply.read()
        assert fixture.pop_token_identity(index) == "profile-valid-token"
        assert fixture.pop_token_identity(index) is None
        if __import__("sys").platform == "linux":
            assert fixture.process_resources()["threads"] == 2
    finally:
        client.close()
        fixture.close()
    assert fixture._process._closed
    assert not fixture.errors
    assert fixture.stats["http_requests"] == fixture.stats["connections"] == 1
    assert fixture.stats["active"] == 0
    assert fixture.resource_summary()["cpu_seconds"] >= 0
    with pytest.raises(OSError), socket.create_connection(("127.0.0.1", fixture.port), timeout=0.2):
        pass
    fixture.close()


def test_fixture_setup_failure_leaves_no_owned_child():
    import multiprocessing

    before = {p.pid for p in multiprocessing.active_children()}
    with pytest.raises(RuntimeError, match="child failed"):
        ProcessHttpFixture("vault", {}, 0, False, bind_host="not-a-bind-address.invalid")
    assert {p.pid for p in multiprocessing.active_children()} == before


def test_readonly_docker_process_keeps_the_actual_foreign_request_and_releases_body():
    from scripts.performance_readonly import readonly_wire_errors

    index = int(ipaddress.IPv4Address("127.0.0.1")) - BASE_IP
    fixture = ProcessHttpFixture(
        "docker", {index: "foreign"}, 0, False, bind_host="127.0.0.1", mode="run", access_case="open"
    )
    client = http.client.HTTPConnection("127.0.0.1", fixture.port, timeout=2)
    try:
        client.request("GET", "/_ping", headers={"Authorization": "Basic deliberately-unexpected"})
        reply = client.getresponse()
        assert reply.status == 404
        reply.read()
        wire = fixture.pop_read_calls(index)
        assert wire["complete"] and len(wire["calls"]) == 1
        assert wire["calls"][0]["headers"]["authorization"] == "Basic deliberately-unexpected"
        assert readonly_wire_errors(wire)
        assert fixture.pop_read_calls(index) == {"complete": True, "calls": []}
    finally:
        client.close()
        fixture.close()
    assert fixture.read_wire_summary() == {
        "recorded_calls": 1,
        "pending_calls": 0,
        "pending_targets": 0,
        "overflow": 0,
        "malformed": 0,
    }
    assert fixture._process._closed and not fixture.errors


@pytest.mark.parametrize(
    "case,secret,status",
    [("valid", "profile-password", 200), ("limited", "profile-password", 403), ("valid", "wrong", 403)],
)
def test_s3_process_preserves_received_signature_and_consumes_it_before_cleanup(case, secret, status):
    from redposture_core.clients.s3_sigv4 import EMPTY_PAYLOAD_HASH, sign_request
    from scripts.performance_http_fixtures import verified_s3_access_key

    index = int(ipaddress.IPv4Address("127.0.0.1")) - BASE_IP
    fixture = ProcessHttpFixture(
        "minio", {index: "positive"}, 0, False, bind_host="127.0.0.1", mode="credentials", auth_case=case
    )
    client = http.client.HTTPConnection("127.0.0.1", fixture.port, timeout=2)
    try:
        host = f"127.0.0.1:{fixture.port}"
        signed = sign_request(
            method="GET",
            host=host,
            path="/",
            payload_hash=EMPTY_PAYLOAD_HASH,
            access_key="profile-user",
            secret_key=secret,
        )
        client.request("GET", "/", headers={"Host": host, **signed})
        reply = client.getresponse()
        assert reply.status == status
        reply.read()
        wire = fixture.pop_s3_calls(index)
        assert wire is not None and wire["complete"] and len(wire["calls"]) == 1
        fields = {k.encode(): v.encode() for k, v in wire["calls"][0]["headers"].items()}
        assert verified_s3_access_key("GET", "/", fields, b"", secret_key=secret) == "profile-user"
        empty = fixture.pop_s3_calls(index)
        assert empty is not None and empty["calls"] == []
    finally:
        client.close()
        fixture.close()
    assert fixture._process._closed and not fixture.errors
    stats = fixture.s3_wire_summary()
    assert (
        stats is not None and stats["recorded_calls"] == 1 and stats["pending_calls"] == stats["pending_targets"] == 0
    )


@pytest.mark.parametrize("module", ["mongodb", "postgres", "redis", "grpc", "zookeeper", "keeper"])
def test_native_process_has_exact_wire_replies_and_releases_child_and_listener(module):
    from scripts.performance_native_fixtures import serve_invalid_credentials

    if module == "mongodb":
        data = mongo_request({"hello": 1}, 1) + mongo_request({"saslStart": 1}, 2)
    elif module == "redis":
        data = resp(b"PING") + resp(b"AUTH", b"default", b"wrong") + resp(b"QUIT")
    elif module == "grpc":
        from tests.test_performance_native_program_parity import requests

        data = requests("grpc")
    elif module in {"zookeeper", "keeper"}:
        from tests.test_performance_coordination_auth import auth, frame, handshake, string

        data = (
            handshake()
            + frame(auth())
            + frame(struct.pack(">ii", 7, 12) + string("/") + b"\0")
            + frame(struct.pack(">ii", 8, -11))
        )
    else:
        startup = struct.pack(">i", 196608) + b"user\0probe\0database\0postgres\0\0"
        data = (
            struct.pack(">ii", 8, 80877103)
            + struct.pack(">i", len(startup) + 4)
            + startup
            + b"p"
            + struct.pack(">i", 10)
            + b"wrong\0"
        )
    reference = Wire(data[4:])
    expected_commands = []
    try:
        serve_invalid_credentials(module, reference, data[:4], expected_commands.append)
    except EOFError:
        pass
    index = int(ipaddress.IPv4Address("127.0.0.1")) - BASE_IP
    fixture = ProcessHttpFixture(
        module,
        {index: "positive"},
        0,
        False,
        bind_host="127.0.0.1",
        mode="credentials",
        native_peer="async",
        auth_surface="digest-acl" if module in {"zookeeper", "keeper"} else "default",
    )
    try:
        with socket.create_connection(("127.0.0.1", fixture.port), timeout=2) as client:
            for offset in range(0, len(data), 3):
                client.sendall(data[offset : offset + 3])
            client.shutdown(socket.SHUT_WR)
            observed = bytearray()
            while portion := client.recv(65536):
                observed.extend(portion)
        assert bytes(observed) == bytes(reference.replies)
        if module == "grpc":
            wire = fixture.pop_grpc_calls(index)
            assert wire is not None
            assert wire["complete"] is True and len(wire["calls"]) == 1
            assert wire["calls"][0]["authorization"] is None and wire["calls"][0]["status"] == 16
            empty = fixture.pop_grpc_calls(index)
            assert empty is not None and empty["calls"] == []
        elif module in {"zookeeper", "keeper"}:
            wire = fixture.pop_coordination_calls(index)
            assert wire is not None and wire["complete"] and len(wire["calls"]) == 2
            assert wire["calls"] == [
                {"kind": "digest_ack", "username": "admin", "password": "wrong", "path": None, "error": 0},
                {"kind": "read", "username": "admin", "password": "wrong", "path": "/", "error": -102},
            ]
            assert fixture.pop_coordination_calls(index) == {"complete": True, "calls": []}
    finally:
        fixture.close()
    assert fixture._process._closed and not fixture.errors
    assert fixture.stats["native_sessions"] == 1
    assert fixture.stats["native_messages"] == len(expected_commands)
    assert fixture.stats["active"] == 0
    if module in {"zookeeper", "keeper"}:
        summary = fixture.coordination_wire_summary()
        assert summary is not None
        assert summary["recorded_calls"] == 2 and summary["pending_calls"] == summary["pending_targets"] == 0
    assert fixture.resource_summary()["cpu_seconds"] >= 0
    with pytest.raises(OSError), socket.create_connection(("127.0.0.1", fixture.port), timeout=0.2):
        pass
    fixture.close()
