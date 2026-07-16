from __future__ import annotations

import threading
import time
from types import SimpleNamespace

import pytest

from redposture_core.cli_args import parse_args
from redposture_core.clients import zookeeper as zk_client
from redposture_core.clients.zookeeper import (
    ZkFourLetterResult,
    ZkImplementationFingerprint,
    ZkTransportConfig,
    _ZkClient,
    fingerprint_zookeeper_implementation,
    query_four_letter_word,
)
from redposture_core.modules.keeper import actions, policy, render
from redposture_core.modules.keeper.stage import build_keeper_plan, build_keeper_spec
from redposture_core.modules.keeper.types import KeeperFingerprintCache


def _patch_four_letter(monkeypatch: pytest.MonkeyPatch, responses: dict[str, str]) -> None:
    def fake_query(_host, _port, _timeout, command, **_kwargs):
        return ZkFourLetterResult(command=command, response=responses.get(command, ""))

    monkeypatch.setattr(zk_client, "query_four_letter_word", fake_query)


def test_fingerprint_confirms_keeper_and_extracts_raft_health(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_four_letter(
        monkeypatch,
        {
            "srvr": "ClickHouse Keeper version: v26.4.1\nMode: leader\nConnections: 4\nLatency min/avg/max: 0/1/9",
            "stat": "ClickHouse Keeper version: v26.4.1\nMode: leader",
            "isro": "rw",
            "mntr": (
                "zk_version\tv26.4.1\n"
                "zk_server_state\tleader\n"
                "zk_num_alive_connections\t4\n"
                "zk_min_latency\t0\nzk_avg_latency\t1\nzk_max_latency\t9\n"
                "zk_followers\t2\nzk_synced_followers\t2\nzk_pending_syncs\t0\n"
                "last_log_idx\t101\nlast_log_term\t7\nlast_committed_idx\t100\n"
                "leader_committed_log_idx\t100\ntarget_committed_log_idx\t100\n"
                "last_snapshot_idx\t90\nsnapshot_dir_size\t4096\nlog_dir_size\t8192"
            ),
        },
    )

    result = fingerprint_zookeeper_implementation(
        "keeper",
        9181,
        1.0,
        transport="plaintext",
        config=ZkTransportConfig(),
    )

    assert result.implementation == "clickhouse-keeper"
    assert result.is_keeper is True
    assert result.confidence == "confirmed"
    assert result.version == "v26.4.1"
    assert result.server_state == "leader"
    assert result.read_only is False
    assert result.connections == 4
    assert result.latency_ms == {"min": 0, "avg": 1, "max": 9}
    assert result.raft["last_log_term"] == 7
    assert result.raft["commit_lag"] == 0
    assert result.raft["snapshot_dir_size"] == 4096
    assert result.quorum_status == "healthy"


def test_fingerprint_rejects_apache_and_keeps_disabled_commands_unconfirmed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_four_letter(
        monkeypatch,
        {
            "srvr": "Zookeeper version: 3.9.3-aabbcc\nMode: standalone",
            "stat": "",
            "mntr": "zk_server_state\tstandalone",
            "isro": "rw",
        },
    )
    apache = fingerprint_zookeeper_implementation("zk", 2181, 1.0, transport="plaintext", config=ZkTransportConfig())
    assert apache.implementation == "apache-zookeeper"
    assert apache.is_keeper is False
    assert apache.confidence == "rejected"
    assert apache.quorum_status == "unknown"

    _patch_four_letter(
        monkeypatch,
        {
            command: "This command is not executed because it is not in the whitelist."
            for command in ("srvr", "stat", "mntr", "isro")
        },
    )
    unknown = fingerprint_zookeeper_implementation(
        "compatible", 9181, 1.0, transport="plaintext", config=ZkTransportConfig()
    )
    assert unknown.implementation == "zookeeper-compatible"
    assert unknown.is_keeper is None
    assert unknown.confidence == "unconfirmed"
    assert unknown.quorum_status == "unknown"


def test_fingerprint_marks_unsynced_leader_and_lagging_follower_degraded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_four_letter(
        monkeypatch,
        {
            "srvr": "ClickHouse Keeper version: v26.4\nMode: leader",
            "stat": "",
            "isro": "rw",
            "mntr": "zk_server_state\tleader\nzk_followers\t2\nzk_synced_followers\t1",
        },
    )
    leader = fingerprint_zookeeper_implementation(
        "keeper", 9181, 1.0, transport="plaintext", config=ZkTransportConfig()
    )
    assert leader.quorum_status == "degraded"

    _patch_four_letter(
        monkeypatch,
        {
            "srvr": "ClickHouse Keeper version: v26.4\nMode: follower",
            "stat": "",
            "isro": "rw",
            "mntr": (
                "zk_server_state\tfollower\nzk_peer_state\tfollowing - broadcast\n"
                "last_committed_idx\t95\ntarget_committed_log_idx\t100"
            ),
        },
    )
    follower = fingerprint_zookeeper_implementation(
        "keeper", 9181, 1.0, transport="plaintext", config=ZkTransportConfig()
    )
    assert follower.raft["commit_lag"] == 5
    assert follower.quorum_status == "degraded"


def test_four_letter_exchange_handles_partial_reads_and_closes(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeSocket:
        def __init__(self) -> None:
            self.chunks = [b"ClickHouse Keeper ", b"version: v26.4\n", b""]
            self.sent = b""
            self.closed = False

        def sendall(self, payload: bytes) -> None:
            self.sent += payload

        def shutdown(self, _how: int) -> None:
            return

        def recv(self, _size: int) -> bytes:
            return self.chunks.pop(0)

        def close(self) -> None:
            self.closed = True

    sock = FakeSocket()
    monkeypatch.setattr(zk_client, "_open_zk_socket", lambda *_a, **_k: sock)
    result = query_four_letter_word("keeper", 9181, 1.0, "srvr", transport="plaintext", config=ZkTransportConfig())
    assert result.response == "ClickHouse Keeper version: v26.4"
    assert sock.sent == b"srvr"
    assert sock.closed is True


def test_auto_transport_falls_back_but_not_after_connection_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _ZkClient("keeper", 9181, 1.0, transport_config=ZkTransportConfig(mode="auto"))
    attempts: list[str] = []

    def fake_connect_once(mode: str) -> None:
        attempts.append(mode)
        if mode == "plaintext":
            raise ValueError("invalid ZooKeeper frame size")

    monkeypatch.setattr(client, "_connect_once", fake_connect_once)
    client.connect()
    assert attempts == ["plaintext", "tls"]
    assert client.selected_transport == "tls"

    refused = _ZkClient("keeper", 9181, 1.0, transport_config=ZkTransportConfig(mode="auto"))
    refused_attempts: list[str] = []

    def refuse(mode: str) -> None:
        refused_attempts.append(mode)
        raise ConnectionRefusedError()

    monkeypatch.setattr(refused, "_connect_once", refuse)
    with pytest.raises(ConnectionRefusedError):
        refused.connect()
    assert refused_attempts == ["plaintext"]


def test_tls_options_prefer_tls_and_load_client_chain(monkeypatch: pytest.MonkeyPatch) -> None:
    config = ZkTransportConfig(mode="auto", insecure=True, cert_file="client.pem", key_file="client.key")
    assert zk_client._transport_attempt_order(config) == ("tls", "plaintext")

    loaded: list[tuple[str, str]] = []

    class Context:
        def load_cert_chain(self, cert: str, key: str) -> None:
            loaded.append((cert, key))

    monkeypatch.setattr(zk_client.ssl, "_create_unverified_context", lambda: Context())
    assert zk_client._build_tls_context(config).__class__ is Context
    assert loaded == [("client.pem", "client.key")]


def test_keeper_cache_single_flight() -> None:
    cache = KeeperFingerprintCache()
    calls = 0
    lock = threading.Lock()
    results: list[ZkImplementationFingerprint] = []

    def probe() -> ZkImplementationFingerprint:
        nonlocal calls
        with lock:
            calls += 1
        time.sleep(0.02)
        return ZkImplementationFingerprint("clickhouse-keeper", True, "confirmed")

    threads = [threading.Thread(target=lambda: results.append(cache.get_or_probe(("k",), probe))) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert calls == 1
    assert len(results) == 8


def test_keeper_adapter_classifies_and_renders_keeper(monkeypatch: pytest.MonkeyPatch) -> None:
    base = {
        "host": "127.0.0.1",
        "port": 9181,
        "status": "open_no_auth",
        "auth_required": False,
        "is_zookeeper": True,
        "transport": "plaintext",
        "znode_count": 3,
        "can_create_znode": True,
        "can_delete_znode": True,
        "show_znodes": False,
        "dump": False,
    }
    monkeypatch.setattr(actions.zookeeper_actions, "_audit_zookeeper_host", lambda **_kwargs: dict(base))
    monkeypatch.setattr(
        actions,
        "fingerprint_zookeeper_implementation",
        lambda *_a, **_k: ZkImplementationFingerprint(
            "clickhouse-keeper",
            True,
            "confirmed",
            version="v26.4",
            server_state="standalone",
            read_only=False,
            connections=2,
            raft={"commit_lag": 0},
            quorum_status="healthy",
        ),
    )
    record = actions._audit_keeper_host(
        "127.0.0.1",
        9181,
        1.0,
        0,
        None,
        None,
        False,
        False,
        None,
        100,
        False,
        False,
        1,
        None,
        False,
        False,
        False,
        None,
        None,
        None,
        KeeperFingerprintCache(),
    )
    record["module"] = "keeper"
    assert record["service"] == "clickhouse-keeper"
    assert record["protocol"] == "zookeeper"
    assert record["is_keeper"] is True
    line = render._format_detect_record(record, "txt")
    assert line.startswith("KEEPER")
    assert line.endswith("[*] ClickHouse Keeper version:v26.4")
    assert "quorum:" not in line
    assert "transport:" not in line


def test_keeper_policy_and_stage_contract() -> None:
    class Console:
        def __init__(self) -> None:
            self.errors: list[str] = []

        def error(self, message: str) -> None:
            self.errors.append(message)

    args = parse_args(["keeper", "-t", "127.0.0.1"])
    assert build_keeper_plan(args).ports == (9181,)
    assert build_keeper_spec(args).module == "keeper"
    assert policy.validate_args(args, Console()) is None

    invalid = SimpleNamespace(**vars(args))
    invalid.no_tls = True
    invalid.insecure = True
    console = Console()
    assert policy.validate_args(invalid, console) == 2
    assert "TLS options" in console.errors[0]
