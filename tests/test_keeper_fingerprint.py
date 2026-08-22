from __future__ import annotations

import threading
import time

import pytest

from redposture_core.clients import zookeeper as zk_client
from redposture_core.clients.zookeeper import (
    ZkFourLetterResult,
    ZkImplementationFingerprint,
    ZkTransportConfig,
    _ZkClient,
    fingerprint_zookeeper_implementation,
    query_four_letter_word,
)
from redposture_core.modules.zookeeper.types import ZooKeeperFingerprintCache


def _patch_four_letter(monkeypatch: pytest.MonkeyPatch, responses: dict[str, str]) -> None:
    def fake_query(_host, _port, _timeout, command, **_kwargs):
        return ZkFourLetterResult(command=command, response=responses.get(command, ""))

    monkeypatch.setattr(zk_client, "query_four_letter_word", fake_query)


def test_fingerprint_confirms_clickhouse_keeper_and_extracts_raft_health(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_four_letter(
        monkeypatch,
        {
            "srvr": (
                "ClickHouse Keeper version: v26.4.1-stable-abcdef\n"
                "Mode: leader\nConnections: 4\nLatency min/avg/max: 0/1/9"
            ),
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
        "keeper-lab",
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


def test_fingerprint_classifies_apache_and_keeps_disabled_diagnostics_unconfirmed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_four_letter(
        monkeypatch,
        {
            "srvr": "Zookeeper version: 3.9.3-aabbcc\nMode: standalone",
            "mntr": "zk_server_state\tstandalone",
            "isro": "rw",
        },
    )
    apache = fingerprint_zookeeper_implementation(
        "zk",
        2181,
        1.0,
        transport="plaintext",
        config=ZkTransportConfig(),
    )
    assert apache.implementation == "apache-zookeeper"
    assert apache.is_keeper is False
    assert apache.confidence == "rejected"
    assert apache.version == "3.9.3"

    disabled = "This command is not executed because it is not in the whitelist."
    _patch_four_letter(monkeypatch, {command: disabled for command in ("srvr", "stat", "mntr", "isro")})
    unknown = fingerprint_zookeeper_implementation(
        "compatible",
        9181,
        1.0,
        transport="plaintext",
        config=ZkTransportConfig(),
    )
    assert unknown.implementation == "zookeeper-compatible"
    assert unknown.is_keeper is None
    assert unknown.confidence == "unconfirmed"


@pytest.mark.parametrize(
    ("raw_version", "expected"),
    [
        ("3.7.2-c06c7c8a", "3.7.2"),
        ("v25.3.3.42-stable-c4bfe68b", "v25.3.3.42"),
        ("3.9.3", "3.9.3"),
        ("", None),
        (None, None),
    ],
)
def test_fingerprint_normalizes_version_invariant(raw_version: str | None, expected: str | None) -> None:
    fingerprint = ZkImplementationFingerprint(
        implementation="zookeeper-compatible",
        is_keeper=None,
        confidence="unconfirmed",
        version=raw_version,
    )

    assert fingerprint.version == expected


def test_fingerprint_uses_sequential_strong_first_request_budget(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []
    responses = {
        "srvr": "ClickHouse Keeper version: v26.4\nMode: leader",
        "mntr": "zk_server_state\tleader\nzk_followers\t1\nzk_synced_followers\t1",
        "isro": "rw",
    }

    def fake_query(_host, _port, _timeout, command, **_kwargs):
        calls.append(command)
        return ZkFourLetterResult(command=command, response=responses.get(command, ""))

    monkeypatch.setattr(zk_client, "query_four_letter_word", fake_query)
    result = fingerprint_zookeeper_implementation(
        "keeper-lab",
        9181,
        1.0,
        transport="plaintext",
        config=ZkTransportConfig(),
    )
    assert result.is_keeper is True
    assert calls == ["srvr", "mntr", "isro"]

    calls.clear()
    responses.clear()
    responses["srvr"] = "Zookeeper version: 3.9.3\nMode: standalone"
    result = fingerprint_zookeeper_implementation(
        "zookeeper",
        2181,
        1.0,
        transport="plaintext",
        config=ZkTransportConfig(),
    )
    assert result.is_keeper is False
    assert calls == ["srvr"]


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
    monkeypatch.setattr(zk_client, "_open_zk_socket", lambda *_args, **_kwargs: sock)
    result = query_four_letter_word(
        "keeper-lab",
        9181,
        1.0,
        "srvr",
        transport="plaintext",
        config=ZkTransportConfig(),
    )
    assert result.response == "ClickHouse Keeper version: v26.4"
    assert sock.sent == b"srvr"
    assert sock.closed is True


def test_auto_transport_falls_back_on_protocol_mismatch_but_not_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = _ZkClient("keeper-lab", 9181, 1.0, transport_config=ZkTransportConfig(mode="auto"))
    attempts: list[str] = []

    def fake_connect_once(mode: str) -> None:
        attempts.append(mode)
        if mode == "plaintext":
            raise ValueError("invalid ZooKeeper frame size")

    monkeypatch.setattr(client, "_connect_once", fake_connect_once)
    client.connect()
    assert attempts == ["plaintext", "tls"]
    assert client.selected_transport == "tls"

    refused = _ZkClient("keeper-lab", 9181, 1.0, transport_config=ZkTransportConfig(mode="auto"))
    refused_attempts: list[str] = []

    def refuse(mode: str) -> None:
        refused_attempts.append(mode)
        raise ConnectionRefusedError()

    monkeypatch.setattr(refused, "_connect_once", refuse)
    with pytest.raises(ConnectionRefusedError):
        refused.connect()
    assert refused_attempts == ["plaintext"]


def test_tls_material_prefers_tls_and_loads_client_chain(monkeypatch: pytest.MonkeyPatch) -> None:
    config = ZkTransportConfig(mode="auto", insecure=True, cert_file="client.pem", key_file="client.key")
    assert zk_client._transport_attempt_order(config) == ("tls", "plaintext")
    loaded: list[tuple[str, str]] = []

    class Context:
        def load_cert_chain(self, cert: str, key: str) -> None:
            loaded.append((cert, key))

    monkeypatch.setattr(zk_client.ssl, "_create_unverified_context", lambda: Context())
    assert isinstance(zk_client._build_tls_context(config), Context)
    assert loaded == [("client.pem", "client.key")]


def test_zookeeper_fingerprint_cache_is_single_flight_and_lru_bounded() -> None:
    cache = ZooKeeperFingerprintCache(max_entries=2)
    calls = 0
    lock = threading.Lock()
    results: list[ZkImplementationFingerprint] = []

    def probe() -> ZkImplementationFingerprint:
        nonlocal calls
        with lock:
            calls += 1
        time.sleep(0.02)
        return ZkImplementationFingerprint("clickhouse-keeper", True, "confirmed")

    threads = [threading.Thread(target=lambda: results.append(cache.get_or_probe(("one",), probe))) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert calls == 1
    assert len(results) == 8

    cache.get_or_probe(("two",), lambda: ZkImplementationFingerprint("clickhouse-keeper", True, "confirmed"))
    cache.get_transport(("missing",))
    cache.remember_transport(("one",), "plaintext")
    cache.remember_transport(("two",), "tls")
    assert cache.get_transport(("one",)) == "plaintext"
    cache.remember_transport(("three",), "tls")
    assert cache.get_transport(("two",)) is None

    with pytest.raises(ValueError, match="max_entries must be positive"):
        ZooKeeperFingerprintCache(max_entries=0)
