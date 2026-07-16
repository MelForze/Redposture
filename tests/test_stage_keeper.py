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
from redposture_core.stage_runtime import AuditCommandRunner, AuditCredentialRun, AuditHookContext


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


def test_keeper_lifecycle_classifies_anonymously_before_credentials_and_runs_deep_once(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    credentials = tmp_path / "keeper.creds"
    credentials.write_text("bad:bad\ngood:good\n", encoding="utf-8")
    events: list[str] = []

    class FakeClient:
        selected_transport = "plaintext"

        def __init__(self, *_args, **_kwargs) -> None:
            self.username: str | None = None

        def connect(self) -> None:
            events.append("connect")

        def get_children2(self, _path: str):
            if self.username == "good":
                events.append("auth_root")
                return [], 0, {}
            events.append("anonymous_root")
            return [], -102, {}

        def auth_digest(self, username: str, _password: str):
            self.username = username
            events.append(f"auth:{username}")
            if username == "good":
                return True, None
            return False, "authentication failed"

        def close(self) -> None:
            return

    def fake_fingerprint(*_args, **_kwargs):
        events.append("fingerprint")
        return ZkImplementationFingerprint(
            "clickhouse-keeper",
            True,
            "confirmed",
            version="v26.4",
            server_state="standalone",
            read_only=False,
            connections=1,
            quorum_status="healthy",
        )

    action_calls = 0

    def fake_capabilities(*_args, **_kwargs):
        nonlocal action_calls
        action_calls += 1
        events.append("actions")
        return True, True, None

    monkeypatch.setattr(actions.zookeeper_actions, "_ZkClient", FakeClient)
    monkeypatch.setattr(actions, "fingerprint_zookeeper_implementation", fake_fingerprint)
    monkeypatch.setattr(
        actions.zookeeper_actions,
        "_infer_auth_required_from_anonymous_probes",
        lambda *_args, **_kwargs: (True, "root_noauth", ["/:noauth"]),
    )
    monkeypatch.setattr(actions.zookeeper_actions, "_probe_znode_create_delete", fake_capabilities)
    monkeypatch.setattr(
        actions.zookeeper_actions,
        "_enumerate_znodes",
        lambda *_args, **_kwargs: (["/clickhouse"], 1, False, {"/clickhouse": {}}, None),
    )

    args = parse_args(
        [
            "keeper",
            "-t",
            "127.0.0.1",
            "--port",
            "9181",
            "-u",
            str(credentials),
            "--show-znodes",
            "--format",
            "json",
        ]
    )
    args.keeper_probe_cache = KeeperFingerprintCache()
    plan = build_keeper_plan(args)
    runner = AuditCommandRunner(args=args, spec=build_keeper_spec(args), emit_line=lambda _line: None)
    result = runner.run_plan(plan)

    assert events == [
        "connect",
        "anonymous_root",
        "fingerprint",
        "connect",
        "auth:bad",
        "connect",
        "auth:good",
        "auth_root",
        "actions",
    ]
    assert action_calls == 1
    assert result.records[0]["is_keeper"] is True
    assert result.records[0]["status"] == "valid_credentials"


def test_keeper_auth_retries_transient_connect_and_reuses_successful_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fingerprinted = False
    detect_connects = 0
    auth_connects = 0
    auth_calls = 0
    action_calls = 0

    class FakeClient:
        selected_transport = "plaintext"

        def __init__(self, *_args, **_kwargs) -> None:
            self.authenticated = False

        def connect(self) -> None:
            nonlocal detect_connects, auth_connects
            if not fingerprinted:
                detect_connects += 1
                return
            auth_connects += 1
            if auth_connects == 1:
                raise TimeoutError("timed out")

        def auth_digest(self, _username: str, _password: str):
            nonlocal auth_calls
            auth_calls += 1
            self.authenticated = True
            return True, None

        def get_children2(self, _path: str):
            return ([], 0, {}) if self.authenticated else ([], -102, {})

        def close(self) -> None:
            return

    def fake_fingerprint(*_args, **_kwargs):
        nonlocal fingerprinted
        fingerprinted = True
        return ZkImplementationFingerprint("clickhouse-keeper", True, "confirmed")

    def fake_capabilities(*_args, **_kwargs):
        nonlocal action_calls
        action_calls += 1
        return True, True, None

    monkeypatch.setattr(actions.zookeeper_actions, "_ZkClient", FakeClient)
    monkeypatch.setattr(actions, "fingerprint_zookeeper_implementation", fake_fingerprint)
    monkeypatch.setattr(
        actions.zookeeper_actions,
        "_infer_auth_required_from_anonymous_probes",
        lambda *_args, **_kwargs: (True, "root_noauth", ["/:noauth"]),
    )
    monkeypatch.setattr(actions.zookeeper_actions, "_probe_znode_create_delete", fake_capabilities)
    monkeypatch.setattr(
        actions.zookeeper_actions,
        "_enumerate_znodes",
        lambda *_args, **_kwargs: ([], 0, False, {}, None),
    )
    monkeypatch.setattr(actions.zookeeper_actions.time, "sleep", lambda _delay: None)

    args = parse_args(
        [
            "keeper",
            "-t",
            "127.0.0.1",
            "--port",
            "9181",
            "-u",
            "good",
            "-p",
            "good",
            "--retries",
            "2",
            "--format",
            "json",
        ]
    )
    args.keeper_probe_cache = KeeperFingerprintCache()
    runner = AuditCommandRunner(args=args, spec=build_keeper_spec(args), emit_line=lambda _line: None)
    result = runner.run_plan(build_keeper_plan(args))

    assert detect_connects == 1
    assert auth_connects == 2
    assert auth_calls == 1
    assert action_calls == 1
    assert result.records[0]["status"] == "valid_credentials"


def _keeper_lifecycle_options() -> dict[str, object]:
    return {
        "show_znodes": True,
        "dump": False,
        "dump_limit": None,
        "query_znode": None,
        "max_znodes": 100,
        "keeper_probe_cache": KeeperFingerprintCache(),
    }


def test_keeper_apache_negative_control_has_exact_terminal_stage_contract(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    detect_calls = 0
    fingerprint_calls = 0
    state = actions.KeeperLifecycleState(requested_config=ZkTransportConfig(mode="auto"))

    def fake_detect(ctx, _options):
        nonlocal detect_calls
        detect_calls += 1
        ctx.lifecycle_state.selected_transport_config = ZkTransportConfig(mode="plaintext")
        return {
            "host": "127.0.0.1",
            "port": 2181,
            "is_zookeeper": True,
            "status": "open_no_auth",
            "auth_required": False,
            "stages": [],
            "stage_durations_ms": {},
            "stage_attempts": {},
        }

    def fake_fingerprint(*_args, **_kwargs):
        nonlocal fingerprint_calls
        fingerprint_calls += 1
        return ZkImplementationFingerprint("apache-zookeeper", False, "rejected")

    monkeypatch.setattr(actions.zookeeper_actions, "detect_zookeeper", fake_detect)
    monkeypatch.setattr(actions, "fingerprint_zookeeper_implementation", fake_fingerprint)
    ctx = AuditHookContext(
        lifecycle_state=state,
        args=SimpleNamespace(timeout=0.1, retries=2),
        host="127.0.0.1",
        port=2181,
        credential=AuditCredentialRun(source="anonymous"),
        logger=None,
    )

    record = actions.detect_keeper(ctx, _keeper_lifecycle_options())

    assert detect_calls == 1
    assert fingerprint_calls == 1
    assert record["status"] == "not_keeper"
    assert record["is_keeper"] is False
    assert [stage["stage_name"] for stage in record["stages"]] == [
        "detect_protocol",
        "auth_inference_credentials",
    ]
    assert [stage["result"] for stage in record["stages"]] == ["ok", "ok"]
    assert [stage["error"] for stage in record["stages"]] == [None, None]
    assert record["stage_failed_at"] is None
    assert record["stage_durations_ms"] == {
        "detect_protocol": 0,
        "auth_inference_credentials": 0,
    }
    assert record["stage_attempts"] == {
        "detect_protocol": 1,
        "auth_inference_credentials": 1,
    }


def test_keeper_failed_detect_preserves_zookeeper_retry_telemetry(monkeypatch: pytest.MonkeyPatch) -> None:
    retry_error = "connection refused (service is not listening on target port)"
    stages = [
        {
            "stage_name": "detect_protocol",
            "attempt": attempt,
            "duration_ms": attempt,
            "result": "retry" if attempt < 3 else "fail",
            "error": retry_error,
        }
        for attempt in range(1, 4)
    ]
    monkeypatch.setattr(
        actions.zookeeper_actions,
        "detect_zookeeper",
        lambda *_args, **_kwargs: {
            "host": "127.0.0.1",
            "port": 9181,
            "is_zookeeper": False,
            "status": "fail",
            "auth_required": None,
            "error": retry_error,
            "connect_error": retry_error,
            "attempts": 3,
            "max_attempts": 3,
            "stages": stages,
            "stage_failed_at": "detect_protocol",
            "stage_durations_ms": {"detect_protocol": 6},
            "stage_attempts": {"detect_protocol": 3},
            "debug_events": [],
            "debug_events_streamed": False,
        },
    )
    ctx = AuditHookContext(
        lifecycle_state=actions.KeeperLifecycleState(requested_config=ZkTransportConfig(mode="auto")),
        args=SimpleNamespace(timeout=0.1, retries=2),
        host="127.0.0.1",
        port=9181,
        credential=AuditCredentialRun(source="anonymous"),
        logger=None,
    )

    record = actions.detect_keeper(ctx, _keeper_lifecycle_options())

    assert record["status"] == "fail"
    assert record["stages"] == stages
    assert record["stage_failed_at"] == "detect_protocol"
    assert record["stage_durations_ms"] == {"detect_protocol": 6}
    assert record["stage_attempts"] == {"detect_protocol": 3}
    assert record["attempts"] == 3
    assert record["max_attempts"] == 3
    assert record["connect_error"] == retry_error
