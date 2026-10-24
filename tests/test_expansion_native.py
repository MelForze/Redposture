"""Native data selection, retry ownership, and incomplete-result contracts."""

from __future__ import annotations

import struct
from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest

from redposture_core.clients import kafka, mongodb, oracle
from redposture_core.modules.postgres import actions as pg
from redposture_core.modules.redis import actions as redis
from redposture_core.modules.zookeeper import actions as zk


def _pg_options(**overrides: Any) -> dict[str, Any]:
    options: dict[str, Any] = dict(
        database_name="app",
        include_database_prefix=True,
        show_tables=True,
        show_row_counts=True,
        show_columns=True,
        table_targets=["public.good", "public.bad"],
        table_columns=[],
        dump_table_rows=True,
        dump_row_limit=3,
    )
    options.update(overrides)
    return options


def test_postgres_artifacts_preserve_successful_siblings_and_reuse_columns(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        pg, "_pg_query_readable_tables", Mock(return_value=(["public.good", "public.bad"], "inventory incomplete"))
    )
    columns = Mock(
        side_effect=[
            ("public.good", ["ID"], None),
            ("public.bad", None, "metadata denied"),
            ("public.bad", None, "metadata denied"),
        ]
    )
    monkeypatch.setattr(pg, "_pg_query_table_columns", columns)
    monkeypatch.setattr(
        pg,
        "_pg_query_table_row_count",
        Mock(side_effect=[("public.good", 8, None), ("public.bad", None, "count denied")]),
    )
    rows = Mock(side_effect=[("public.good", ['{"ID":1}'], None), ("public.bad", None, "rows denied")])
    monkeypatch.setattr(pg, "_pg_query_table_rows", rows)
    names, metadata, counts, dumps, readable, error = pg._pg_collect_database_artifacts(None, **_pg_options())
    assert names == ["app.public.good", "app.public.bad"] and readable == 2
    assert metadata == [
        {"database": "app", "table": "app.public.good", "columns": ["ID"], "error": None},
        {"database": "app", "table": "app.public.bad", "columns": None, "error": "metadata denied"},
    ]
    assert [item["row_count"] for item in counts] == [8, None]
    assert counts[1]["error"] == "count denied"
    assert dumps == [
        {"database": "app", "table": "app.public.good", "columns": ["ID"], "rows": ['{"ID":1}'], "error": None},
        {"database": "app", "table": "app.public.bad", "columns": None, "rows": None, "error": "rows denied"},
    ]
    assert error == "inventory incomplete; metadata denied"
    assert columns.call_count == 3
    assert rows.call_args.kwargs == {"columns": None, "max_rows": 3}


def test_postgres_explicit_columns_avoid_inventory_and_metadata(monkeypatch: pytest.MonkeyPatch) -> None:
    inventory = Mock(side_effect=AssertionError("unrequested inventory"))
    metadata = Mock(side_effect=AssertionError("unrequested columns"))
    rows = Mock(return_value=("public.events", ['{"Case":1}'], None))
    monkeypatch.setattr(pg, "_pg_query_readable_tables", inventory)
    monkeypatch.setattr(pg, "_pg_query_table_columns", metadata)
    monkeypatch.setattr(pg, "_pg_query_table_rows", rows)
    result = pg._pg_collect_database_artifacts(
        None,
        **_pg_options(
            show_tables=False,
            show_columns=False,
            show_row_counts=False,
            table_targets=["public.events"],
            table_columns=["Case"],
            include_database_prefix=False,
        ),
    )
    assert result == (
        None,
        [],
        [],
        [{"database": "app", "table": "public.events", "columns": ["Case"], "rows": ['{"Case":1}'], "error": None}],
        None,
        None,
    )
    assert rows.call_args.kwargs == {"columns": ["Case"], "max_rows": 3}
    inventory.assert_not_called()
    metadata.assert_not_called()


def test_postgres_scram_handshake_validates_server_signature(monkeypatch: pytest.MonkeyPatch) -> None:
    state = pg._ScramState(client_first_bare="n=alice,r=clientnonce", client_nonce="clientnonce")
    challenge = "r=clientnonceserver,s=c2FsdA==,i=4096"
    final, signature = pg._scram_client_final(state, "secret", challenge)
    monkeypatch.setattr(pg, "_scram_client_first", Mock(return_value=(state, "n,,n=alice,r=clientnonce")))
    startup, initial, response = Mock(), Mock(), Mock()
    monkeypatch.setattr(pg, "_pg_send_startup", startup)
    monkeypatch.setattr(pg, "_pg_send_sasl_initial", initial)
    monkeypatch.setattr(pg, "_pg_send_sasl_response", response)
    monkeypatch.setattr(
        pg,
        "_pg_read_message",
        Mock(
            side_effect=[
                (b"R", struct.pack(">i", 10) + b"SCRAM-SHA-256\0\0"),
                (b"R", struct.pack(">i", 11) + challenge.encode()),
                (b"R", struct.pack(">i", 12) + f"v={signature}".encode()),
                (b"R", struct.pack(">i", 0)),
                (b"K", b"backend key"),
                (b"N", b"notice"),
                (b"S", b"server_version\0" + b"16.4\0"),
                (b"Z", b"I"),
            ]
        ),
    )
    session = pg._pg_startup_and_auth(None, "alice", "secret", "app")
    assert session == pg._PgSession(True, "scram-sha-256", "16.4")
    initial.assert_called_once_with(None, "SCRAM-SHA-256", "n,,n=alice,r=clientnonce")
    response.assert_called_once_with(None, final)
    assert state.expected_server_signature == signature


@pytest.mark.parametrize(
    ("auth_code", "payload", "message", "method"),
    [
        (5, b"x", "invalid MD5 authentication payload", "md5"),
        (10, b"SCRAM-SHA-256\0\0", "SCRAM authentication required", "scram-sha-256"),
        (11, b"unexpected challenge", "unexpected SCRAM continue", "scram-sha-256"),
        (12, b"v=signature", "unexpected SCRAM final", "scram-sha-256"),
        (99, b"", "unsupported auth method: 99", None),
    ],
)
def test_postgres_auth_challenges_do_not_turn_malformed_sequences_into_success(
    monkeypatch: pytest.MonkeyPatch, auth_code: int, payload: bytes, message: str, method: str | None
) -> None:
    monkeypatch.setattr(pg, "_pg_send_startup", Mock())
    monkeypatch.setattr(pg, "_pg_read_message", Mock(return_value=(b"R", struct.pack(">i", auth_code) + payload)))
    with pytest.raises(pg._PgAuditError, match=message) as caught:
        pg._pg_startup_and_auth(None, "alice", None, "app")
    assert caught.value.detected is True
    assert caught.value.auth_required is True and caught.value.auth_method == method


@pytest.mark.parametrize(
    ("oid_rows", "oid_error", "message"),
    [
        ([], None, "lo_import returned empty oid"),
        ([["not-an-oid"]], None, "lo_import returned invalid oid: not-an-oid"),
        ([], "permission denied", "lo_import failed: permission denied"),
    ],
)
def test_postgres_file_fallback_reports_both_failures_without_unlinking_unknown_oid(
    monkeypatch: pytest.MonkeyPatch, oid_rows: list[Any], oid_error: str | None, message: str
) -> None:
    query = Mock(side_effect=[([], "pg_read_file denied"), ([], "directory denied"), (oid_rows, oid_error)])
    monkeypatch.setattr(pg, "_pg_query_rows", query)
    rows, error, method, attempts = pg._pg_try_read_server_file(None, r"C:\private\file.txt")
    assert rows is None and method is None and error
    assert "pg_read_file failed: pg_read_file denied" in error and message in error
    assert attempts[0]["ok"] is False and attempts[1]["ok"] is False
    assert query.call_args_list[1].args[1] == "SELECT pg_ls_dir('C:\\private', FALSE, TRUE)"
    assert query.call_count == 3


@pytest.mark.parametrize(
    ("get_rows", "get_error", "unlink_error"),
    [
        ([["kept\nvalue"]], None, "cleanup denied"),
        ([], "read denied", "cleanup denied"),
        ([], None, None),
    ],
)
def test_postgres_large_object_cleanup_runs_after_read_failure(
    monkeypatch: pytest.MonkeyPatch, get_rows: list[Any], get_error: str | None, unlink_error: str | None
) -> None:
    query = Mock(
        side_effect=[
            ([], "file denied"),
            ([["file.txt"]], None),
            ([["42"]], None),
            (get_rows, get_error),
            ([], unlink_error),
        ]
    )
    monkeypatch.setattr(pg, "_pg_query_rows", query)
    output, error, method, attempts = pg._pg_try_read_server_file(None, "/private/file.txt")
    assert query.call_args.args[1] == "SELECT lo_unlink(42)"
    if get_rows:
        assert output == ["kept", "value"] and error is None and method == "lo_import"
        assert attempts[-1]["warning"] == "lo_unlink failed: cleanup denied"
    else:
        assert output is None and method is None and error
        assert ("lo_get failed: read denied" if get_error else "empty lo_get result") in error


@pytest.mark.parametrize("function", [pg._pg_execute_remote_command, pg._pg_execute_sql_query])
def test_postgres_read_operation_retries_connection_then_closes_selected_session(
    monkeypatch: pytest.MonkeyPatch, function: Any
) -> None:
    sock = Mock(__enter__=Mock(), __exit__=Mock(return_value=None))
    sock.__enter__.return_value = sock
    opening = Mock(side_effect=[ConnectionResetError("reset"), sock])
    monkeypatch.setattr(pg, "_pg_open_socket", opening)
    auth = Mock()
    monkeypatch.setattr(pg, "_pg_startup_and_auth", auth)
    monkeypatch.setattr(pg, "_pg_try_execute_command", Mock(return_value=(["kept"], "permission denied")))
    monkeypatch.setattr(pg, "_pg_try_query_sql", Mock(return_value=(["kept"], "permission denied")))
    terminate = Mock(side_effect=OSError("already closed"))
    monkeypatch.setattr(pg, "_pg_send_terminate", terminate)
    sleep = Mock()
    monkeypatch.setattr(pg.time, "sleep", sleep)
    result = function("h", 5432, 1, 1, "u", "p", "app", "query")
    assert result == (["kept"], "permission denied")
    assert opening.call_count == 2 and sleep.call_count == 1
    auth.assert_called_once_with(sock, username="u", password="p", database="app")
    sock.close.assert_called_once()


def _zk_context(retries: int = 0) -> SimpleNamespace:
    return SimpleNamespace(
        host="h",
        port=2181,
        args=SimpleNamespace(retries=retries),
        credential=SimpleNamespace(username="u", password="p", source="explicit"),
        debug_emit=None,
    )


@pytest.mark.parametrize(
    ("children_code", "data_code", "value", "query_error", "dump_error"),
    [
        (0, 0, b"secret", None, None),
        (0, -102, None, None, "Access Denied"),
        (0, -101, None, None, "znode not found"),
        (0, -8, None, None, "BADARGUMENTS"),
        (-102, 0, None, "NOAUTH", "Access Denied"),
        (-101, 0, None, "NONODE", "znode not found"),
        (-8, 0, None, "BADARGUMENTS", "BADARGUMENTS"),
    ],
)
def test_zookeeper_direct_lookup_never_enumerates_and_retains_query_metadata(
    monkeypatch: pytest.MonkeyPatch,
    children_code: int,
    data_code: int,
    value: bytes | None,
    query_error: str | None,
    dump_error: str | None,
) -> None:
    ctx = _zk_context()
    client = Mock()
    client.get_children2.return_value = (["child"], children_code, {"data_length": 6})
    client.get_data.return_value = (value, data_code, {})
    state = zk.ZooKeeperLifecycleState(anonymous_client=client)
    ctx.lifecycle_state = state
    monkeypatch.setattr(zk, "_refresh_zookeeper_lifecycle_client", Mock(return_value=(client, None)))
    enumeration = Mock(side_effect=AssertionError("direct lookup must not traverse tree"))
    monkeypatch.setattr(zk, "_enumerate_zookeeper_lifecycle", enumeration)
    result = zk.collect_zookeeper_data(
        ctx,
        {"status": "open_no_auth", "is_keeper": True},
        dict(show_znodes=True, dump=True, query_znode="/chosen", max_znodes=10),
    )
    assert result["is_keeper"] is True
    assert result["znodes"] == [] and result["znode_count"] is None
    assert result["query_error"] == query_error and result["query_znode_dump_error"] == dump_error
    assert result["znode_values"] is None
    assert result["query_znode_dump"] == ("secret" if children_code == data_code == 0 else None)
    if children_code == 0:
        assert result["query_znode_value"] == "/chosen (children:1,bytes:6)"
        client.get_data.assert_called_once_with("/chosen")
    else:
        client.get_data.assert_not_called()
    enumeration.assert_not_called()


@pytest.mark.parametrize("operation", ["children", "data"])
def test_zookeeper_read_retry_reopens_same_identity_and_preserves_final_result(
    monkeypatch: pytest.MonkeyPatch, operation: str
) -> None:
    ctx = _zk_context(retries=1)
    first, second = Mock(), Mock()
    getattr(first, "get_children2" if operation == "children" else "get_data").side_effect = ConnectionResetError(
        "connection reset by peer"
    )
    expected = (["kept"] if operation == "children" else b"kept", 0, {})
    getattr(second, "get_children2" if operation == "children" else "get_data").return_value = expected
    reopening = Mock(return_value=second)
    monkeypatch.setattr(zk, "_reopen_zookeeper_lifecycle_client", reopening)
    monkeypatch.setattr(zk.time, "sleep", Mock())
    state = zk.ZooKeeperLifecycleState()
    client, result, error, attempts = zk._read_zookeeper_lifecycle_with_retry(
        ctx, state, first, authenticated=True, operation=operation, path="/secret"
    )
    assert (client, result, error, attempts) == (second, expected, None, 2)
    reopening.assert_called_once_with(ctx, state, authenticated=True)


@pytest.mark.parametrize("sasl", [False, True])
def test_zookeeper_failed_identity_refresh_closes_new_session_and_keeps_previous(
    monkeypatch: pytest.MonkeyPatch, sasl: bool
) -> None:
    ctx = _zk_context()
    old, new = Mock(), Mock()
    new.auth_digest.return_value = (False, "credential rejected")
    new.auth_sasl_digest.return_value = (False, "credential rejected")
    state = zk.ZooKeeperLifecycleState(digest_auth_unsupported=sasl)
    key = zk._zookeeper_lifecycle_key(ctx)
    state.credential_clients[key] = old
    monkeypatch.setattr(zk, "_zookeeper_lifecycle_client", Mock(return_value=new))
    with pytest.raises(ConnectionError, match="credential rejected"):
        zk._reopen_zookeeper_lifecycle_client(ctx, state, authenticated=True)
    assert state.credential_clients[key] is old
    old.close.assert_not_called()
    new.close.assert_called_once()
    (new.auth_sasl_digest if sasl else new.auth_digest).assert_called_once_with("u", "p")


def test_zookeeper_tree_dump_retains_siblings_and_marks_noauth_coverage(monkeypatch: pytest.MonkeyPatch) -> None:
    ctx = _zk_context()
    client = Mock()
    client.get_data.side_effect = [(b"retained", 0, {}), (None, -102, {}), (None, -101, {}), (None, -8, {})]
    ctx.lifecycle_state = zk.ZooKeeperLifecycleState(anonymous_client=client)
    monkeypatch.setattr(zk, "_refresh_zookeeper_lifecycle_client", Mock(return_value=(client, None)))
    monkeypatch.setattr(
        zk,
        "_enumerate_zookeeper_lifecycle",
        Mock(return_value=(["/d", "/a", "/c", "/b"], 4, False, {"/b": {"error": "Access Denied"}}, None)),
    )
    result = zk.collect_zookeeper_data(
        ctx,
        {"status": "open_no_auth", "error": "prior warning", "stage_attempts": {"detect_protocol": 1}},
        dict(show_znodes=True, dump=True, query_znode=None, max_znodes=20),
    )
    assert result["znodes"] == ["/a", "/b", "/c", "/d"]
    assert result["znode_dump_items"] == [{"path": "/a", "value": "retained"}]
    assert result["znode_values"] == ["/a:retained", "/b:<Access Denied>", "/c:<not found>", "/d:<error:BADARGUMENTS>"]
    assert result["dump_error"] == "BADARGUMENTS,NOAUTH,NONODE"
    assert result["znode_count_partial"] is True and result["znode_count_unknown"] is True
    assert result["znode_truncated_reason"] == "noauth"
    assert result["error"] == "prior warning"
    assert result["stage_attempts"] == {"detect_protocol": 1, "access_capabilities": 0, "data": 1}


@pytest.mark.parametrize("operation", ["children", "data"])
def test_zookeeper_read_retry_handles_refresh_failure_without_reusing_bad_session(
    monkeypatch: pytest.MonkeyPatch, operation: str
) -> None:
    ctx = _zk_context(retries=2)
    client = Mock()
    getattr(client, "get_children2" if operation == "children" else "get_data").side_effect = ConnectionResetError(
        "connection reset"
    )
    monkeypatch.setattr(
        zk,
        "_reopen_zookeeper_lifecycle_client",
        Mock(side_effect=[ConnectionResetError("connection reset"), ValueError("invalid transport config")]),
    )
    monkeypatch.setattr(zk.time, "sleep", Mock())
    _, result, error, attempts = zk._read_zookeeper_lifecycle_with_retry(
        ctx, zk.ZooKeeperLifecycleState(), client, authenticated=False, operation=operation, path="/a"
    )
    assert result is None and error and "invalid transport config" in error
    assert attempts == 3
    getattr(client, "get_children2" if operation == "children" else "get_data").assert_called_once_with("/a")


def test_redis_scan_keeps_completed_page_when_next_page_is_malformed(monkeypatch: pytest.MonkeyPatch) -> None:
    send = Mock(side_effect=[("array", [b"7", [b"b", b"a"]]), ("array", [b"0", "malformed"])])
    monkeypatch.setattr(redis, "_send_cmd", send)
    dump = Mock(side_effect=[("first", None), ("", "WRONGTYPE")])
    monkeypatch.setattr(redis, "_dump_redis_key_value", dump)
    entries, error = redis._stream_dump_redis_keys(None, batch=2, delay_ms=0)
    assert entries == [{"key": "a", "value": "first", "error": None}, {"key": "b", "value": None, "error": "WRONGTYPE"}]
    assert error == "unexpected SCAN keys payload: str"
    assert send.call_args.args[2] == "7"


def test_redis_scan_failure_flushes_already_discovered_pending_keys(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(redis, "_send_cmd", Mock(side_effect=[("array", [b"7", [b"kept"]]), ("error", "NOPERM")]))
    monkeypatch.setattr(redis, "_dump_redis_key_value", Mock(return_value=("value", None)))
    entries, error = redis._stream_dump_redis_keys(None, batch=2, delay_ms=0)
    assert error and "NOPERM" in error
    assert entries == [{"key": "kept", "value": "value", "error": None}]


@pytest.mark.parametrize("failure", ["response", "keys", "rounds"])
def test_redis_scan_fault_flushes_pending_after_completed_page(monkeypatch: pytest.MonkeyPatch, failure: str) -> None:
    replies = [("array", [b"7", [b"a", b"b", b"c"]])]
    if failure == "response":
        replies.append(("error", "NOPERM"))
    elif failure == "keys":
        replies.append(("array", [b"0", "malformed"]))
    else:
        monkeypatch.setattr(redis, "_DUMP_MAX_SCAN_ROUNDS", 1)
    monkeypatch.setattr(redis, "_send_cmd", Mock(side_effect=replies))
    dump = Mock(side_effect=[("first", None), ("second", None), ("", "WRONGTYPE")])
    monkeypatch.setattr(redis, "_dump_redis_key_value", dump)
    entries, error = redis._stream_dump_redis_keys(None, batch=2, delay_ms=0)
    assert entries == [
        {"key": "a", "value": "first", "error": None},
        {"key": "b", "value": "second", "error": None},
        {"key": "c", "value": None, "error": "WRONGTYPE"},
    ]
    assert error and {"response": "NOPERM", "keys": "payload", "rounds": "too many iterations"}[failure] in error


@pytest.mark.parametrize("limit,expected", [(None, []), (1, [{"key": "a", "value": "kept", "error": None}])])
def test_redis_empty_scan_and_limit_finish_without_later_fault(
    monkeypatch: pytest.MonkeyPatch, limit, expected
) -> None:
    first = ("array", [b"0", []]) if limit is None else ("array", [b"7", [b"a", b"b"]])
    monkeypatch.setattr(redis, "_send_cmd", Mock(side_effect=[first, AssertionError("unneeded SCAN")]))
    monkeypatch.setattr(redis, "_dump_redis_key_value", Mock(return_value=("kept", None)))
    assert redis._stream_dump_redis_keys(None, batch=2, delay_ms=0, limit=limit) == (expected, None)


def _kstring(value: str) -> bytes:
    encoded = value.encode()
    return struct.pack(">h", len(encoded)) + encoded


def test_kafka_metadata_retains_broker_leaders_and_mixed_topic_authorization() -> None:
    broker = struct.pack(">i", 3) + _kstring("broker.example") + struct.pack(">i", 9093)
    partition = struct.pack(">hiii", 0, 2, 3, 1) + struct.pack(">i", 3) + struct.pack(">ii", 1, 3)
    allowed = struct.pack(">h", 0) + _kstring("allowed") + struct.pack(">i", 1) + partition
    denied = struct.pack(">h", 29) + _kstring("denied") + struct.pack(">i", 0)
    payload = struct.pack(">ii", 42, 1) + broker + struct.pack(">i", 2) + allowed + denied
    result, error = kafka._parse_metadata_response(payload, 42)
    assert error is None and result == {
        "broker_map": {3: ("broker.example", 9093)},
        "partition_leaders": {"allowed": {2: 3}},
        "topic_map": {"allowed": 1, "denied": 0},
        "topics": ["allowed", "denied"],
        "topic_count": 2,
        "topic_errors": {"allowed": 0, "denied": 29},
        "error_codes": [0, 0, 29],
        "auth_required": False,
    }


@pytest.mark.parametrize("cut", [0, 3, 5, 15])
def test_kafka_apiversions_rejects_truncation_with_explicit_error(cut: int) -> None:
    payload = struct.pack(">ihihhh", 42, 0, 1, 1, 0, 10)
    result = kafka._parse_apiversions_response(payload[:cut], 42)
    assert result.ok is False and result.error


@pytest.mark.parametrize("cut", [6, 7, 8, 9])
def test_kafka_apiversions_rejects_missing_array_length(cut: int) -> None:
    payload = struct.pack(">ihihhh", 42, 0, 1, 1, 0, 10)
    result = kafka._parse_apiversions_response(payload[:cut], 42)
    assert result.ok is False and result.error


@pytest.mark.parametrize("maximum", [False, -1, 0, 2, 10001])
def test_mongodb_hello_requires_coherent_non_boolean_wire_version_range(maximum: Any) -> None:
    hello = {"ok": 1, "minWireVersion": 1, "maxWireVersion": maximum, "secondary": False}
    assert mongodb.is_mongodb_hello_response(hello) is (type(maximum) is int and maximum == 2)


def test_oracle_listener_partial_success_preserves_both_endpoint_errors_and_inventory() -> None:
    result = oracle.parse_listener_dump(
        {"ok": False, "error": "status denied", "text": "TNS-01169: listener has not recognized the password"},
        {
            "ok": True,
            "error": "one endpoint unreachable",
            "payload_text": '(SERVICE_NAME=APP)(SID=ORCL)\nService "APP" has 1 instance(s).\nTNS-12528',
        },
    )
    assert result["ok"] is True and result["status_ok"] is False and result["services_ok"] is True
    assert result["services"] == ["APP"] and result["sids"] == ["ORCL"]
    assert result["summary"] == {"password_protected": True, "restricted": True}
    assert result["status_error"] == "status denied" and result["services_error"] == "one endpoint unreachable"
