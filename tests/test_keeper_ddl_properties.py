"""Generated Keeper DDL queue and worker-result contracts."""

from __future__ import annotations

import hashlib
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from redposture_core.modules.keeper import ddl

_QUEUE = "/clickhouse/task_queue/ddl"
_IDENTIFIER = st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789_", min_size=1, max_size=18).filter(
    lambda value: value[0].isalpha() or value[0] == "_"
)
_HOST = st.tuples(
    st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789-", min_size=1, max_size=18),
    st.integers(min_value=1, max_value=65535),
).map(lambda parts: f"{parts[0]}:{parts[1]}")


def _entry(cluster: str, hosts: list[str], *, version: int = 5, query: str | None = None) -> bytes:
    statement = query or f"CREATE DATABASE qa ON CLUSTER {cluster}"
    return (
        f"version: {version}\n"
        f"query: {statement}\n"
        f"hosts: {hosts!r}\n"
        f"initiator: {hosts[0]}\n"
        "tracing: 00000000-0000-0000-0000-000000000000\n"
        "0\n\n0\n"
        "initial_query_id: 11111111-1111-1111-1111-111111111111\n"
    ).encode()


class QueueKeeper:
    def __init__(self, entries: dict[str, bytes], finished: dict[str, bytes] | None = None) -> None:
        self.entries = entries
        self.finished = finished or {}
        self.created: list[bytes] = []

    def get_children2(self, path: str) -> tuple[list[str], int, None]:
        if path == _QUEUE:
            return list(self.entries), 0, None
        if path.endswith("/finished"):
            return list(self.finished), 0, None
        return [], -101, None

    def get_data(self, path: str) -> tuple[bytes | None, int, None]:
        name = path.rsplit("/", 1)[-1]
        if path.startswith(f"{_QUEUE}/query-") and name in self.entries:
            return self.entries[name], 0, None
        if "/finished/" in path and name in self.finished:
            return self.finished[name], 0, None
        return None, -101, None

    def create_sequential(self, path: str, data: bytes) -> tuple[str | None, int]:
        assert path == f"{_QUEUE}/query-"
        self.created.append(data)
        return f"{_QUEUE}/query-{len(self.created):010d}", 0


@given(st.binary(max_size=4096))
def test_keeper_template_parser_is_total_for_arbitrary_bytes(raw: bytes) -> None:
    parsed = ddl._parse_template(raw)
    if parsed is not None:
        assert parsed[0] == raw.decode("utf-8")
        assert parsed[1]
        assert all(isinstance(host, str) and ":" in host for host in parsed[1])
        assert parsed[2]


@given(_IDENTIFIER, st.lists(_HOST, min_size=1, max_size=10, unique=True), st.integers(5, 8), st.booleans())
def test_keeper_template_round_trips_valid_cluster_and_hosts(
    cluster: str, hosts: list[str], version: int, quoted: bool
) -> None:
    cluster_token = f"'{cluster}'" if quoted else cluster
    raw = _entry(cluster, hosts, version=version, query=f"CREATE DATABASE qa ON CLUSTER {cluster_token}")
    parsed = ddl._parse_template(raw)
    assert parsed is not None
    assert parsed[1:] == (hosts, cluster)


@given(st.lists(st.tuples(_IDENTIFIER, _HOST), min_size=0, max_size=8))
def test_keeper_topology_and_selection_follow_distinct_valid_clusters(tasks: list[tuple[str, str]]) -> None:
    entries = {f"query-{index:010d}": _entry(cluster, [host]) for index, (cluster, host) in enumerate(tasks)}
    client = QueueKeeper(entries)
    expected: dict[str, str] = {}
    for cluster, host in tasks:
        expected[cluster] = host

    topology = ddl.read_ddl_topology(client)
    assert topology["status"] == "ok"
    assert topology["clusters"] == {cluster: [host] for cluster, host in expected.items()}
    _template, selected_hosts, selected_cluster, reason = ddl._select_template(client, None)
    if len(expected) == 1:
        assert reason is None
        assert selected_cluster in expected
        assert selected_hosts == [expected[selected_cluster]]
    elif len(expected) > 1:
        assert selected_hosts is None and selected_cluster is None
        assert "multiple ClickHouse clusters" in str(reason)
    else:
        assert selected_hosts is None and selected_cluster is None and reason is None


@given(st.lists(st.booleans(), min_size=1, max_size=8))
def test_keeper_worker_results_never_call_partial_success_full_success(states: list[bool]) -> None:
    hosts = [f"worker-{index}:9000" for index in range(len(states))]
    client = QueueKeeper({}, dict(zip(hosts, (b"0\n" if ok else b"497\nfailed" for ok in states), strict=True)))
    status, results = ddl._wait_for_hosts(client, f"{_QUEUE}/query-0000000000", hosts, 0.1)
    assert results == {host: "ok" if ok else "failed" for host, ok in zip(hosts, states, strict=True)}
    assert status == ("created" if all(states) else "partial" if any(states) else "failed")


@given(_IDENTIFIER, st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789", min_size=8, max_size=40), st.booleans())
def test_keeper_auto_create_uses_discovered_topology_without_exposing_password(
    username: str, password_suffix: str, grant_admin: bool
) -> None:
    password = f"qa-secret-{password_suffix}"
    client = QueueKeeper({"query-0000000000": _entry("qa", ["clickhouse:9000"])}, {"clickhouse:9000": b"0\n"})
    result = ddl.create_user_via_ddl(
        client,
        username,
        password,
        access="Write",
        grant_admin=grant_admin,
        clickhouse_host=None,
        clickhouse_port=None,
        timeout=0.1,
    )
    assert result["status"] == "created"
    assert result["admin_status"] == ("granted" if grant_admin else "not_requested")
    assert len(client.created) == (2 if grant_admin else 1)
    assert b"ON CLUSTER qa" in client.created[0]
    assert hashlib.sha256(password.encode()).hexdigest().encode() in client.created[0]
    assert password not in str(result)
    assert password.encode() not in b"".join(client.created)


@pytest.mark.parametrize(
    "query",
    ["SELECT 'ON CLUSTER qa'", "CREATE DATABASE qa -- ON CLUSTER qa", "SELECT 1 /* ON CLUSTER qa */"],
)
def test_keeper_does_not_infer_cluster_from_sql_literal_or_comment(query: str) -> None:
    assert ddl._parse_template(_entry("qa", ["clickhouse:9000"], query=query)) is None


@given(st.text(alphabet="abcXYZ0123 'ONCLUSTER/", max_size=50))
def test_keeper_cluster_parser_ignores_quoted_decoys_before_real_clause(decoy: str) -> None:
    escaped = decoy.replace("'", "''")
    raw = _entry(
        "qa",
        ["clickhouse:9000"],
        query=f"CREATE USER '{escaped} ON CLUSTER wrong' ON CLUSTER qa",
    )
    parsed = ddl._parse_template(raw)
    assert parsed is not None
    assert parsed[2] == "qa"


@pytest.mark.parametrize("query", ["CREATE USER '' ON CLUSTER qa", "CREATE USER 'a''b' ON CLUSTER qa"])
def test_keeper_cluster_parser_handles_empty_and_doubled_sql_quotes(query: str) -> None:
    assert ddl._cluster_from_query(query) == "qa"


def test_keeper_parses_clickhouse_escaped_uuid_before_cluster_clause() -> None:
    raw = _entry(
        "qa_second",
        ["clickhouse:9000"],
        query=(
            "CREATE DATABASE IF NOT EXISTS redposture_second_probe "
            "UUID \\'1c3c40a6-085e-4e8e-a4b1-8ad7199bab87\\' ON CLUSTER qa_second"
        ),
    )
    parsed = ddl._parse_template(raw)
    assert parsed is not None
    assert parsed[2] == "qa_second"


@given(_IDENTIFIER, st.lists(_HOST, min_size=1, max_size=6, unique=True))
def test_keeper_generated_clickhouse_escaped_uuid_keeps_cluster_and_hosts(cluster: str, hosts: list[str]) -> None:
    raw = _entry(
        cluster,
        hosts,
        query=(
            f"CREATE DATABASE IF NOT EXISTS qa UUID \\'1c3c40a6-085e-4e8e-a4b1-8ad7199bab87\\' ON CLUSTER {cluster}"
        ),
    )
    parsed = ddl._parse_template(raw)
    assert parsed is not None
    assert parsed[1:] == (hosts, cluster)


def test_keeper_escaped_sql_literal_cannot_supply_cluster_name() -> None:
    raw = _entry("qa", ["clickhouse:9000"], query="CREATE USER \\'ON CLUSTER qa\\'")
    assert ddl._parse_template(raw) is None


def test_keeper_does_not_assume_a_literal_cluster_macro_is_configured() -> None:
    raw = _entry("qa", ["clickhouse:9000"], query="CREATE DATABASE qa ON CLUSTER '{cluster}'")
    assert ddl._parse_template(raw) is None
    client = QueueKeeper({})
    result = ddl.create_user_via_ddl(
        client,
        "audituser",
        "secret",
        access="Write",
        grant_admin=False,
        clickhouse_host="clickhouse",
        clickhouse_port=9000,
        clickhouse_cluster="{cluster}",
        timeout=0.1,
    )
    assert result["status"] == "unavailable"
    assert not client.created


def test_keeper_cluster_clause_after_block_comment_is_recognized() -> None:
    raw = _entry("qa", ["clickhouse:9000"], query="CREATE DATABASE qa /* ON CLUSTER wrong */ ON CLUSTER qa")
    parsed = ddl._parse_template(raw)
    assert parsed is not None and parsed[2] == "qa"


@pytest.mark.parametrize("access", ["Read", "Denied", "Absent", "Unknown"])
def test_keeper_non_writable_ddl_access_never_creates_task(access: str) -> None:
    client = QueueKeeper({"query-0000000000": _entry("qa", ["clickhouse:9000"])}, {"clickhouse:9000": b"0\n"})
    result = ddl.create_user_via_ddl(
        client,
        "audituser",
        "secret",
        access=access,
        grant_admin=True,
        clickhouse_host=None,
        clickhouse_port=None,
        timeout=0.1,
    )
    assert result["status"] == "unavailable"
    assert result["reason"] == f"DDL access is {access}"
    assert not client.created


def test_keeper_auto_create_refuses_missing_and_ambiguous_topology_without_writes() -> None:
    cases = [
        ({}, "ClickHouse host and cluster"),
        (
            {
                "query-0000000000": _entry("qa", ["clickhouse:9000"]),
                "query-0000000001": _entry("prod", ["other:9000"]),
            },
            "multiple ClickHouse clusters",
        ),
    ]
    for entries, expected_reason in cases:
        client = QueueKeeper(entries)
        result = ddl.create_user_via_ddl(
            client,
            "audituser",
            "secret",
            access="Write",
            grant_admin=True,
            clickhouse_host=None,
            clickhouse_port=None,
            timeout=0.1,
        )
        assert result["status"] == "unavailable"
        assert expected_reason in result["reason"]
        assert not client.created


def test_keeper_explicit_cluster_selects_only_its_workers() -> None:
    client = QueueKeeper(
        {
            "query-0000000000": _entry("qa", ["qa-worker:9000"]),
            "query-0000000001": _entry("prod", ["prod-worker:9000"]),
        },
        {"qa-worker:9000": b"0\n"},
    )
    result = ddl.create_user_via_ddl(
        client,
        "audituser",
        "secret",
        access="Write",
        grant_admin=False,
        clickhouse_host=None,
        clickhouse_port=None,
        clickhouse_cluster="qa",
        timeout=0.1,
    )
    assert result["status"] == "created"
    assert result["hosts"] == ["qa-worker:9000"]
    assert b"ON CLUSTER qa" in client.created[0]
    assert b"prod-worker" not in client.created[0]


def test_keeper_bad_templates_are_ignored_before_auto_selection() -> None:
    invalid = _entry("wrong", ["other:9000"]).replace(b"initial_query_id:", b"missing_query_id:")
    client = QueueKeeper(
        {
            "query-0000000000": _entry("qa", ["clickhouse:9000"]),
            "query-0000000001": invalid,
            "not-a-task": _entry("wrong", ["other:9000"]),
        }
    )
    topology = ddl.read_ddl_topology(client)
    assert topology["clusters"] == {"qa": ["clickhouse:9000"]}


def test_keeper_auto_topology_uses_newest_host_list_not_retired_workers() -> None:
    client = QueueKeeper(
        {
            "query-0000000000": _entry("qa", ["retired-worker:9000"]),
            "query-0000000001": _entry("qa", ["current-worker:9000"]),
        }
    )
    assert ddl.read_ddl_topology(client)["clusters"] == {"qa": ["current-worker:9000"]}
    _template, hosts, cluster, reason = ddl._select_template(client, None)
    assert (hosts, cluster, reason) == (["current-worker:9000"], "qa", None)


def test_keeper_task_order_remains_numeric_after_ten_digit_boundary() -> None:
    client = QueueKeeper(
        {
            "query-9999999999": _entry("qa", ["old-worker:9000"]),
            "query-10000000000": _entry("qa", ["new-worker:9000"]),
        }
    )
    assert ddl.read_ddl_topology(client)["clusters"] == {"qa": ["new-worker:9000"]}


def test_keeper_large_queue_cannot_hide_a_second_cluster_from_auto_selection() -> None:
    entries = {f"query-{index:010d}": _entry("qa", ["clickhouse:9000"]) for index in range(1, 514)}
    entries["query-0000000000"] = _entry("other", ["other-worker:9000"])
    client = QueueKeeper(entries, {"clickhouse:9000": b"0\n"})
    result = ddl.create_user_via_ddl(
        client,
        "audituser",
        "secret",
        access="Write",
        grant_admin=False,
        clickhouse_host=None,
        clickhouse_port=None,
        timeout=0.1,
    )
    assert result["status"] == "unavailable"
    assert "limit" in str(result["reason"]).lower()
    assert not client.created
    assert ddl.read_ddl_topology(client)["status"] == "unavailable"


def test_keeper_large_queue_allows_explicit_host_and_cluster() -> None:
    entries = {f"query-{index:010d}": _entry("qa", ["clickhouse:9000"]) for index in range(514)}
    client = QueueKeeper(entries, {"clickhouse:9000": b"0\n"})
    result = ddl.create_user_via_ddl(
        client,
        "audituser",
        "secret",
        access="Write",
        grant_admin=False,
        clickhouse_host="clickhouse",
        clickhouse_port=9000,
        clickhouse_cluster="qa",
        timeout=0.1,
    )
    assert result["status"] == "created"
    assert result["hosts"] == ["clickhouse:9000"]


def test_keeper_task_scan_accepts_exact_limit_and_rejects_next_task() -> None:
    entries = {f"query-{index:010d}": _entry("qa", ["clickhouse:9000"]) for index in range(512)}
    client = QueueKeeper(entries)
    assert ddl.read_ddl_topology(client)["clusters"] == {"qa": ["clickhouse:9000"]}
    client.entries["query-0000000512"] = _entry("qa", ["clickhouse:9000"])
    assert ddl.read_ddl_topology(client)["status"] == "unavailable"


def test_keeper_explicit_topology_needs_confirmed_queue_response() -> None:
    class EmptyResponse(QueueKeeper):
        def get_children2(self, path: str) -> tuple[list[str] | None, int, None]:  # type: ignore[override]
            if path == _QUEUE:
                return None, 0, None
            return super().get_children2(path)

    client = EmptyResponse({})
    result = ddl.create_user_via_ddl(
        client,
        "audituser",
        "secret",
        access="Write",
        grant_admin=False,
        clickhouse_host="clickhouse",
        clickhouse_port=9000,
        clickhouse_cluster="qa",
        timeout=0.1,
    )
    assert result["status"] == "unavailable"
    assert not client.created


def test_keeper_unavailable_queue_reports_reason_without_writing() -> None:
    class MissingQueue(QueueKeeper):
        def get_children2(self, path: str) -> tuple[list[str], int, None]:
            if path == _QUEUE:
                return [], -101, None
            return super().get_children2(path)

    client = MissingQueue({})
    assert ddl.read_ddl_topology(client)["reason"] == "DDL queue does not exist"
    result = ddl.create_user_via_ddl(
        client,
        "audituser",
        "secret",
        access="Write",
        grant_admin=True,
        clickhouse_host="clickhouse",
        clickhouse_port=9000,
        clickhouse_cluster="qa",
        timeout=0.1,
    )
    assert result["status"] == "unavailable"
    assert result["task_path"] is None
    assert not client.created


def test_keeper_topology_read_error_does_not_escape_or_mutate() -> None:
    class DisconnectedQueue(QueueKeeper):
        def get_children2(self, path: str) -> tuple[list[str], int, None]:
            if path == _QUEUE:
                raise ConnectionError("QA disconnect")
            return super().get_children2(path)

    client = DisconnectedQueue({})
    assert ddl.read_ddl_topology(client)["reason"] == "ConnectionError"
    result = ddl.create_user_via_ddl(
        client,
        "audituser",
        "secret",
        access="Write",
        grant_admin=True,
        clickhouse_host=None,
        clickhouse_port=None,
        timeout=0.1,
    )
    assert result["status"] == "unavailable"
    assert result["reason"] == "ConnectionError"
    assert not client.created


def test_keeper_create_enqueue_failure_never_claims_success() -> None:
    class RejectedCreate(QueueKeeper):
        def create_sequential(self, path: str, data: bytes) -> tuple[None, int]:
            self.created.append(data)
            return None, -102

    client = RejectedCreate({"query-0000000000": _entry("qa", ["clickhouse:9000"])})
    result = ddl.create_user_via_ddl(
        client,
        "audituser",
        "secret",
        access="Write",
        grant_admin=True,
        clickhouse_host=None,
        clickhouse_port=None,
        timeout=0.1,
    )
    assert result["status"] == "failed"
    assert result["admin_status"] == "not_attempted"
    assert result["task_path"] is None
    assert len(client.created) == 1


def test_keeper_grant_enqueue_failure_preserves_confirmed_create() -> None:
    class RejectedGrant(QueueKeeper):
        def create_sequential(self, path: str, data: bytes) -> tuple[str | None, int]:
            if self.created:
                self.created.append(data)
                return None, -102
            return super().create_sequential(path, data)

    client = RejectedGrant({"query-0000000000": _entry("qa", ["clickhouse:9000"])}, {"clickhouse:9000": b"0\n"})
    result = ddl.create_user_via_ddl(
        client,
        "audituser",
        "secret",
        access="Write",
        grant_admin=True,
        clickhouse_host=None,
        clickhouse_port=None,
        timeout=0.1,
    )
    assert result["status"] == "created"
    assert result["admin_status"] == "failed"
    assert result["task_path"] is not None
    assert result["grant_task_path"] is None


def test_keeper_finished_read_failure_is_unverified_not_created() -> None:
    class RejectedFinishedRead(QueueKeeper):
        def get_children2(self, path: str) -> tuple[list[str], int, None]:
            if path.endswith("/finished"):
                return [], -102, None
            return super().get_children2(path)

    client = RejectedFinishedRead({"query-0000000000": _entry("qa", ["clickhouse:9000"])})
    result = ddl.create_user_via_ddl(
        client,
        "audituser",
        "secret",
        access="Write",
        grant_admin=True,
        clickhouse_host=None,
        clickhouse_port=None,
        timeout=0.1,
    )
    assert result["status"] == "unverified"
    assert result["admin_status"] == "not_attempted"
    assert len(client.created) == 1


def test_keeper_partially_confirmed_workers_never_trigger_admin_grant() -> None:
    hosts = ["worker-a:9000", "worker-b:9000"]
    client = QueueKeeper({"query-0000000000": _entry("qa", hosts)}, {hosts[0]: b"0\n"})
    result = ddl.create_user_via_ddl(
        client,
        "audituser",
        "secret",
        access="Write",
        grant_admin=True,
        clickhouse_host=None,
        clickhouse_port=None,
        timeout=0.1,
    )
    assert result["status"] == "partial"
    assert result["admin_status"] == "not_attempted"
    assert result["results"] == {hosts[0]: "ok"}
    assert len(client.created) == 1


@pytest.mark.parametrize(
    "query", ["CREATE USER x; DROP USER y", "CREATE USER x\nDROP USER y", "CREATE USER x\rDROP USER y"]
)
def test_keeper_entry_builder_rejects_multiple_statements(query: str) -> None:
    with pytest.raises(ValueError, match="exactly one statement"):
        ddl._build_entry(query, ["clickhouse:9000"])


def test_keeper_entry_builder_escapes_query_quotes_like_clickhouse() -> None:
    query = "CREATE USER audituser ON CLUSTER qa IDENTIFIED WITH sha256_hash BY 'abcdef'"
    entry = ddl._build_entry(query, ["clickhouse:9000"])
    assert b"query: CREATE USER audituser ON CLUSTER qa IDENTIFIED WITH sha256_hash BY \\'abcdef\\'\n" in entry
    parsed = ddl._parse_template(entry)
    assert parsed is not None
    assert parsed[2] == "qa"


def test_keeper_entry_builder_serializes_multiple_workers_without_spaces() -> None:
    entry = ddl._build_entry("CREATE DATABASE qa ON CLUSTER qa", ["ch-a:9000", "ch-b:9000"])
    assert b"hosts: ['ch-a:9000','ch-b:9000']\n" in entry
    parsed = ddl._parse_template(entry)
    assert parsed is not None
    assert parsed[1] == ["ch-a:9000", "ch-b:9000"]


def test_keeper_parser_rejects_oversized_and_invalid_escapes() -> None:
    assert ddl._parse_template(b"a" * (64 * 1024 + 1)) is None
    assert ddl._parse_template(_entry("qa", ["clickhouse:9000"], query=r"CREATE DATABASE qa \q ON CLUSTER qa")) is None
    assert ddl._valid_hosts("[" + "x" * 16_385 + "]") is None
    assert ddl._valid_hosts("[") is None


@given(st.one_of(st.integers(), st.text(), st.dictionaries(st.text(max_size=5), st.integers()), st.none()))
def test_keeper_host_parser_rejects_non_list_values(value: Any) -> None:
    assert ddl._valid_hosts(repr(value)) is None
