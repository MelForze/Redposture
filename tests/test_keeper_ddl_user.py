from __future__ import annotations

import hashlib

import pytest

from redposture_core.audit_models import AuditRecord
from redposture_core.cli_args import parse_args
from redposture_core.modules.keeper import ddl, render
from redposture_core.modules.keeper import policy as keeper_policy
from redposture_core.modules.keeper import stage as keeper_stage
from redposture_core.modules.zookeeper import engine
from redposture_core.stage_runtime import AuditCredentialRun, AuditHookContext

_QUEUE = "/clickhouse/task_queue/ddl"
_TEMPLATE = (
    b"version: 5\n"
    b"query: CREATE DATABASE example ON CLUSTER qa\n"
    b"hosts: ['clickhouse:9000']\n"
    b"initiator: clickhouse:9000\n"
    b"tracing: 00000000-0000-0000-0000-000000000000\n"
    b"0\n\n0\n"
    b"initial_query_id: 11111111-1111-1111-1111-111111111111\n"
)


class CompletedKeeper:
    def __init__(self, *, existing: bool = True, result: bytes = b"0\n\n") -> None:
        self.existing = existing
        self.result = result
        self.created: list[bytes] = []

    def get_children2(self, path: str):
        if path == _QUEUE:
            return (["query-0000000000"] if self.existing else []), 0, None
        if path.endswith("/finished"):
            return ["clickhouse:9000"], 0, None
        return [], -101, None

    def get_data(self, path: str):
        if path == f"{_QUEUE}/query-0000000000":
            return _TEMPLATE, 0, None
        if "/finished/" in path:
            return self.result, 0, None
        return None, -101, None

    def create_sequential(self, path: str, data: bytes):
        assert path == f"{_QUEUE}/query-"
        self.created.append(data)
        return f"{_QUEUE}/query-{len(self.created):010d}", 0


def test_keeper_user_create_and_admin_grant_are_separate_confirmed_tasks() -> None:
    client = CompletedKeeper()
    result = ddl.create_user_via_ddl(
        client,
        "audituser",
        "NotInTask-123",
        access="Write",
        grant_admin=True,
        clickhouse_host=None,
        clickhouse_port=None,
        timeout=1.0,
    )

    assert result["status"] == "created"
    assert result["admin_status"] == "granted"
    assert result["hosts"] == ["clickhouse:9000"]
    assert result["cluster"] == "qa"
    assert len(client.created) == 2
    assert b"NotInTask-123" not in b"".join(client.created)
    expected_hash = hashlib.sha256(b"NotInTask-123").hexdigest().encode()
    assert b"sha256_hash BY \\'" + expected_hash + b"\\'" in client.created[0]
    assert b"CREATE USER audituser ON CLUSTER qa" in client.created[0]
    assert b"GRANT ON CLUSTER qa ALL ON *.* TO audituser WITH GRANT OPTION" in client.created[1]


def test_keeper_empty_queue_needs_explicit_clickhouse_host() -> None:
    client = CompletedKeeper(existing=False)
    result = ddl.create_user_via_ddl(
        client,
        "audituser",
        "password",
        access="Write",
        grant_admin=False,
        clickhouse_host=None,
        clickhouse_port=None,
        timeout=1.0,
    )
    assert result["status"] == "unavailable"
    assert client.created == []


def test_keeper_empty_queue_needs_cluster_even_with_host() -> None:
    client = CompletedKeeper(existing=False)
    result = ddl.create_user_via_ddl(
        client,
        "audituser",
        "password",
        access="Write",
        grant_admin=False,
        clickhouse_host="clickhouse",
        clickhouse_port=9000,
        timeout=1.0,
    )
    assert result["status"] == "unavailable"
    assert client.created == []


def test_keeper_empty_queue_uses_explicit_clickhouse_host_and_cluster() -> None:
    client = CompletedKeeper(existing=False)
    result = ddl.create_user_via_ddl(
        client,
        "audituser",
        "password",
        access="Write",
        grant_admin=False,
        clickhouse_host="clickhouse",
        clickhouse_port=9000,
        clickhouse_cluster="qa",
        timeout=1.0,
    )
    assert result["status"] == "created"
    assert result["hosts"] == ["clickhouse:9000"]
    assert result["cluster"] == "qa"
    assert len(client.created) == 1


def test_keeper_cli_accepts_explicit_ddl_user_flags() -> None:
    args = parse_args(
        [
            "keeper",
            "-t",
            "127.0.0.1",
            "--create-user",
            "audituser",
            "--create-userpass",
            "password",
            "--grant-admin",
            "--clickhouse-host",
            "clickhouse",
            "--clickhouse-port",
            "9000",
            "--clickhouse-cluster",
            "qa",
        ]
    )
    assert (args.create_user, args.create_userpass, args.grant_admin) == ("audituser", "password", True)
    assert (args.clickhouse_host, args.clickhouse_port, args.clickhouse_cluster) == ("clickhouse", 9000, "qa")


def test_keeper_ddl_result_renders_without_secret() -> None:
    lines = render._format_ddl_user_creation_records(
        {
            "host": "127.0.0.1",
            "port": 9181,
            "service": "keeper",
            "module": "keeper",
            "ddl_user_creation": {
                "username": "audituser",
                "status": "created",
                "admin_status": "granted",
                "cluster": "qa",
                "hosts": ["clickhouse:9000"],
                "task_path": f"{_QUEUE}/query-0000000001",
            },
        },
        "txt",
    )
    assert lines[0].endswith('[+] ClickHouse user "audituser" created (cluster:qa) (hosts:1:clickhouse:9000)')
    assert lines[1].endswith("[+] Administration rights granted (cluster:qa) (hosts:1:clickhouse:9000)")
    assert "password" not in "\n".join(lines)


def test_keeper_non_writable_queue_does_not_enqueue() -> None:
    client = CompletedKeeper()
    result = ddl.create_user_via_ddl(
        client,
        "audituser",
        "password",
        access="Read",
        grant_admin=True,
        clickhouse_host=None,
        clickhouse_port=None,
        timeout=1.0,
    )
    assert result["status"] == "unavailable"
    assert client.created == []


def test_keeper_worker_error_does_not_enqueue_admin_grant() -> None:
    client = CompletedKeeper(result=b"497\nACCESS_DENIED")
    result = ddl.create_user_via_ddl(
        client,
        "audituser",
        "password",
        access="Write",
        grant_admin=True,
        clickhouse_host=None,
        clickhouse_port=None,
        timeout=1.0,
    )
    assert result["status"] == "failed"
    assert result["admin_status"] == "not_attempted"
    assert len(client.created) == 1


def test_keeper_ddl_template_accepts_quoted_cluster() -> None:
    raw = _TEMPLATE.replace(b"ON CLUSTER qa", b"ON CLUSTER 'qa'")
    parsed = ddl._parse_template(raw)
    assert parsed is not None
    assert parsed[2] == "qa"


@pytest.mark.parametrize("version", [5, 6, 7, 8])
def test_keeper_reads_modern_ddl_versions_without_copying_task_privileges(version: int) -> None:
    raw = _TEMPLATE.replace(b"version: 5", f"version: {version}".encode())
    if version >= 6:
        raw += b"is_backup_restore: 1\n"
    if version >= 7:
        raw += b"parent: 11111111-1111-1111-1111-111111111111\n"
    if version >= 8:
        raw += b"initiator_user: root\ninitiator_roles: admin\n"

    class ModernKeeper(CompletedKeeper):
        def get_data(self, path: str):
            if path == f"{_QUEUE}/query-0000000000":
                return raw, 0, None
            return super().get_data(path)

    client = ModernKeeper()
    assert ddl.read_ddl_topology(client)["clusters"] == {"qa": ["clickhouse:9000"]}
    result = ddl.create_user_via_ddl(
        client,
        "audituser",
        "password",
        access="Write",
        grant_admin=False,
        clickhouse_host=None,
        clickhouse_port=None,
        timeout=1.0,
    )
    assert result["status"] == "created"
    assert client.created[0].startswith(b"version: 5\n")
    assert b"is_backup_restore: 1" not in client.created[0]
    assert b"initiator_user: root" not in client.created[0]


def test_keeper_ddl_does_not_guess_between_multiple_clusters() -> None:
    class MultiClusterKeeper(CompletedKeeper):
        def get_children2(self, path: str):
            if path == _QUEUE:
                return ["query-0000000000", "query-0000000001"], 0, None
            return super().get_children2(path)

        def get_data(self, path: str):
            if path == f"{_QUEUE}/query-0000000001":
                return _TEMPLATE.replace(b"ON CLUSTER qa", b"ON CLUSTER other"), 0, None
            return super().get_data(path)

    client = MultiClusterKeeper()
    result = ddl.create_user_via_ddl(
        client,
        "audituser",
        "password",
        access="Write",
        grant_admin=False,
        clickhouse_host=None,
        clickhouse_port=None,
        timeout=1.0,
    )
    assert result["status"] == "unavailable"
    assert "cluster" in str(result["reason"]).lower()
    assert not client.created


def test_keeper_read_only_topology_lists_all_clusters_and_worker_hosts() -> None:
    class MultiClusterKeeper(CompletedKeeper):
        def get_children2(self, path: str):
            if path == _QUEUE:
                return ["query-0000000000", "query-0000000001"], 0, None
            return super().get_children2(path)

        def get_data(self, path: str):
            if path == f"{_QUEUE}/query-0000000001":
                return (
                    _TEMPLATE.replace(b"ON CLUSTER qa", b"ON CLUSTER other").replace(
                        b"clickhouse:9000", b"othernode:9000"
                    ),
                    0,
                    None,
                )
            return super().get_data(path)

    client = MultiClusterKeeper()
    topology = ddl.read_ddl_topology(client)
    assert topology["status"] == "ok"
    assert topology["clusters"] == {
        "other": ["othernode:9000"],
        "qa": ["clickhouse:9000"],
    }
    assert client.created == []


def test_keeper_cli_accepts_read_only_topology_flags() -> None:
    args = parse_args(["keeper", "-t", "127.0.0.1", "--show-cluster", "--show-hosts"])
    assert args.show_cluster is True
    assert args.show_hosts is True


def test_keeper_help_groups_topology_flags_first_and_cluster_before_host(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exit_info:
        parse_args(["keeper", "--help"])
    assert exit_info.value.code == 0
    help_text = capsys.readouterr().out
    ddl_section = help_text.split("Keeper DDL user creation:", 1)[1]
    flags = ("--show-cluster", "--show-hosts", "--create-user", "--clickhouse-cluster", "--clickhouse-host")
    positions = [ddl_section.index(flag) for flag in flags]
    assert positions == sorted(positions)
    assert "Keeper DDL topology:" not in help_text


@pytest.mark.parametrize(
    "extra",
    [
        ["--create-user", "audituser"],
        ["--create-userpass", "password"],
        ["--grant-admin"],
    ],
)
def test_keeper_rejects_incomplete_mutating_flags(extra: list[str]) -> None:
    class Console:
        def __init__(self) -> None:
            self.errors: list[str] = []

        def error(self, message: str) -> None:
            self.errors.append(message)

    args = parse_args(["keeper", "-t", "127.0.0.1", *extra])
    console = Console()
    assert keeper_policy.validate_args(args, console) == 2
    assert console.errors


@pytest.mark.parametrize(
    ("username", "cluster", "host"),
    [
        ("bad;user", "qa", "clickhouse"),
        ("audituser", "qa;DROP", "clickhouse"),
        ("audituser", "qa", "keeper:9181"),
    ],
)
def test_keeper_rejects_invalid_identifiers_before_writing(username: str, cluster: str, host: str) -> None:
    client = CompletedKeeper(existing=False)
    result = ddl.create_user_via_ddl(
        client,
        username,
        "password",
        access="Write",
        grant_admin=True,
        clickhouse_host=host,
        clickhouse_port=9000,
        clickhouse_cluster=cluster,
        timeout=1.0,
    )
    assert result["status"] == "unavailable"
    assert client.created == []


def test_keeper_data_hook_passes_confirmed_anonymous_queue_to_user_action(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    args = parse_args(["keeper", "-t", "127.0.0.1", "--create-user", "audituser", "--create-userpass", "password"])
    spec = keeper_stage.build_keeper_spec(args)
    assert spec.lifecycle_state_factory is not None and spec.data is not None
    state = spec.lifecycle_state_factory(None)
    state.zookeeper_state.anonymous_client = CompletedKeeper()
    record = AuditRecord.from_mapping(
        {
            "host": "127.0.0.1",
            "port": 9181,
            "status": "open_no_auth",
            "is_keeper": True,
            "is_zookeeper": True,
            "ddl_access": "Write",
        },
        module="keeper",
        service="keeper",
    )
    monkeypatch.setattr(engine, "collect_zookeeper_implementation_data", lambda *_args: record.to_dict())
    ctx = AuditHookContext(
        args=args,
        logger=None,
        host="127.0.0.1",
        port=9181,
        credential=AuditCredentialRun(source="anonymous"),
        lifecycle_state=state,
    )
    output = spec.data(ctx, record).to_dict()
    assert output["ddl_user_creation"]["status"] == "created"
    assert "password" not in str(output["ddl_user_creation"])


def test_keeper_writable_ddl_queue_can_run_action_when_root_requires_auth() -> None:
    args = parse_args(["keeper", "-t", "127.0.0.1", "--create-user", "audituser", "--create-userpass", "password"])
    spec = keeper_stage.build_keeper_spec(args)
    record = AuditRecord.from_mapping(
        {"host": "127.0.0.1", "port": 9181, "status": "auth_required", "ddl_access": "Write"},
        module="keeper",
        service="keeper",
    )
    assert spec.deep_gate is not None and spec.deep_gate(record)[0] is True
    assert spec.credential_gate is not None
    assert spec.credential_gate(AuditCredentialRun(source="anonymous"), record)[0] is True
