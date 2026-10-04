"""Operator decisions around Keeper DDL account creation."""

from __future__ import annotations

from collections.abc import Callable
from io import StringIO
from typing import TextIO, cast

import pytest

from redposture_core.audit_models import AuditRecord
from redposture_core.cli_args import parse_args
from redposture_core.modules.keeper import interactive
from redposture_core.modules.keeper import render as keeper_render
from redposture_core.modules.keeper import stage as keeper_stage
from redposture_core.modules.zookeeper import engine
from redposture_core.stage_runtime import AuditCredentialRun, AuditHookContext

_QUEUE = "/clickhouse/task_queue/ddl"


def _task(cluster: str, hosts: list[str]) -> bytes:
    return (
        "version: 5\n"
        f"query: CREATE DATABASE qa ON CLUSTER {cluster}\n"
        f"hosts: {hosts!r}\n"
        f"initiator: {hosts[0]}\n"
        "tracing: 00000000-0000-0000-0000-000000000000\n"
        "0\n\n0\n"
        "initial_query_id: 11111111-1111-1111-1111-111111111111\n"
    ).encode()


class KeeperQueue:
    def __init__(self, tasks: dict[str, bytes]) -> None:
        self.tasks = tasks
        self.created: list[bytes] = []

    def get_children2(self, path: str) -> tuple[list[str], int, None]:
        if path == _QUEUE:
            return list(self.tasks), 0, None
        if path.endswith("/finished"):
            return ["ch-a:9000", "ch-b:9000", "ch-c:9000"], 0, None
        return [], -101, None

    def get_data(self, path: str) -> tuple[bytes | None, int, None]:
        if path.startswith(f"{_QUEUE}/query-") and path.rsplit("/", 1)[-1] in self.tasks:
            return self.tasks[path.rsplit("/", 1)[-1]], 0, None
        if "/finished/" in path:
            return b"0\n", 0, None
        return None, -101, None

    def create_sequential(self, path: str, data: bytes) -> tuple[str, int]:
        assert path == f"{_QUEUE}/query-"
        self.created.append(data)
        return f"{_QUEUE}/query-{len(self.created) + len(self.tasks):010d}", 0

    def close(self) -> None:
        return None

    def connect(self) -> None:
        return None

    def create(self, path: str, data: bytes, *, flags: int = 0) -> int:
        assert path.startswith(f"{_QUEUE}/redposture-probe-") and data == b"" and flags == 1
        return 0

    def delete(self, path: str, version: int = -1) -> int:
        assert path.startswith(f"{_QUEUE}/redposture-probe-") and version == -1
        return 0


def _run(
    client: KeeperQueue,
    replies: str,
    *,
    grant_admin: bool = True,
    refresh_session: Callable[[], tuple[bool, str | None]] | None = None,
    **kwargs: object,
) -> tuple[dict, str]:
    output = StringIO()
    result = interactive.run_user_creation(
        client,
        "audituser",
        "not-shown-password",
        access="Write",
        grant_admin=grant_admin,
        clickhouse_host=kwargs.get("clickhouse_host"),
        clickhouse_port=9000,
        clickhouse_cluster=kwargs.get("clickhouse_cluster"),
        timeout=0.1,
        keeper_target="127.0.0.1:9181",
        input_stream=StringIO(replies),
        output_stream=output,
        refresh_session=refresh_session,
    )
    return result, output.getvalue()


def test_keeper_interactive_confirms_creation_then_admin_grant() -> None:
    client = KeeperQueue({"query-0000000000": _task("qa", ["ch-a:9000", "ch-b:9000"])})
    result, transcript = _run(client, "a\na\ny\ny\n")
    assert result["status"] == "created"
    assert result["admin_status"] == "granted"
    assert len(client.created) == 2
    assert b"hosts: ['ch-a:9000', 'ch-b:9000']" in client.created[0]
    assert b"GRANT ON CLUSTER qa ALL ON *.* TO audituser WITH GRANT OPTION" in client.created[1]
    assert "127.0.0.1:9181" in transcript
    assert "not-shown-password" not in transcript
    assert "GRANT ALL ON *.*" in transcript


def test_keeper_interactive_selects_one_cluster_and_host_and_declines_grant() -> None:
    client = KeeperQueue(
        {
            "query-0000000000": _task("qa", ["ch-a:9000", "ch-b:9000"]),
            "query-0000000001": _task("prod", ["ch-c:9000"]),
        }
    )
    result, transcript = _run(client, "2\n1\ny\nn\n")
    assert result["status"] == "created"
    assert result["admin_status"] == "declined"
    assert len(client.created) == 1
    assert b"ON CLUSTER qa" in client.created[0]
    assert b"hosts: ['ch-a:9000']" in client.created[0]
    assert "only on selected workers" in transcript


def test_keeper_interactive_all_clusters_create_separate_tasks() -> None:
    client = KeeperQueue(
        {
            "query-0000000000": _task("qa", ["ch-a:9000", "ch-b:9000"]),
            "query-0000000001": _task("prod", ["ch-c:9000"]),
        }
    )
    result, _transcript = _run(client, "a\na\na\ny\ny\nn\n")
    assert len(result["clusters"]) == 2
    assert [item["status"] for item in result["clusters"]] == ["created", "created"]
    assert [item["admin_status"] for item in result["clusters"]] == ["granted", "declined"]
    assert len(client.created) == 3
    assert b"ON CLUSTER prod" in client.created[0]
    assert b"ON CLUSTER qa" in client.created[1]


def test_keeper_interactive_no_or_eof_before_create_never_writes() -> None:
    for replies in ("1\na\nn\n", "1\na\n"):
        client = KeeperQueue({"query-0000000000": _task("qa", ["ch-a:9000"])})
        result, _transcript = _run(client, replies)
        assert result["status"] == "declined"
        assert not client.created


def test_keeper_interactive_empty_queue_requires_explicit_host_and_cluster() -> None:
    client = KeeperQueue({})
    result, transcript = _run(client, "y\n")
    assert result["status"] == "unavailable"
    assert "--clickhouse-host" in transcript
    assert not client.created


def test_keeper_interactive_explicit_topology_skips_menus_but_requires_confirmation() -> None:
    client = KeeperQueue({})
    result, transcript = _run(client, "y\nn\n", clickhouse_host="ch-a", clickhouse_cluster="qa")
    assert result["status"] == "created"
    assert result["admin_status"] == "declined"
    assert len(client.created) == 1
    assert "Choose cluster" not in transcript
    assert "Create user? [y/N]" in transcript


def test_keeper_interactive_refreshes_expired_session_after_each_approval() -> None:
    class ExpiringKeeper(KeeperQueue):
        expired = False

        def get_children2(self, path: str) -> tuple[list[str], int, None]:
            if self.expired:
                raise ConnectionError("session expired while operator was reading")
            return super().get_children2(path)

    client = ExpiringKeeper({"query-0000000000": _task("qa", ["ch-a:9000"])})
    refreshes: list[str] = []

    def refresh() -> tuple[bool, str | None]:
        client.expired = False
        refreshes.append("refresh")
        return True, None

    class ExpiringInput:
        def __init__(self, answers: str) -> None:
            self._stream = StringIO(answers)

        def readline(self, *args: object) -> str:
            answer = self._stream.readline(*args)
            if answer == "y\n":
                client.expired = True
            return answer

    output = StringIO()
    result = interactive.run_user_creation(
        client,
        "audituser",
        "secret",
        access="Write",
        grant_admin=True,
        clickhouse_host=None,
        clickhouse_port=None,
        clickhouse_cluster=None,
        timeout=0.1,
        keeper_target="127.0.0.1:9181",
        input_stream=cast(TextIO, ExpiringInput("a\na\ny\ny\n")),
        output_stream=output,
        refresh_session=refresh,
    )
    assert result["status"] == "created"
    assert result["admin_status"] == "granted"
    assert refreshes == ["refresh", "refresh"]
    assert len(client.created) == 2


def test_keeper_interactive_recheck_denial_blocks_grant_after_user_creation() -> None:
    client = KeeperQueue({"query-0000000000": _task("qa", ["ch-a:9000"])})
    checks = 0

    def refresh() -> tuple[bool, str | None]:
        nonlocal checks
        checks += 1
        return (True, None) if checks == 1 else (False, "DDL access changed to Read")

    result, transcript = _run(client, "a\na\ny\ny\n", refresh_session=refresh)
    assert result["status"] == "created"
    assert result["admin_status"] == "unavailable"
    assert len(client.created) == 1
    assert "DDL access changed to Read" in transcript


def test_keeper_cli_yes_flag_is_explicit_noninteractive_opt_in() -> None:
    args = parse_args(["keeper", "-t", "127.0.0.1:9181", "--create-user", "qa", "--create-userpass", "secret", "--yes"])
    assert args.yes is True


def test_keeper_cli_refuses_noninteractive_write_without_yes(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    args = parse_args(["keeper", "-t", "127.0.0.1:9181", "--create-user", "qa", "--create-userpass", "secret"])
    monkeypatch.setattr("sys.stdin", StringIO())
    monkeypatch.setattr(keeper_stage, "AuditCommandRunner", lambda **_kwargs: pytest.fail("runner must not start"))
    assert keeper_stage.run_keeper_stage(args, None) == 2
    assert "--yes" in capsys.readouterr().err


def test_keeper_cli_refuses_interactive_multi_target_write(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    class TtyInput(StringIO):
        def isatty(self) -> bool:
            return True

    args = parse_args(
        ["keeper", "-t", "127.0.0.1:9181,127.0.0.2:9181", "--create-user", "qa", "--create-userpass", "secret"]
    )
    monkeypatch.setattr("sys.stdin", TtyInput())
    monkeypatch.setattr(keeper_stage, "AuditCommandRunner", lambda **_kwargs: pytest.fail("runner must not start"))
    assert keeper_stage.run_keeper_stage(args, None) == 2
    assert "one target" in capsys.readouterr().err


def test_keeper_data_hook_uses_operator_choices_before_writing(monkeypatch: pytest.MonkeyPatch) -> None:
    args = parse_args(["keeper", "-t", "127.0.0.1:9181", "--create-user", "qa", "--create-userpass", "secret"])
    args._keeper_interactive_create = True
    args._keeper_input_stream = StringIO("a\na\ny\n")
    args._keeper_output_stream = StringIO()
    spec = keeper_stage.build_keeper_spec(args)
    assert spec.lifecycle_state_factory is not None and spec.data is not None
    state = spec.lifecycle_state_factory(None)
    client = KeeperQueue({"query-0000000000": _task("qa", ["ch-a:9000"])})
    state.zookeeper_state.anonymous_client = client
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
    assert len(client.created) == 1


def test_keeper_interactive_result_renders_each_cluster_and_grant() -> None:
    lines = keeper_render._format_ddl_user_creation_records(
        {
            "host": "127.0.0.1",
            "port": 9181,
            "service": "keeper",
            "ddl_user_creation": {
                "username": "audituser",
                "status": "created",
                "admin_status": "partial",
                "clusters": [
                    {"cluster": "prod", "hosts": ["ch-c:9000"], "status": "created", "admin_status": "granted"},
                    {"cluster": "qa", "hosts": ["ch-a:9000"], "status": "created", "admin_status": "declined"},
                ],
            },
        },
        "txt",
    )
    assert len(lines) == 4
    assert "creation:created (cluster:prod) (hosts:1)" in lines[0]
    assert "admin grant:granted (cluster:prod)" in lines[1]
    assert "creation:created (cluster:qa) (hosts:1)" in lines[2]
    assert "admin grant:declined (cluster:qa)" in lines[3]


def test_keeper_interactive_decline_renders_no_unattempted_grant() -> None:
    lines = keeper_render._format_ddl_user_creation_records(
        {
            "host": "127.0.0.1",
            "port": 9181,
            "module": "keeper",
            "service": "keeper",
            "ddl_user_creation": {
                "username": "audituser",
                "status": "declined",
                "admin_status": "not_attempted",
                "clusters": [],
            },
        },
        "txt",
    )
    assert len(lines) == 1
    assert "creation:declined" in lines[0]
