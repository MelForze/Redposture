from __future__ import annotations

import importlib
import json
from types import SimpleNamespace
from typing import Any

import pytest

from redposture_core.cli_args import build_parser, parse_args
from redposture_core.data_discovery import (
    DISCOVERY_MODULES,
    discovery_fields,
    inspect_record,
    prepare_discovery_request,
    project_discovery_output,
    render_discovery,
)
from redposture_core.stage_runtime import (
    AuditCommandPlan,
    AuditCommandRunner,
    AuditRecord,
    ModuleAuditSpec,
    _build_colored_emit,
    build_render_plan,
    render_with_plan,
)


def test_discovery_flags_are_available_for_new_modules() -> None:
    for module in (
        "kafka",
        "redis",
        "etcd",
        "consul",
        "mongodb",
        "postgres",
        "zookeeper",
        "keeper",
        "qdrant",
        "oracle",
        "kubeapi",
        "jenkins",
    ):
        args = parse_args([module, "-t", "127.0.0.1", "--discover"])
        assert args.discover is True


@pytest.mark.parametrize("module", sorted(DISCOVERY_MODULES))
def test_discover_help_is_in_module_inventory_group(module: str) -> None:
    parser = build_parser()
    subparsers = next(action for action in parser._actions if action.dest == "command")
    subparser = subparsers.choices[module]
    title = (
        "Discovery / Dump"
        if module in {"mongodb", "oracle", "postgres"}
        else "Nexus repositories / OCI images"
        if module == "nexus"
        else "OCI images"
        if module in {"harbor", "docker-registry"}
        else "Inventory"
        if module in {"jenkins", "vault", "nomad", "jupyter", "spark", "yarn", "portainer"}
        else "Actions"
    )
    owner = next(
        group for group in subparser._action_groups if any(action.dest == "discover" for action in group._group_actions)
    )
    assert owner.title == title
    help_text = subparser.format_help()
    section = help_text.split(f"\n{title}:\n", 1)[1].split("\n\n", 1)[0]
    assert "--discover" in section
    assert "--discover" not in help_text.split("\noptions:\n", 1)[1].split("\n\n", 1)[0]


def test_discovery_requests_only_existing_read_operations() -> None:
    args = SimpleNamespace(command="redis", discover=True, dump=False, show_keys=False)
    prepare_discovery_request(args)
    assert args.dump == 1000
    assert args.show_keys is False
    assert args._discover_implicit_dump is True


@pytest.mark.parametrize(
    "module",
    [
        "kafka",
        "redis",
        "etcd",
        "consul",
        "mongodb",
        "postgres",
        "zookeeper",
        "keeper",
        "qdrant",
        "oracle",
        "kubeapi",
        "jenkins",
        "vault",
        "nomad",
        "jupyter",
        "spark",
        "yarn",
        "portainer",
    ],
)
def test_shared_discovery_neutral_accessible_content_has_no_false_findings(module: str) -> None:
    value: Any
    neutral = {"request_id": "550e8400-e29b-41d4-a716-446655440000", "display_name": "ordinary text"}
    field = discovery_fields(module)[0]
    if field in {"key_value_entries", "kv_dump_items"}:
        value = [{"key": "app/info", "value": neutral}]
    elif field == "dump_results":
        value = {"orders": [neutral]}
    elif field == "documents":
        value = [{"database": "app", "collection": "items", "document": neutral}]
    elif field == "table_dumps":
        value = [{"database": "app", "table": "items", "rows": [neutral]}]
    elif field == "znode_values":
        value = ["/app/info:ordinary text"]
    elif field == "payload_discovery_items":
        value = [{"collection": "items", "points": [neutral]}]
    elif field == "rows":
        value = [{"schema": "APP", "table": "ITEMS", "row": neutral}]
    elif field == "secrets":
        value = [{"namespace": "app", "name": "items", "data": neutral}]
    elif field == "build_logs":
        value = [{"job": "build", "build": 1, "log": "ordinary text"}]
    else:
        value = [neutral]
    result = inspect_record(module, {"status": "open_no_auth", field: value})
    assert result["status"] == "complete"
    assert result["findings"] == []


@pytest.mark.parametrize(
    "module",
    [
        "kafka",
        "redis",
        "etcd",
        "consul",
        "mongodb",
        "postgres",
        "zookeeper",
        "keeper",
        "qdrant",
        "oracle",
        "kubeapi",
        "jenkins",
        "vault",
        "nomad",
        "jupyter",
        "spark",
        "yarn",
        "portainer",
    ],
)
def test_shared_discovery_detects_token_in_readable_source(module: str) -> None:
    value: Any
    token = "glpat-abcdefghijklmnopqrst"
    field = discovery_fields(module)[0]
    if field in {"key_value_entries", "kv_dump_items"}:
        value = [{"key": "app/api_token", "value": token}]
    elif field == "dump_results":
        value = {"orders": [{"api_token": token}]}
    elif field == "documents":
        value = [{"database": "app", "collection": "items", "document": {"api_token": token}}]
    elif field == "table_dumps":
        value = [{"database": "app", "table": "items", "rows": [{"api_token": token}]}]
    elif field == "znode_values":
        value = [f"/app/api_token:{token}"]
    elif field == "payload_discovery_items":
        value = [{"collection": "items", "points": [{"api_token": token}]}]
    elif field == "rows":
        value = [{"schema": "APP", "table": "ITEMS", "row": {"api_token": token}}]
    elif field == "secrets":
        value = [{"namespace": "app", "name": "token", "data": {"api_token": token}}]
    elif field == "build_logs":
        value = [{"job": "build", "build": 1, "log": f"api_token={token}"}]
    else:
        value = [{"api_token": token}]
    result = inspect_record(module, {"status": "open_no_auth", field: value})
    assert result["status"] == "complete"
    assert result["findings"]
    assert len({(item["type"], item["fingerprint"]) for item in result["findings"]}) == len(result["findings"])
    assert token not in str(result)


def test_kafka_discover_is_partial_when_message_cap_is_reached() -> None:
    record = {
        "status": "open_no_auth",
        "dump_results": {"orders": [{"message": "ordinary text"}]},
        "max_messages": 1,
        "dump_coverage": {"complete": True},
    }
    result = inspect_record("kafka", record)
    assert result["status"] == "partial"
    assert "message_limit_reached" in result["partial_reasons"]


def test_kafka_discover_is_complete_below_message_cap() -> None:
    record = {
        "status": "open_no_auth",
        "dump_results": {"orders": [{"message": "ordinary text"}]},
        "max_messages": 2,
        "dump_coverage": {"complete": True},
    }
    result = inspect_record("kafka", record)
    assert result["status"] == "complete"


def test_mongodb_discover_is_partial_when_collection_document_cap_is_reached() -> None:
    record = {
        "status": "open_no_auth",
        "dump_limit": 1,
        "documents": [{"database": "app", "collection": "users", "document": {"display_name": "Alice"}}],
    }
    result = inspect_record("mongodb", record)
    assert result["status"] == "partial"
    assert "document_limit_reached" in result["partial_reasons"]


def test_mongodb_discover_is_complete_below_collection_document_cap() -> None:
    record = {
        "status": "open_no_auth",
        "dump_limit": 2,
        "documents": [{"database": "app", "collection": "users", "document": {"display_name": "Alice"}}],
    }
    assert inspect_record("mongodb", record)["status"] == "complete"


def test_postgres_discover_marks_table_at_row_cap_partial() -> None:
    record = {
        "status": "open_no_auth",
        "dump_row_limit": 1,
        "table_dumps": [{"database": "app", "table": "users", "rows": ["(Alice)"]}],
    }
    result = inspect_record("postgres", record)
    assert result["status"] == "partial"
    assert "row_limit_reached" in result["partial_reasons"]


_SECRET = "glpat-abcdefghijklmnopqrst"
_IMPLICIT_CASES = (
    (
        "kafka",
        {"dump": True, "dump_topics": ["orders"], "dump_results": {"orders": [{"api_token": _SECRET}]}},
        "dump_results",
    ),
    ("redis", {"dump_keys": True, "key_value_entries": [{"key": "api_token", "value": _SECRET}]}, "key_value_entries"),
    ("etcd", {"dump_keys": True, "key_value_entries": [{"key": "api_token", "value": _SECRET}]}, "key_value_entries"),
    (
        "consul",
        {"dump_requested": True, "keys_requested": True, "kv_dump_items": [{"key": "api_token", "value": _SECRET}]},
        "kv_dump_items",
    ),
    (
        "mongodb",
        {
            "dump_documents": True,
            "documents": [{"database": "app", "collection": "users", "document": {"api_token": _SECRET}}],
        },
        "documents",
    ),
    (
        "postgres",
        {
            "table_dump_enabled": True,
            "show_row_counts": True,
            "table_targets": ["app.users"],
            "table_row_counts": [{"database": "app", "table": "users", "row_count": 1}],
            "table_dumps": [{"database": "app", "table": "users", "rows": [{"api_token": _SECRET}]}],
        },
        "table_dumps",
    ),
    ("zookeeper", {"dump": True, "znode_values": [f"/app/api_token:{_SECRET}"]}, "znode_values"),
    ("keeper", {"dump": True, "znode_values": [f"/app/api_token:{_SECRET}"]}, "znode_values"),
    (
        "qdrant",
        {
            "dump": True,
            "payload_discovery_items": [{"collection": "app", "points": [{"api_token": _SECRET}]}],
            "collection_dump_items": [{"name": "app", "ok": True, "info_raw": f"api_token={_SECRET}"}],
        },
        "payload_discovery_items",
    ),
    ("oracle", {"rows": [{"schema": "APP", "table": "USERS", "row": {"api_token": _SECRET}}]}, "rows"),
    (
        "kubeapi",
        {"show_secrets": True, "secrets": [{"namespace": "app", "name": "api-token", "data": {"api_token": _SECRET}}]},
        "secrets",
    ),
    (
        "jenkins",
        {
            "jobs_requested": True,
            "jobs": [{"name": "build", "color": "blue"}],
            "builds_requested": True,
            "builds": [{"job": "build", "number": 2, "result": "SUCCESS"}],
            "build_logs": [{"job": "build", "build": 2, "log": f"api_token={_SECRET}"}],
        },
        "build_logs",
    ),
)


@pytest.mark.parametrize(("module", "raw", "private_field"), _IMPLICIT_CASES)
def test_bare_discover_scans_content_without_exposing_implicit_raw_inventory(
    module: str, raw: dict[str, object], private_field: str
) -> None:
    args = SimpleNamespace(command=module, discover=True, dump=False, secrets=False, show_builds=None)
    prepare_discovery_request(args)
    record = {"host": "qa", "port": 1234, "status": "open_no_auth", **raw}
    discovery = inspect_record(module, record)
    assert discovery["findings"], module
    projected = project_discovery_output(args, {**record, "content_discovery": discovery})
    assert private_field not in projected
    assert _SECRET not in str(projected)
    assert projected["content_discovery"]["findings"]
    assert "\x1b[" not in str(projected)


@pytest.mark.parametrize(("module", "raw", "private_field"), _IMPLICIT_CASES)
def test_implicit_inventory_is_absent_from_each_modules_txt_renderer(
    module: str, raw: dict[str, object], private_field: str
) -> None:
    args = SimpleNamespace(command=module, discover=True, dump=False, secrets=False, show_builds=None)
    prepare_discovery_request(args)
    record = {
        "host": "qa",
        "port": 1234,
        "status": "open_no_auth",
        "auth_required": False,
        "version": "1.0",
        "is_kafka": True,
        "is_jenkins": True,
        "is_kubeapi": True,
        "is_qdrant": True,
        "is_consul": True,
        **raw,
    }
    render_module = importlib.import_module(f"redposture_core.modules.{module}.render")
    plan = build_render_plan(render_module)
    before = render_with_plan(plan, record, "txt", debug=False)
    after = render_with_plan(plan, project_discovery_output(args, record), "txt", debug=False)
    assert len(before) > len(after), module
    assert all(_SECRET not in line for line in after), module
    assert all("\x1b[" not in line for line in after), module


def test_explicit_dump_query_and_inventory_survive_discovery_projection() -> None:
    args = SimpleNamespace(command="redis", discover=True, dump=7, show_keys=True)
    prepare_discovery_request(args)
    record = {
        "dump_keys": True,
        "show_keys": True,
        "keys": ["api_token"],
        "key_value_entries": [{"key": "api_token", "value": _SECRET}],
        "query_key_entry": {"key": "selected", "value": _SECRET},
    }
    assert project_discovery_output(args, record) == record

    implicit = SimpleNamespace(command="redis", discover=True, dump=False, show_keys=True)
    prepare_discovery_request(implicit)
    projected = project_discovery_output(implicit, record)
    assert projected["show_keys"] is True
    assert projected["keys"] == ["api_token"]
    assert "key_value_entries" not in projected
    assert projected["query_key_entry"] == record["query_key_entry"]


def test_consul_implicit_dump_is_scoped_to_kv_and_explicit_key_list_survives() -> None:
    implicit = SimpleNamespace(command="consul", discover=True, dump=False, show_keys=False)
    prepare_discovery_request(implicit)
    assert implicit.show_keys is True
    assert implicit._discover_implicit_show_keys is True
    projected = project_discovery_output(
        implicit,
        {"keys_requested": True, "dump_requested": True, "kv_dump_items": [{"key": "app/api_token", "value": _SECRET}]},
    )
    assert projected["keys_requested"] is False
    assert projected["dump_requested"] is False
    assert "kv_dump_items" not in projected

    explicit_keys = SimpleNamespace(command="consul", discover=True, dump=False, show_keys=True)
    prepare_discovery_request(explicit_keys)
    projected_keys = project_discovery_output(
        explicit_keys,
        {"keys_requested": True, "dump_requested": True, "kv_dump_items": [{"key": "app/api_token", "value": _SECRET}]},
    )
    assert projected_keys["kv_keys_list"] == ["app/api_token"]
    assert projected_keys["keys_requested"] is True


def test_postgres_implicit_dump_hides_derived_row_counts_but_explicit_rows_remain() -> None:
    record = {
        "table_dump_enabled": True,
        "table_dumps": [{"table": "users", "rows": [{"api_token": _SECRET}]}],
        "show_row_counts": True,
        "table_targets": ["users"],
        "table_row_counts": [{"table": "users", "row_count": 1}],
    }
    implicit = SimpleNamespace(command="postgres", discover=True, dump=False, rows=False, tables=None)
    prepare_discovery_request(implicit)
    projected = project_discovery_output(implicit, record)
    assert "table_row_counts" not in projected
    assert "table_targets" not in projected
    assert projected["show_row_counts"] is False

    explicit_rows = SimpleNamespace(command="postgres", discover=True, dump=False, rows=True, tables=None)
    prepare_discovery_request(explicit_rows)
    projected = project_discovery_output(explicit_rows, record)
    assert projected["table_row_counts"] == record["table_row_counts"]
    assert projected["show_row_counts"] is True


@pytest.mark.parametrize("output_format", ["txt", "json"])
def test_bare_discover_never_emits_raw_values_in_live_or_saved_output(tmp_path, output_format: str) -> None:
    args = SimpleNamespace(command="redis", discover=True, dump=False, show_keys=False, debug=False)
    prepare_discovery_request(args)
    emitted: list[str] = []
    output_path = tmp_path / f"redis.{output_format}"

    def detect(ctx) -> AuditRecord:
        return AuditRecord.from_mapping(
            {"host": ctx.host, "port": ctx.port, "status": "open_no_auth", "is_redis": True},
            module="redis",
            service="redis",
        )

    def data(_ctx, prior: AuditRecord) -> AuditRecord:
        return AuditRecord.from_mapping(
            {
                **prior.to_dict(),
                "dump_keys": True,
                "key_value_entries": [{"key": "app/api_token", "value": _SECRET}],
            },
            module="redis",
            service="redis",
        )

    def render(record: AuditRecord) -> list[str]:
        payload: Any
        payload = record.to_dict()
        lines = [f"REDIS {record.host} [*] Redis"]
        for item in payload.get("key_value_entries", []):
            lines.append(f"REDIS {record.host} value:{item['value']}")
        lines.extend(render_discovery("redis", payload))
        return lines

    runner = AuditCommandRunner(
        args=args,
        spec=ModuleAuditSpec(
            module="redis",
            label="REDIS",
            default_port=6379,
            detect=detect,
            data=data,
            render=render,
            is_detected=lambda _record: True,
        ),
        emit_line=emitted.append,
    )
    runner.run_plan(
        AuditCommandPlan(
            targets_by_port={6379: ("host",)},
            output_path=str(output_path),
            output_format=output_format,
            workers=1,
        )
    )
    saved = output_path.read_text(encoding="utf-8")
    assert _SECRET not in saved
    assert "\x1b[" not in saved
    assert _SECRET not in "\n".join(emitted)
    if output_format == "txt":
        assert len([line for line in emitted if "Redis" in line]) == 1
        assert "Discover Secrets" in saved
        assert "value:" not in saved
    else:
        result = json.loads(saved.splitlines()[0])
        assert "key_value_entries" not in result
        assert result["content_discovery"]["findings"]


def test_secret_key_name_enters_path_and_source_is_anonymous() -> None:
    record = {
        "host": "qa",
        "port": 6379,
        "status": "open_no_auth",
        "key_value_entries": [{"key": "app/password", "value": "secretvalue"}],
    }
    result = inspect_record("redis", record)
    assert result["source"] == "anonymous"
    assert len(result["findings"]) == 1
    assert "app/password" in result["findings"][0]["object_path"]
    assert "secretvalue" not in str(result)
    rendered = render_discovery("redis", {**record, "content_discovery": result})
    assert "Place=" in rendered[0]
    assert "Discover Secrets (status:complete)" in rendered[-1]


def test_discovery_budget_marks_partial_without_false_findings() -> None:
    record = {"status": "open_no_auth", "kv_dump_items": [{"key": "safe", "value": "x" * 200}]}
    result = inspect_record("consul", record, max_bytes=20)
    assert result["status"] == "partial"
    assert result["findings"] == []


def test_empty_accessible_discovery_source_is_complete() -> None:
    assert inspect_record("redis", {"status": "open_no_auth", "key_value_entries": []})["status"] == "complete"
    assert inspect_record("kafka", {"status": "open_no_auth", "dump_results": {}})["status"] == "complete"


def test_discovery_reports_partial_after_read_error_without_losing_prior_finding() -> None:
    record = {
        "status": "valid_credentials",
        "kv_dump_items": [{"key": "app/api_token", "value": "glpat-abcdefghijklmnopqrst"}],
        "kv_dump_error": "reading a later key timed out",
    }
    result = inspect_record("consul", record)
    assert result["status"] == "partial"
    assert result["findings"]
    assert all("app/api_token" in finding["object_path"] for finding in result["findings"])


def test_discovery_denied_entire_source_is_unavailable() -> None:
    result = inspect_record("kubeapi", {"status": "auth_required", "secrets_error": "Forbidden"})
    assert result["status"] == "unavailable"
    assert result["findings"] == []


def test_discovery_denied_sources_with_empty_result_lists_are_unavailable() -> None:
    record = {
        "host": "qa",
        "port": 6443,
        "status": "auth_required",
        "secrets": [],
        "secrets_error": "Forbidden",
        "secrets_partial": True,
        "configmaps": [],
        "configmaps_error": "Forbidden",
        "configmaps_partial": True,
    }
    result = inspect_record("kubeapi", record)
    assert result["status"] == "unavailable"
    assert result["findings"] == []
    assert "secrets_error" in result["partial_reasons"]
    assert "configmaps_error" in result["partial_reasons"]
    line = render_discovery("kubeapi", {**record, "content_discovery": result})[0]
    assert "status:unavailable" in line and "reason:" in line
    assert "Forbidden" not in line and "\x1b[" not in line


def test_discovery_one_accessible_empty_source_and_one_denied_is_partial() -> None:
    result = inspect_record(
        "kubeapi",
        {
            "status": "auth_required",
            "secrets": [],
            "configmaps": [],
            "configmaps_error": "Forbidden",
            "configmaps_partial": True,
        },
    )
    assert result["status"] == "partial"
    assert "configmaps_error" in result["partial_reasons"]


def test_postgres_json_row_preserves_column_name() -> None:
    record = {
        "status": "valid_credentials",
        "table_dumps": [{"database": "app", "table": "users", "rows": ['{"api_token":"glpat-abcdefghijklmnopqrst"}']}],
    }
    result = inspect_record("postgres", record)
    assert any("api_token" in entry["object_path"] for entry in result["findings"])


def test_explicit_key_and_znode_paths_are_retained_without_access_denied_false_positive() -> None:
    key_record = {
        "status": "open_no_auth",
        "query_key_entry": {"key": "app/api_token", "value": "glpat-abcdefghijklmnopqrst"},
    }
    key_findings = inspect_record("redis", key_record)["findings"]
    assert any("app/api_token" in entry["object_path"] for entry in key_findings)
    znode_record = {
        "status": "open_no_auth",
        "znode_values": ["/app/password:<Access Denied>", "/app/api_token:glpat-abcdefghijklmnopqrst"],
    }
    znode_findings = inspect_record("keeper", znode_record)["findings"]
    assert znode_findings
    assert all("/app/password" not in entry["object_path"] for entry in znode_findings)


def test_kafka_oracle_and_jenkins_source_names_survive_discovery() -> None:
    value: Any
    value = {"api_token": "glpat-abcdefghijklmnopqrst"}
    records = (
        ("kafka", {"ui_dump_records": [{"cluster": "qa", "topic": "orders", "messages": [value]}]}, "orders"),
        ("oracle", {"rows": [{"schema": "APP", "table": "USERS", "row": value}]}, "USERS"),
        ("jenkins", {"build_envs": [{"job": "build", "build": 2, "env": value}]}, "job.build.build.2"),
    )
    for module, source, expected in records:
        findings = inspect_record(module, {"status": "open_no_auth", **source})["findings"]
        assert any(expected in item["object_path"] for item in findings)


def test_new_discovery_lines_follow_airflow_palette_and_remain_plain_in_storage() -> None:

    class PaintConsole:
        def __init__(self) -> None:
            self.calls: list[tuple[str, str]] = []
            self.lines: list[str] = []

        def _paint(self, value: str, color: str, _stream: object) -> str:
            self.calls.append((value, color))
            return value

        def plain(self, value: str) -> None:
            self.lines.append(value)

    record = {
        "host": "qa",
        "port": 6379,
        "status": "open_no_auth",
        "key_value_entries": [{"key": "app/password", "value": "QaSecret2026"}],
    }
    lines = render_discovery("redis", {**record, "content_discovery": inspect_record("redis", record)})
    console = PaintConsole()
    emit = _build_colored_emit(console, None)
    for line in lines:
        emit(line)
    assert any("findings:1" in value and color == "true_red" for value, color in console.calls)
    assert any("status:complete" in value and color == "bright_green" for value, color in console.calls)
    assert any("Pass Value=" in value and color == "orange" for value, color in console.calls)
    assert all("\x1b[" not in line and "QaSecret2026" not in line for line in lines)


@pytest.mark.parametrize("module", ["vault", "nomad", "jupyter", "redis"])
def test_runtime_honors_explicit_secret_inspection_byte_budget(module: str, tmp_path) -> None:
    from redposture_core.data_discovery import discovery_fields

    args = SimpleNamespace(command=module, discover=True, discover_max_bytes=1, debug=False)
    field = discovery_fields(module)[0]
    record = AuditRecord.from_mapping(
        {
            "host": "host",
            "port": 1234,
            "status": "open_no_auth",
            f"is_{module}": True,
            field: [{"key": "password", "value": _SECRET}],
        },
        module=module,
    )
    runner = AuditCommandRunner(
        args=args,
        spec=ModuleAuditSpec(
            module=module,
            label=module.upper(),
            default_port=1234,
            detect=lambda _: record,
            data=lambda _ctx, prior: prior,
            is_detected=lambda _: True,
            render=lambda _: [],
        ),
        emit_line=lambda _: None,
    )
    output = tmp_path / "result.json"
    runner.run_plan(
        AuditCommandPlan(targets_by_port={1234: ("host",)}, output_path=str(output), output_format="json", workers=1)
    )
    saved = json.loads(output.read_text())
    assert saved["content_discovery"]["status"] == "partial"
    assert saved["content_discovery"]["bytes_inspected"] == 0
