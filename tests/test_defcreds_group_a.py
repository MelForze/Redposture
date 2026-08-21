from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

import redposture_core.stage_clickhouse as clickhouse
import redposture_core.stage_elastic as elastic
import redposture_core.stage_etcd as etcd
import redposture_core.stage_grafana as grafana
import redposture_core.stage_grpc as grpc
import redposture_core.stage_kafka as kafka
from redposture_core.cli_args import parse_args
from redposture_core.stage_runtime import AuditCommandPlan, AuditCommandRunner, AuditCredentialRun


def _run_key(run: AuditCredentialRun) -> tuple[str, str | None, str | None]:
    if run.token is not None:
        return "token", run.token, None
    return "basic", run.username, run.password


def _basic_defaults(module_name: str) -> list[tuple[str, str]]:
    if module_name == "clickhouse":
        return [
            (user, password) for user, password, _source in clickhouse._build_credential_candidates(None, None, True)
        ]
    if module_name == "elastic":
        return [
            (user, password)
            for user, password in elastic._build_credential_runs(None, None, True)
            if user is not None and password is not None
        ]
    if module_name == "etcd":
        return list(etcd._ETCD_DEFAULT_CREDS)
    if module_name == "grafana":
        return [(user, password) for user, password, _source in grafana._build_credential_candidates(None, None, True)]
    if module_name == "kafka":
        return [
            (user, password)
            for user, password in kafka._build_credential_runs(None, None, True)
            if user is not None and password is not None
        ]
    raise AssertionError(module_name)


@pytest.mark.parametrize(
    ("module_name", "build_plan"),
    [
        ("clickhouse", clickhouse.build_clickhouse_plan),
        ("elastic", elastic.build_elastic_plan),
        ("etcd", etcd.build_etcd_plan),
        ("grafana", grafana.build_grafana_plan),
        ("grpc", grpc.build_grpc_plan),
        ("kafka", kafka.build_kafka_plan),
    ],
)
def test_credential_file_is_followed_by_defaults_once_with_stable_deduplication(
    tmp_path: Path,
    module_name: str,
    build_plan: Callable[[Any], AuditCommandPlan],
) -> None:
    credentials = tmp_path / f"{module_name}.creds"
    credentials.write_text("alice:one\nadmin:admin\nalice:one\n", encoding="utf-8")
    args = parse_args([module_name, "-t", "127.0.0.1", "-u", str(credentials), "--defcreds"])

    runs = build_plan(args).credential_runs

    assert [(run.username, run.password, run.source) for run in runs[:2]] == [
        ("alice", "one", "file"),
        ("admin", "admin", "file"),
    ]
    assert sum(_run_key(run) == ("basic", "admin", "admin") for run in runs) == 1
    assert all(run.source == "default" for run in runs[2:])
    if module_name == "grpc":
        expected_default_keys = [("token", token, None) for token in grpc._DEFAULT_BEARER_TOKENS] + [
            ("basic", username, password)
            for username, password in grpc._DEFAULT_BASIC_CREDENTIALS
            if (username, password) != ("admin", "admin")
        ]
    else:
        expected_default_keys = [
            ("basic", username, password)
            for username, password in _basic_defaults(module_name)
            if (username, password) != ("admin", "admin")
        ]
    assert [_run_key(run) for run in runs[2:]] == expected_default_keys


@pytest.mark.parametrize(
    ("module_name", "build_plan", "token_option", "token_source"),
    [
        ("elastic", elastic.build_elastic_plan, "--apitoken", "token"),
        ("grafana", grafana.build_grafana_plan, "--apitoken", "provided"),
        ("grpc", grpc.build_grpc_plan, "--token", "provided"),
    ],
)
def test_token_precedes_credential_file_and_defaults(
    tmp_path: Path,
    module_name: str,
    build_plan: Callable[[Any], AuditCommandPlan],
    token_option: str,
    token_source: str,
) -> None:
    credentials = tmp_path / f"{module_name}.creds"
    credentials.write_text("alice:one\nbob:two\n", encoding="utf-8")
    args = parse_args(
        [
            module_name,
            "-t",
            "127.0.0.1",
            token_option,
            "secret-token",
            "-u",
            str(credentials),
            "--defcreds",
        ]
    )

    runs = build_plan(args).credential_runs

    assert (runs[0].token, runs[0].source) == ("secret-token", token_source)
    assert [(run.username, run.password, run.source) for run in runs[1:3]] == [
        ("alice", "one", "file"),
        ("bob", "two", "file"),
    ]
    assert all(run.source == "default" for run in runs[3:])


@pytest.mark.parametrize(
    ("module_name", "build_plan"),
    [
        ("clickhouse", clickhouse.build_clickhouse_plan),
        ("elastic", elastic.build_elastic_plan),
        ("etcd", etcd.build_etcd_plan),
        ("grafana", grafana.build_grafana_plan),
        ("grpc", grpc.build_grpc_plan),
        ("kafka", kafka.build_kafka_plan),
    ],
)
def test_explicit_pair_overlapping_defaults_stays_provided(
    module_name: str,
    build_plan: Callable[[Any], AuditCommandPlan],
) -> None:
    args = parse_args(
        [
            module_name,
            "-t",
            "127.0.0.1",
            "-u",
            "admin",
            "-p",
            "admin",
            "--defcreds",
        ]
    )

    matching = [
        run
        for run in build_plan(args).credential_runs
        if run.token is None and (run.username, run.password) == ("admin", "admin")
    ]

    assert matching == [AuditCredentialRun(username="admin", password="admin", source="provided")]


def test_etcd_runtime_passes_file_and_defaults_as_one_source_aware_batch(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    credentials = tmp_path / "etcd.creds"
    credentials.write_text("root:root\napp:secret\n", encoding="utf-8")
    batches: list[list[dict[str, Any]] | None] = []

    def fake_audit(
        host: str,
        port: int,
        _timeout: float,
        _retries: int,
        _show_keys: bool,
        _dump_keys: bool,
        _query_key: str | None,
        *,
        username: str | None = None,
        password: str | None = None,
        defcreds: bool = False,
        credential_candidates: list[dict[str, Any]] | None = None,
        **_kwargs: Any,
    ) -> dict[str, Any]:
        _ = (username, password, defcreds)
        batch = [dict(item) for item in credential_candidates] if credential_candidates else None
        batches.append(batch)
        return {
            "host": host,
            "port": port,
            "is_etcd": True,
            "status": "weak_default_creds" if batch else "auth_required",
            "auth_required": True,
            "api_versions": "v3",
            "server_version": "3.5.14",
            "provided_credentials": bool(batch),
            "provided_credentials_ok": False if batch else None,
            "defcreds_enabled": bool(batch),
            "effective_username": "root" if batch else None,
            "effective_password": "etcd" if batch else None,
            "credential_attempts": [],
            "error": None,
        }

    monkeypatch.setattr(etcd, "_audit_etcd_host", fake_audit)
    args = parse_args(
        [
            "etcd",
            "-t",
            "127.0.0.1",
            "--port",
            "2379",
            "-u",
            str(credentials),
            "--defcreds",
            "--format",
            "json",
        ]
    )
    plan = etcd.build_etcd_plan(args)
    AuditCommandRunner(
        args=args,
        spec=etcd.build_etcd_spec(args),
        emit_line=lambda _line: None,
    ).run_plan(plan)

    nonempty_batches = [batch for batch in batches if batch]
    assert len(nonempty_batches) == 1
    assert [(item["username"], item["password"], item["source"]) for item in nonempty_batches[0]] == [
        ("root", "root", "file"),
        ("app", "secret", "file"),
        ("admin", "admin", "default"),
        ("admin", "changeme", "default"),
        ("admin", "etcd", "default"),
        ("admin", "password", "default"),
        ("etcd", "etcd", "default"),
        ("etcd", "password", "default"),
        ("root", "admin", "default"),
        ("root", "etcd", "default"),
        ("root", "password", "default"),
        ("root", "rootpass", "default"),
        ("service", "service", "default"),
        ("user", "password", "default"),
        ("user", "user", "default"),
    ]
