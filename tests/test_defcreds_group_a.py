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
from redposture_core.stage_runtime import AuditCommandPlan, AuditCommandRunner

# `--defcreds` is a standalone curated-default spray — it is mutually exclusive
# with any supplied credential (explicit pair, credential file, or token). The former
# "provided/file/token → defaults" layering is removed, so combining them is now rejected
# at the CLI. These tests cover the new contract: --defcreds alone yields the deduplicated
# default set; combining it with any supplied credential exits with an error.


def _run_key(run: Any) -> tuple[str, str | None, str | None]:
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
def test_defcreds_alone_yields_deduplicated_default_set(
    module_name: str,
    build_plan: Callable[[Any], AuditCommandPlan],
) -> None:
    args = parse_args([module_name, "-t", "127.0.0.1", "--defcreds"])
    runs = build_plan(args).credential_runs

    assert runs and all(run.source == "default" for run in runs)
    keys = [_run_key(run) for run in runs]
    assert len(keys) == len(set(keys))  # deduplicated
    if module_name == "grpc":
        expected = {("token", token, None) for token in grpc._DEFAULT_BEARER_TOKENS} | {
            ("basic", username, password) for username, password in grpc._DEFAULT_BASIC_CREDENTIALS
        }
    else:
        expected = {("basic", username, password) for username, password in _basic_defaults(module_name)}
    assert set(keys) == expected


@pytest.mark.parametrize(
    ("module_name", "token_option"),
    [
        ("elastic", "--apitoken"),
        ("grafana", "--apitoken"),
        ("grpc", "--token"),
    ],
)
def test_defcreds_rejects_supplied_token(module_name: str, token_option: str) -> None:
    with pytest.raises(SystemExit):
        parse_args([module_name, "-t", "127.0.0.1", token_option, "secret-token", "--defcreds"])


@pytest.mark.parametrize(
    ("module_name", "credential_option", "value"),
    [
        ("proxmox", "--pveapitoken", "audit@pve!reader=secret"),
        ("gitlab", "--registry-token", "secret-token"),
        ("minio", "--session-token", "secret-token"),
        ("postgres", "--pgadmin-server-password", "secret-password"),
    ],
)
def test_defcreds_rejects_product_specific_credentials(
    module_name: str, credential_option: str, value: str, capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit) as error:
        parse_args([module_name, "-t", "127.0.0.1", "--defcreds", credential_option, value])
    assert error.value.code == 2
    diagnostic = capsys.readouterr().err
    assert credential_option in diagnostic
    assert value not in diagnostic


@pytest.mark.parametrize(
    ("credential_option", "value"),
    [
        ("--user-list", "users.txt"),
        ("--pass-list", "passwords.txt"),
        ("--combo-list", "combos.txt"),
        ("--spray-passwords", None),
    ],
)
def test_oracle_defcreds_rejects_wordlists_and_spray_order(
    credential_option: str, value: str | None, capsys: pytest.CaptureFixture[str]
) -> None:
    args = ["oracle", "-t", "127.0.0.1", "--defcreds", credential_option]
    if value is not None:
        args.append(value)
    with pytest.raises(SystemExit) as error:
        parse_args(args)
    assert error.value.code == 2
    diagnostic = capsys.readouterr().err
    assert credential_option in diagnostic
    if value is not None:
        assert value not in diagnostic


@pytest.mark.parametrize("credential_option", ["--user-list", "--pass-list", "--combo-list"])
def test_oracle_wordlist_without_defcreds_remains_available(credential_option: str) -> None:
    parsed = parse_args(["oracle", "-t", "127.0.0.1", credential_option, "candidates.txt"])
    assert getattr(parsed, credential_option.removeprefix("--").replace("-", "_")) == "candidates.txt"


@pytest.mark.parametrize(
    "module_name",
    ["clickhouse", "elastic", "etcd", "grafana", "grpc", "kafka"],
)
def test_defcreds_rejects_credential_file(tmp_path: Path, module_name: str) -> None:
    credentials = tmp_path / f"{module_name}.creds"
    credentials.write_text("alice:one\nadmin:admin\n", encoding="utf-8")
    with pytest.raises(SystemExit):
        parse_args([module_name, "-t", "127.0.0.1", "-u", str(credentials), "--defcreds"])


@pytest.mark.parametrize(
    "module_name",
    ["clickhouse", "elastic", "etcd", "grafana", "grpc", "kafka"],
)
def test_defcreds_rejects_explicit_pair(module_name: str) -> None:
    with pytest.raises(SystemExit):
        parse_args([module_name, "-t", "127.0.0.1", "-u", "admin", "-p", "admin", "--defcreds"])


def test_etcd_runtime_passes_defaults_as_one_source_aware_batch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
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
    args = parse_args(["etcd", "-t", "127.0.0.1", "--port", "2379", "--defcreds", "--format", "json"])
    plan = etcd.build_etcd_plan(args)
    AuditCommandRunner(
        args=args,
        spec=etcd.build_etcd_spec(args),
        emit_line=lambda _line: None,
    ).run_plan(plan)

    nonempty_batches = [batch for batch in batches if batch]
    assert len(nonempty_batches) == 1
    batch = nonempty_batches[0]
    # --defcreds alone: one batch of curated defaults only (no provided/file source), deduplicated.
    assert all(item["source"] == "default" for item in batch)
    pairs = [(item["username"], item["password"]) for item in batch]
    assert len(pairs) == len(set(pairs))
    assert set(pairs) == set(etcd._ETCD_DEFAULT_CREDS)
