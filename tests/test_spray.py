"""Credential-only spray contracts and all-module registration checks."""

from __future__ import annotations

import json
import os
import sqlite3
from argparse import Namespace
from contextlib import closing
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from redposture_core.audit_models import AuditRecord
from redposture_core.cli_args import parse_args
from redposture_core.console import Console
from redposture_core.module_registry import AUDIT_MODULE_NAMES
from redposture_core.stage_runtime import AuditCredentialRun, AuditHookContext, ModuleAuditSpec
from redposture_core.stage_spray import (
    AttemptJournal,
    Candidate,
    RateGate,
    SpraySink,
    _config,
    _credential_detail,
    _effective_origin,
    _group_txt_replay_rows,
    _input_fingerprint,
    _job_targets,
    _module_runtime_args,
    _oracle_spray_preflight,
    _render_rows,
    _run_target,
    _supported,
    classify,
    load_candidates,
    run_spray_stage,
)
from redposture_core.targeting import ScanTargetSpec


def test_spray_input_order_dedup_and_first_colon(tmp_path: Path) -> None:
    pairs = tmp_path / "pairs"
    users = tmp_path / "users"
    passwords = tmp_path / "passwords"
    tokens = tmp_path / "tokens"
    pairs.write_text("a:one:two\na:one:two\n", encoding="utf-8")
    users.write_text("a\nb\n", encoding="utf-8")
    passwords.write_text("first\nsecond\n", encoding="utf-8")
    tokens.write_text("ey.test.token\ney.test.token\n", encoding="utf-8")
    args = Namespace(pairs=str(pairs), users=str(users), passwords=str(passwords), tokens=str(tokens))
    assert [item.display for item in load_candidates(args)] == [
        "a:one:two",
        "a:first",
        "b:first",
        "a:second",
        "b:second",
        "ey.test.token",
    ]


def test_spray_short_options_mix_literal_and_file_sources(tmp_path: Path) -> None:
    users = tmp_path / "users.txt"
    passwords = tmp_path / "passwords.txt"
    users.write_text("alice\nbob\n", encoding="utf-8")
    passwords.write_text("first\nsecond\n", encoding="utf-8")
    argv = ["spray", "-t", "localhost", "--modules", "airflow"]
    args = parse_args([*argv, "-u", "alice", "-p", f"@{passwords}"])
    assert [item.display for item in load_candidates(args)] == ["alice:first", "alice:second"]
    args = parse_args([*argv, "-u", str(users), "-p", "secret"])
    assert [item.display for item in load_candidates(args)] == ["alice:secret", "bob:secret"]
    args = parse_args([*argv, "-u", "alice", "-p", "secret"])
    assert [item.display for item in load_candidates(args)] == ["alice:secret"]
    long_password = "x" * 300
    args = parse_args([*argv, "-u", "alice", "-p", long_password])
    assert load_candidates(args)[0].password == long_password
    with pytest.raises(ValueError, match="does not exist"):
        load_candidates(parse_args([*argv, "-u", "alice", "-p", "@missing-passwords.txt"]))


def test_spray_literal_change_invalidates_resume_fingerprint(tmp_path: Path) -> None:
    argv = ["spray", "-t", "localhost", "--modules", "airflow", "-u", "alice"]
    first = parse_args([*argv, "-p", "first"])
    second = parse_args([*argv, "-p", "second"])
    assert _input_fingerprint(first, ("airflow",), {}) != _input_fingerprint(second, ("airflow",), {})


def test_spray_explicit_source_file_cannot_be_overwritten(tmp_path: Path) -> None:
    passwords = tmp_path / "passwords.txt"
    passwords.write_text("secret\n", encoding="utf-8")
    args = parse_args(
        [
            "spray",
            "-t",
            "localhost",
            "--modules",
            "airflow",
            "-u",
            "alice",
            "-p",
            f"@{passwords}",
            "-o",
            str(passwords),
        ]
    )
    assert run_spray_stage(args, None) == 2
    assert passwords.read_text() == "secret\n"


def test_spray_requires_modules_and_rejects_action_config(tmp_path: Path) -> None:
    with pytest.raises(SystemExit):
        parse_args(["spray", "-t", "localhost", "--pairs", "pairs.txt"])
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"keeper": {"create_user": "evil"}}), encoding="utf-8")
    with pytest.raises(ValueError, match="rejects"):
        _config(str(path), ("keeper",))


def test_spray_configures_clickhouse_driver_logging_before_workers(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import redposture_core.stage_spray as spray
    from redposture_core.modules.clickhouse import actions as clickhouse_actions

    targets = tmp_path / "targets.txt"
    targets.write_text("127.0.0.1:6379\n", encoding="utf-8")
    calls: list[str] = []
    monkeypatch.setattr(clickhouse_actions, "_configure_clickhouse_loggers", lambda: calls.append("configured"))
    monkeypatch.setattr(spray, "_job_targets", lambda _module, _args: iter(()))
    args = parse_args(["spray", "-t", str(targets), "--modules", "clickhouse", "-u", "admin", "-p", "admin"])
    assert run_spray_stage(args, None) == 0
    assert calls == ["configured"]


def test_module_config_applies_only_auth_transport_settings(tmp_path: Path) -> None:
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"keycloak": {"realm": "corp"}, "keeper": {"znode": "/protected"}}), encoding="utf-8")
    config = _config(str(path), ("keycloak", "keeper"))
    parent = SimpleNamespace(
        targets="localhost:8080", timeout=1, retries=0, workers=1, proxy=None, debug=False, no_color=True
    )
    assert _module_runtime_args("keycloak", parent, config["keycloak"]).realm == ["corp"]
    assert _module_runtime_args("keeper", parent, config["keeper"]).znode == "/protected"


def test_kafka_sasl_transport_config_is_deterministic() -> None:
    parent = SimpleNamespace(
        targets="127.0.0.1:9092", timeout=1, retries=0, workers=1, proxy=None, debug=False, no_color=True
    )
    ssl_args = _module_runtime_args("kafka", parent, {"security_protocol": "SASL_SSL", "sasl_mechanism": "PLAIN"})
    assert ssl_args.tls is True and ssl_args.plaintext is False
    plain_args = _module_runtime_args("kafka", parent, {"security_protocol": "SASL_PLAINTEXT"})
    assert plain_args.tls is False and plain_args.plaintext is True
    with pytest.raises(ValueError, match="conflicts"):
        _module_runtime_args("kafka", parent, {"security_protocol": "SASL_SSL", "plaintext": True})
    with pytest.raises(ValueError, match="PLAIN only"):
        _module_runtime_args("kafka", parent, {"sasl_mechanism": "SCRAM-SHA-256"})


@pytest.mark.parametrize("module", AUDIT_MODULE_NAMES)
def test_every_audit_module_builds_spray_plan_and_spec(module: str) -> None:
    import importlib

    parent = SimpleNamespace(
        targets="http://127.0.0.1:49123/base", timeout=0.1, retries=0, workers=1, proxy=None, debug=False, no_color=True
    )
    args = _module_runtime_args(module, parent, {})
    targets = list(_job_targets(module, args))
    assert len(targets) == 1
    assert targets[0][1] == 49123
    stage = importlib.import_module(f"redposture_core.modules.{module.replace('-', '_')}.stage")
    spec = getattr(stage, f"build_{module.replace('-', '_')}_spec")(args)
    assert spec.is_detected is not None
    assert spec.detect is not None or spec.host_stage is not None


@pytest.mark.parametrize("protocol", ["tcp", "tcps"])
def test_oracle_spray_preflight_accepts_confirmed_listener_without_driver(
    monkeypatch: pytest.MonkeyPatch, protocol: str
) -> None:
    from redposture_core.clients import oracle as oracle_client

    calls: list[str] = []

    def status(*_args, **kwargs):
        calls.append(kwargs["protocol"])
        return {"ok": True, "text": "TNSLSNR for Linux: Version 23"}

    monkeypatch.setattr(oracle_client, "tns_listener_command", status)
    monkeypatch.setattr(
        oracle_client,
        "tns_service_fingerprint",
        lambda *_args, **_kwargs: pytest.fail("STATUS already confirmed the product"),
    )
    assert _oracle_spray_preflight("db.local", 1521, SimpleNamespace(protocol=protocol, timeout=1, secure=False))
    assert calls == [protocol]


def test_oracle_spray_preflight_accepts_status_blocked_tns_refusal(monkeypatch: pytest.MonkeyPatch) -> None:
    from redposture_core.clients import oracle as oracle_client

    checked: list[tuple[str | None, str | None]] = []
    monkeypatch.setattr(oracle_client, "tns_listener_command", lambda *_a, **_k: {"ok": False})

    def fingerprint(*_args, **kwargs):
        checked.append((kwargs["service"], kwargs["sid"]))
        return True

    monkeypatch.setattr(oracle_client, "tns_service_fingerprint", fingerprint)
    args = SimpleNamespace(protocol="tcp", service="FREEPDB1", sid=None, service_list=None, sid_list=None, timeout=1)
    assert _oracle_spray_preflight("db.local", 1521, args)
    assert checked == [("FREEPDB1", None)]


def test_oracle_spray_rejects_foreign_port_before_driver_or_auth(monkeypatch: pytest.MonkeyPatch) -> None:
    import redposture_core.stage_spray as spray

    monkeypatch.setattr(spray, "_oracle_spray_preflight", lambda *_args: False)
    monkeypatch.setattr(
        spray.importlib,
        "import_module",
        lambda *_args: pytest.fail("foreign port must not start Oracle lifecycle"),
    )
    _run_target(
        "oracle",
        SimpleNamespace(),
        "localhost",
        6379,
        ScanTargetSpec("localhost", raw="localhost:6379"),
        (Candidate("pair", "admin", "admin"),),
        None,
        None,
        None,
    )


@pytest.mark.parametrize(("module", "default_port"), [("airflow", 8080), ("postgres", 5432), ("kafka", 9092)])
def test_bare_host_uses_module_default_ports(module: str, default_port: int) -> None:
    parent = SimpleNamespace(
        targets="127.0.0.1", timeout=0.1, retries=0, workers=1, proxy=None, debug=False, no_color=True
    )
    args = _module_runtime_args(module, parent, {})
    ports = {port for _host, port, _target in _job_targets(module, args)}
    assert default_port in ports


def test_spray_parses_target_file_once_for_multiple_modules(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import redposture_core.stage_runtime as runtime
    import redposture_core.stage_spray as spray

    targets = tmp_path / "targets.txt"
    targets.write_text("http://127.0.0.1:49123/base\n", encoding="utf-8")
    pairs = tmp_path / "pairs.txt"
    pairs.write_text("user:password\n", encoding="utf-8")
    parse_calls = 0
    original_parse = spray.stream_scan_target_specs

    def counted_parse(*args, **kwargs):
        nonlocal parse_calls
        parse_calls += 1
        return original_parse(*args, **kwargs)

    monkeypatch.setattr(spray, "stream_scan_target_specs", counted_parse)
    monkeypatch.setattr(runtime, "stream_scan_target_specs", lambda *_args, **_kwargs: pytest.fail("targets reparsed"))
    visited: set[str] = set()
    monkeypatch.setattr(spray, "_run_target", lambda module, *_args: visited.add(module))
    args = parse_args(["spray", "-t", str(targets), "--modules", "airflow,jenkins", "--pairs", str(pairs)])
    assert run_spray_stage(args, None) == 0
    assert parse_calls == 1
    assert visited == {"airflow", "jenkins"}


def test_journal_resume_marks_begun_attempt_without_storing_secret(tmp_path: Path) -> None:
    path = tmp_path / "journal.sqlite3"
    journal = AttemptJournal(str(path), "same-input", False)
    journal.put("attempt", "airflow", "localhost", 8080, 0, "started", "request begun")
    journal.close()
    assert path.stat().st_mode & 0o777 == 0o600
    journal = AttemptJournal(str(path), "same-input", True)
    try:
        assert journal.get("attempt")[0] == "inconclusive"
        assert b"secret-password" not in path.read_bytes()
        with pytest.raises(ValueError, match="changed"):
            AttemptJournal(str(path), "different-input", True)
    finally:
        journal.close()


def test_legacy_spray_checkpoint_can_resume_with_empty_credential_detail(tmp_path: Path) -> None:
    path = tmp_path / "legacy.sqlite3"
    with closing(sqlite3.connect(path)) as db:
        with db:
            db.execute("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
            db.execute("INSERT INTO meta VALUES ('fingerprint', 'same')")
            db.execute(
                "CREATE TABLE results (id TEXT PRIMARY KEY, module TEXT NOT NULL, host TEXT NOT NULL, "
                "port INTEGER NOT NULL, candidate INTEGER, status TEXT NOT NULL, evidence TEXT NOT NULL)"
            )
            db.execute(
                "INSERT INTO results VALUES ('one', 'jenkins', 'localhost', 8080, 0, 'valid', 'identity verified')"
            )
    journal = AttemptJournal(str(path), "same", True)
    try:
        assert journal.rows() == [("jenkins", "localhost", 8080, 0, "valid", "identity verified", "")]
    finally:
        journal.close()


def test_input_file_mutation_changes_resume_fingerprint(tmp_path: Path) -> None:
    pairs = tmp_path / "pairs"
    pairs.write_text("alice:first\n", encoding="utf-8")
    args = Namespace(
        targets="localhost:1",
        pairs=str(pairs),
        users=None,
        passwords=None,
        tokens=None,
        module_config=None,
        timeout=1,
        retries=0,
        origin_rate=2,
        account_interval=60,
        proxy=None,
    )
    original = _input_fingerprint(args, ("airflow",), {})
    pairs.write_text("alice:second\n", encoding="utf-8")
    assert _input_fingerprint(args, ("airflow",), {}) != original
    pairs.write_text("alice:first\n", encoding="utf-8")
    args.output_format = "json"
    assert _input_fingerprint(args, ("airflow",), {}) != original


def test_classification_never_accepts_public_response_or_ambiguous_403() -> None:
    class Runner:
        def _credential_gate(self, _credential: object, _record: object) -> tuple[bool, str]:
            return True, "public resource"

    credential = AuditCredentialRun("alice", "secret", source="provided")
    public = AuditRecord.from_mapping({"host": "localhost", "port": 80, "status": "open_no_auth"})
    denied = AuditRecord.from_mapping({"host": "localhost", "port": 80, "status": "forbidden"})
    assert classify(public, credential, Runner())[0] == "inconclusive"
    assert classify(denied, credential, Runner())[0] == "inconclusive"


@settings(max_examples=int(os.getenv("REDPOSTURE_SPRAY_FUZZ_EXAMPLES", "250")), deadline=None)
@given(
    status=st.sampled_from(
        ["detected", "open_no_auth", "auth_required", "forbidden", "valid_credentials", "auth_valid", "unknown"]
    ),
    http_status=st.sampled_from([200, 201, 302, 401, 403, 404, 429, 500]),
    error=st.text(max_size=80),
)
def test_fuzz_unverified_responses_never_validate_credentials(status: str, http_status: int, error: str) -> None:
    class Runner:
        def _credential_gate(self, _credential: object, _record: object) -> tuple[bool, str]:
            return False, "identity not proven"

    record = AuditRecord.from_mapping(
        {"host": "localhost", "port": 80, "status": status, "http_status": http_status, "error": error}
    )
    outcome, _evidence = classify(record, AuditCredentialRun("alice", "secret"), Runner())
    assert outcome != "valid"
    if status == "forbidden" and http_status == 403:
        assert outcome != "invalid"


@pytest.mark.parametrize(
    ("fields", "expected"),
    [
        ({"status": "valid_credentials", "provided_credentials_ok": True}, "valid"),
        ({"status": "invalid_credentials", "provided_credentials_ok": False}, "invalid"),
        ({"status": "forbidden", "auth_valid": True}, "access_denied"),
        ({"status": "detected", "http_status": 429}, "rate_limited"),
        ({"status": "detected", "error": "CAPTCHA required"}, "rate_limited"),
        ({"status": "detected", "http_status": 200}, "inconclusive"),
        ({"status": "forbidden", "http_status": 403}, "inconclusive"),
    ],
)
def test_classification_evidence_matrix(fields: dict[str, object], expected: str) -> None:
    class Runner:
        def _credential_gate(self, _credential: object, record: AuditRecord) -> tuple[bool, str]:
            return record.extra.get("provided_credentials_ok") is True or record.extra.get(
                "auth_valid"
            ) is True, "identity"

    record = AuditRecord.from_mapping({"host": "localhost", "port": 1, **fields})
    assert classify(record, AuditCredentialRun("u", "p"), Runner())[0] == expected


def test_mongodb_auth_required_is_not_mistaken_for_proven_invalid_credentials() -> None:
    class Runner:
        def _credential_gate(self, _credential: object, _record: object) -> tuple[bool, str]:
            return False, "status=auth_required"

    record = AuditRecord.from_mapping({"host": "localhost", "port": 27018, "status": "auth_required"})
    status, evidence = classify(record, AuditCredentialRun("admin", "admin"), Runner())
    assert (status, evidence) == ("inconclusive", "credential not verified; authentication still required")
    row = ("mongodb", "localhost", 27018, 0, status, evidence)
    assert _render_rows([row], (Candidate("pair", "admin", "admin"),), "txt") == [
        "MONGODB\tlocalhost\t27018\t [-] admin:admin"
    ]
    legacy = ("mongodb", "localhost", 27018, 0, status, "status=auth_required")
    assert _render_rows([legacy], (Candidate("pair", "admin", "admin"),), "txt") == _render_rows(
        [row], (Candidate("pair", "admin", "admin"),), "txt"
    )
    json_row = json.loads(_render_rows([row], (Candidate("pair", "admin", "admin"),), "json")[0])
    assert json_row["status"] == "inconclusive"
    assert json_row["evidence"] == evidence
    assert _render_rows([row], (Candidate("pair", "admin", "admin"),), "txt", debug=True) == [
        "MONGODB\tlocalhost\t27018\t [-] admin:admin (evidence:credential not verified; authentication still required)"
    ]


def test_unsupported_credentials_and_private_output_shape() -> None:
    detected = AuditRecord.from_mapping({"host": "localhost", "port": 2375, "status": "detected"})
    assert not _supported("docker", Candidate("pair", "u", "p"), detected)
    assert not _supported("keycloak", Candidate("pair", "u", "p"), detected)
    assert _supported("keycloak", Candidate("token", token="jwt"), detected)
    lines = _render_rows(
        [("airflow", "localhost", 8080, 0, "valid", "identity verified")], (Candidate("pair", "u", "p"),), "txt"
    )
    assert lines == ["AIRFLOW\tlocalhost\t8080\t [+] u:p"]
    assert "\x1b" not in lines[0]


def test_rate_gate_origin_and_account_limits() -> None:
    gate = RateGate(2, 60)
    assert gate.reserve("origin", "alice") == (True, 0)
    assert gate.reserve("origin", "bob")[1] > 0
    assert gate.reserve("origin", "alice")[1] > 59
    gate.stop("origin", "429")
    assert gate.reserve("origin", "charlie") == (False, "429")


@settings(max_examples=int(os.getenv("REDPOSTURE_SPRAY_FUZZ_EXAMPLES", "250")), deadline=None)
@given(
    accounts=st.lists(st.tuples(st.integers(0, 3), st.integers(0, 5)), min_size=1, max_size=80),
    origin_rate=st.integers(min_value=1, max_value=20),
    account_interval=st.integers(min_value=0, max_value=120),
)
def test_fuzz_rate_gate_matches_independent_origin_account_schedule(
    accounts: list[tuple[int, int]], origin_rate: int, account_interval: int
) -> None:
    expected_origin: dict[str, float] = {}
    expected_account: dict[tuple[str, str], float] = {}
    with patch("redposture_core.stage_spray.time.monotonic", return_value=100.0):
        gate = RateGate(origin_rate, account_interval)
        for origin_number, account_number in accounts:
            origin = f"origin-{origin_number}"
            account = f"user-{account_number}"
            start = max(
                100.0,
                expected_origin.get(origin, 100.0),
                expected_account.get((origin, account), 100.0),
            )
            allowed, delay = gate.reserve(origin, account)
            assert allowed is True
            assert delay == pytest.approx(start - 100.0)
            expected_origin[origin] = start + 1 / origin_rate
            expected_account[(origin, account)] = start + account_interval


def test_resolved_redirect_origin_is_used_for_rate_limit() -> None:
    record = AuditRecord.from_mapping(
        {"host": "proxy", "port": 8080, "status": "detected", "api_endpoint": "https://real.example:8443/prefix"}
    )
    target = ScanTargetSpec("proxy", scheme="http", explicit_port=8080)
    assert _effective_origin(record, target, "proxy", 8080) == "https://real.example:8443"


def test_rate_limit_stops_remaining_candidates(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    import redposture_core.stage_spray as spray

    calls: list[str] = []

    def detect(_ctx: object) -> AuditRecord:
        return AuditRecord.from_mapping({"host": "localhost", "port": 8080, "status": "detected", "is_airflow": True})

    def auth(ctx: object, _record: AuditRecord) -> AuditRecord:
        calls.append(ctx.credential.password)
        return AuditRecord.from_mapping(
            {"host": "localhost", "port": 8080, "status": "rate_limited", "http_status": 429}
        )

    spec = ModuleAuditSpec(
        module="airflow",
        label="AIRFLOW",
        default_port=8080,
        detect=detect,
        auth=auth,
        is_detected=lambda record: record.extra.get("is_airflow") is True,
    )
    monkeypatch.setattr(
        spray.importlib, "import_module", lambda _name: SimpleNamespace(build_airflow_spec=lambda _args: spec)
    )
    journal = AttemptJournal(str(tmp_path / "journal.sqlite3"), "x", False)
    try:
        _run_target(
            "airflow",
            Namespace(),
            "localhost",
            8080,
            ScanTargetSpec("localhost", raw="localhost:8080"),
            (Candidate("pair", "u", "p1"), Candidate("pair", "u", "p2")),
            journal,
            RateGate(1000, 0.001),
            None,
        )
        assert calls == ["p1"]
        assert [row[4] for row in journal.rows()] == ["confirmed", "rate_limited", "rate_limited"]
    finally:
        journal.close()


def test_spray_color_marker_and_private_txt_file(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    monkeypatch.setenv("FORCE_COLOR", "1")
    output = tmp_path / "spray.txt"
    sink = SpraySink(str(output), "txt", (Candidate("pair", "user", "pass"),), Console(no_color=False))
    try:
        sink.emit("airflow", "localhost", 8080, None, "confirmed", "auth required:True; version:2.9.2")
        sink.emit("airflow", "localhost", 8080, 0, "valid", "identity verified")
    finally:
        sink.close()
    terminal = capsys.readouterr().out
    assert "\x1b[" in terminal
    assert "[+]" in terminal and "user:pass" in terminal
    assert "\x1b[" not in output.read_text()
    assert len(output.read_text().splitlines()) == 2
    assert output.stat().st_mode & 0o777 == 0o600


def test_parallel_txt_targets_emit_contiguous_blocks(tmp_path: Path) -> None:
    import threading

    output = tmp_path / "spray.txt"
    sink = SpraySink(
        str(output), "txt", (Candidate("pair", "admin", "admin"),), Console(no_color=True), group_targets=True
    )
    first_detected = threading.Event()
    second_finished = threading.Event()

    def first() -> None:
        sink.begin_target()
        try:
            sink.emit("postgres", "localhost", 5432, None, "confirmed", "auth required:True; version:unknown")
            first_detected.set()
            assert second_finished.wait(5)
            sink.emit("postgres", "localhost", 5432, 0, "invalid", "rejected")
        finally:
            sink.end_target()

    def second() -> None:
        assert first_detected.wait(5)
        sink.begin_target()
        try:
            sink.emit("docker-registry", "localhost", 5000, None, "confirmed", "auth required:True; version:unknown")
            sink.emit("docker-registry", "localhost", 5000, 0, "invalid", "rejected")
        finally:
            sink.end_target()
            second_finished.set()

    threads = [threading.Thread(target=first), threading.Thread(target=second)]
    try:
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(5)
        assert all(not thread.is_alive() for thread in threads)
    finally:
        sink.close()

    lines = output.read_text().splitlines()
    assert [line.split("\t", 1)[0] for line in lines] == [
        "DOCKER-REGISTRY",
        "DOCKER-REGISTRY",
        "POSTGRES",
        "POSTGRES",
    ]
    assert all("\x1b[" not in line for line in lines)


def test_txt_resume_rows_group_by_target_without_reordering_attempts() -> None:
    rows = [
        ("postgres", "a", 5432, None, "confirmed", "detected", ""),
        ("docker-registry", "b", 5000, None, "confirmed", "detected", ""),
        ("postgres", "a", 5432, 0, "invalid", "rejected", ""),
        ("docker-registry", "b", 5000, 0, "valid", "verified", ""),
    ]
    assert _group_txt_replay_rows(rows) == [rows[0], rows[2], rows[1], rows[3]]


def test_txt_resume_keeps_partial_detection_with_later_attempt(tmp_path: Path) -> None:
    output = tmp_path / "spray.txt"
    sink = SpraySink(
        str(output), "txt", (Candidate("pair", "admin", "admin"),), Console(no_color=True), group_targets=True
    )
    key = ("postgres", "localhost", 5432)
    sink.defer_replay_rows(
        key,
        [("postgres", "localhost", 5432, None, "confirmed", "auth required:True; version:unknown", "")],
    )
    try:
        sink.begin_target(*key)
        assert output.read_text() == ""
        sink.emit("postgres", "localhost", 5432, 0, "invalid", "rejected")
        sink.end_target()
    finally:
        sink.close()
    assert [line.split("\t", 1)[0] for line in output.read_text().splitlines()] == ["POSTGRES", "POSTGRES"]


def test_grouped_target_finishing_after_sink_close_is_safe(tmp_path: Path) -> None:
    output = tmp_path / "spray.txt"
    sink = SpraySink(
        str(output), "txt", (Candidate("pair", "admin", "admin"),), Console(no_color=True), group_targets=True
    )
    sink.begin_target()
    sink.emit("postgres", "localhost", 5432, None, "confirmed", "auth required:True; version:unknown")
    sink.close()
    sink.end_target()
    assert output.read_text() == ""


def test_multi_module_spray_groups_txt_without_serializing_auth(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import threading

    import redposture_core.stage_spray as spray

    grafana_auth_started = threading.Event()

    def make_spec(module: str) -> ModuleAuditSpec:
        def detect(ctx: AuditHookContext) -> AuditRecord:
            return AuditRecord.from_mapping(
                {"host": "localhost", "port": ctx.port, "status": "detected", f"is_{module}": True}
            )

        def auth(ctx: AuditHookContext, _record: AuditRecord) -> AuditRecord:
            if module == "grafana":
                grafana_auth_started.set()
            else:
                assert grafana_auth_started.wait(2), "second module did not run concurrently"
            return AuditRecord.from_mapping(
                {"host": "localhost", "port": ctx.port, "status": "valid_credentials", "provided_credentials_ok": True}
            )

        return ModuleAuditSpec(
            module=module,
            label=module.upper(),
            default_port=8080 if module == "airflow" else 3000,
            detect=detect,
            auth=auth,
            is_detected=lambda record: record.extra.get(f"is_{module}") is True,
            credential_gate=lambda _candidate, record: (
                record.extra.get("provided_credentials_ok") is True,
                "identity",
            ),
        )

    specs = {module: make_spec(module) for module in ("airflow", "grafana")}

    def import_stage(name: str) -> SimpleNamespace:
        module = name.rsplit(".", 2)[-2]
        return SimpleNamespace(**{f"build_{module}_spec": lambda _args: specs[module]})

    monkeypatch.setattr(spray.importlib, "import_module", import_stage)
    monkeypatch.setattr(
        spray,
        "_job_targets",
        lambda module, _args: iter(
            [
                (
                    "localhost",
                    8080 if module == "airflow" else 3000,
                    ScanTargetSpec("localhost", explicit_port=8080 if module == "airflow" else 3000),
                )
            ]
        ),
    )
    output = tmp_path / "spray.txt"
    checkpoint = tmp_path / "spray.sqlite3"
    args = parse_args(
        [
            "spray",
            "-t",
            "localhost",
            "--modules",
            "airflow,grafana",
            "-u",
            "admin",
            "-p",
            "admin",
            "--workers",
            "2",
            "--checkpoint",
            str(checkpoint),
            "-o",
            str(output),
            "--no-color",
        ]
    )
    assert run_spray_stage(args, None) == 0
    labels = [line.split("\t", 1)[0] for line in output.read_text().splitlines()]
    assert len(labels) == 4
    assert labels[0] == labels[1] and labels[2] == labels[3] and labels[0] != labels[2]


def test_spray_uses_jenkins_credential_detail_without_repeating_secret() -> None:
    from redposture_core.modules.jenkins import render as jenkins_render

    candidate = Candidate("pair", "admin", "secret")
    record = AuditRecord.from_mapping(
        {
            "host": "localhost",
            "port": 8080,
            "status": "valid_credentials",
            "credential_state": "valid",
            "credential_results": [{"username": "admin"}],
            "credential_password": "secret",
            "credential_jobs_access": "allowed",
            "credential_jobs_count": 2,
        }
    )
    spec = ModuleAuditSpec(module="jenkins", label="JENKINS", default_port=8080, render_module=jenkins_render)
    assert _credential_detail(spec, record, candidate) == "(Jobs:2)"
    row = ("jenkins", "localhost", 8080, 0, "valid", "Jenkins identity verified", "(Jobs:2)")
    assert _render_rows([row], (candidate,), "txt") == ["JENKINS\tlocalhost\t8080\t [+] admin:secret (Jobs:2)"]
    payload = json.loads(_render_rows([row], (candidate,), "json")[0])
    assert payload["status"] == "valid"
    assert payload["credential_detail"] == "(Jobs:2)"
    unsafe = ("jenkins", "localhost", 8080, 0, "valid", "verified", "(Jobs:2)\x1b[31m")
    assert "\x1b" not in _render_rows([unsafe], (candidate,), "txt")[0]
    assert "\x1b" not in _render_rows([unsafe], (candidate,), "json")[0]


def test_spray_colors_follow_airflow_semantics() -> None:
    class ConsoleStub:
        def __init__(self) -> None:
            self.lines: list[str] = []

        def _paint(self, value: str, color: str, _stream: object) -> str:
            return f"<{color}>{value}</{color}>"

        def plain(self, value: str) -> None:
            self.lines.append(value)

    console = ConsoleStub()
    sink = SpraySink(None, "txt", (Candidate("pair", "alice", "secret"),), console)
    try:
        sink.emit("airflow", "localhost", 8080, None, "confirmed", "auth required:True; version:unknown")
        sink.emit("airflow", "localhost", 8080, 0, "valid", "identity verified", "(Jobs:2)")
        sink.emit("airflow", "localhost", 8080, 0, "invalid", "credential rejected")
        sink.emit("mongodb", "localhost", 27018, 0, "inconclusive", "credential not verified")
        sink.emit("redis", "localhost", 6379, 0, "valid", "identity verified", "(version:7.2.4) (keys:Access Denied)")
    finally:
        sink.close()
    assert "<bright_green>auth required:True</bright_green>" in console.lines[0]
    assert "<orange>version:unknown</orange>" in console.lines[0]
    assert "<true_red>alice:secret</true_red>" in console.lines[1]
    assert "<green>[+]</green>" in console.lines[1]
    assert "<true_red>Jobs:2</true_red>" in console.lines[1]
    assert "<true_red>[-]</true_red>" in console.lines[2]
    assert "<white>alice:secret</white>" in console.lines[2]
    assert "<true_red>[-]</true_red>" in console.lines[3]
    assert "<white>alice:secret</white>" in console.lines[3]
    assert "<orange>version:7.2.4</orange>" in console.lines[4]
    assert "<bright_green>keys:Access Denied</bright_green>" in console.lines[4]
    assert "(valid)" not in console.lines[1] and "(invalid)" not in console.lines[2]


def test_spray_negative_marker_red_pair_white_ansi(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("FORCE_COLOR", "1")
    monkeypatch.delenv("NO_COLOR", raising=False)
    sink = SpraySink(None, "txt", (Candidate("pair", "admin", "admin"),), Console(no_color=False))
    try:
        sink.emit("mongodb", "localhost", 27018, 0, "inconclusive", "credential not verified")
    finally:
        sink.close()
    terminal = capsys.readouterr().out
    assert "\x1b[1;38;5;196m[-]\x1b[0m" in terminal
    assert "\x1b[1;97madmin:admin\x1b[0m" in terminal
    assert "evidence:" not in terminal


def test_spray_debug_includes_evidence_in_terminal_and_txt(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    output = tmp_path / "spray-debug.txt"
    sink = SpraySink(str(output), "txt", (Candidate("pair", "admin", "admin"),), Console(no_color=True), debug=True)
    try:
        sink.emit("mongodb", "localhost", 27018, 0, "inconclusive", "credential not verified")
    finally:
        sink.close()
    assert "(evidence:credential not verified)" in capsys.readouterr().out
    assert "(evidence:credential not verified)" in output.read_text()
    assert "\x1b[" not in output.read_text()


def test_spray_no_color_and_checkpoint_replay_preserve_detail(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    candidate = Candidate("pair", "admin", "secret")
    checkpoint = tmp_path / "spray.sqlite3"
    output = tmp_path / "spray.txt"
    journal = AttemptJournal(str(checkpoint), "same", False)
    try:
        journal.put("one", "jenkins", "localhost", 8080, 0, "valid", "identity verified", "(Jobs:2)")
    finally:
        journal.close()
    assert b"secret" not in checkpoint.read_bytes()
    resumed = AttemptJournal(str(checkpoint), "same", True)
    try:
        sink = SpraySink(str(output), "txt", (candidate,), Console(no_color=True))
        try:
            for row in resumed.rows():
                sink.emit(*row)
        finally:
            sink.close()
    finally:
        resumed.close()
    assert "\x1b[" not in capsys.readouterr().out
    assert output.read_text().splitlines() == ["JENKINS\tlocalhost\t8080\t [+] admin:secret (Jobs:2)"]
    assert "\x1b[" not in output.read_text()


def test_confirmed_only_and_no_data_hook(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    calls: list[str] = []
    confirmed = True

    def detect(_ctx: object) -> AuditRecord:
        calls.append("detect")
        return AuditRecord.from_mapping(
            {"host": "localhost", "port": 8080, "status": "detected", "is_airflow": confirmed}
        )

    def auth(_ctx: object, _record: AuditRecord) -> AuditRecord:
        calls.append("auth")
        return AuditRecord.from_mapping(
            {"host": "localhost", "port": 8080, "status": "valid_credentials", "provided_credentials_ok": True}
        )

    def data(_ctx: object, _record: AuditRecord) -> AuditRecord:
        raise AssertionError("data must not run")

    spec = ModuleAuditSpec(
        module="airflow",
        label="AIRFLOW",
        default_port=8080,
        detect=detect,
        auth=auth,
        data=data,
        is_detected=lambda record: record.extra.get("is_airflow") is True,
        credential_gate=lambda _credential, record: (record.extra.get("provided_credentials_ok") is True, "identity"),
    )
    monkeypatch.setattr(
        "redposture_core.stage_spray.importlib.import_module",
        lambda _name: SimpleNamespace(build_airflow_spec=lambda _args: spec),
    )
    journal = AttemptJournal(str(tmp_path / "journal.sqlite3"), "x", False)
    target = ScanTargetSpec(host="localhost", explicit_port=8080, raw="localhost:8080")
    try:
        args = Namespace()
        _run_target(
            "airflow",
            args,
            "localhost",
            8080,
            target,
            (Candidate("pair", "u", "p"),),
            journal,
            RateGate(1000, 0.001),
            None,
        )
        assert calls == ["detect", "auth"]
        assert [row[4] for row in journal.rows()] == ["confirmed", "valid"]
        calls.clear()
        confirmed = False
        other = ScanTargetSpec(host="localhost", explicit_port=8081, raw="localhost:8081")
        _run_target(
            "airflow",
            args,
            "localhost",
            8081,
            other,
            (Candidate("pair", "u", "p"),),
            journal,
            RateGate(1000, 0.001),
            None,
        )
        assert calls == ["detect"]
    finally:
        journal.close()


def test_spray_valid_result_uses_module_capabilities_but_never_inventory(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import redposture_core.stage_spray as spray

    calls: list[str] = []

    def detect(_ctx: object) -> AuditRecord:
        calls.append("detect")
        return AuditRecord.from_mapping({"host": "localhost", "port": 8080, "status": "detected", "is_airflow": True})

    def auth(_ctx: object, _record: AuditRecord) -> AuditRecord:
        calls.append("auth")
        return AuditRecord.from_mapping(
            {"host": "localhost", "port": 8080, "status": "valid_credentials", "provided_credentials_ok": True}
        )

    def capabilities(_ctx: object, record: AuditRecord) -> AuditRecord:
        calls.append("capabilities")
        return AuditRecord.from_mapping({**record.to_dict(), "dags_count": 3})

    def render(record: AuditRecord) -> list[str]:
        return [f"AIRFLOW\tlocalhost\t8080\t [+] alice:secret (Dags:{record.extra['dags_count']})"]

    spec = ModuleAuditSpec(
        module="airflow",
        label="AIRFLOW",
        default_port=8080,
        detect=detect,
        auth=auth,
        capabilities=capabilities,
        data=lambda _ctx, _record: pytest.fail("inventory must not run"),
        render=render,
        is_detected=lambda record: record.extra.get("is_airflow") is True,
        credential_gate=lambda _credential, record: (record.extra.get("provided_credentials_ok") is True, "verified"),
    )
    monkeypatch.setattr(
        spray.importlib, "import_module", lambda _name: SimpleNamespace(build_airflow_spec=lambda _args: spec)
    )
    journal = AttemptJournal(str(tmp_path / "journal.sqlite3"), "same", False)
    try:
        _run_target(
            "airflow",
            Namespace(),
            "localhost",
            8080,
            ScanTargetSpec("localhost", raw="localhost:8080"),
            (Candidate("pair", "alice", "secret"),),
            journal,
            RateGate(1000, 0.001),
            None,
        )
        assert calls == ["detect", "auth", "capabilities"]
        assert journal.rows()[1][6] == "(Dags:3)"
        assert b"secret" not in (tmp_path / "journal.sqlite3").read_bytes()
    finally:
        journal.close()


@pytest.mark.parametrize(
    "module, field, value, suffix",
    [
        ("grafana", "datasource_count", 3, "(datasources:3)"),
        ("redis", "key_count", 7, "(version:7.2.4) (keys:7)"),
    ],
)
def test_spray_reads_verified_capability_count_without_inventory(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    module: str,
    field: str,
    value: int,
    suffix: str,
) -> None:
    import redposture_core.stage_spray as spray

    calls: list[str] = []

    def detect(_ctx: object) -> AuditRecord:
        calls.append("detect")
        return AuditRecord.from_mapping(
            {"host": "localhost", "port": 8080, "status": "auth_required", f"is_{module}": True}
        )

    def auth(ctx: object, _record: AuditRecord) -> AuditRecord:
        calls.append("auth")
        username = ctx.credential.username
        return AuditRecord.from_mapping(
            {
                "host": "localhost",
                "port": 8080,
                "status": "valid_credentials" if username == "alice" else "auth_required",
                "provided_credentials_ok": username == "alice",
                "provided_username": username,
                f"is_{module}": True,
                "server_version": "7.2.4" if module == "redis" and username == "alice" else None,
            }
        )

    def data(ctx: object, record: AuditRecord) -> AuditRecord:
        calls.append("data")
        assert ctx.credential.username == "alice"
        assert ctx.run_deep_checks is True
        return AuditRecord.from_mapping({**record.to_dict(), field: value})

    def render(record: AuditRecord) -> list[str]:
        count = record.extra.get(field)
        count_text = str(count) if count is not None else "unknown"
        label = "datasources" if module == "grafana" else "keys"
        return [f"{module.upper()}\tlocalhost\t8080\t [+] alice:secret ({label}:{count_text})"]

    spec = ModuleAuditSpec(
        module=module,
        label=module.upper(),
        default_port=8080,
        detect=detect,
        auth=auth,
        data=data,
        render=render,
        is_detected=lambda record: record.extra.get(f"is_{module}") is True,
        credential_gate=lambda _credential, record: (record.extra.get("provided_credentials_ok") is True, "verified"),
    )
    monkeypatch.setattr(
        spray.importlib,
        "import_module",
        lambda _name: SimpleNamespace(**{f"build_{module}_spec": lambda _args: spec}),
    )
    journal = AttemptJournal(str(tmp_path / "journal.sqlite3"), "same", False)
    try:
        _run_target(
            module,
            Namespace(),
            "localhost",
            8080,
            ScanTargetSpec("localhost", raw="localhost:8080"),
            (Candidate("pair", "bob", "wrong"), Candidate("pair", "alice", "secret")),
            journal,
            RateGate(1000, 0.001),
            None,
        )
        assert calls == ["detect", "auth", "auth", "data"]
        assert journal.rows()[2][6] == suffix
    finally:
        journal.close()


def test_spray_uses_product_version_fields_and_denied_capability_text() -> None:
    from redposture_core.stage_spray import _record_version, _spray_credential_detail

    record = AuditRecord.from_mapping({"server_version": "11.3.1", "status": "detected"})
    assert _record_version(record) == "11.3.1"
    assert _record_version(AuditRecord.from_mapping({"server_version": None})) is None
    denied = AuditRecord.from_mapping({"error": "NOPERM this user cannot run DBSIZE"})
    assert _spray_credential_detail("redis", denied, "(keys:unknown)") == "(keys:Access Denied)"


def test_spray_postgres_suffix_uses_verified_privilege_results() -> None:
    from redposture_core.modules.postgres.stage import build_postgres_spec

    spec = build_postgres_spec(Namespace(defcreds=False))
    record = AuditRecord.from_mapping(
        {
            "host": "localhost",
            "port": 5432,
            "status": "valid_credentials",
            "provided_credentials": True,
            "provided_username": "postgres",
            "provided_password": "secret",
            "credential_verified": True,
            "superuser": True,
            "can_execute_commands": True,
            "can_read_tables": False,
            "database_count": 2,
        }
    )
    assert _credential_detail(spec, record, Candidate("pair", "postgres", "secret")) == (
        "(superuser:True) (execute:True) (read:False) (DBs:2)"
    )


def test_live_output_resume_and_json_keep_exactly_one_result(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    import threading

    import redposture_core.stage_spray as spray

    entered = threading.Event()
    release = threading.Event()
    auth_calls = 0

    def detect(_ctx: object) -> AuditRecord:
        return AuditRecord.from_mapping({"host": "localhost", "port": 8080, "status": "detected", "is_airflow": True})

    def auth(_ctx: object, _record: AuditRecord) -> AuditRecord:
        nonlocal auth_calls
        auth_calls += 1
        entered.set()
        release.wait(5)
        return AuditRecord.from_mapping(
            {"host": "localhost", "port": 8080, "status": "valid_credentials", "provided_credentials_ok": True}
        )

    spec = ModuleAuditSpec(
        module="airflow",
        label="AIRFLOW",
        default_port=8080,
        detect=detect,
        auth=auth,
        is_detected=lambda record: record.extra.get("is_airflow") is True,
        credential_gate=lambda _candidate, record: (record.extra.get("provided_credentials_ok") is True, "identity"),
    )
    monkeypatch.setattr(
        spray.importlib, "import_module", lambda _name: SimpleNamespace(build_airflow_spec=lambda _args: spec)
    )
    monkeypatch.setattr(
        spray,
        "_job_targets",
        lambda _module, _args: iter(
            [("localhost", 8080, ScanTargetSpec("localhost", explicit_port=8080, raw="localhost:8080"))]
        ),
    )
    pairs = tmp_path / "pairs"
    pairs.write_text("alice:secret\n", encoding="utf-8")
    output = tmp_path / "results.jsonl"
    checkpoint = tmp_path / "checkpoint.sqlite3"
    argv = [
        "spray",
        "-t",
        "localhost:8080",
        "--modules",
        "airflow",
        "--pairs",
        str(pairs),
        "--checkpoint",
        str(checkpoint),
        "-o",
        str(output),
        "-f",
        "json",
        "--no-color",
    ]
    args = parse_args(argv)
    result: list[int] = []
    thread = threading.Thread(target=lambda: result.append(run_spray_stage(args, None)))
    thread.start()
    assert entered.wait(5)
    assert [json.loads(line)["status"] for line in output.read_text().splitlines()] == ["confirmed"]
    release.set()
    thread.join(5)
    assert result == [0]
    assert auth_calls == 1
    assert [json.loads(line)["status"] for line in output.read_text().splitlines()] == ["confirmed", "valid"]
    assert json.loads(output.read_text().splitlines()[1])["password"] == "secret"
    assert output.stat().st_mode & 0o777 == 0o600
    assert b"secret" not in checkpoint.read_bytes()
    assert run_spray_stage(parse_args([*argv, "--resume"]), None) == 0
    assert auth_calls == 1
    assert len(output.read_text().splitlines()) == 2


def test_interrupted_request_is_inconclusive_without_retry(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    import redposture_core.stage_spray as spray

    auth_calls = 0

    def detect(_ctx: object) -> AuditRecord:
        return AuditRecord.from_mapping({"host": "localhost", "port": 8080, "status": "detected", "is_airflow": True})

    def auth(_ctx: object, _record: AuditRecord) -> AuditRecord:
        nonlocal auth_calls
        auth_calls += 1
        raise KeyboardInterrupt

    spec = ModuleAuditSpec(
        module="airflow",
        label="AIRFLOW",
        default_port=8080,
        detect=detect,
        auth=auth,
        is_detected=lambda record: record.extra.get("is_airflow") is True,
    )
    monkeypatch.setattr(
        spray.importlib, "import_module", lambda _name: SimpleNamespace(build_airflow_spec=lambda _args: spec)
    )
    monkeypatch.setattr(
        spray,
        "_job_targets",
        lambda _module, _args: iter([("localhost", 8080, ScanTargetSpec("localhost", raw="localhost:8080"))]),
    )
    pairs = tmp_path / "pairs"
    pairs.write_text("alice:secret\n", encoding="utf-8")
    output = tmp_path / "results.jsonl"
    checkpoint = tmp_path / "checkpoint.sqlite3"
    argv = [
        "spray",
        "-t",
        "localhost:8080",
        "--modules",
        "airflow",
        "--pairs",
        str(pairs),
        "--checkpoint",
        str(checkpoint),
        "-o",
        str(output),
        "-f",
        "json",
        "--no-color",
    ]
    with pytest.raises(KeyboardInterrupt):
        run_spray_stage(parse_args(argv), None)
    assert auth_calls == 1
    assert run_spray_stage(parse_args([*argv, "--resume"]), None) == 0
    assert auth_calls == 1
    assert [json.loads(line)["status"] for line in output.read_text().splitlines()] == ["confirmed", "inconclusive"]


def test_keeper_read_only_detection_does_not_probe_ddl(monkeypatch: pytest.MonkeyPatch) -> None:
    from redposture_core.modules.keeper import actions as keeper_actions
    from redposture_core.modules.zookeeper import engine
    from redposture_core.stage_spray import _readonly_keeper_detection

    monkeypatch.setattr(keeper_actions, "probe_ddl_access", lambda _client: pytest.fail("DDL write probe used"))
    monkeypatch.setattr(
        engine,
        "detect_zookeeper_implementation",
        lambda _ctx, _options: {
            "host": "localhost",
            "port": 9181,
            "status": "detected",
            "is_zookeeper": True,
            "is_keeper": True,
        },
    )
    context = SimpleNamespace(args=None, host="localhost", port=9181)
    args = _module_runtime_args(
        "keeper",
        SimpleNamespace(
            targets="localhost:9181", timeout=1, retries=0, workers=1, proxy=None, debug=False, no_color=True
        ),
        {},
    )
    record = _readonly_keeper_detection(context, args)
    assert record.extra["is_keeper"] is True


@settings(max_examples=int(os.getenv("REDPOSTURE_SPRAY_FUZZ_EXAMPLES", "250")), deadline=None)
@given(st.text(max_size=100), st.text(max_size=100))
def test_fuzz_txt_and_json_keep_four_fields_and_no_terminal_escape(username: str, password: str) -> None:
    candidate = Candidate("pair", username, password)
    row = [("airflow", "localhost", 8080, 0, "invalid", "credential rejected")]
    text_line = _render_rows(row, (candidate,), "txt")[0]
    json_line = _render_rows(row, (candidate,), "json")[0]
    assert len(text_line.split("\t")) == 4
    assert "\x1b" not in text_line
    assert "\x1b" not in json_line
    parsed = json.loads(json_line)
    assert parsed["username"] == username
    assert parsed["password"] == password


@pytest.mark.parametrize("module", AUDIT_MODULE_NAMES)
def test_credential_type_matrix_and_ambiguous_evidence(module: str) -> None:
    detected = AuditRecord.from_mapping({"host": "localhost", "port": 1, "status": "detected"})
    assert _supported(module, Candidate("pair", "u", "p"), detected) == (
        module not in {"docker", "keycloak", "qdrant", "kubeapi"}
    )
    assert _supported(module, Candidate("token", token="jwt"), detected) == (
        module
        in {
            "consul",
            "docker-registry",
            "harbor",
            "nexus",
            "elastic",
            "gitlab",
            "grafana",
            "grpc",
            "keycloak",
            "kubeapi",
            "proxmox",
            "qdrant",
        }
    )


@pytest.mark.parametrize("module", AUDIT_MODULE_NAMES)
@pytest.mark.parametrize("kind", ("pair", "token"))
def test_all_modules_gate_attempts_after_confirmation(
    module: str, kind: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import redposture_core.stage_spray as spray

    calls: list[str] = []
    detection = AuditRecord.from_mapping(
        {
            "host": "localhost",
            "port": 1,
            "status": "detected",
            "credential_verification_status": "available",
        }
    )

    def detect(_ctx: object) -> AuditRecord:
        calls.append("detect")
        return detection

    def auth(_ctx: object, _record: AuditRecord) -> AuditRecord:
        calls.append("auth")
        return AuditRecord.from_mapping(
            {"host": "localhost", "port": 1, "status": "valid_credentials", "provided_credentials_ok": True}
        )

    spec = ModuleAuditSpec(
        module=module,
        label=module.upper(),
        default_port=1,
        detect=detect,
        auth=auth,
        is_detected=lambda _record: True,
        credential_gate=lambda _credential, _record: (True, "verified"),
    )
    builder = f"build_{module.replace('-', '_')}_spec"
    monkeypatch.setattr(
        spray.importlib, "import_module", lambda _name: SimpleNamespace(**{builder: lambda _args: spec})
    )
    if module == "oracle":
        monkeypatch.setattr(spray, "_oracle_spray_preflight", lambda *_args: True)
    if module == "keeper":
        monkeypatch.setattr(spray, "_readonly_keeper_detection", lambda _ctx, _args: detect(_ctx))
    candidate = Candidate("pair", "alice", "secret") if kind == "pair" else Candidate("token", token="token")
    journal = AttemptJournal(str(tmp_path / "attempts.sqlite3"), "fingerprint", False)
    try:
        _run_target(
            module,
            Namespace(),
            "localhost",
            1,
            ScanTargetSpec("localhost", raw="localhost:1"),
            (candidate,),
            journal,
            RateGate(1000, 0.001),
            None,
        )
        expected_auth = _supported(module, candidate, detection)
        assert calls == (["detect", "auth"] if expected_auth else ["detect"])
        assert [row[4] for row in journal.rows()] == ["confirmed", "valid" if expected_auth else "unsupported"]
    finally:
        journal.close()


def test_confirmed_product_does_not_stop_other_selected_detectors(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import redposture_core.stage_spray as spray

    seen: list[str] = []

    def build(module: str) -> ModuleAuditSpec:
        def detect(_ctx: object) -> AuditRecord:
            seen.append(f"{module}:detect")
            return AuditRecord.from_mapping({"host": "localhost", "port": 8080, "status": "detected"})

        def auth(_ctx: object, _record: AuditRecord) -> AuditRecord:
            seen.append(f"{module}:auth")
            return AuditRecord.from_mapping(
                {"host": "localhost", "port": 8080, "status": "invalid_credentials", "provided_credentials_ok": False}
            )

        return ModuleAuditSpec(
            module=module,
            label=module.upper(),
            default_port=8080,
            detect=detect,
            auth=auth,
            is_detected=lambda _record: True,
        )

    monkeypatch.setattr(
        spray.importlib,
        "import_module",
        lambda name: SimpleNamespace(**{f"build_{name.split('.')[-2]}_spec": lambda _args: build(name.split(".")[-2])}),
    )
    monkeypatch.setattr(
        spray,
        "_job_targets",
        lambda _module, _args: iter(
            [("localhost", 8080, ScanTargetSpec("localhost", explicit_port=8080, raw="localhost:8080"))]
        ),
    )
    pairs = tmp_path / "pairs"
    pairs.write_text("alice:secret\n", encoding="utf-8")
    args = parse_args(
        [
            "spray",
            "-t",
            "localhost:8080",
            "--modules",
            "airflow,grafana",
            "--pairs",
            str(pairs),
            "--account-interval",
            "0.001",
            "--origin-rate",
            "1000",
            "--no-color",
        ]
    )
    assert run_spray_stage(args, None) == 0
    assert sorted(seen) == ["airflow:auth", "airflow:detect", "grafana:auth", "grafana:detect"]
