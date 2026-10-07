"""Credential-only spray contracts and all-module registration checks."""

from __future__ import annotations

import json
from argparse import Namespace
from pathlib import Path
from types import SimpleNamespace

import pytest
from hypothesis import given
from hypothesis import strategies as st

from redposture_core.audit_models import AuditRecord
from redposture_core.cli_args import parse_args
from redposture_core.console import Console
from redposture_core.module_registry import AUDIT_MODULE_NAMES
from redposture_core.stage_runtime import AuditCredentialRun, ModuleAuditSpec
from redposture_core.stage_spray import (
    AttemptJournal,
    Candidate,
    RateGate,
    SpraySink,
    _config,
    _effective_origin,
    _input_fingerprint,
    _job_targets,
    _module_runtime_args,
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


def test_spray_requires_modules_and_rejects_action_config(tmp_path: Path) -> None:
    with pytest.raises(SystemExit):
        parse_args(["spray", "-t", "localhost", "--pairs", "pairs.txt"])
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"keeper": {"create_user": "evil"}}), encoding="utf-8")
    with pytest.raises(ValueError, match="rejects"):
        _config(str(path), ("keeper",))


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


@pytest.mark.parametrize(("module", "default_port"), [("airflow", 8080), ("postgres", 5432), ("kafka", 9092)])
def test_bare_host_uses_module_default_ports(module: str, default_port: int) -> None:
    parent = SimpleNamespace(
        targets="127.0.0.1", timeout=0.1, retries=0, workers=1, proxy=None, debug=False, no_color=True
    )
    args = _module_runtime_args(module, parent, {})
    ports = {port for _host, port, _target in _job_targets(module, args)}
    assert default_port in ports


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


def test_unsupported_credentials_and_private_output_shape() -> None:
    detected = AuditRecord.from_mapping({"host": "localhost", "port": 2375, "status": "detected"})
    assert not _supported("docker", Candidate("pair", "u", "p"), detected)
    assert not _supported("keycloak", Candidate("pair", "u", "p"), detected)
    assert _supported("keycloak", Candidate("token", token="jwt"), detected)
    lines = _render_rows(
        [("airflow", "localhost", 8080, 0, "valid", "identity verified")], (Candidate("pair", "u", "p"),), "txt"
    )
    assert lines == ["AIRFLOW\tlocalhost\t8080\t [+] u:p (valid) (evidence:identity verified)"]
    assert "\x1b" not in lines[0]


def test_rate_gate_origin_and_account_limits() -> None:
    gate = RateGate(2, 60)
    assert gate.reserve("origin", "alice") == (True, 0)
    assert gate.reserve("origin", "bob")[1] > 0
    assert gate.reserve("origin", "alice")[1] > 59
    gate.stop("origin", "429")
    assert gate.reserve("origin", "charlie") == (False, "429")


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
