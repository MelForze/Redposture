from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

import redposture_core.stage_keeper as keeper_facade
from redposture_core import stage_runtime
from redposture_core.audit_models import AuditRecord
from redposture_core.cli_args import parse_args
from redposture_core.clients.zookeeper import (
    ZkImplementationFingerprint,
    ZkKeeperVirtualProbe,
    ZkTransportConfig,
)
from redposture_core.modules.keeper import stage as keeper_stage
from redposture_core.modules.zookeeper import engine as implementation_engine
from redposture_core.stage_runtime import (
    AuditCommandResult,
    AuditCommandRunner,
    AuditCredentialRun,
    AuditHookContext,
)


def _protocol_detect(ctx, _options):
    ctx.lifecycle_state.selected_transport_config = ZkTransportConfig(mode="plaintext")
    return {
        "host": ctx.host,
        "port": ctx.port,
        "service": "zookeeper",
        "status": "open_no_auth",
        "auth_required": False,
        "is_zookeeper": True,
        "error": None,
        "stages": [],
    }


def _detect_record(
    monkeypatch: pytest.MonkeyPatch,
    fingerprint: ZkImplementationFingerprint,
) -> tuple[object, AuditRecord]:
    args = parse_args(["keeper", "-t", "127.0.0.1", "--retries", "0"])
    spec = keeper_stage.build_keeper_spec(args)
    assert spec.lifecycle_state_factory is not None
    assert spec.detect is not None
    state = spec.lifecycle_state_factory(None)
    monkeypatch.setattr(implementation_engine.zookeeper_actions, "detect_zookeeper", _protocol_detect)
    monkeypatch.setattr(
        implementation_engine,
        "fingerprint_zookeeper_implementation",
        lambda *_args, **_kwargs: fingerprint,
    )
    ctx = AuditHookContext(
        args=args,
        logger=None,
        host="127.0.0.1",
        port=9181,
        credential=AuditCredentialRun(source="anonymous"),
        lifecycle_state=state,
    )
    return spec, spec.detect(ctx)


def test_keeper_plan_uses_only_keeper_default_ports_and_keeper_credentials() -> None:
    args = parse_args(["keeper", "-t", "127.0.0.1", "--defcreds"])
    plan = keeper_stage.build_keeper_plan(args)

    assert plan.ports == (9181, 19181, 29181)
    assert keeper_stage._DEFAULT_CREDENTIALS == keeper_stage.KEEPER_DIGEST_DEFAULT_CREDENTIALS
    assert tuple((item.username, item.password) for item in plan.credential_runs) == keeper_stage._DEFAULT_CREDENTIALS
    assert ("keeper", "keeper") in keeper_stage._DEFAULT_CREDENTIALS
    assert ("clickhouse", "clickhouse") in keeper_stage._DEFAULT_CREDENTIALS
    assert all(item.username not in {"hadoop", "solr", "zookeeper"} for item in plan.credential_runs)


def test_keeper_accepts_only_confirmed_keeper(monkeypatch: pytest.MonkeyPatch) -> None:
    spec, record = _detect_record(
        monkeypatch,
        ZkImplementationFingerprint("clickhouse-keeper", True, "confirmed", version="v25.3.3.42"),
    )
    payload = record.to_dict()

    assert spec.is_detected is not None and spec.is_detected(record) is True
    assert payload["module"] == "keeper"
    assert payload["service"] == "keeper"
    assert payload["implementation"] == "clickhouse-keeper"
    assert payload["is_keeper"] is True
    assert payload["status"] == "open_no_auth"


def test_keeper_rejects_apache_before_auth_or_actions(monkeypatch: pytest.MonkeyPatch) -> None:
    spec, record = _detect_record(
        monkeypatch,
        ZkImplementationFingerprint("apache-zookeeper", False, "confirmed", version="3.9.5"),
    )
    payload = record.to_dict()

    assert spec.is_detected is not None and spec.is_detected(record) is False
    assert payload["status"] == "not_keeper"
    assert payload["is_zookeeper"] is True
    assert payload["is_keeper"] is False
    assert "does not match keeper module" in str(payload["error"])


def test_keeper_virtual_znode_fallback_confirms_no4lw_service(monkeypatch: pytest.MonkeyPatch) -> None:
    class AnonymousClient:
        def probe_keeper_virtual_nodes(self) -> ZkKeeperVirtualProbe:
            return ZkKeeperVirtualProbe(True, api_version=2, children=("api_version", "feature_flags"))

        def close(self) -> None:
            return None

    def fake_detect(ctx, options):
        result = _protocol_detect(ctx, options)
        ctx.lifecycle_state.anonymous_client = AnonymousClient()
        return result

    args = parse_args(["keeper", "-t", "127.0.0.1", "--retries", "0"])
    spec = keeper_stage.build_keeper_spec(args)
    assert spec.lifecycle_state_factory is not None and spec.detect is not None
    state = spec.lifecycle_state_factory(None)
    monkeypatch.setattr(implementation_engine.zookeeper_actions, "detect_zookeeper", fake_detect)
    monkeypatch.setattr(
        implementation_engine,
        "fingerprint_zookeeper_implementation",
        lambda *_args, **_kwargs: ZkImplementationFingerprint("zookeeper-compatible", None, "unconfirmed"),
    )
    ctx = AuditHookContext(
        args=args,
        logger=None,
        host="127.0.0.1",
        port=39181,
        credential=AuditCredentialRun(source="anonymous"),
        lifecycle_state=state,
    )

    payload = spec.detect(ctx).to_dict()

    assert payload["is_keeper"] is True
    assert payload["implementation"] == "clickhouse-keeper"
    assert payload["implementation_evidence"] == "keeper_virtual_znodes"
    assert payload["keeper_virtual_probe"]["api_version"] == 2


def test_unconfirmed_keeper_is_hidden_in_txt_but_preserved_in_json(monkeypatch: pytest.MonkeyPatch) -> None:
    class AnonymousClient:
        def probe_keeper_virtual_nodes(self) -> ZkKeeperVirtualProbe:
            return ZkKeeperVirtualProbe(False, reason="virtual markers unavailable")

        def close(self) -> None:
            return None

    def fake_detect(ctx, options):
        result = _protocol_detect(ctx, options)
        ctx.lifecycle_state.anonymous_client = AnonymousClient()
        return result

    monkeypatch.setattr(implementation_engine.zookeeper_actions, "detect_zookeeper", fake_detect)
    monkeypatch.setattr(
        implementation_engine,
        "fingerprint_zookeeper_implementation",
        lambda *_args, **_kwargs: ZkImplementationFingerprint("zookeeper-compatible", None, "unconfirmed"),
    )
    auth_calls = 0

    def fail_auth(*_args, **_kwargs):
        nonlocal auth_calls
        auth_calls += 1
        raise AssertionError("auth must not run for unconfirmed implementation")

    monkeypatch.setattr(implementation_engine, "authenticate_zookeeper_implementation", fail_auth)

    txt_args = parse_args(["keeper", "-t", "127.0.0.1", "--retries", "0"])
    txt_lines: list[str] = []
    txt_runner = AuditCommandRunner(
        args=txt_args,
        spec=keeper_stage.build_keeper_spec(txt_args),
        emit_line=txt_lines.append,
    )
    txt_result = txt_runner.run_plan(keeper_stage.build_keeper_plan(txt_args))

    assert txt_result.detected_count == 0
    assert auth_calls == 0
    assert not any("ClickHouse Keeper" in line for line in txt_lines)

    json_args = parse_args(["keeper", "-t", "127.0.0.1", "--retries", "0", "--format", "json"])
    json_lines: list[str] = []
    json_runner = AuditCommandRunner(
        args=json_args,
        spec=keeper_stage.build_keeper_spec(json_args),
        emit_line=json_lines.append,
    )
    json_runner.run_plan(keeper_stage.build_keeper_plan(json_args))
    records = [json.loads(line) for line in json_lines]

    assert any(item.get("status") == "not_keeper_unconfirmed" for item in records)
    assert any(item.get("implementation") == "zookeeper-compatible" for item in records)


def test_keeper_spec_adapts_shared_auth_data_and_capability_hooks(monkeypatch: pytest.MonkeyPatch) -> None:
    args = parse_args(["keeper", "-t", "127.0.0.1"])
    spec = keeper_stage.build_keeper_spec(args)
    assert spec.lifecycle_state_factory is not None
    state = spec.lifecycle_state_factory(None)
    ctx = AuditHookContext(
        args=args,
        logger=None,
        host="127.0.0.1",
        port=9181,
        credential=AuditCredentialRun(username="keeper", password="keeper", source="provided"),
        lifecycle_state=state,
    )
    record = AuditRecord.from_mapping(
        {
            "host": "127.0.0.1",
            "port": 9181,
            "status": "open_no_auth",
            "is_zookeeper": True,
            "is_keeper": True,
        },
        module="keeper",
        service="keeper",
    )

    monkeypatch.setattr(
        implementation_engine,
        "authenticate_zookeeper_implementation",
        lambda *_args, **_kwargs: {**record.to_dict(), "provided_credentials_ok": True},
    )
    monkeypatch.setattr(
        implementation_engine,
        "collect_zookeeper_implementation_data",
        lambda *_args, **_kwargs: {**record.to_dict(), "znode_count": 2},
    )
    monkeypatch.setattr(
        implementation_engine,
        "probe_zookeeper_implementation_capabilities",
        lambda *_args, **_kwargs: {**record.to_dict(), "can_create_znode": False},
    )

    assert spec.auth is not None and spec.auth(ctx, record).extra["provided_credentials_ok"] is True
    assert spec.data is not None and spec.data(ctx, record).extra["znode_count"] == 2
    assert spec.capabilities is not None and spec.capabilities(ctx, record).extra["can_create_znode"] is False
    assert spec.credential_gate is not None
    assert spec.credential_gate(ctx.credential, spec.auth(ctx, record))[0] is True
    assert spec.credential_gate(AuditCredentialRun(source="anonymous"), record)[0] is True
    assert spec.is_detected is not None and spec.is_detected(record) is True
    assert spec.lifecycle_state_close is not None
    spec.lifecycle_state_close(state)


def test_run_keeper_stage_debug_success_and_error_paths(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    result = AuditCommandResult(records=[], detected_count=0, emitted_lines=0, typed_records=[])
    monkeypatch.setattr(AuditCommandRunner, "run_plan", lambda *_args, **_kwargs: result)
    args = parse_args(["keeper", "-t", "127.0.0.1", "--debug", "-u", " keeper ", "-p", ""])

    assert keeper_stage.run_keeper_stage(args, logger=None) == 0
    assert args.username == "keeper"
    assert args.password == ""
    output = capsys.readouterr().out
    assert "keeper audit started" in output
    assert "no target confirmed as ClickHouse Keeper" in output

    invalid = parse_args(["keeper", "-t", "127.0.0.1", "-u", "keeper"])
    assert keeper_stage.run_keeper_stage(invalid, logger=None) == 2

    valid = parse_args(["keeper", "-t", "127.0.0.1"])
    monkeypatch.setattr(keeper_stage, "build_keeper_plan", lambda _args: (_ for _ in ()).throw(ValueError("bad plan")))
    assert keeper_stage.run_keeper_stage(valid, logger=None) == 2


def test_run_keeper_stage_handles_output_error(monkeypatch: pytest.MonkeyPatch) -> None:
    args = parse_args(["keeper", "-t", "127.0.0.1"])
    monkeypatch.setattr(
        AuditCommandRunner, "run_plan", lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("disk"))
    )
    assert keeper_stage.run_keeper_stage(args, logger=None) == 2


def test_keeper_compatibility_facade_forwards_runtime_and_stage_attributes(monkeypatch: pytest.MonkeyPatch) -> None:
    assert keeper_facade.collect_scan_ports is stage_runtime.collect_scan_ports
    with pytest.raises(AttributeError):
        keeper_facade.__getattr__("missing_keeper_attribute")

    def runtime_sentinel(*_args, **_kwargs):
        return (9181,)

    monkeypatch.setattr(keeper_facade, "collect_scan_ports", runtime_sentinel)
    assert stage_runtime.collect_scan_ports is runtime_sentinel

    stage_sentinel = SimpleNamespace(name="keeper-stage")
    monkeypatch.setattr(keeper_facade, "run_keeper_stage", stage_sentinel)
    assert keeper_stage.run_keeper_stage is stage_sentinel
