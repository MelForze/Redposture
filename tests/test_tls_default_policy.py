"""CLI contract for audit-tool TLS trust without verification toggles."""

from __future__ import annotations

import argparse
from types import SimpleNamespace
from typing import Any

import pytest

from redposture_core.cli_args import build_parser, parse_args
from redposture_core.clients.zookeeper import _transport_attempt_order
from redposture_core.module_registry import AUDIT_MODULE_NAMES
from redposture_core.modules.clickhouse.stage import _clickhouse_transport_kwargs
from redposture_core.modules.consul.stage import build_consul_spec
from redposture_core.modules.grpc.stage import build_grpc_spec
from redposture_core.modules.kafka.stage import build_kafka_spec
from redposture_core.modules.keeper.stage import build_keeper_spec
from redposture_core.modules.kubeapi import actions as kubeapi_actions
from redposture_core.modules.proxmox.stage import _proxmox_lifecycle_state_factory
from redposture_core.modules.redis.actions import redis_lifecycle_state_factory
from redposture_core.modules.zookeeper.stage import build_zookeeper_spec
from redposture_core.stage_runtime import _argument_value_for_hook

_REMOVED_TLS_FLAGS = {"--insecure", "--no-insecure", "--tls-insecure"}


@pytest.mark.parametrize("command", AUDIT_MODULE_NAMES)
def test_audit_help_has_no_tls_verification_bypass_switch(command: str) -> None:
    parser = build_parser()
    subcommands = next(action for action in parser._actions if isinstance(action, argparse._SubParsersAction))
    module_parser = subcommands.choices[command]
    options = {option for action in module_parser._actions for option in action.option_strings}
    assert options.isdisjoint(_REMOVED_TLS_FLAGS)


@pytest.mark.parametrize("workflow", ("scan", "collect", "trigger"))
def test_exporter_help_has_no_tls_verification_bypass_switch(workflow: str) -> None:
    parser = build_parser()
    subcommands = next(action for action in parser._actions if isinstance(action, argparse._SubParsersAction))
    exporters = subcommands.choices["exporters"]
    workflows = next(action for action in exporters._actions if isinstance(action, argparse._SubParsersAction))
    workflow_parser = workflows.choices[workflow]
    options = {option for action in workflow_parser._actions for option in action.option_strings}
    assert options.isdisjoint(_REMOVED_TLS_FLAGS)


def _ctx(args: Any) -> SimpleNamespace:
    return SimpleNamespace(
        args=args,
        host="127.0.0.1",
        port=9181,
        target=SimpleNamespace(scheme=None, path=""),
        debug_emit=None,
    )


@pytest.mark.parametrize("command,build_spec", (("kafka", build_kafka_spec), ("grpc", build_grpc_spec)))
def test_native_auto_transport_remains_auto_and_trusts_server_without_ca(command: str, build_spec: Any) -> None:
    args = parse_args([command, "-t", "127.0.0.1"])
    factory = build_spec(args).lifecycle_state_factory
    assert callable(factory)
    state = factory(_ctx(args))
    assert state.requested_use_tls is None
    assert state.tls_config.insecure is True
    state.close()


@pytest.mark.parametrize("command,build_spec", (("kafka", build_kafka_spec), ("grpc", build_grpc_spec)))
def test_native_explicit_tls_trusts_server_but_ca_verifies(command: str, build_spec: Any) -> None:
    for extra, expected in ((["--tls"], True), (["--tls-ca", "ca.pem"], False)):
        args = parse_args([command, "-t", "127.0.0.1", *extra])
        factory = build_spec(args).lifecycle_state_factory
        assert callable(factory)
        state = factory(_ctx(args))
        assert state.requested_use_tls is True
        assert state.tls_config.insecure is expected
        state.close()


def test_consul_and_redis_trust_without_ca_without_forcing_tls() -> None:
    consul_args = parse_args(["consul", "-t", "127.0.0.1"])
    factory = build_consul_spec(consul_args).lifecycle_state_factory
    assert callable(factory)
    consul = factory(_ctx(consul_args))
    assert consul.preferred_scheme is None
    assert consul.insecure is True
    consul.close()

    redis_args = parse_args(["redis", "-t", "127.0.0.1"])
    redis = redis_lifecycle_state_factory(_ctx(redis_args))
    assert redis.use_tls is False
    assert redis.insecure is True


@pytest.mark.parametrize("command,build_spec", (("zookeeper", build_zookeeper_spec), ("keeper", build_keeper_spec)))
def test_zookeeper_protocol_keeps_plaintext_first_with_unverified_tls_fallback(command: str, build_spec: Any) -> None:
    args = parse_args([command, "-t", "127.0.0.1"])
    factory = build_spec(args).lifecycle_state_factory
    assert callable(factory)
    state = factory(_ctx(args))
    assert state.requested_config.insecure is True
    assert _transport_attempt_order(state.requested_config) == ("plaintext", "tls")


def test_clickhouse_explicit_tls_trusts_without_ca_and_verifies_with_ca() -> None:
    default_args = parse_args(["clickhouse", "-t", "127.0.0.1", "--tls"])
    assert _clickhouse_transport_kwargs(default_args)["tls_config"].verify is False
    ca_args = parse_args(["clickhouse", "-t", "127.0.0.1", "--tls", "--tls-ca", "ca.pem"])
    assert _clickhouse_transport_kwargs(ca_args)["tls_config"].verify is True


@pytest.mark.parametrize(
    "command,without_ca,with_ca",
    (
        ("docker", [], ["--tls-ca", "ca.pem"]),
        ("oracle", [], ["--ssl-server-dn", "CN=db.example"]),
    ),
)
def test_generic_host_stage_trusts_by_default_and_honors_explicit_identity(
    command: str, without_ca: list[str], with_ca: list[str]
) -> None:
    for extra, expected in ((without_ca, True), (with_ca, False)):
        args = parse_args([command, "-t", "127.0.0.1", *extra])
        ctx = SimpleNamespace(args=args, target=None, credential=None)
        assert _argument_value_for_hook("insecure", ctx, object()) is expected


def test_mongodb_tls_does_not_turn_on_by_trust_default() -> None:
    for extra, expected in (([], False), (["--tls"], True), (["--tls-ca", "ca.pem"], False)):
        args = parse_args(["mongodb", "-t", "127.0.0.1", *extra])
        ctx = SimpleNamespace(args=args, target=None, credential=None)
        assert _argument_value_for_hook("tls_insecure", ctx, object()) is expected


def test_proxmox_uses_unverified_https_without_a_toggle() -> None:
    args = parse_args(["proxmox", "-t", "127.0.0.1"])
    state = _proxmox_lifecycle_state_factory(_ctx(args))
    assert state.http is not None
    assert state.http.insecure is True
    state.close()


@pytest.mark.parametrize("workflow", ("scan", "collect", "trigger"))
def test_exporter_workflows_trust_target_tls_without_a_toggle(workflow: str) -> None:
    args = parse_args(["exporters", workflow, "-t", "127.0.0.1"])
    assert args.insecure is True


def test_kubeapi_trusts_by_default_and_explicit_ca_does_not_downgrade(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[bool, bool, str | None]] = []

    def request(*_args: Any, use_https: bool, insecure: bool, ca_file: str | None, **_kwargs: Any) -> Any:
        calls.append((use_https, insecure, ca_file))
        return 0, None, {}, "certificate verify failed"

    monkeypatch.setattr(kubeapi_actions, "_state_http_client_or_none", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(kubeapi_actions, "_api_request_json_with_retries", request)
    args = parse_args(["kubeapi", "-t", "https://127.0.0.1:6443", "--ca-file", "ca.pem"])
    state = kubeapi_actions.KubeApiLifecycleState(use_https=True, ca_file="ca.pem")
    state.configure_transport("127.0.0.1", 6443, 1)
    kubeapi_actions._lifecycle_get_json_with_retries(_ctx(args), state, "/version", response_size_cap=1024)
    assert calls == [(True, False, "ca.pem")]
    assert state.use_https is True
    assert state.insecure is False

    without_ca = parse_args(["kubeapi", "-t", "https://127.0.0.1:6443"])
    no_ca_state = kubeapi_actions.KubeApiLifecycleState()
    no_ca_ctx = _ctx(without_ca)
    no_ca_ctx.lifecycle_state = no_ca_state
    monkeypatch.setattr(
        kubeapi_actions,
        "_lifecycle_get_json_with_retries",
        lambda *_args, **_kwargs: (0, None, {}, "unreachable"),
    )
    result = kubeapi_actions.detect_kubeapi(no_ca_ctx, {})
    assert result["insecure_effective"] is True
