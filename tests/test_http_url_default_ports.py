"""URL scheme ports override product port matrices only when no CLI port is given."""

from __future__ import annotations

import importlib
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from redposture_core.cli_args import parse_args
from redposture_core.modules.clickhouse import actions as clickhouse_actions
from redposture_core.stage_runtime import AuditCommandPlan

HTTP_AUDIT_MODULES = (
    "airflow",
    "consul",
    "docker",
    "docker-registry",
    "harbor",
    "nexus",
    "elastic",
    "etcd",
    "gitlab",
    "grafana",
    "grpc",
    "jenkins",
    "keycloak",
    "kubeapi",
    "minio",
    "proxmox",
    "qdrant",
    "rabbitmq",
    "clickhouse",
)


def _plan(module: str, *arguments: str) -> AuditCommandPlan:
    package = module.replace("-", "_")
    stage = importlib.import_module(f"redposture_core.modules.{package}.stage")
    return getattr(stage, f"build_{package}_plan")(parse_args([module, *arguments]))


def _targets(plan: AuditCommandPlan) -> list[tuple[str, int, str | None, str]]:
    return [(host, port, target.scheme, target.path) for _index, host, port, target in plan.iter_target_specs()]


@pytest.mark.parametrize("module", HTTP_AUDIT_MODULES)
@pytest.mark.parametrize(("scheme", "expected_port"), [("http", 80), ("https", 443)])
def test_http_url_without_port_uses_scheme_port(module: str, scheme: str, expected_port: int) -> None:
    plan = _plan(module, "-t", f"{scheme}://example.test/prefix")

    assert _targets(plan) == [("example.test", expected_port, scheme, "/prefix")]
    assert plan.target_count == 1
    assert plan.target_counts_by_port() == {expected_port: 1}


@pytest.mark.parametrize("module", HTTP_AUDIT_MODULES)
def test_explicit_url_port_keeps_precedence(module: str) -> None:
    plan = _plan(module, "-t", "https://example.test:19443/prefix")

    assert _targets(plan) == [("example.test", 19443, "https", "/prefix")]


@pytest.mark.parametrize("module", HTTP_AUDIT_MODULES)
def test_explicit_cli_port_overrides_implicit_url_port(module: str) -> None:
    plan = _plan(module, "-t", "https://example.test/prefix", "--port", "19443")

    assert _targets(plan) == [("example.test", 19443, "https", "/prefix")]


@pytest.mark.parametrize("module", HTTP_AUDIT_MODULES)
def test_mixed_url_and_bare_target_preserves_product_matrix(module: str, tmp_path: Path) -> None:
    targets = tmp_path / "targets.txt"
    targets.write_text("https://web.example/prefix\nnode.example\n", encoding="utf-8")
    plan = _plan(module, "-t", str(targets))
    resolved = _targets(plan)

    assert [(host, port, scheme) for host, port, scheme, _path in resolved if host == "web.example"] == [
        ("web.example", 443, "https")
    ]
    assert {port for host, port, _scheme, _path in resolved if host == "node.example"} == set(plan.ports)
    assert plan.target_count == len(resolved) == len(plan.ports) + 1


@pytest.mark.parametrize("scheme", ("http", "https"))
def test_clickhouse_url_selects_http_and_url_tls_without_explicit_protocol(
    scheme: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    class StopProbe(Exception):
        pass

    observed: list[tuple[str, bool]] = []

    def probe(protocol: str, *_args: Any, **kwargs: Any) -> None:
        observed.append((protocol, bool(kwargs.get("tls_config") and kwargs["tls_config"].enabled)))
        raise StopProbe

    monkeypatch.setattr(clickhouse_actions, "_connect_and_probe", probe)
    args = parse_args(["clickhouse", "-t", f"{scheme}://example.test/prefix"])
    ctx = SimpleNamespace(
        args=args,
        target=SimpleNamespace(scheme=scheme, path="/prefix"),
        lifecycle_state=clickhouse_actions.ClickHouseLifecycleState(),
        host="example.test",
        port=443 if scheme == "https" else 80,
    )

    with pytest.raises(StopProbe):
        clickhouse_actions.detect_clickhouse(ctx, {"protocol": "native"})
    assert observed == [("http", scheme == "https")]


def test_clickhouse_explicit_native_protocol_keeps_operator_choice(monkeypatch: pytest.MonkeyPatch) -> None:
    class StopProbe(Exception):
        pass

    protocols: list[str] = []

    def probe(protocol: str, *_args: Any, **_kwargs: Any) -> None:
        protocols.append(protocol)
        raise StopProbe

    monkeypatch.setattr(clickhouse_actions, "_connect_and_probe", probe)
    args = parse_args(["clickhouse", "-t", "http://example.test", "--protocol", "native"])
    ctx = SimpleNamespace(
        args=args,
        target=SimpleNamespace(scheme="http", path=""),
        lifecycle_state=clickhouse_actions.ClickHouseLifecycleState(),
        host="example.test",
        port=80,
    )

    with pytest.raises(StopProbe):
        clickhouse_actions.detect_clickhouse(ctx, {"protocol": "native"})
    assert protocols == ["native"]
