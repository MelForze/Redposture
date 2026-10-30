"""Regression for the removed CLI byte limit leaking into discovery engines."""

from __future__ import annotations

import time
from types import SimpleNamespace

from redposture_core.storage_discovery import DiscoveryCollector


def test_storage_collector_default_does_not_stop_after_300_decimal_mb() -> None:
    """No large allocation is needed to prove the removed storage limit."""
    ctx = SimpleNamespace(
        args=SimpleNamespace(discover_time=900.0),
        discovery_started_at=time.monotonic(),
    )
    collector = DiscoveryCollector("gitlab", ctx, {})

    assert collector.charge(300_000_001)
    assert collector.partial_reasons == []


def test_airflow_discovery_default_does_not_cap_source_at_300_decimal_mb() -> None:
    from redposture_core.modules.airflow.discover import DiscoverConfig

    assert DiscoverConfig().max_bytes > 300_000_000


def test_token_api_discovery_default_does_not_cap_source_at_300_decimal_mb() -> None:
    from redposture_core.modules.token_api import ReadBudget

    budget = ReadBudget(SimpleNamespace(discover_time=900))
    assert budget.remaining > 300_000_000


def test_common_record_scanner_does_not_pass_hidden_300_mb_cap(monkeypatch) -> None:
    from redposture_core import data_discovery

    portions = []

    def scan(_value, _path, portion_bytes, **_kwargs):
        portions.append(portion_bytes)
        return [], 0, True

    monkeypatch.setattr(data_discovery, "_scan_portioned_value", scan)
    data_discovery.inspect_record("consul", {"kv_dump_items": [{"key": "qa", "value": "ordinary"}]})
    assert portions and min(portions) > 300_000_000


def test_clickhouse_discovery_default_does_not_stop_at_300_decimal_mb() -> None:
    from redposture_core.modules.clickhouse.discover.engine import DiscoverConfig

    assert DiscoverConfig().max_total_bytes is None


def test_etcd_discovery_default_does_not_stop_at_300_decimal_mb(monkeypatch) -> None:
    from redposture_core.modules.etcd import actions

    captured = []
    original = actions._EtcdDiscoveryBudget

    def capture_budget(*, deadline, remaining_bytes):
        captured.append(remaining_bytes)
        return original(deadline=deadline, remaining_bytes=remaining_bytes)

    monkeypatch.setattr(actions, "_EtcdDiscoveryBudget", capture_budget)
    steps = actions._detect_audit_etcd_host_steps("localhost", 2379, 1.0, 0, False, True, None, discover=True)
    next(steps)
    steps.close()
    assert captured and captured[0] > 300_000_000


def test_kubeapi_discovery_default_does_not_stop_at_300_decimal_mb(monkeypatch) -> None:
    from redposture_core.modules.kubeapi import actions

    captured = []

    class Captured(Exception):
        pass

    def capture(*, remaining, deadline):
        captured.append(remaining)
        raise Captured

    monkeypatch.setattr(actions, "KubeDiscoveryReadBudget", capture)
    ctx = SimpleNamespace(
        lifecycle_state=actions.KubeApiLifecycleState(),
        args=SimpleNamespace(discover=True, discover_time=900),
    )
    try:
        actions.collect_kubeapi_data(
            ctx, {"status": "detected"}, {"show_namespaces": False, "show_pods": False, "show_secrets": False}
        )
    except Captured:
        pass
    assert captured and captured[0] > 300_000_000


def test_kafka_ui_discovery_default_does_not_stop_at_300_decimal_mb(monkeypatch) -> None:
    from redposture_core.modules.kafka import ui

    captured = []

    class Captured(Exception):
        pass

    def capture(*, remaining, deadline):
        captured.append(remaining)
        raise Captured

    monkeypatch.setattr(ui, "_UiDiscoveryBudget", capture)
    ctx = SimpleNamespace(args=SimpleNamespace(discover=True, discover_time=900))
    state = SimpleNamespace(ui_base="http://localhost:8080", ui_http=object())
    try:
        ui.collect_ui(ctx, {"status": "detected"}, state, {"ui_dump_all": False})
    except Captured:
        pass
    assert captured and captured[0] > 300_000_000
