from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

import pytest

from redposture_core.detection_diagnostics import (
    FallbackDiagnostics,
    capture_fallbacks,
    fallback_category,
    measure_sync_detect,
    note_fallback,
    sync_fallback,
)


@pytest.mark.parametrize(
    ("reason", "expected"),
    [
        ("hostname requires synchronous resolver", "dns"),
        ("ambiguous HTTP framing", "framing"),
        ("redirect body needs the original client", "redirect"),
        ("native fingerprint needs full synchronous response", "body_limit"),
        ("proxied detection client", "proxy"),
        ("TLS upgrade unavailable", "tls"),
        ("detector override", "override"),
        ("unsupported operation", "unsupported"),
        ("timed out", "timeout"),
    ],
)
def test_fallback_categories_do_not_store_raw_reason(reason, expected):
    assert fallback_category(reason) == expected
    stats = FallbackDiagnostics()
    stats.record("grafana", reason + " secret-token", seconds=0.25, requests=2)
    assert stats.snapshot() == [
        {"module": "grafana", "category": expected, "count": 1, "native_us": 250000, "http_requests": 2, "worker_us": 0}
    ]
    assert "secret-token" not in "".join(stats.debug_lines())


def test_observer_is_optional_scoped_and_only_times_detect(monkeypatch):
    stats = FallbackDiagnostics()
    now = iter([10.0, 10.5])
    monkeypatch.setattr("redposture_core.detection_diagnostics.time.monotonic", lambda: next(now))
    note_fallback("ignored", "DNS")
    with capture_fallbacks(stats), sync_fallback("postgres"):
        note_fallback("postgres", "hostname requires resolver", requests=1)
        with pytest.raises(RuntimeError), measure_sync_detect():
            raise RuntimeError("read failed")
    with measure_sync_detect():
        pass
    note_fallback("ignored", "DNS")
    assert stats.snapshot() == [
        {"module": "postgres", "category": "dns", "count": 1, "native_us": 0, "http_requests": 1, "worker_us": 0},
        {
            "module": "postgres",
            "category": "sync_work",
            "count": 1,
            "native_us": 0,
            "http_requests": 0,
            "worker_us": 500000,
        },
    ]


def test_concurrent_totals_and_bounded_cardinality():
    stats = FallbackDiagnostics()
    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(lambda i: stats.record("kafka", "hostname resolver", requests=2), range(1000)))
    assert stats.snapshot()[0]["count"] == 1000
    assert stats.snapshot()[0]["http_requests"] == 2000
    for i in range(10000):
        stats.record(f"target-{i}", "dynamic reason " + str(i))
    assert len(stats.snapshot()) <= 66
    assert sum(int(row["count"]) for row in stats.snapshot()) == 11000


def test_surface_breakdown_does_not_change_legacy_totals_or_retain_unknown_labels():
    stats = FallbackDiagnostics()
    stats.record("redis", "invalid HTTP status", seconds=0.2, requests=1, surface="ui")
    stats.record("redis", "invalid HTTP status", seconds=0.1, requests=2, surface="backend")
    assert stats.snapshot() == [
        {"module": "redis", "category": "framing", "count": 2, "native_us": 300000, "http_requests": 3, "worker_us": 0}
    ]
    rows = {row["surface"]: row for row in stats.surface_snapshot()}
    assert rows["ui"]["count"] == rows["backend"]["count"] == 1
    assert rows["ui"]["http_requests"] == 1
    assert "worker_us" not in rows["ui"]  # Not attributed by this counter.
    for index in range(10000):
        stats.record("redis", "bad framing", surface=f"target-{index}-secret")
    assert len(stats.surface_snapshot()) == 3
    assert "target-" not in str(stats.surface_snapshot())
    assert "secret" not in "".join(stats.debug_lines())


def test_surface_breakdown_is_opt_in_and_concurrent_counts_are_exact():
    stats = FallbackDiagnostics()
    stats.record("redis", "invalid HTTP status")
    assert stats.surface_snapshot() == []
    with ThreadPoolExecutor(max_workers=4) as pool:
        list(
            pool.map(
                lambda index: stats.record("redis", "framing", surface="ui" if index % 2 else "backend"), range(1000)
            )
        )
    assert stats.snapshot()[0]["count"] == 1001
    assert {row["surface"]: row["count"] for row in stats.surface_snapshot()} == {"backend": 500, "ui": 500}


@pytest.mark.parametrize(
    "module,surface,expected",
    [("redis", "ui", "ui"), ("redis", "backend", "backend"), ("redis", None, "mixed"), ("docker", None, "backend")],
)
@pytest.mark.parametrize("enabled", [False, True])
def test_runtime_attributes_explicit_surface_without_guessing_from_error(
    monkeypatch, module, surface, expected, enabled
):
    import asyncio
    from types import SimpleNamespace

    from redposture_core.clients.async_http_detect import AsyncHttpFallback
    from redposture_core.stage_runtime import AuditCommandRunner, ModuleAuditSpec
    from redposture_core.targeting import ScanTargetSpec

    async def unsupported(ctx, http):
        raise AsyncHttpFallback("invalid HTTP status")

    args = SimpleNamespace(timeout=1, retries=0, debug=enabled)
    spec = ModuleAuditSpec(module=module, label=module.upper(), default_port=9999, detect_async=unsupported)
    runner = AuditCommandRunner(args=args, spec=spec, emit_line=lambda _: None)
    monkeypatch.setattr(runner, "_detect_async", unsupported)
    target = ScanTargetSpec(host="127.0.0.1", explicit_port=9999, surface_hint=surface)
    result = asyncio.run(
        runner._run_async_detect_attempt(target.host, 9999, target, None, args, sync_timeout_fallback=True)
    )
    assert result is None
    if not enabled:
        assert runner._fallback_stats.surface_snapshot() == []
        assert runner._fallback_stats.snapshot()[0]["count"] == 1
        return
    assert runner._fallback_stats.surface_snapshot()[0]["surface"] == expected
    assert runner._fallback_stats.surface_snapshot()[0]["count"] == 1


def test_runtime_fallback_reaches_worker_context_without_changing_results():
    import time
    from types import SimpleNamespace

    from redposture_core.audit_models import AuditRecord
    from redposture_core.clients.async_http_detect import AsyncHttpFallback
    from redposture_core.stage_runtime import AuditCommandPlan, AuditCommandRunner, ModuleAuditSpec

    def sync(ctx):
        time.sleep(0.001)
        return AuditRecord(host=ctx.host, port=9999, module="grafana", service="grafana", status="open_no_auth")

    async def native(ctx, http):
        raise AsyncHttpFallback("unsupported HTTP framing")

    args = SimpleNamespace(timeout=1, retries=0, debug=False)
    spec = ModuleAuditSpec(
        module="grafana",
        label="GRAFANA",
        default_port=9999,
        detect=sync,
        detect_async=native,
        async_detect_sync_hook=sync,
        is_detected=lambda row: row.status == "open_no_auth",
        render=lambda _: (),
    )
    runner = AuditCommandRunner(args=args, spec=spec, emit_line=lambda _: None)
    result = runner.run_plan(
        AuditCommandPlan(targets_by_port={9999: tuple(f"qa-{i}" for i in range(40))}, ports=(9999,), workers=2)
    )
    assert result.detected_count == result.record_count == 40
    rows = {row["category"]: row for row in runner._fallback_stats.snapshot()}
    assert rows["framing"]["count"] == rows["sync_work"]["count"] == 40
    assert rows["sync_work"]["worker_us"] > 0
    assert rows["framing"]["http_requests"] == 0
