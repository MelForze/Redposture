"""Real module decision trees must agree on native versus sync redirects."""

from __future__ import annotations

import asyncio

import pytest

from redposture_core.stage_runtime import AuditCommandRunner
from redposture_core.targeting import ScanTargetSpec
from tests.test_async_http_timeout_retries import make_runner
from tests.test_async_retained_parity import normalize
from tests.test_network_fingerprint_matrix import HTTP_PRODUCTS, _product_server, _redirect_server


def compare(module, port, path="", host="127.0.0.1"):
    args, spec = make_runner(module)
    args.timeout = 0.5
    target = ScanTargetSpec(host, scheme="http", explicit_port=port, path=path, surface_hint="backend")
    runner = AuditCommandRunner(args=args, spec=spec, emit_line=lambda line: None)
    try:
        expected = runner._run_detect_with_state(target.host, port, target, None)
        expected_record = normalize(expected.record.to_dict())
        runner._close_all_lifecycle_states()
        native = asyncio.run(runner._run_async_detect_with_state(target.host, port, target, None))
        assert native is not None, (module, "unexpected sync fallback")
        assert normalize(native.record.to_dict()) == expected_record
        return runner._is_detected(native.record)
    finally:
        runner._close_all_lifecycle_states()


@pytest.mark.parametrize("module", HTTP_PRODUCTS)
@pytest.mark.parametrize("relative", [False, True])
def test_all_native_http_modules_keep_same_origin_redirect_mount_and_record(module, relative):
    with _product_server(
        module, proxy_headers=True, prefix="/edge/app", redirect_from="", relative_redirect=relative
    ) as (port, requests):
        assert compare(module, port) is True
        assert requests


@pytest.mark.parametrize("module", HTTP_PRODUCTS)
def test_all_native_http_modules_keep_original_cross_origin_redirect_decision(module):
    with _product_server(module, proxy_headers=True) as (destination, requests):
        with _redirect_server(destination) as (source, paths):
            compare(module, source)
            assert paths


@pytest.mark.parametrize("module", HTTP_PRODUCTS)
@pytest.mark.parametrize("redirect", [False, True])
def test_all_http_modules_keep_exact_records_for_hostname_and_prefix(module, redirect):
    with _product_server(
        module,
        proxy_headers=True,
        origin_host="localhost",
        prefix="/edge/app",
        redirect_from="" if redirect else None,
    ) as (port, requests):
        assert compare(module, port, "" if redirect else "/edge/app", host="localhost") is True
        assert requests
