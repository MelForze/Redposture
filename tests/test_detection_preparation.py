"""Preparation memoization must not change target identity or fallback policy."""

import asyncio
from dataclasses import replace
from unittest.mock import Mock

import pytest

from redposture_core.clients.async_http_detect import AsyncHttpFallback
from redposture_core.clients.async_retained_socket import RetainedSocketIO
from redposture_core.targeting import StreamingTargetPlan, stream_scan_target_specs


def test_loop_readiness_is_checked_once_per_loop(monkeypatch):
    import socket

    original = socket.socketpair
    calls = []

    def pair(*args, **kwargs):
        calls.append(1)
        return original(*args, **kwargs)

    monkeypatch.setattr(socket, "socketpair", pair)

    async def run():
        before = len(calls)
        for _ in range(20):
            RetainedSocketIO().check_supported()
        assert len(calls) - before == 1

    asyncio.run(run())
    asyncio.run(run())  # A new loop must be checked independently.


def test_unsupported_readiness_is_never_cached_as_supported(monkeypatch):
    async def run():
        loop = asyncio.get_running_loop()
        monkeypatch.setattr(loop, "add_reader", Mock(side_effect=NotImplementedError))
        for _ in range(2):
            with pytest.raises(AsyncHttpFallback):
                RetainedSocketIO().check_supported()

    asyncio.run(run())


@pytest.mark.parametrize("ports", [(5432,), (80, 5432), (5432, 80, 5432)])
def test_count_cache_preserves_expansion_and_new_plan_identity(tmp_path, monkeypatch, ports):
    path = tmp_path / "targets"
    path.write_text("10.0.0.1:80\n10.0.0.1:5432\n10.0.0.2\n[::1]:5432\nhttps://10.0.0.3/root\n")
    plan = stream_scan_target_specs(str(path))
    expected = plan.count_for_ports(ports)
    calls = []
    original = StreamingTargetPlan._count_for_ports

    def count(self, matrix):
        calls.append(self)
        return original(self, matrix)

    monkeypatch.setattr(StreamingTargetPlan, "_count_for_ports", count)
    assert plan.count_for_ports(tuple(dict.fromkeys(ports))) == expected
    assert not calls
    clone = replace(plan)
    assert clone.count_for_ports(ports) == expected
    assert len(calls) == 1
    expanded = plan.with_additional_ports_for_bare_explicit_targets()
    assert expanded.count_for_ports(ports) == sum(
        1 for port in expanded.execution_ports(ports) for _ in expanded.iter_specs_for_port(port, ports)
    )
    # Scheme/default and matrix variants own their caches.
    mapped = plan.with_scheme_default_ports({"https": 443})
    assert mapped.count_for_ports(ports) == sum(
        1 for port in mapped.execution_ports(ports) for _ in mapped.iter_specs_for_port(port, ports)
    )
    assert len(calls) == 3


def test_numeric_memo_is_bounded_and_does_not_accept_names(monkeypatch):
    import ipaddress
    import socket

    from redposture_core.clients.async_detect_stream import require_numeric_host
    from redposture_core.clients.numeric_host import numeric_host_family

    numeric_host_family.cache_clear()
    original = ipaddress.ip_address
    calls = []

    def parse(host):
        calls.append(host)
        return original(host)

    monkeypatch.setattr(ipaddress, "ip_address", parse)
    assert numeric_host_family("198.18.0.1") == socket.AF_INET
    assert numeric_host_family("198.18.0.1") == socket.AF_INET
    assert numeric_host_family("::1") == socket.AF_INET6
    assert calls == ["198.18.0.1", "::1"]
    for _ in range(2):
        with pytest.raises(AsyncHttpFallback):
            require_numeric_host("not-a-numeric-host.invalid")
        with pytest.raises(AsyncHttpFallback):
            require_numeric_host("fe80::1%en0")
    for number in range(5000):
        numeric_host_family(str(original(0xC6120000 + number)))
    assert numeric_host_family.cache_info().currsize <= 4096


def test_port_matrix_cache_does_not_grow_without_bound(tmp_path):
    path = tmp_path / "targets"
    path.write_text("10.0.0.1:80\n10.0.0.2\n")
    plan = stream_scan_target_specs(str(path))
    for port in range(1000, 1020):
        assert plan.count_for_ports((port,)) == 2
        assert len(plan._port_count_cache) <= 8
