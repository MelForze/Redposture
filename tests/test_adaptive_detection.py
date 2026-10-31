"""Adaptive detection changes admissions, never the endpoint/protocol contract."""

import errno

import pytest

from redposture_core import async_detection


def controller(initial=64, maximum=128):
    # Import inside the helper so RED reports the missing behavior per test.
    from redposture_core.adaptive_detection import AdaptiveDetectLimit

    return AdaptiveDetectLimit(initial, maximum)


def sample(policy, completed=64, **kw):
    return policy.observe(completed=completed, elapsed=0.5, **kw)


def test_grows_only_when_saturated_and_keeps_a_measured_gain():
    p = controller()
    for _ in range(3):
        assert sample(p, saturated=False) == 64
    assert sample(p) == 64
    assert sample(p) > 64
    increased = p.limit
    assert sample(p, completed=96) == increased
    for _ in range(12):
        sample(p, completed=int(p.limit))
    assert 64 < p.limit <= p.maximum == 128


def test_unhelpful_probe_returns_to_previous_limit_without_repeated_oscillation():
    p = controller()
    sample(p)
    assert sample(p) > 64
    assert sample(p, completed=64) > 64
    assert sample(p, completed=64) == 64
    for _ in range(20):
        assert sample(p) == 64


@pytest.mark.parametrize(
    "pressure",
    [
        {"lag": 0.1},
        {"cpu": 1.5},
        {"rss_growth": 70_000_000},
        {"fd_limit": 12},
        {"resource_errors": 1},
    ],
)
def test_local_pressure_reduces_future_admissions(pressure):
    p = controller()
    assert 1 <= sample(p, **pressure) < 64
    if "fd_limit" in pressure:
        assert p.limit <= 12


def test_cpu_busy_or_idle_window_does_not_start_speculative_connections():
    for kwargs in ({"cpu": 0.9}, {"completed": 0}, {"saturated": False}):
        p = controller()
        for _ in range(5):
            assert sample(p, **kwargs) == 64


def test_zero_elapsed_and_tiny_caps_are_safe():
    p = controller(1, 1)
    assert p.observe(completed=1, elapsed=0) == 1
    for _ in range(10):
        assert sample(p, resource_errors=1) == 1


@pytest.mark.parametrize(
    "code,expected",
    [
        (errno.EMFILE, True),
        (errno.ENFILE, True),
        (errno.ENOBUFS, True),
        (errno.ENOMEM, True),
        (errno.EADDRNOTAVAIL, True),
        (errno.ECONNREFUSED, False),
        (errno.ETIMEDOUT, False),
        (errno.ECONNRESET, False),
    ],
)
def test_resource_pressure_does_not_confuse_remote_failures(code, expected):
    from redposture_core.adaptive_detection import is_local_resource_error

    assert is_local_resource_error(OSError(code, "fixture")) is expected
    assert not is_local_resource_error(TimeoutError("timed out"))


def test_adaptive_upper_bound_respects_fd_target_and_explicit_caps(monkeypatch):
    import os
    import resource

    monkeypatch.setattr(resource, "getrlimit", lambda _: (100000, 100000))
    monkeypatch.setattr(os, "listdir", lambda _: ["0", "1", "2"])
    limit = async_detection.adaptive_detect_ceiling
    assert limit(1000, initial=128, deep_workers=16) == 256
    assert limit(10, initial=8, deep_workers=2) == 10
    assert limit(1_000_000, initial=1024, deep_workers=16) == 2048
    assert limit(1000, initial=128, deep_workers=16, max_inflight=130) == 130
    monkeypatch.setattr(resource, "getrlimit", lambda _: (128, 128))
    assert limit(1000, initial=8, deep_workers=16, retained_fds=32) == 0


def test_memory_plateau_is_not_repeatedly_treated_as_new_allocation(monkeypatch):
    from redposture_core import adaptive_detection as module

    rss = iter([20_000_000, 90_000_000, 90_000_000])
    monkeypatch.setattr(module, "peak_rss", lambda: next(rss))
    resources = module.DetectResources()
    assert resources.sample(0.5)[1] == 70_000_000
    assert resources.sample(0.5)[1] == 0


def test_probe_waits_for_slow_new_admissions_before_comparing_throughput():
    p = controller()
    assert sample(p, completed=0, latency=0.6) == 64
    assert sample(p, completed=64, latency=0.6) == 64
    raised = sample(p, completed=64, latency=0.6)
    assert raised > 64
    # The extra admissions cannot finish in the very first 0.5s window.
    assert sample(p, completed=64, latency=0.6) == raised
    assert sample(p, completed=80, latency=0.6) == raised
    for _ in range(3):
        sample(p, completed=80, latency=0.6)
    assert p.limit >= raised and p.reason != "no_throughput_gain"
