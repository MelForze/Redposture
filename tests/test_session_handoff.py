"""Bounds, identity isolation and cancellation ownership for reusable sessions."""

from __future__ import annotations

from functools import partial

import pytest

from redposture_core.clients.http_handoff import HttpHandoffBudget
from redposture_core.clients.session_handoff import SessionHandoff


def test_idle_and_borrowed_sessions_are_closed_once_on_cancel():
    budget = HttpHandoffBudget(1)
    closed = []
    cache = SessionHandoff(budget)
    lease = cache.track(("user", "db", "tls"), object(), lambda: closed.append("closed"))
    assert cache.finish(lease, keep=True)
    assert budget.active == 1
    assert cache.take(("other-user", "db", "tls")) is None
    assert cache.take(lease.key) is lease
    assert budget.active == 0
    cache.close()
    assert closed == ["closed"]
    assert not cache.finish(lease, keep=True)
    cache.close()
    assert closed == ["closed"]
    with pytest.raises(RuntimeError, match="closed"):
        cache.track(lease.key, object(), lambda: closed.append("late"))
    assert closed == ["closed", "late"]


@pytest.mark.parametrize("units", [1, 3])
def test_global_budget_and_per_target_single_slot_are_enforced(units):
    budget = HttpHandoffBudget(units)
    caches = [SessionHandoff(budget, budget_units=units) for _ in range(4)]
    closed = []
    for i, cache in enumerate(caches):
        lease = cache.track((i,), i, partial(closed.append, i))
        assert cache.finish(lease, keep=True) is (i == 0)
    assert budget.active == units
    assert sorted(closed) == [1, 2, 3]
    caches[0].close()
    assert budget.active == 0
    assert sorted(closed) == [0, 1, 2, 3]


def test_partial_multi_socket_reservation_is_rolled_back():
    budget = HttpHandoffBudget(2)
    cache = SessionHandoff(budget, budget_units=3)
    closed = []
    lease = cache.track(("mongo",), object(), lambda: closed.append(True))
    assert not cache.finish(lease, keep=True)
    assert budget.active == 0 and closed == [True]
