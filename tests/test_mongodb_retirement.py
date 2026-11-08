"""Closed SDK clients cannot create an unbounded monitor backlog."""

from __future__ import annotations

import threading
import time
import weakref
from types import SimpleNamespace

import pytest

from redposture_core.clients.mongodb import MongoAuditClient
from redposture_core.clients.mongodb_retirement import MongoRetirements, mongodb_monitor_threads


def test_fixed_backlog_waits_only_after_close_without_owning_clients():
    stop = threading.Event()
    entered = threading.Event()
    completed = threading.Event()
    threads = [threading.Thread(target=stop.wait) for _ in range(2)]
    for thread in threads:
        thread.start()
    budget = MongoRetirements(1)
    budget.retire((threads[0],))

    def close_second():
        entered.set()
        budget.retire((threads[1],))
        completed.set()

    worker = threading.Thread(target=close_second)
    worker.start()
    try:
        assert entered.wait(1)
        assert not completed.wait(0.03)
        assert len(budget._pending) == 1
    finally:
        stop.set()
        worker.join(2)
        for thread in threads:
            thread.join(2)
    assert completed.is_set()
    assert not worker.is_alive()
    budget.retire(())
    # Only thread handles are retained; no daemon/reaper thread was created.
    assert not budget._pending


def test_self_join_and_not_started_handles_do_not_block():
    budget = MongoRetirements(1)
    budget.retire((threading.current_thread(), threading.Thread()))
    assert not budget._pending
    with pytest.raises(ValueError):
        MongoRetirements(0)


def test_collected_driver_thread_proxy_is_harmless():
    raw = threading.Thread()
    proxy = weakref.proxy(raw)
    del raw
    budget = MongoRetirements(1)
    budget.retire((proxy,))
    assert not budget._pending


def test_foreign_factory_is_never_probed_with_dynamic_attributes():
    class Foreign:
        def __getattr__(self, name):
            raise AssertionError("must not probe foreign client's private layout")

    assert mongodb_monitor_threads(Foreign()) == ()


def test_monitor_snapshot_is_closed_and_retired_once(monkeypatch):
    from redposture_core.clients import mongodb, mongodb_retirement

    events = []
    raw = SimpleNamespace(close=lambda: events.append("close"))
    handles = (threading.current_thread(),)
    monkeypatch.setattr(mongodb_retirement, "mongodb_monitor_threads", lambda client: handles)
    monkeypatch.setattr(mongodb_retirement.MONGODB_RETIREMENTS, "retire", lambda threads: events.append(threads))
    audit = MongoAuditClient(raw)
    audit.close()
    assert events == ["close", handles]
    # Existing direct client identity and the regular network helpers survive.
    assert audit.client is raw
    assert mongodb.MongoAuditClient is MongoAuditClient


def test_original_close_exception_survives_without_waiting_on_unsignalled_monitors(monkeypatch):
    from redposture_core.clients import mongodb_retirement

    retired = []

    def fail():
        raise OSError("socket close failure")

    monkeypatch.setattr(mongodb_retirement, "mongodb_monitor_threads", lambda client: ())
    monkeypatch.setattr(mongodb_retirement.MONGODB_RETIREMENTS, "retire", retired.append)
    with pytest.raises(OSError, match="socket close failure"):
        MongoAuditClient(SimpleNamespace(close=fail)).close()
    assert retired == []


def test_raw_credential_cleanup_also_participates_in_retirement(monkeypatch):
    from redposture_core.clients import mongodb_retirement
    from redposture_core.clients.mongodb import close_quietly

    events = []
    raw = SimpleNamespace(close=lambda: events.append("raw close"))
    handles = (threading.current_thread(),)
    monkeypatch.setattr(mongodb_retirement, "mongodb_monitor_threads", lambda client: handles)
    monkeypatch.setattr(mongodb_retirement.MONGODB_RETIREMENTS, "retire", lambda threads: events.append(threads))
    close_quietly(raw)
    assert events == ["raw close", handles]


def test_repeated_close_does_not_charge_the_same_thread_twice():
    stop = threading.Event()
    thread = threading.Thread(target=stop.wait)
    thread.start()
    budget = MongoRetirements(1)
    try:
        budget.retire((thread,))
        budget.retire((thread,))
        assert len(budget._pending) == 1
    finally:
        stop.set()
        thread.join(2)
        budget.retire(())


@pytest.mark.parametrize("module", ["pymongo.mongo_client", "pymongo.synchronous.mongo_client"])
def test_known_sync_layout_captures_only_own_cursor_monitor_and_rtt_threads(module):
    handles = [threading.Thread() for _ in range(5)]
    monitor = SimpleNamespace(
        _executor=SimpleNamespace(_thread=handles[1]),
        _rtt_monitor=SimpleNamespace(_executor=SimpleNamespace(_thread=handles[2])),
    )
    topology = SimpleNamespace(
        _lock=threading.Lock(),
        _servers={"x": SimpleNamespace(_monitor=monitor)},
        _srv_monitor=SimpleNamespace(_executor=SimpleNamespace(_thread=handles[3])),
        _Topology__events_executor=SimpleNamespace(_thread=handles[4]),
    )
    raw_class = type("MongoClient", (), {"__module__": module})
    raw = raw_class()
    raw._topology = topology
    raw._kill_cursors_executor = SimpleNamespace(_thread=handles[0])
    assert mongodb_monitor_threads(raw) == tuple(handles)
    raw._topology = SimpleNamespace()  # SDK layout drift never prevents ordinary close.
    assert mongodb_monitor_threads(raw) == ()


def test_unopened_real_driver_keeps_raw_identity_and_does_not_start_threads():
    import pymongo

    before = {t.ident for t in threading.enumerate()}
    raw = pymongo.MongoClient("mongodb://localhost:27017", connect=False)
    audit = MongoAuditClient(raw)
    try:
        assert audit.client is raw
        assert mongodb_monitor_threads(raw) == ()
    finally:
        audit.close()
    # Earlier tests may have already-closed SDK monitors finishing now.
    assert {t.ident for t in threading.enumerate()} <= before


def test_real_closed_driver_threads_are_reaped_without_a_daemon_reaper(monkeypatch):
    import socket

    import pymongo

    from redposture_core.clients import mongodb_retirement

    budget = MongoRetirements(1)
    monkeypatch.setattr(mongodb_retirement, "MONGODB_RETIREMENTS", budget)
    before = {t.ident for t in threading.enumerate()}
    # Reserve a loopback port without listening: it cannot be another service.
    with socket.socket() as reserve:
        reserve.bind(("127.0.0.1", 0))
        port = reserve.getsockname()[1]
        for _ in range(4):
            raw = pymongo.MongoClient("127.0.0.1", port, serverSelectionTimeoutMS=100, connectTimeoutMS=100)
            try:
                with pytest.raises(pymongo.errors.ServerSelectionTimeoutError):
                    raw.admin.command("ping")
                handles = mongodb_monitor_threads(raw)
                assert handles, "adapter must observe actual driver monitors"
            finally:
                MongoAuditClient(raw).close()
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        budget.retire(())
        if not budget._pending:
            break
        threading.Event().wait(0.01)
    assert not budget._pending
    assert {t.ident for t in threading.enumerate()} <= before
