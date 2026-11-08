"""Lazy RESP bodies, not only their headers, must be read before acknowledgment."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from redposture_core.modules.redis.discovery import discover_redis


def bulk(value):
    return b"$" + str(len(value)).encode() + b"\r\n" + value + b"\r\n"


class Socket:
    def __init__(self, body):
        self.body, self.position, self.closed = body, 0, False

    def recv(self, length):
        result = self.body[self.position : self.position + length]
        self.position += len(result)
        return result

    def sendall(self, body):
        assert not self.closed

    def gettimeout(self):
        return 1

    def settimeout(self, value):
        pass

    def close(self):
        self.closed = True


def run(*, denied=None, query=False, broken=False, empty=False):
    catalog = b"*2\r\n" + bulk(b"0") + (b"*0\r\n" if empty else b"*1\r\n" + bulk(b"password"))
    value = bulk(b"inactive-native!42")
    if denied == "values":
        value = b"-NOPERM not allowed\r\n"
    elif broken:
        value = b"$1000\r\nunfinished"
    body = b"-NOPERM not allowed\r\n" if denied == "catalog" else catalog if empty else catalog + b"+string\r\n" + value
    if query:
        body = b"+string\r\n" + value
    sock = Socket(body)
    ctx = SimpleNamespace(
        host="qa", port=6379, args=SimpleNamespace(discover_time=30, key="password" if query else None)
    )
    return discover_redis(ctx, {"status": "valid_credentials"}, sock)["content_discovery"], sock


def test_native_catalog_and_value_have_independent_completion():
    result, _ = run()
    rows = {r["id"]: r for r in result["sources"]}
    assert result["status"] == "complete"
    assert rows["redis.key_catalog"]["read"] == rows["redis.key_values"]["read"] == 1
    assert all(r["complete"] for r in rows.values())
    assert [f["value"] for f in result["findings"]] == ["inactive-native!42"]


@pytest.mark.parametrize("denied,kind", [("catalog", "key_catalog"), ("values", "key_values")])
def test_noauth_noperm_do_not_count_as_reads(denied, kind):
    result, _ = run(denied=denied)
    rows = {r["id"]: r for r in result["sources"]}
    assert rows["redis." + kind]["denied"] == 1 and rows["redis." + kind]["read"] == 0
    assert not rows["redis." + kind]["complete"]
    if denied == "values":
        assert rows["redis.key_catalog"]["complete"]


def test_short_bulk_is_incomplete_and_socket_cannot_be_reused():
    result, sock = run(broken=True)
    row = next(r for r in result["sources"] if r["id"] == "redis.key_values")
    assert result["status"] == "partial" and not row["complete"] and row["read"] == 0
    assert not result["findings"] and sock.closed


def test_empty_scan_is_complete_but_has_no_read_values():
    result, _ = run(empty=True)
    rows = {r["id"]: r for r in result["sources"]}
    assert result["status"] == "complete" and rows["redis.key_catalog"]["read"] == 1
    assert rows["redis.key_values"]["requested"] == 0


def test_explicit_key_does_not_claim_scan_catalog_was_read():
    result, _ = run(query=True)
    rows = {r["id"]: r for r in result["sources"]}
    assert result["status"] == "complete" and rows["redis.key_values"]["complete"]
    assert rows["redis.key_catalog"]["requested"] == 0


def test_transport_cancellation_closes_partially_consumed_socket():
    from redposture_core.scheduler import NestedSchedulerCancelled

    class Interrupted(Socket):
        def recv(self, length):
            raise NestedSchedulerCancelled("cancel during RESP read")

    sock = Interrupted(b"")
    ctx = SimpleNamespace(host="qa", port=6379, args=SimpleNamespace(discover_time=30, key="password"))
    with pytest.raises(NestedSchedulerCancelled):
        discover_redis(ctx, {"status": "valid_credentials"}, sock)
    assert sock.closed


def test_cancel_before_next_scan_page_keeps_catalog_incomplete():
    from redposture_core.modules.redis.discovery import _DiscoverySession
    from redposture_core.scheduler import NestedSchedulerCancelled

    emitted = []
    body = b"*2\r\n" + bulk(b"7") + b"*1\r\n" + bulk(b"password") + b"+string\r\n" + bulk(b"inactive-native!42")
    ctx = SimpleNamespace(
        host="qa",
        port=6379,
        args=SimpleNamespace(discover_time=30),
        live_emit=emitted.extend,
        cancelled=lambda: bool(emitted),
    )
    session = _DiscoverySession(ctx, {"status": "open_no_auth"}, Socket(body))
    with pytest.raises(NestedSchedulerCancelled):
        session.scan()
    row = next(r for r in session.collector.result()["sources"] if r["id"] == "redis.key_catalog")
    assert row["read"] == 1 and not row["complete"]
