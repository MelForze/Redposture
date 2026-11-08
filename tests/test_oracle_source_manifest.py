"""Catalog reads do not imply SELECT access; cancellation stops later tables."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from redposture_core.scheduler import NestedSchedulerCancelled
from tests.test_oracle_discover import _collect


def run(*, denied=False, cancel=False):
    emitted, calls, closed = [], [], []

    class Client:
        def current_context(self):
            return {"session_user": "QA"}

        def server_banner(self):
            return {"version": "23ai"}

        def iter_tables(self, schema):
            yield {"owner": "QA", "table_name": "FIRST"}
            yield {"owner": "QA", "table_name": "SECOND"}

        def iter_table_rows(self, owner, name):
            calls.append(name)
            try:
                if denied:
                    raise RuntimeError("ORA-01031: insufficient privileges")
                yield {"password": "inactive-" + name + "!42"}
            finally:
                closed.append(name)

    ctx = SimpleNamespace(
        host="qa",
        port=1521,
        args=SimpleNamespace(discover_time=30),
        live_emit=emitted.extend,
        cancelled=lambda: cancel and bool(emitted),
    )
    if cancel:
        with pytest.raises(NestedSchedulerCancelled):
            _collect(Client(), implicit=True, discover_ctx=ctx)
        assert calls == closed == ["FIRST"]
        return None
    result = _collect(Client(), implicit=True, discover_ctx=ctx)["content_discovery"]
    return result


@pytest.mark.parametrize("denied", [False, True])
def test_catalog_and_table_streams_have_independent_access_evidence(denied):
    report = run(denied=denied)
    rows = {r["id"]: r for r in report["sources"]}
    assert rows["oracle.table_catalog"]["read"] == 1 and rows["oracle.table_catalog"]["complete"]
    assert rows["oracle.table_rows"]["requested"] == 2
    assert rows["oracle.table_rows"]["read"] == (0 if denied else 2)
    assert rows["oracle.table_rows"]["denied"] == (2 if denied else 0)
    assert rows["oracle.table_rows"]["complete"] == (not denied)
    assert rows["oracle.query_rows"]["requested"] == 0
    assert report["status"] != "complete" if denied else report["status"] == "complete"


def test_cancellation_is_not_turned_into_read_failed_and_next_table_query():
    run(cancel=True)
    for _ in range(2):
        result = run()
        assert result["status"] == "complete"
        assert {f["value"] for f in result["findings"]} == {"inactive-FIRST!42", "inactive-SECOND!42"}
