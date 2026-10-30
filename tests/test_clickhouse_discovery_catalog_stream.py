"""Discovery catalog reads must use the same bounded transport as table rows."""

from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from redposture_core.modules.clickhouse import actions


@pytest.mark.parametrize("protocol", ["native", "http"])
@pytest.mark.parametrize("fail", [False, True])
def test_discovery_catalog_uses_stream_and_preserves_completed_prefix(protocol, fail):
    class Client:
        def execute(self, *args, **kwargs):
            pytest.fail("discovery used eager execute")

        def query(self, *args, **kwargs):
            pytest.fail("discovery used eager query")

        def rows(self, query):
            assert query == "SELECT database,name FROM system.tables"
            yield ["app", "events"]
            if fail:
                raise OSError("catalog interrupted")
            yield ["app", "audit"]

        execute_iter = rows

        @contextmanager
        def query_rows_stream(self, query):
            yield self.rows(query)

    rows, error = actions._query_rows(
        SimpleNamespace(protocol=protocol, client=Client()),
        "SELECT database,name FROM system.tables",
        max_execution_time=5,
        discovery=True,
    )
    assert list(rows) == [["app", "events"]] + ([] if fail else [["app", "audit"]])
    assert ("catalog interrupted" in error) if fail else error is None


def test_expired_discovery_catalog_never_starts_a_query():
    class Client:
        def execute_iter(self, *args, **kwargs):
            pytest.fail("expired discovery started network work")

    rows, error = actions._query_rows(
        SimpleNamespace(protocol="native", client=Client()), "SHOW DATABASES", max_execution_time=0, discovery=True
    )
    assert not rows and error == "discover_time"
