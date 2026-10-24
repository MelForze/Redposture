"""Selected-identity read failures and retention across a failed tree retry."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest

from redposture_core.modules.zookeeper import actions as zk


def context(client: Any, *, authenticated: bool = False, retries: int = 0) -> SimpleNamespace:
    state = zk.ZooKeeperLifecycleState(anonymous_client=client)
    ctx = SimpleNamespace(
        lifecycle_state=state,
        host="192.0.2.1",
        port=2181,
        args=SimpleNamespace(retries=retries, timeout=0.1),
        credential=SimpleNamespace(username="qa", password="qa", source="provided"),
        debug_emit=None,
    )
    if authenticated:
        state.credential_clients[zk._zookeeper_lifecycle_key(ctx)] = client
    return ctx


@pytest.mark.parametrize("authenticated", [False, True])
@pytest.mark.parametrize("dump", [False, True])
def test_selected_znode_children_transport_error_retains_scope_and_selected_identity(
    monkeypatch: pytest.MonkeyPatch, authenticated: bool, dump: bool
) -> None:
    client = Mock()
    client.get_children2.side_effect = ConnectionResetError("connection reset by peer")
    ctx = context(client, authenticated=authenticated)
    refresh = Mock(return_value=(client, None))
    monkeypatch.setattr(zk, "_refresh_zookeeper_lifecycle_client", refresh)
    monkeypatch.setattr(
        zk, "_enumerate_zookeeper_lifecycle", Mock(side_effect=AssertionError("selected read traversed tree"))
    )
    record = zk.collect_zookeeper_data(
        ctx,
        {"status": "valid_credentials" if authenticated else "open_no_auth"},
        {"show_znodes": True, "dump": dump, "query_znode": "/qa", "max_znodes": 20},
    )
    assert record["query_znode"] == "/qa"
    assert "connection reset" in record["query_error"]
    assert record["znodes"] == [] and record["znode_count"] is None
    assert record["query_znode_dump"] is None
    if dump:
        assert "connection reset" in record["query_znode_dump_error"]
        assert "connection reset" in record["dump_error"]
    else:
        assert record["query_znode_dump_error"] is None and record["dump_error"] is None
    assert refresh.call_args.kwargs["authenticated"] is authenticated
    client.get_children2.assert_called_once_with("/qa")
    client.get_data.assert_not_called()


@pytest.mark.parametrize("failure", ["transport", "BADARGUMENTS", "NOAUTH", "NONODE"])
def test_selected_znode_dump_failure_keeps_successful_children_metadata(
    monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    client = Mock()
    client.get_children2.return_value = (["child-a", "child-b"], 0, {"data_length": 9})
    if failure == "transport":
        client.get_data.side_effect = TimeoutError("timed out")
    else:
        client.get_data.return_value = (None, {"BADARGUMENTS": -8, "NOAUTH": -102, "NONODE": -101}[failure], {})
    ctx = context(client, authenticated=True)
    monkeypatch.setattr(zk, "_refresh_zookeeper_lifecycle_client", lambda *_args, **_kwargs: (client, None))
    record = zk.collect_zookeeper_data(
        ctx,
        {"status": "valid_credentials", "provided_credentials_ok": True},
        {"show_znodes": False, "dump": True, "query_znode": "/qa", "max_znodes": 20},
    )
    assert record["provided_credentials_ok"] is True
    assert record["query_znode_value"] == "/qa (children:2,bytes:9)"
    assert record["query_error"] is None
    assert record["query_znode_dump"] is None
    if failure == "transport":
        assert "timeout" in record["query_znode_dump_error"]
        assert record["dump_error"] == record["query_znode_dump_error"]
    else:
        assert (
            record["query_znode_dump_error"]
            == {"BADARGUMENTS": "BADARGUMENTS", "NOAUTH": "Access Denied", "NONODE": "znode not found"}[failure]
        )
        assert record["dump_error"] == failure
    client.get_data.assert_called_once_with("/qa")


def test_tree_refresh_failure_preserves_prior_partial_paths_and_live_progress(monkeypatch: pytest.MonkeyPatch) -> None:
    client = Mock()
    ctx = context(client, retries=2)
    messages: list[str] = []
    ctx.debug_emit = messages.append
    monkeypatch.setattr(zk, "_refresh_zookeeper_lifecycle_client", lambda *_args, **_kwargs: (client, None))
    reopening = Mock(side_effect=[ConnectionResetError("connection reset by peer"), ValueError("invalid transport")])
    monkeypatch.setattr(zk, "_reopen_zookeeper_lifecycle_client", reopening)
    monkeypatch.setattr(zk.time, "sleep", lambda _delay: None)

    def enumerate_partial(*_args: Any, **kwargs: Any) -> tuple[Any, ...]:
        progress = kwargs["progress_hook"]
        progress(
            {"event": "enumerate_progress", "total_count": 1, "listed_count": 1, "processed_parents": 1, "queued": 1}
        )
        progress(
            {
                "event": "enumerate_done",
                "total_count": 1,
                "listed_count": 1,
                "processed_parents": 1,
                "queued": 1,
                "elapsed_s": 0.5,
            }
        )
        return ["/kept"], 1, False, {"/kept": {"bytes": 4}}, "connection timeout"

    enumeration = Mock(side_effect=enumerate_partial)
    monkeypatch.setattr(zk, "_enumerate_zookeeper_lifecycle", enumeration)
    record = zk.collect_zookeeper_data(
        ctx,
        {"status": "open_no_auth", "stage_attempts": {"detect_protocol": 1}},
        {"show_znodes": True, "dump": True, "query_znode": None, "max_znodes": 20},
    )
    assert record["znodes"] == ["/kept"]
    assert record["znode_count"] == 1 and record["znode_count_partial"] is True
    assert "invalid transport" in record["enum_error"]
    assert "invalid transport" in record["dump_error"]
    assert record["znode_values"] is None
    assert record["stage_attempts"]["detect_protocol"] == 1 and record["stage_attempts"]["data"] == 3
    assert enumeration.call_count == 1 and reopening.call_count == 2
    assert any("enumerate progress discovered=1 listed=1 processed=1 queued=1" in m for m in messages)
    assert any("enumerate done discovered=1 listed=1 processed=1 queued=1 elapsed=0.5s" in m for m in messages)
    client.get_data.assert_not_called()
