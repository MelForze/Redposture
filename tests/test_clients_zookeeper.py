from __future__ import annotations

import pytest

import redposture_core.clients.zookeeper as zk


def test_parallel_znode_enumeration_success_truncation_and_progress(monkeypatch: pytest.MonkeyPatch) -> None:
    tree = {
        "/": ["app", "zookeeper"],
        "/app": ["config", "secret"],
        "/app/config": [],
        "/app/secret": [],
    }

    class FakeClient:
        def __init__(self, host: str, port: int, timeout: float) -> None:
            self.host = host
            self.port = port
            self.timeout = timeout
            self.closed = False

        def connect(self) -> None:
            return None

        def auth_digest(self, username: str, password: str):
            assert (username, password) == ("user", "pass")
            return True, None

        def get_children2(self, parent: str):
            stat = {"data_length": len(parent), "num_children": len(tree.get(parent, []))}
            return list(tree[parent]), zk._ZK_ERR_OK, stat

        def close(self) -> None:
            self.closed = True

    events: list[dict[str, object]] = []
    monkeypatch.setattr(zk, "_ZkClient", FakeClient)

    nodes, total, truncated, meta, error = zk._enumerate_znodes_parallel(
        host="zk.internal",
        port=2181,
        timeout=1.0,
        max_znodes=2,
        progress_hook=events.append,
        progress_interval_s=0.000001,
        enum_workers=2,
        auth_username="user",
        auth_password="pass",
    )

    assert error is None
    assert total == 3
    assert truncated is True
    assert nodes == ["/app", "/app/config"]
    assert "/zookeeper" not in nodes
    assert meta["/app"]["children"] == 2
    assert events[-1]["event"] == "enumerate_done"


def test_parallel_znode_enumeration_worker_auth_and_result_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    class AuthFailClient:
        def __init__(self, *_args) -> None:
            return None

        def connect(self) -> None:
            return None

        def auth_digest(self, _username: str, _password: str):
            return False, "bad digest"

        def close(self) -> None:
            return None

    monkeypatch.setattr(zk, "_ZkClient", AuthFailClient)
    _nodes, _total, _truncated, _meta, error = zk._enumerate_znodes_parallel(
        host="zk.internal",
        port=2181,
        timeout=1.0,
        max_znodes=10,
        enum_workers=1,
        auth_username="user",
        auth_password="bad",
    )
    assert error == "worker init failed: bad digest"

    class ErrorClient:
        def __init__(self, *_args) -> None:
            return None

        def connect(self) -> None:
            return None

        def get_children2(self, _parent: str):
            raise TimeoutError("slow")

        def close(self) -> None:
            return None

    monkeypatch.setattr(zk, "_ZkClient", ErrorClient)
    _nodes, _total, _truncated, _meta, error = zk._enumerate_znodes_parallel(
        host="zk.internal",
        port=2181,
        timeout=1.0,
        max_znodes=10,
        enum_workers=1,
    )
    assert "getChildren failed for /" in str(error)


def test_parallel_znode_enumeration_non_ok_statuses(monkeypatch: pytest.MonkeyPatch) -> None:
    responses = {
        "/": (["missing", "denied", "bad"], zk._ZK_ERR_OK, {"data_length": 1}),
        "/missing": ([], zk._ZK_ERR_NONODE, {}),
        "/denied": ([], zk._ZK_ERR_NOAUTH, {}),
        "/bad": ([], -7, {}),
    }

    class StatusClient:
        def __init__(self, *_args) -> None:
            return None

        def connect(self) -> None:
            return None

        def get_children2(self, parent: str):
            return responses[parent]

        def close(self) -> None:
            return None

    monkeypatch.setattr(zk, "_ZkClient", StatusClient)

    nodes, total, truncated, meta, error = zk._enumerate_znodes_parallel(
        host="zk.internal",
        port=2181,
        timeout=1.0,
        max_znodes=10,
        enum_workers=1,
    )

    assert nodes == ["/missing", "/denied", "/bad"]
    assert total == 3
    assert truncated is False
    assert meta["/missing"]["error"] == "not found"
    assert meta["/denied"]["error"] == "Access Denied"
    assert error == "getChildren failed for /bad: OPERATIONTIMEOUT"
