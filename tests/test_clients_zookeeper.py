from __future__ import annotations

import subprocess
import sys
import threading
from pathlib import Path

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


def test_parallel_znode_enumeration_unexpected_worker_error_cancels_without_hanging(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    blocked_worker_started = threading.Event()
    release_blocked_worker = threading.Event()

    class UnexpectedErrorClient:
        def __init__(self, *_args) -> None:
            return None

        def connect(self) -> None:
            return None

        def get_children2(self, parent: str):
            if parent == "/":
                return ["blocked", "boom"], zk._ZK_ERR_OK, {}
            if parent == "/blocked":
                blocked_worker_started.set()
                release_blocked_worker.wait(timeout=5.0)
                return [], zk._ZK_ERR_OK, {}
            assert parent == "/boom"
            assert blocked_worker_started.wait(timeout=1.0)
            raise RuntimeError("unexpected worker crash")

        def close(self) -> None:
            return None

    monkeypatch.setattr(zk, "_ZkClient", UnexpectedErrorClient)
    results: list[tuple[list[str], int, bool, dict[str, dict[str, object]], str | None]] = []

    def _enumerate() -> None:
        results.append(
            zk._enumerate_znodes_parallel(
                host="zk.internal",
                port=2181,
                timeout=1.0,
                max_znodes=10,
                enum_workers=2,
            )
        )

    enumeration_thread = threading.Thread(target=_enumerate, daemon=True)
    enumeration_thread.start()
    try:
        enumeration_thread.join(timeout=2.0)
        assert not enumeration_thread.is_alive(), "parallel enumeration did not stop after a fatal worker error"
    finally:
        release_blocked_worker.set()
        enumeration_thread.join(timeout=0.5)

    assert results
    nodes, total, truncated, _meta, error = results[0]
    assert nodes == ["/blocked", "/boom"]
    assert total == 2
    assert truncated is False
    assert error == "getChildren failed for /boom: unexpected worker crash"


def test_parallel_znode_enumeration_unexpected_worker_error_subprocess_deadline() -> None:
    repository_root = Path(__file__).resolve().parents[1]
    script = """
import redposture_core.clients.zookeeper as zk

class UnexpectedErrorClient:
    def __init__(self, *_args):
        pass

    def connect(self):
        pass

    def get_children2(self, parent):
        if parent == "/":
            return ["boom"], zk._ZK_ERR_OK, {}
        raise RuntimeError("unexpected worker crash")

    def close(self):
        pass

zk._ZkClient = UnexpectedErrorClient
result = zk._enumerate_znodes_parallel(
    host="zk.internal",
    port=2181,
    timeout=1.0,
    max_znodes=10,
    enum_workers=2,
)
assert result[1] == 1, result
assert result[-1] == "getChildren failed for /boom: unexpected worker crash", result
"""
    completed = subprocess.run(
        [sys.executable, "-c", script],
        cwd=repository_root,
        capture_output=True,
        text=True,
        timeout=2.0,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr or completed.stdout
