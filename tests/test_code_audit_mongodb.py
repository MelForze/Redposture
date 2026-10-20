"""Regression tests for bounded MongoDB handshake failures."""

from types import SimpleNamespace
from unittest.mock import patch

import pytest
from pymongo.errors import NetworkTimeout, OperationFailure, ProtocolError, ServerSelectionTimeoutError

from redposture_core.clients.mongodb import MongoAuditClient, normalize_mongodb_error


class _Raw:
    def __init__(self, error, *, topology_error=None):
        self.error = error
        self.calls = []
        self.topology_description = SimpleNamespace(
            server_descriptions=lambda: {("host", 27017): SimpleNamespace(error=topology_error)}
        )

    def __getitem__(self, name):
        return self

    def command(self, command):
        self.calls.append(command)
        if command == "hello":
            raise self.error
        return {"ok": 1, "ismaster": True, "minWireVersion": 0, "maxWireVersion": 8}


@pytest.mark.parametrize(
    "error",
    [
        NetworkTimeout("socket timed out"),
        ServerSelectionTimeoutError("No servers available, Timeout: 0.5s"),
        OperationFailure("not authorized", code=13),
        RuntimeError("unrelated error"),
    ],
)
def test_failed_handshake_does_not_get_a_second_selection_budget(error):
    raw = _Raw(error)
    with pytest.raises(type(error)) as caught:
        MongoAuditClient(raw).hello()
    assert caught.value is error
    assert raw.calls == ["hello"]


def test_legacy_unsupported_hello_still_uses_ismaster():
    raw = _Raw(OperationFailure("no such command: hello", code=59))
    assert MongoAuditClient(raw).hello()["ismaster"] is True
    assert raw.calls == ["hello", "isMaster"]


def test_protocol_error_does_not_become_a_generic_timeout():
    raw = _Raw(
        ServerSelectionTimeoutError("Got response id 808464928 but expected 1, Timeout: 0.5s"),
        topology_error=ProtocolError("Got response id 808464928 but expected 1"),
    )
    with pytest.raises(Exception) as caught:
        MongoAuditClient(raw).hello()
    message = normalize_mongodb_error(caught.value)
    assert "protocol" in message.lower()
    assert "connection timeout" not in message
    assert "timed out" not in message
    assert raw.calls == ["hello"]


def test_real_timeout_remains_eligible_for_runtime_timeout_handling():
    error = ServerSelectionTimeoutError("No servers available, Timeout: 0.5s")
    raw = _Raw(error, topology_error=NetworkTimeout("socket timed out"))
    with pytest.raises(ServerSelectionTimeoutError) as caught:
        MongoAuditClient(raw).hello()
    assert normalize_mongodb_error(caught.value) == "connection timeout"


def test_injected_client_failure_is_preserved_without_optional_driver():
    error = RuntimeError("injected client failed")
    raw = _Raw(error)
    with patch.dict("sys.modules", {"pymongo.errors": None}), pytest.raises(RuntimeError) as caught:
        MongoAuditClient(raw).hello()
    assert caught.value is error
    assert raw.calls == ["hello"]


@pytest.mark.parametrize("product", ["grafana", "redis", "mongodb"])
def test_real_wire_detect_does_not_escalate_protocol_errors(monkeypatch, product):
    from redposture_core.modules.mongodb import actions
    from tests.test_network_fingerprint_matrix import _detect, _product_server

    timeouts = []
    original = actions._open_client

    def open_client(host, port, timeout, **kwargs):
        timeouts.append(timeout)
        return original(host, port, timeout, **kwargs)

    monkeypatch.setattr(actions, "_open_client", open_client)
    with _product_server(product) as (port, _requests):
        detected, _record = _detect("mongodb", port)
    assert detected is (product == "mongodb")
    # A confirmed service also gets its normal authenticated audit stage.
    assert timeouts == [0.5] * (2 if product == "mongodb" else 1)
