"""Owned Oracle auth-to-data connection transfer without action replay."""

from __future__ import annotations

import json
from typing import Any

import pytest

from redposture_core.modules.oracle import actions
from redposture_core.modules.oracle.stage import run_oracle_stage
from tests.test_stage_oracle import _args, _FakeOracleClient


class Client(_FakeOracleClient):
    def __init__(self, *, fault=None, **options):
        super().__init__(**options)
        self.fault, self.closed, self.closes, self.context_calls = fault, False, 0, 0

    def current_context(self):
        assert not self.closed, "closed client was reused"
        self.context_calls += 1
        if self.context_calls == 2 and self.fault:
            raise self.fault
        return super().current_context()

    def close(self):
        self.closed = True
        self.closes += 1


def setup(monkeypatch, *, first_fault=None, next_open_fault=None):
    clients, requests = [], []

    def factory(host, port, **options):
        requests.append((host, port, dict(options)))
        if len(clients) == 1 and next_open_fault:
            raise next_open_fault
        client = Client(
            username=options["username"], password=options["password"], fault=first_fault if not clients else None
        )
        clients.append(client)
        return client

    def probe(*args, **options):
        return [
            {
                "protocol": options["protocol_candidates"][0],
                "service": "FREEPDB1",
                "sid": None,
                "status": "available",
                "exists": True,
                "auth_required": True,
                "error": "authentication required",
            }
        ]

    monkeypatch.setattr(
        actions, "tns_listener_command", lambda *a, **k: {"ok": True, "text": "(DESCRIPTION=(ERR=1189))", "error": None}
    )
    monkeypatch.setattr(actions, "_probe_listener_targets", probe)
    monkeypatch.setattr(actions, "_open_client", factory)
    return clients, requests


def run(tmp_path, **options):
    output = tmp_path / "oracle.jsonl"
    args = _args(
        username="system",
        password="oracle",
        service="FREEPDB1",
        protocol="tcp",
        output=str(output),
        output_format="json",
        **options,
    )
    code = run_oracle_stage(args, object())
    records = [json.loads(line) for line in output.read_text().splitlines()]
    return code, next(r for r in records if "host" in r)


@pytest.mark.parametrize("protocol,sysdba", [("tcp", False), ("tcps", False), ("tcps", True)])
def test_verified_client_reaches_metadata_once_with_the_same_connection_options(
    monkeypatch, tmp_path, protocol, sysdba
):
    clients, requests = setup(monkeypatch)
    output = tmp_path / "oracle.jsonl"
    args = _args(
        username="system",
        password="oracle",
        service="FREEPDB1",
        protocol=protocol,
        as_sysdba=sysdba,
        output=str(output),
        output_format="json",
    )
    assert run_oracle_stage(args, object()) == 0
    assert len(clients) == len(requests) == 1 and clients[0].closed and clients[0].closes == 1
    assert clients[0].context_calls == 2  # Auth proof + the collector's first read; no third query.
    assert requests[0][2]["protocol"] == protocol and requests[0][2]["as_sysdba"] is sysdba
    assert requests[0][2]["service"] == "FREEPDB1" and requests[0][2]["timeout"] == args.timeout
    raw = output.read_bytes()
    assert b"\x1b" not in raw and b"object at" not in raw and b"verified_context" not in raw


@pytest.mark.parametrize("fault", [ConnectionError("DPY-4011: closed"), RuntimeError("permission changed")])
def test_failed_preflight_gets_one_fresh_connection_before_any_data_or_action(monkeypatch, tmp_path, fault):
    clients, requests = setup(monkeypatch, first_fault=fault)
    calls = []

    def collect(client, **options):
        assert not client.closed and client is clients[1]
        calls.append((client, options))
        return {"error": None}

    monkeypatch.setattr(actions, "_collect_oracle_data", collect)
    code, record = run(tmp_path, exec_cmd="qa-never-replayed")
    assert code == 0 and len(clients) == len(requests) == 2 and len(calls) == 1
    assert requests[0] == requests[1] and all(c.closed and c.closes == 1 for c in clients)
    assert calls[0][1]["exec_cmd"] == "qa-never-replayed" and "verified_context" not in calls[0][1]
    assert len(record["credential_attempts"]) == 1 and record["credential_attempts"][0]["ok"] is True


@pytest.mark.parametrize("handoff", [False, True])
def test_failed_fresh_login_does_not_replay_the_catalogue_or_start_an_action(monkeypatch, tmp_path, handoff):
    clients, requests = setup(
        monkeypatch,
        first_fault=ConnectionError("stale"),
        next_open_fault=actions.OracleAuthError("invalid credentials"),
    )
    monkeypatch.setattr(
        actions, "_collect_oracle_data", lambda *_a, **_k: pytest.fail("data/action ran after failed fresh login")
    )
    if not handoff:
        original = actions._try_credentials

        def legacy(*args, **options):
            options.pop("selected_client_handoff", None)
            return original(*args, **options)

        monkeypatch.setattr(actions, "_try_credentials", legacy)
    code, record = run(tmp_path, exec_cmd="qa-never-run")
    # A rejected password keeps the existing audit exit contract in both the
    # legacy fresh-login route and the handoff route. It must never look valid.
    assert code == 0 and record["status"] == "fail" and record["error"] == "invalid credentials"
    assert record["exec_result"] is None and record["provided_credentials"] is False
    assert len(requests) == 2 and len(clients) == 1 and clients[0].closed and clients[0].closes == 1


def test_data_exception_does_not_reconnect_or_replay_the_action(monkeypatch, tmp_path):
    clients, requests = setup(monkeypatch)
    calls = []

    def collect(client, **options):
        calls.append(client)
        raise RuntimeError("data fault")

    monkeypatch.setattr(actions, "_collect_oracle_data", collect)
    _code, record = run(tmp_path, exec_cmd="qa-action")
    assert len(calls) == len(clients) == len(requests) == 1
    assert clients[0].closed and clients[0].closes == 1 and record["error"] == "data fault"


def test_interrupted_catalogue_closes_the_session_not_yet_handed_to_data(monkeypatch, tmp_path):
    clients, _requests = setup(monkeypatch)
    original = actions._open_client
    count = 0

    def interrupted(*args, **options):
        nonlocal count
        count += 1
        if count == 2:
            raise KeyboardInterrupt
        return original(*args, **options)

    monkeypatch.setattr(actions, "_open_client", interrupted)
    output = tmp_path / "cancelled.jsonl"
    args = _args(service="FREEPDB1", protocol="tcp", defcreds=True, output=str(output), output_format="json")
    try:
        run_oracle_stage(args, object())
    except KeyboardInterrupt:
        pass
    assert len(clients) == 1 and clients[0].closed and clients[0].closes == 1


@pytest.mark.parametrize("handoff", [False, True])
def test_multiple_valid_candidates_retain_only_the_selected_owner(monkeypatch, handoff):
    clients, _requests = setup(monkeypatch)
    candidates = [{"username": "one", "password": "p1"}, {"username": "two", "password": "p2"}]
    owned: list[tuple[dict[str, Any], Any]] = []
    selected, attempts, terminal = actions._try_credentials(
        "qa",
        1521,
        2,
        protocol="tcp",
        service="FREEPDB1",
        sid=None,
        wallet=None,
        ssl_server_dn=None,
        insecure=True,
        as_sysdba=False,
        credential_candidates=candidates,
        **({"selected_client_handoff": owned} if handoff else {}),
    )
    assert terminal is None and len(attempts) == 2 and selected is attempts[0]
    assert clients[1].closed and clients[1].closes == 1
    if handoff:
        assert owned == [(selected, clients[0])] and not clients[0].closed
        clients[0].close()
    else:
        assert not owned and clients[0].closed


def test_handoff_with_a_different_proof_object_is_closed_and_not_reused(monkeypatch, tmp_path):
    clients, requests = setup(monkeypatch)
    original = actions._try_credentials

    def replaced_proof(*args, **options):
        selected, attempts, terminal = original(*args, **options)
        return dict(selected), attempts, terminal

    monkeypatch.setattr(actions, "_try_credentials", replaced_proof)
    code, record = run(tmp_path)
    assert code == 0 and record["status"] == "valid_credentials"
    assert len(clients) == len(requests) == 2 and requests[0] == requests[1]
    assert all(c.closed and c.closes == 1 for c in clients)
    assert clients[0].context_calls == 1 and clients[1].context_calls == 1


def test_cancellation_during_preflight_closes_owned_client_without_starting_data(monkeypatch, tmp_path):
    clients, requests = setup(monkeypatch, first_fault=KeyboardInterrupt())
    monkeypatch.setattr(actions, "_collect_oracle_data", lambda *_a, **_k: pytest.fail("action after cancellation"))
    try:
        run(tmp_path, exec_cmd="qa-never-run")
    except KeyboardInterrupt:
        pass
    assert len(clients) == len(requests) == 1 and clients[0].closed and clients[0].closes == 1


def test_nonempty_handoff_cannot_be_reused_for_another_authentication(monkeypatch):
    clients, requests = setup(monkeypatch)
    foreign = Client(username="foreign", password="foreign")
    owned = [({"username": "foreign"}, foreign)]
    with pytest.raises(ValueError, match="start empty"):
        actions._try_credentials(
            "another-host",
            1521,
            2,
            protocol="tcp",
            service="OTHERPDB",
            sid=None,
            wallet=None,
            ssl_server_dn=None,
            insecure=True,
            as_sysdba=False,
            credential_candidates=[{"username": "other", "password": "other"}],
            selected_client_handoff=owned,
        )
    assert not clients and not requests and not foreign.closed and len(owned) == 1


def test_large_accepted_catalogue_keeps_only_one_retained_session(monkeypatch):
    clients, _requests = setup(monkeypatch)
    original = actions._open_client
    peak = 0

    def counted(*args, **options):
        nonlocal peak
        client = original(*args, **options)
        peak = max(peak, sum(not c.closed for c in clients))
        return client

    monkeypatch.setattr(actions, "_open_client", counted)
    pairs = [(f"user{i}", f" opaque:password-{i} ") for i in range(20)]
    owned = []
    selected, attempts, _terminal = actions._try_credentials(
        "qa",
        1521,
        2,
        protocol="tcp",
        service="FREEPDB1",
        sid=None,
        wallet=None,
        ssl_server_dn=None,
        insecure=True,
        as_sysdba=False,
        credential_candidates=[{"username": u, "password": p} for u, p in pairs],
        selected_client_handoff=owned,
    )
    assert [(r["username"], r["password"]) for r in attempts] == pairs
    assert len(owned) == 1 and owned[0] == (selected, clients[0]) and peak == 2
    assert all(c.closed and c.closes == 1 for c in clients[1:]) and not clients[0].closed
    clients[0].close()


class TimeoutConnection:
    def __init__(self, previous):
        self.value, self.healthy, self.writes, self.invalid_access = previous, True, [], 0

    def is_healthy(self):
        return self.healthy

    @property
    def call_timeout(self):
        if not self.healthy:
            self.invalid_access += 1
            raise AssertionError("native timeout getter after invalidation")
        return self.value

    @call_timeout.setter
    def call_timeout(self, value):
        if not self.healthy:
            self.invalid_access += 1
            raise AssertionError("native timeout setter after invalidation")
        self.writes.append(value)
        self.value = value


@pytest.mark.parametrize("previous", [0, 500, 5000])
def test_retained_preflight_bounds_roundtrip_and_restores_timeout_before_data(monkeypatch, tmp_path, previous):
    clients, requests = setup(monkeypatch)
    original = actions._open_client

    def opened(*args, **options):
        client = original(*args, **options)
        client.connection = TimeoutConnection(previous)
        context = client.current_context

        def guarded():
            if client.context_calls == 1:
                assert client.connection.value == (min(previous, 1000) if previous else 1000)
            return context()

        monkeypatch.setattr(client, "current_context", guarded)
        return client

    def collect(client, **options):
        assert client.connection.value == previous
        assert options["verified_context"]
        return {"error": None}

    monkeypatch.setattr(actions, "_open_client", opened)
    monkeypatch.setattr(actions, "_collect_oracle_data", collect)
    code, record = run(tmp_path, exec_cmd="qa-only-once")
    assert code == 0 and record["status"] == "valid_credentials"
    assert len(clients) == len(requests) == 1 and clients[0].closed
    assert clients[0].connection.writes == [min(previous, 1000) if previous else 1000, previous]


@pytest.mark.parametrize("already_dead", [False, True])
def test_invalidated_preflight_never_accesses_native_timeout_again(monkeypatch, tmp_path, already_dead):
    clients, requests = setup(monkeypatch)
    original = actions._open_client

    def opened(*args, **options):
        client = original(*args, **options)
        client.connection = TimeoutConnection(0)
        context = client.current_context

        def guarded():
            if client is clients[0] and client.context_calls == 1:
                client.connection.healthy = False
                raise ConnectionError("DPY-4011: session invalidated")
            result = context()
            if already_dead and client is clients[0]:
                client.connection.healthy = False
            return result

        monkeypatch.setattr(client, "current_context", guarded)
        return client

    monkeypatch.setattr(actions, "_open_client", opened)
    code, record = run(tmp_path)
    assert code == 0 and record["status"] == "valid_credentials"
    assert len(clients) == len(requests) == 2 and all(c.closed for c in clients)
    assert clients[0].connection.invalid_access == 0
    assert clients[0].connection.writes == ([] if already_dead else [1000])


def test_preflight_read_failure_restores_timeout_and_does_not_replay_action(monkeypatch, tmp_path):
    clients, requests = setup(monkeypatch, first_fault=PermissionError("context denied"))
    original = actions._open_client
    calls = []

    def opened(*args, **options):
        client = original(*args, **options)
        client.connection = TimeoutConnection(5000)
        return client

    def collect(client, **options):
        assert client is clients[1] and client.connection.value == 5000
        assert clients[0].connection.value == 5000
        assert "verified_context" not in options
        calls.append(options["exec_cmd"])
        return {"error": None}

    monkeypatch.setattr(actions, "_open_client", opened)
    monkeypatch.setattr(actions, "_collect_oracle_data", collect)
    code, _record = run(tmp_path, exec_cmd="qa-only-once")
    assert code == 0 and calls == ["qa-only-once"] and len(requests) == 2
    assert clients[0].connection.writes == [1000, 5000]
    assert all(c.closed for c in clients)
