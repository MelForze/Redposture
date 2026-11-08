"""etcd profiles require actual login/session and full selected key values."""

from __future__ import annotations

import base64
import json
from copy import deepcopy

import pytest

from redposture_core.modules.etcd import actions
from scripts.performance_etcd import (
    VALUES,
    EtcdWireLedger,
    etcd_inventory_errors,
    etcd_reply,
    token_for,
    wire_etcd_record,
)

PAIR = ("qa-reader", " full:password ")


def exchange(method, path, value=None, token=None, *, pair=PAIR, limited=False):
    body = json.dumps(value).encode() if value is not None else b""
    headers = {b"authorization": token.encode(), b"grpc-metadata-authorization": token.encode()} if token else {}
    raw = etcd_reply(method, path, headers, body, valid_pair=pair, limited=limited)
    head, data = raw.split(b"\r\n\r\n", 1)
    return int(head.split(b" ", 2)[1]), data, headers, body, raw


@pytest.mark.parametrize("pair", [None, (PAIR[0], "wrong"), ("other", PAIR[1])])
def test_actual_login_body_is_required_to_issue_a_token(pair):
    status, payload, *_ = exchange("POST", "/v3/auth/authenticate", {"name": PAIR[0], "password": PAIR[1]}, pair=pair)
    assert status == 400 and json.loads(payload)["code"] == 3
    assert exchange("POST", "/v3/kv/range", {"key": "AA==", "range_end": "AA=="}, pair=pair)[0] == 401


@pytest.mark.parametrize("limited", [False, True])
def test_pagination_and_selected_key_permission_are_independent_of_authentication(limited):
    token = token_for(PAIR, limited)
    status, payload, *_ = exchange(
        "POST", "/v3/kv/range", {"key": "AA==", "range_end": "AA==", "limit": 2}, token, limited=limited
    )
    if limited:
        assert status == 403 and json.loads(payload)["code"] == 7
    else:
        body = json.loads(payload)
        assert status == 200 and body["count"] == "3" and body["more"] is True
        first = [base64.b64decode(kv["key"]).decode() for kv in body["kvs"]]
        assert first == sorted(VALUES)[:2]
        start = base64.b64encode(sorted(VALUES)[1].encode() + b"\0").decode()
        body = json.loads(exchange("POST", "/v3/kv/range", {"key": start, "range_end": "AA==", "limit": 2}, token)[1])
        assert body["count"] == "1" and body["more"] is False
    key = "/services/billing/config"
    result = json.loads(
        exchange("POST", "/v3/kv/range", {"key": base64.b64encode(key.encode()).decode()}, token, limited=limited)[1]
    )
    assert base64.b64decode(result["kvs"][0]["value"]).decode() == VALUES[key]
    assert exchange("POST", "/v3/kv/put", {}, token, limited=limited)[0] == 405
    assert exchange("GET", "/unknown", token=token, limited=limited)[0] == 404


@pytest.fixture
def actual_audit(monkeypatch):
    def run(*, limited=False, pair=PAIR, selected=None, dump=False, catalogue=False):
        ledger = EtcdWireLedger()

        def request(_host, _port, method, path, _timeout, **kwargs):
            status, payload, headers, body, raw = exchange(
                method, path, kwargs.get("payload"), kwargs.get("auth_token"), limited=limited
            )
            ledger.record_response(0, method, path, headers, body, raw)
            return status, payload.decode()

        monkeypatch.setattr(actions, "_http_json_request", request)
        record = actions._audit_etcd_host(
            "qa.invalid",
            2379,
            1,
            0,
            not selected,
            dump,
            selected,
            username=pair[0],
            password=pair[1],
            dump_batch=2,
            dump_delay=0,
            credential_candidates=[
                {"username": u, "password": p, "source": "default"} for u, p in actions._ETCD_DEFAULT_CREDS
            ]
            if catalogue
            else None,
        )
        return record, ledger.pop(0)

    return run


@pytest.mark.parametrize("limited", [False, True])
@pytest.mark.parametrize("selected", [None, "/services/billing/config"])
def test_actual_product_auth_and_readability_use_matching_received_tokens(actual_audit, limited, selected):
    record, wire = actual_audit(limited=limited, selected=selected)
    original = deepcopy(record)
    assert record["provided_credentials_ok"] is True
    assert wire_etcd_record(record, wire)[1] is None and record == original
    assert not etcd_inventory_errors(record, limited=limited, selected=selected, dump=False)


def test_actual_dump_crosses_page_and_preserves_unicode_values(actual_audit):
    record, wire = actual_audit(dump=True)
    assert wire_etcd_record(record, wire)[1] is None
    assert not etcd_inventory_errors(record, limited=False, selected=None, dump=True)
    assert len([c for c in wire["calls"] if c["kind"] == "etcd_read"]) == 3  # count plus two dump pages


def test_wrong_credentials_are_explicit_and_never_read_keys(actual_audit):
    record, wire = actual_audit(pair=(PAIR[0], "wrong"))
    assert record["provided_credentials_ok"] is False
    assert len(wire["calls"]) == 1 and wire["calls"][0]["password"] == "wrong"
    assert wire_etcd_record(record, wire)[1] is None


@pytest.mark.parametrize("limited,selected", [(False, "/missing-key"), (True, "/services/events/config")])
def test_missing_and_forbidden_selected_values_need_real_range_receipts(actual_audit, limited, selected):
    record, wire = actual_audit(limited=limited, selected=selected)
    assert wire_etcd_record(record, wire)[1] is None
    assert not etcd_inventory_errors(record, limited=limited, selected=selected, dump=False)
    wire["calls"].pop()
    assert wire_etcd_record(record, wire)[1] is not None


@pytest.mark.parametrize(
    "fault",
    [
        "password",
        "token",
        "token-and-metadata",
        "metadata",
        "status",
        "body",
        "missing-login",
        "missing-read",
        "malformed",
        "unverified",
    ],
)
def test_corrupt_or_incomplete_observation_cannot_pass(actual_audit, fault):
    record, wire = actual_audit()
    if fault == "password":
        wire["calls"][0]["password"] += "wrong"
    elif fault == "token":
        wire["calls"][-1]["authorization"] += "wrong"
    elif fault == "token-and-metadata":
        wire["calls"][-1]["authorization"] += "wrong"
        wire["calls"][-1]["grpc_authorization"] += "wrong"
    elif fault == "metadata":
        wire["calls"][-1]["grpc_authorization"] += "wrong"
    elif fault == "status":
        wire["calls"][0]["status"] = 403
    elif fault == "body":
        wire["calls"][0]["body"] += "wrong"
    elif fault == "missing-login":
        wire["calls"].pop(0)
    elif fault == "missing-read":
        wire["calls"].pop()
    elif fault == "malformed":
        wire["calls"][0]["path"] = []
    elif fault == "unverified":
        record["credential_attempts"][0]["ok"] = None
    assert wire_etcd_record(record, wire)[1] is not None


def test_receipt_capacity_is_visible_and_consumption_releases_memory():
    ledger = EtcdWireLedger(body_limit=1)
    _, _, headers, body, raw = exchange("POST", "/v3/auth/authenticate", {"name": PAIR[0], "password": PAIR[1]})
    ledger.record_response(0, "POST", "/v3/auth/authenticate", headers, body, raw)
    assert ledger.snapshot()["overflow"] == 1 and ledger.pop(0) == {"complete": False, "calls": []}
    ledger = EtcdWireLedger()
    ledger.record_response(0, "POST", "/v3/auth/authenticate", headers, body, raw)
    assert ledger.pending_body_bytes > 0
    ledger.pop(0)
    assert ledger.pending_body_bytes == 0


@pytest.mark.parametrize("fault", ["key-names", "selected-key", "entry-key"])
def test_malformed_key_fields_fail_the_gate_without_raising(actual_audit, fault):
    record, wire = actual_audit()
    if fault == "key-names":
        record["keys"] = [{}]
    elif fault == "selected-key":
        record["query_key"] = ["key"]
    else:
        record["key_value_entries"] = [{"key": ["key"], "value": "wrong"}]
    assert wire_etcd_record(record, wire)[1] is not None


def test_client_cannot_report_a_value_different_from_the_received_range(actual_audit):
    record, wire = actual_audit(dump=True)
    record["key_value_entries"][0]["value"] = "not-the-received-value"
    assert wire_etcd_record(record, wire)[1] is not None
