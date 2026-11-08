"""Elasticsearch performance fixtures must prove identity and disposable CRUD."""

from __future__ import annotations

import base64
import hashlib
import json
from copy import deepcopy
from types import SimpleNamespace

import pytest

from redposture_core.modules.elastic import actions
from redposture_core.stage_runtime import AuditCredentialRun
from scripts.performance_contracts import HttpRouteStats, wire_http_pair_record
from scripts.performance_elastic import ElasticModel, ElasticWireLedger, basic_pair, elastic_inventory_errors

PAIR = ("qa-reader", " full:password ")
HEADERS = {b"authorization": b"Basic " + base64.b64encode(":".join(PAIR).encode())}
INDEX = "/redposture-access-probe-" + "a" * 32


def request(model, method, path, body=b"", *, host="qa.invalid", headers=HEADERS):
    raw = model.reply(method, path, headers, body, host)
    head, payload = raw.split(b"\r\n\r\n", 1)
    return int(head.split(b" ", 2)[1]), json.loads(payload), raw


@pytest.mark.parametrize("limited", [False, True])
def test_probe_lifecycle_and_host_ownership_are_observed(limited):
    model = ElasticModel(valid_pair=PAIR, limited=limited)
    doc = INDEX + "/_doc/redposture-probe"
    assert request(model, "PUT", INDEX, b"{}")[0] == 200
    assert request(model, "PUT", doc, b'{"redposture_probe":true}')[0] == 201
    assert request(model, "DELETE", INDEX, host="other.invalid")[0] == 404
    assert request(model, "DELETE", doc)[0] == (403 if limited else 200)
    assert request(model, "DELETE", INDEX)[0] == 200
    summary = model.summary()
    assert summary["active_indices"] == summary["unexpected_mutations"] == summary["overflows"] == 0
    assert summary["created"] == summary["indices_deleted"] == summary["documents_written"] == 1
    assert summary["documents_deleted"] == int(not limited)
    assert summary["denied_document_deletes"] == int(limited)
    assert request(model, "DELETE", INDEX)[0] == 404


def test_full_pairs_and_mutation_namespace_cannot_be_guessed():
    model = ElasticModel(valid_pair=PAIR, limited=False, max_active=1)
    for headers in [{}, {b"authorization": b"Basic broken"}, {b"authorization": b"Basic cWE6d3Jvbmc="}]:
        assert basic_pair(headers) != PAIR
        assert request(model, "GET", "/_security/_authenticate", headers=headers)[0] == 401
        assert request(model, "PUT", INDEX, b"{}", headers=headers)[0] == 401
    for body in [b"null", b"[]", b"broken", b'{"not_probe":true}']:
        assert request(model, "PUT", INDEX, body)[0] == 400
    assert request(model, "PUT", INDEX, b"{}")[0] == 200
    assert request(model, "PUT", INDEX.replace("a" * 32, "b" * 32), b"{}")[0] == 503
    assert request(model, "DELETE", "/billing-logs")[0] == 405
    assert request(model, "GET", "/unknown")[0] == 404
    assert model.summary()["overflows"] == model.summary()["unexpected_mutations"] == 1


@pytest.fixture
def actual_auth(monkeypatch):
    def run(*, limited=False, pair=PAIR, inventory=False):
        model = ElasticModel(valid_pair=PAIR, limited=limited)
        ledger = ElasticWireLedger()

        def wire(_host, _port, path, _timeout, **kwargs):
            headers = {k.lower().encode(): v.encode() for k, v in kwargs.get("headers", {}).items()}
            method, body = kwargs.get("method", "GET"), kwargs.get("data") or b""
            raw = model.reply(method, path, headers, body, _host)
            ledger.record_response(0, method, path, headers, body, raw)
            head, payload = raw.split(b"\r\n\r\n", 1)
            return int(head.split(b" ", 2)[1]), payload, {}, None

        monkeypatch.setattr(actions, "_elastic_request", wire)
        monkeypatch.setattr(actions, "_activate_lifecycle_session", lambda *_: None)
        ctx = SimpleNamespace(
            host="qa.invalid",
            port=9200,
            args=SimpleNamespace(timeout=1, ca_file=None),
            credential=AuditCredentialRun(username=pair[0], password=pair[1], source="provided"),
            lifecycle_state=actions.ElasticLifecycleState(),
        )
        record = actions.authenticate_elastic(
            ctx,
            {
                "is_elastic": True,
                "vendor": "elasticsearch",
                "scheme": "http",
                "auth_required": True,
                "anonymous_root_status": 401,
                "server_version": "8.19.0",
            },
            {},
        )
        if inventory:
            record = actions.collect_elastic_data(
                ctx,
                record,
                {
                    "show_endpoints": True,
                    "show_plugins": True,
                    "show_cluster": True,
                    "show_users": True,
                    "discover": False,
                },
            )
        return record, ledger.pop(0), model

    return run


@pytest.mark.parametrize("limited", [False, True])
def test_actual_auth_proves_identity_and_all_four_cleanup_operations(actual_auth, limited):
    record, wire, model = actual_auth(limited=limited)
    before = deepcopy(record)
    observed, error = wire_http_pair_record(record, wire, module="elastic")
    assert error is None and record == before and observed["attempted_credentials"][0]["password"] == PAIR[1]
    assert record["auth_valid"] is record["identity_verified"] is True
    assert record["credential_write_access"] == "allowed"
    assert record["credential_delete_access"] == ("denied" if limited else "allowed")
    assert record["credential_indices_access"] == ("denied" if limited else "allowed")
    assert model.summary()["active_indices"] == 0 and model.summary()["indices_deleted"] == 1


def test_wrong_password_has_no_inventory_or_mutation(actual_auth):
    record, wire, model = actual_auth(pair=(PAIR[0], "wrong"))
    assert record["auth_valid"] is False and record["credential_accepted"] is False
    assert [c["path"] for c in wire["calls"]] == ["/_security/_authenticate"]
    assert wire_http_pair_record(record, wire, module="elastic")[1] is None
    assert not any(model.summary().values())


@pytest.mark.parametrize("limited", [False, True])
def test_actual_inventory_values_and_acl_are_checked(actual_auth, limited):
    record, wire, model = actual_auth(limited=limited, inventory=True)
    categories = ["endpoints", "plugins", "cluster", "users"]
    assert not elastic_inventory_errors(record, limited=limited, categories=categories)
    assert wire_http_pair_record(record, wire, module="elastic")[1] is None
    assert model.summary()["active_indices"] == 0
    record["cluster_nodes"][0]["name"] = "not-the-seeded-node"
    assert elastic_inventory_errors(record, limited=limited, categories=["cluster"])


@pytest.mark.parametrize(
    "fault",
    [
        "no-identity",
        "identity-user",
        "password",
        "body",
        "sha",
        "missing-cleanup",
        "path",
        "ack",
        "delete-verdict",
        "malformed",
    ],
)
def test_partial_or_corrupted_evidence_cannot_pass(actual_auth, fault):
    record, wire, _ = actual_auth()
    if fault == "no-identity":
        wire["calls"].pop(0)
    elif fault == "identity-user":
        wire["calls"][0]["response_body"] = '{"username":"other","enabled":true}'
        wire["calls"][0]["response_sha256"] = hashlib.sha256(wire["calls"][0]["response_body"].encode()).hexdigest()
    elif fault == "password":
        wire["calls"][0]["password"] += "wrong"
    elif fault in {"body", "sha"}:
        wire["calls"][-1]["response_body" if fault == "body" else "body_sha256"] += "wrong"
    elif fault == "missing-cleanup":
        wire["calls"].pop()
    elif fault == "path":
        wire["calls"][-1]["path"] = "/billing-logs"
    elif fault == "ack":
        wire["calls"][-1]["response_body"] = "{}"
        wire["calls"][-1]["response_sha256"] = hashlib.sha256(b"{}").hexdigest()
    elif fault == "delete-verdict":
        record["credential_delete_access"] = "denied"
    elif fault == "malformed":
        wire["calls"][0]["path"] = []
    assert wire_http_pair_record(record, wire, module="elastic")[1] is not None


def test_receipt_memory_is_bounded_and_pop_releases_bodies():
    ledger = ElasticWireLedger(body_limit=30)
    raw = b"HTTP/1.1 401 Unauthorized\r\n\r\n{}"
    ledger.record_response(0, "GET", "/", HEADERS, b"payload", raw)
    assert ledger.pending_body_bytes == 9
    ledger.pop(0)
    assert ledger.pending_body_bytes == 0
    ledger.record_response(0, "GET", "/", HEADERS, b"x" * 29, raw)
    assert ledger.snapshot()["overflow"] == 1
    ledger.close()
    assert ledger.pending_body_bytes == 0


def test_random_probe_routes_are_grouped_without_merging_credentials_or_methods():
    stats = HttpRouteStats(limit=20)
    other = {b"authorization": b"Basic " + base64.b64encode(b"qa-reader:other-password")}
    for number in range(400):
        path = "/redposture-access-probe-" + f"{number:032x}"
        stats.record("PUT", path, HEADERS, b"{}", body_group="elastic-probe-index")
        stats.record("DELETE", path, HEADERS, b"", body_group="elastic-probe-index")
        stats.record("PUT", path, other, b"{}", body_group="elastic-probe-index")
    value = stats.snapshot()
    assert value["complete"] and value["overflow_requests"] == 0
    assert len(value["routes"]) == 3 and {r["requests"] for r in value["routes"]} == {400}
    assert len({r["auth_identity_sha256"] for r in value["routes"] if r["method"] == "PUT"}) == 2
    # An explicit grouping hint is mandatory; arbitrary indices never collapse.
    for path in [INDEX, INDEX.replace("a" * 32, "b" * 32), "/billing-a", "/billing-b"]:
        stats.record("GET", path, HEADERS, b"")
    assert len(stats.snapshot()["routes"]) == 7
