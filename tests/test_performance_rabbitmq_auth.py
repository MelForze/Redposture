"""Product-shaped RabbitMQ identity/permissions peer, not a real broker."""

from __future__ import annotations

import base64
import json
from copy import deepcopy

import pytest

from scripts.performance_contracts import HttpPairWireLedger, rabbitmq_inventory_errors, wire_http_pair_record
from scripts.performance_http_fixtures import rabbitmq_reply

PAIR = ("qa-operator", " opaque:password ")


def call(path, *, pair=PAIR, limited=False, method="GET"):
    headers = {} if pair is None else {b"authorization": b"Basic " + base64.b64encode(":".join(pair).encode())}
    raw = rabbitmq_reply(method, path, headers, b"", valid_pair=PAIR, limited=limited)
    head, body = raw.split(b"\r\n\r\n", 1)
    return int(head.split(b" ", 2)[1]), json.loads(body), head


@pytest.mark.parametrize("pair", [None, (PAIR[0], "wrong"), ("other-user", PAIR[1])])
def test_missing_or_wrong_identity_cannot_receive_management_data(pair):
    for path in ["/api/overview", "/api/whoami", "/api/vhosts", "/api/users", "/api/queues"]:
        status, data, headers = call(path, pair=pair)
        assert status == 401 and data["error"] == "not_authorized"
        assert b'WWW-Authenticate: Basic realm="RabbitMQ Management"' in headers


@pytest.mark.parametrize("limited,tag", [(False, "administrator"), (True, "management")])
def test_full_identity_is_verified_independently_of_admin_rights(limited, tag):
    status, identity, _ = call("/api/whoami", limited=limited)
    assert status == 200 and identity == {"name": PAIR[0], "tags": [tag]}
    admin_status, users, _ = call("/api/users?page=1&page_size=1&columns=name", limited=limited)
    assert admin_status == (401 if limited else 200)
    if not limited:
        assert users == [{"name": PAIR[0]}]


def test_pagination_visits_all_known_queues_once_and_keeps_full_metadata():
    rows = []
    for page in [1, 2]:
        status, data, _ = call(f"/api/queues?page={page}&page_size=2&pagination=true")
        assert status == 200 and data["page"] == page
        assert data["page_count"] == 2 and data["total_count"] == data["filtered_count"] == 3
        rows.extend(data["items"])
    assert [(r["vhost"], r["name"], r["messages"], r["consumers"]) for r in rows] == [
        ("billing", "billing.invoices", 12, 2),
        ("billing", "billing.retry", 3, 0),
        ("events", "events.audit", 7, 1),
    ]


def test_management_only_identity_has_precisely_its_visible_vhost_data():
    assert call("/api/vhosts", limited=True)[1] == [{"name": "billing"}]
    status, data, _ = call("/api/queues?page=1&page_size=1&pagination=true", limited=True)
    assert status == 200 and data["page_count"] == 2 and data["total_count"] == 2
    assert data["items"][0]["name"] == "billing.invoices"
    assert call("/api/queues/events", limited=True)[0] == 401
    # v4.1.4 uses 401 for this ACL denial even after whoami confirmed identity.
    assert call("/api/users/qa-operator/permissions", limited=True)[0] == 401
    assert call("/api/global-parameters/internal_cluster_id", limited=True)[0] == 401


@pytest.mark.parametrize("query", ["page=0", "page=-1", "page=no", "page_size=0", "page_size=501"])
def test_invalid_page_does_not_turn_into_successful_or_unbounded_inventory(query):
    assert call("/api/queues?pagination=true&" + query)[0] == 400


@pytest.mark.parametrize("method", ["POST", "PUT", "DELETE"])
def test_peer_never_claims_that_a_state_changing_request_succeeded(method):
    assert call("/api/queues/billing/new", method=method)[0] == 405


def test_unknown_route_never_returns_a_product_shaped_success():
    assert call("/api/not-a-real-route")[0] == 404


def wire_and_record():
    ledger = HttpPairWireLedger()
    rows = []
    for pair, state, status in [(PAIR, "valid", 200), (("other", "bad:opaque"), "rejected", 401)]:
        ledger.record(
            0,
            "rabbitmq",
            "GET",
            "/api/whoami",
            {b"authorization": b"Basic " + base64.b64encode(":".join(pair).encode())},
            b"",
            status,
        )
        rows.append(
            {
                "username": pair[0],
                "password": pair[1],
                "credential_state": state,
                "credential_http_status": status,
                "status": "valid_credentials" if status == 200 else "invalid_credentials",
            }
        )
    return ledger.pop(0), {
        "is_rabbitmq": True,
        "auth_required": True,
        "credential_verification_status": "available",
        "attempted_credentials": rows,
    }


def test_actual_full_received_pairs_match_each_client_decision_without_changing_product_records():
    wire, record = wire_and_record()
    original = deepcopy(record)
    assert wire_http_pair_record(record, wire, module="rabbitmq") == (record, None)
    assert record == original
    assert [(r["username"], r["password"]) for r in wire["calls"]] == [PAIR, ("other", "bad:opaque")]


@pytest.mark.parametrize(
    "fault",
    ["missing", "wrong-value", "duplicate", "denied", "unavailable", "unknown", "wrong-route", "missing-http-proof"],
)
def test_incomplete_ambiguous_or_denied_identity_is_not_an_invalid_password_or_quality_success(fault):
    wire, record = wire_and_record()
    if fault == "missing":
        wire["calls"].pop()
    elif fault == "wrong-value":
        wire["calls"][1]["password"] = "different"
    elif fault == "duplicate":
        wire["calls"].append(dict(wire["calls"][0]))
    elif fault == "denied":
        wire["calls"][1]["status"] = record["attempted_credentials"][1]["credential_http_status"] = 403
    elif fault == "unavailable":
        record["credential_verification_status"] = "unavailable"
    elif fault == "unknown":
        record["attempted_credentials"][1]["credential_state"] = "unverified"
        record["attempted_credentials"][1]["status"] = "auth_required"
    elif fault == "wrong-route":
        wire["calls"][0]["path"] = "/api/overview"
    else:
        record["attempted_credentials"][0].pop("credential_http_status")
    assert wire_http_pair_record(record, wire, module="rabbitmq")[1]


@pytest.mark.parametrize("limited", [False, True])
def test_inventory_matcher_checks_every_known_queue_and_acl(limited):
    row = {
        "provided_credentials_ok": True,
        "cluster_id": None if limited else "rabbitmq-cluster-id-qa-billing",
        "admin": not limited,
        "enumeration": {
            "queues": {"status": "ok", "truncated": False, "items": call("/api/queues", limited=limited)[1]}
        },
    }
    assert rabbitmq_inventory_errors(row, limited=limited) == []
    for fault in ["lost", "duplicate", "corrupt", "partial", "wrong-admin", "missing-identity"]:
        changed = deepcopy(row)
        queue = changed["enumeration"]["queues"]
        if fault == "lost":
            queue["items"].pop()
        elif fault == "duplicate":
            queue["items"].append(dict(queue["items"][0]))
        elif fault == "corrupt":
            queue["items"][0]["messages"] = -1
        elif fault == "partial":
            queue["truncated"] = True
        elif fault == "wrong-admin":
            changed["admin"] = limited
        else:
            changed["provided_credentials_ok"] = None
        assert rabbitmq_inventory_errors(changed, limited=limited)


@pytest.mark.parametrize(
    "limited,vhost,status,count",
    [(False, "billing", "ok", 2), (True, "billing", "ok", 2), (True, "events", "denied", 0)],
)
def test_selector_does_not_confuse_restricted_vhost_with_invalid_credentials(limited, vhost, status, count):
    http_status, body, _ = call("/api/queues/" + vhost, limited=limited)
    items = body if http_status == 200 else []
    assert len(items) == count
    row = {
        "provided_credentials_ok": True,
        "cluster_id": None if limited else "rabbitmq-cluster-id-qa-billing",
        "admin": not limited,
        "enumeration": {"queues": {"status": status, "truncated": False, "items": items}},
    }
    assert rabbitmq_inventory_errors(row, limited=limited, vhost=vhost) == []
    row["enumeration"]["queues"]["status"] = "ok" if status == "denied" else "denied"
    assert rabbitmq_inventory_errors(row, limited=limited, vhost=vhost)


def test_rabbitmq_public_options_keep_basic_pairs_and_have_no_token_substitution():
    from scripts.profile_module_performance import PAIR_WIRE_SURFACES, module_options

    options = module_options("rabbitmq", "credentials", "http://127.0.0.1:15672", 2, auth_case="valid")
    assert options[options.index("-u") + 1] == "profile-user"
    assert options[options.index("-p") + 1] == "profile-password"
    assert "--token" not in options and PAIR_WIRE_SURFACES["rabbitmq"] == "default"
