"""Harbor Basic/API performance controls; no real Harbor claim."""

from __future__ import annotations

import base64
import hashlib
import json
from copy import deepcopy

import pytest

from scripts.performance_contracts import HttpPairWireLedger, harbor_inventory_errors, wire_http_pair_record
from scripts.performance_http_fixtures import harbor_reply

PAIR = ("qa-reader", " opaque:password ")


def call(path, *, pair=PAIR, limited=False, method="GET", body=b""):
    headers = {} if pair is None else {b"authorization": b"Basic " + base64.b64encode(":".join(pair).encode())}
    raw = harbor_reply(method, path, headers, body, valid_pair=PAIR, limited=limited)
    head, data = raw.split(b"\r\n\r\n", 1)
    return int(head.split(b" ", 2)[1]), json.loads(data), head


@pytest.mark.parametrize("pair", [None, (PAIR[0], "wrong"), ("other", PAIR[1])])
def test_foreign_credentials_never_receive_identity_or_inventory(pair):
    assert call("/api/v2.0/systeminfo", pair=pair)[1]["harbor_version"] == "v2.14.0"
    for path in ["/api/v2.0/users/current", "/api/v2.0/projects", "/v2/", "/v2/_catalog"]:
        assert call(path, pair=pair)[0] == 401


@pytest.mark.parametrize("limited", [True, False])
def test_full_pair_verified_independently_of_project_acl(limited):
    assert call("/api/v2.0/users/current", limited=limited)[:2] == (
        200,
        {"user_id": 42, "username": PAIR[0], "sysadmin_flag": not limited},
    )
    assert call("/api/v2.0/projects", limited=limited)[0] == (403 if limited else 200)
    assert call("/v2/", limited=limited)[0] == 200
    assert call("/v2/_catalog", limited=limited)[0] == (403 if limited else 200)


def test_pages_and_full_artifact_digests():
    pages = [call(f"/api/v2.0/projects?page={page}&page_size=2") for page in [1, 2, 3]]
    assert [v["name"] for _, rows, _ in pages for v in rows] == ["billing", "observability", "platform"]
    assert all(b"X-Total-Count: 3" in head for _, _, head in pages)
    artifacts = [
        call(f"/api/v2.0/projects/billing/repositories/worker/artifacts?with_tag=true&page={p}&page_size=2")[1]
        for p in [1, 2]
    ]
    assert [v["tags"][0]["name"] for rows in artifacts for v in rows] == ["2026.11", "stable", "rollback"]
    assert all(
        v["digest"] == "sha256:" + hashlib.sha256(("billing/worker:" + v["tags"][0]["name"]).encode()).hexdigest()
        for rows in artifacts
        for v in rows
    )


@pytest.mark.parametrize("query", ["page=0", "page=-1", "page=no", "page_size=0", "page_size=101"])
def test_bad_pagination_cannot_become_an_empty_success(query):
    assert call("/api/v2.0/projects?" + query)[0] == 400


@pytest.mark.parametrize("method", ["POST", "PUT", "DELETE"])
def test_readonly_peer_never_claims_execute_upload_or_mutation(method):
    assert call("/api/v2.0/projects", method=method)[0] == 405
    assert call("/v2/", method=method)[0] == 403


def test_unknown_routes_and_repositories_fail():
    assert call("/not-api")[0] == 404
    assert call("/api/v2.0/no-route")[0] == 404
    assert call("/api/v2.0/projects/finance/repositories")[0] == 404
    assert call("/api/v2.0/projects/billing/repositories/not-worker/artifacts")[0] == 404


def record_and_wire():
    ledger = HttpPairWireLedger()
    rows = []
    for pair, status in [(PAIR, 200), (("other", "invalid:opaque"), 401)]:
        ledger.record(
            0,
            "harbor",
            "GET",
            "/api/v2.0/users/current",
            {b"authorization": b"Basic " + base64.b64encode(":".join(pair).encode())},
            b"",
            status,
        )
        rows.append(
            {
                "username": pair[0],
                "password": pair[1],
                "status": "valid_credentials" if status == 200 else "auth_required",
                "error": None if status == 200 else "authentication rejected",
            }
        )
    return {
        "is_harbor": True,
        "is_registry": True,
        "credential_verification_status": "available",
        "provided_credentials_ok": True,
        "attempted_credentials": rows,
    }, ledger.pop(0)


def test_wire_identity_is_actual_full_pair_and_does_not_mutate_product_output():
    record, wire = record_and_wire()
    original = deepcopy(record)
    assert wire_http_pair_record(record, wire, module="harbor") == (record, None)
    assert record == original
    assert [(v["username"], v["password"]) for v in wire["calls"]] == [PAIR, ("other", "invalid:opaque")]


@pytest.mark.parametrize(
    "fault", ["password", "verdict", "count", "product", "unavailable", "missing", "route", "order"]
)
def test_corrupted_observations_never_pass_as_verified(fault):
    record, wire = record_and_wire()
    if fault == "password":
        wire["calls"][0]["password"] = "other"
    elif fault == "verdict":
        wire["calls"][0]["status"] = 401
    elif fault == "count":
        wire["calls"].append(dict(wire["calls"][0]))
    elif fault == "product":
        record["is_harbor"] = False
    elif fault == "unavailable":
        record["credential_verification_status"] = "unavailable"
    elif fault == "missing":
        wire["complete"] = False
    elif fault == "route":
        wire["calls"][0]["path"] = "/api/v2.0/projects"
    elif fault == "order":
        wire["calls"].reverse()
    assert wire_http_pair_record(record, wire, module="harbor")[1]


@pytest.mark.parametrize("valid", [True, False])
def test_single_provided_pair_requires_explicit_received_identity(valid):
    record, wire = record_and_wire()
    row = record.pop("attempted_credentials")[0 if valid else 1]
    wire["calls"] = [wire["calls"][0 if valid else 1]]
    record.update(
        status=row["status"],
        provided_username=row["username"],
        provided_password=row["password"],
        provided_credentials_ok=valid,
        error=row["error"],
    )
    observed, error = wire_http_pair_record(record, wire, module="harbor")
    assert error is None and len(observed["attempted_credentials"]) == 1


def test_limited_inventory_keeps_verified_identity_and_explicit_two_surface_denial():
    record = {
        "is_harbor": True,
        "provided_credentials_ok": True,
        "show_images": True,
        "images": [],
        "harbor_projects": [],
        "harbor_repositories": [],
        "harbor_artifacts": [],
        "images_error": "authentication required",
        "harbor_error": "authentication required",
    }
    assert harbor_inventory_errors(record, limited=True) == []
    for field in ["images_error", "harbor_error", "provided_credentials_ok", "is_harbor"]:
        corrupt = {**record, field: None}
        assert harbor_inventory_errors(corrupt, limited=True)


def test_optional_auth_stage_field_is_not_invented_on_final_data_record():
    record, wire = record_and_wire()
    del record["credential_verification_status"]
    before = deepcopy(record)
    assert wire_http_pair_record(record, wire, module="harbor") == (record, None)
    assert record == before and "credential_verification_status" not in record
    del record["provided_credentials_ok"]
    assert wire_http_pair_record(record, wire, module="harbor")[1]


@pytest.mark.parametrize("role", ["positive", "foreign", "closed"])
def test_closed_peer_cannot_pass_the_new_transport_quality_gate(role):
    from scripts.performance_contracts import vendor_transport_errors

    record = {"status": "not_registry", "is_registry": False, "error": "requested harbor fingerprint not confirmed"}
    assert bool(vendor_transport_errors(record, role=role)) is (role == "closed")
    fixed = {**record, "status": "fail", "error": "connection refused"}
    assert not vendor_transport_errors(fixed, role=role)
    if role == "closed":
        assert vendor_transport_errors({**fixed, "is_registry": True}, role=role)
        assert vendor_transport_errors({**fixed, "error": None}, role=role)
        assert vendor_transport_errors({**fixed, "provided_credentials_ok": True}, role=role)
