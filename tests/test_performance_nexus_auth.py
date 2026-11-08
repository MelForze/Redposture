"""Nexus Basic identity, restricted differential proof and cursor fixtures."""

from __future__ import annotations

import base64
import json
from copy import deepcopy
from types import SimpleNamespace

import pytest

from redposture_core.modules.registry import actions
from scripts.performance_contracts import HttpPairWireLedger, nexus_inventory_errors, wire_http_pair_record
from scripts.performance_http_fixtures import nexus_reply

PAIR = ("qa-reader", " opaque:password ")
ORIGIN = "http://qa.invalid:8081"


def call(path, *, pair=PAIR, limited=False, method="GET", body=b""):
    headers = {} if pair is None else {b"authorization": b"Basic " + base64.b64encode(":".join(pair).encode())}
    raw = nexus_reply(method, path, headers, body, valid_pair=PAIR, limited=limited, origin=ORIGIN)
    head, data = raw.split(b"\r\n\r\n", 1)
    return int(head.split(b" ", 2)[1]), json.loads(data), head


@pytest.mark.parametrize("pair", [None, (PAIR[0], "wrong"), ("other", PAIR[1])])
def test_no_identity_or_inventory_for_missing_or_incorrect_pair(pair):
    for path in [
        "/service/rest/v1/status",
        "/service/rest/v1/security/users",
        "/service/rest/v1/repositories",
        "/service/rest/v1/components?repository=billing-images",
    ]:
        assert call(path, pair=pair)[0] == 401
    assert call("/v2/", pair=pair)[0] == 404


@pytest.mark.parametrize("limited", [False, True])
def test_metadata_and_identity_privileges_are_independent(limited):
    assert call("/service/rest/v1/status", limited=limited)[0] == 200
    assert call("/service/rest/v1/security/users", limited=limited)[0] == (403 if limited else 200)
    assert call("/service/rest/v1/repositories", limited=limited)[0] == (403 if limited else 200)


def test_cursor_retains_all_components_and_exact_assets():
    first = call("/service/rest/v1/components?repository=billing-images")[1]
    second = call(
        "/service/rest/v1/components?repository=billing-images&continuationToken=" + first["continuationToken"]
    )[1]
    assert len(first["items"]) == 2 and len(second["items"]) == 1 and second["continuationToken"] is None
    assert [r["version"] for r in first["items"] + second["items"]] == ["2026.11", "stable", "rollback"]
    assert (
        first["items"][0]["assets"][0]["downloadUrl"]
        == ORIGIN + "/repository/billing-images/billing/worker/2026.11/manifest.json"
    )
    assert call("/service/rest/v1/components?repository=billing-images&continuationToken=bad")[0] == 400
    assert call("/service/rest/v1/components?repository=not-there")[0] == 404


@pytest.mark.parametrize("method", ["POST", "PUT", "DELETE"])
def test_script_and_writes_never_claim_success(method):
    assert call("/service/rest/v1/script", method=method)[0] == 405


def test_missing_api_and_connector_do_not_receive_generic_product_success():
    for path in ["/v2/", "/api/v2.0/systeminfo", "/api/systeminfo", "/service/rest/v1/not-real", "/jwt/auth", "/"]:
        assert call(path)[0] == 404


@pytest.fixture
def verified_pair_wire(monkeypatch):
    previous = getattr(actions._THREAD_LOCAL_HTTP, "state", None)

    def run(*, limited=False, pair=PAIR):
        ledger = HttpPairWireLedger()

        def request(_host, _port, method, path, _timeout, *, headers=None):
            fields = {k.lower().encode(): v.encode() for k, v in (headers or {}).items()}
            raw = nexus_reply(method, path, fields, b"", valid_pair=PAIR, limited=limited, origin=ORIGIN)
            head, body = raw.split(b"\r\n\r\n", 1)
            status = int(head.split(b" ", 2)[1])
            response_headers = {
                k.decode().lower(): v.decode().strip()
                for line in head.split(b"\r\n")[1:]
                for k, _, v in [line.partition(b":")]
            }
            ledger.record(0, "nexus", method, path, fields, b"", status)
            return status, body, response_headers, None

        monkeypatch.setattr(actions, "_http_request", request)
        ctx = SimpleNamespace(
            host="qa.invalid",
            port=8081,
            args=SimpleNamespace(timeout=1, retries=0),
            lifecycle_state=actions.RegistryLifecycleState(anonymous_probe=(404, b"", {}, None)),
            credential=SimpleNamespace(username=pair[0], password=pair[1], token=None, source="provided"),
        )
        result = actions.authenticate_registry(
            ctx,
            {"is_nexus": True, "is_registry": True, "status": "auth_required", "auth_required": True},
            {"product": "nexus"},
        )
        return result, ledger.pop(0)

    yield run
    actions._THREAD_LOCAL_HTTP.state = previous


@pytest.mark.parametrize("limited", [False, True])
def test_real_product_verifier_uses_exact_pair_and_control_instead_of_accepting_403(verified_pair_wire, limited):
    record, wire = verified_pair_wire(limited=limited)
    original = deepcopy(record)
    assert record["provided_credentials_ok"] is True
    observed, error = wire_http_pair_record(record, wire, module="nexus")
    assert error is None and record == original
    assert observed["attempted_credentials"][0]["password"] == PAIR[1]
    identities = [r for r in wire["calls"] if r["path"].endswith("/security/users")]
    assert len(identities) == 1 and identities[0]["status"] == (403 if limited else 200)
    assert (identities[0]["username"], identities[0]["password"]) == PAIR
    if limited:
        controls = [r for r in wire["calls"] if r["password"] != PAIR[1]]
        assert len(controls) == 1 and controls[0]["username"] == PAIR[0] and controls[0]["status"] == 401
        assert controls[0]["password"].startswith("rp-verification-")


def test_real_product_wrong_pair_stays_rejected(verified_pair_wire):
    record, wire = verified_pair_wire(pair=(PAIR[0], "wrong"))
    assert record["provided_credentials_ok"] is False
    assert len(wire["calls"]) == 1 and wire["calls"][0]["status"] == 401
    assert wire_http_pair_record(record, wire, module="nexus")[1] is None


@pytest.mark.parametrize(
    "fault",
    [
        "control-status",
        "missing-control",
        "other-user",
        "control-password",
        "missing-positive",
        "missing-metadata",
        "extra",
        "method",
        "path",
        "provided",
        "product",
        "pair",
        "verdict",
    ],
)
def test_incomplete_or_corrupted_differential_never_becomes_verified(verified_pair_wire, fault):
    record, wire = verified_pair_wire(limited=True)
    control = next(r for r in wire["calls"] if r["password"] != PAIR[1])
    if fault == "control-status":
        control["status"] = 200
    elif fault == "missing-control":
        wire["calls"].remove(control)
    elif fault == "other-user":
        control["username"] = "other"
    elif fault == "control-password":
        control["password"] = "opaque-unrelated-control"
    elif fault == "missing-positive":
        wire["calls"].pop(1)
    elif fault == "missing-metadata":
        wire["calls"].pop()
    elif fault == "extra":
        wire["calls"].append(dict(control))
    elif fault == "method":
        control["method"] = "POST"
    elif fault == "path":
        control["path"] = "/service/rest/v1/repositories"
    elif fault == "provided":
        record["provided_credentials_ok"] = None
    elif fault == "product":
        record["is_nexus"] = False
    elif fault == "pair":
        wire["calls"][0]["password"] = "different"
    elif fault == "verdict":
        record["provided_credentials_ok"] = False
        record["status"] = "auth_required"
        record["error"] = "authentication rejected"
    assert wire_http_pair_record(record, wire, module="nexus")[1]


def test_limited_inventory_needs_both_identity_and_explicit_access_error():
    record = {
        "is_nexus": True,
        "provided_credentials_ok": True,
        "show_repositories": True,
        "nexus_error": "authentication required",
        "nexus_repository_details": [],
        "nexus_repositories": [],
    }
    assert not nexus_inventory_errors(record, limited=True)
    for field in ["nexus_error", "provided_credentials_ok", "is_nexus"]:
        assert nexus_inventory_errors({**record, field: None}, limited=True)


def inventory_record():
    record = {
        "host": "qa.invalid",
        "port": 8081,
        "is_nexus": True,
        "provided_credentials_ok": True,
        "show_repositories": True,
        "nexus_error": None,
        "images_error": None,
    }
    details = [
        {"name": "billing-images", "format": "docker", "type": "hosted", "online": True},
        {"name": "platform-maven", "format": "maven2", "type": "hosted", "online": True},
        {"name": "release-assets", "format": "raw", "type": "hosted", "online": True},
    ]
    for row in details:
        row.update(url=ORIGIN + "/repository/" + row["name"], components=None)
    record["nexus_repository_details"] = details
    record["nexus_repositories"] = [f"{r['name']} (format={r['format']}, type=hosted, url={r['url']})" for r in details]
    return record


def test_repository_matcher_checks_full_metadata_and_displayed_values():
    record = inventory_record()
    assert not nexus_inventory_errors(record, limited=False)
    for field, value in [("online", False), ("format", "raw"), ("url", "http://other"), ("components", 0)]:
        corrupt = deepcopy(record)
        corrupt["nexus_repository_details"][0][field] = value
        assert nexus_inventory_errors(corrupt, limited=False)


@pytest.mark.parametrize("details", [None, [], [None] * 3, [{}] * 3, [{"name": "other"}] * 3])
def test_malformed_repository_result_is_a_failed_gate_instead_of_a_crash(details):
    assert nexus_inventory_errors({**inventory_record(), "nexus_repository_details": details}, limited=False)


def probe_body(index=0, command=None):
    from redposture_core.modules.nexus.execution import _script

    return json.dumps(
        {
            "name": "redposture-exec-" + f"{index:020x}",
            "type": "groovy",
            "content": _script(
                command or "echo REDPOSTURE_RCE_" + f"{index:024x}", "RP_NEXUS_" + f"{index:024x}" + ":", 5, 1048576
            ),
        }
    ).encode()


def test_nonce_grouping_stays_bounded_with_actual_body_proof_for_every_target():
    import hashlib

    from scripts.performance_contracts import HttpRouteStats, nexus_probe_body_error

    stats = HttpRouteStats(limit=4)
    ledger = HttpPairWireLedger()
    headers = {b"authorization": b"Basic " + base64.b64encode(":".join(PAIR).encode())}
    digests = set()
    for index in range(1000):
        body = probe_body(index)
        stats.record("POST", "/service/rest/v1/script", headers, body, body_group="nexus-script-endpoint")
        ledger.record(index, "nexus", "POST", "/service/rest/v1/script", headers, body, 405)
        wire = ledger.pop(index)
        assert wire["complete"] and len(wire["calls"]) == 1
        call = wire["calls"][0]
        assert call["kind"] == "nexus_probe" and call["body"].encode() == body
        assert call["body_sha256"] == hashlib.sha256(body).hexdigest()
        assert not nexus_probe_body_error(call["body"], call["body_sha256"])
        digests.add(call["body_sha256"])
        assert ledger.pending_body_bytes == 0
    observed = stats.snapshot()
    assert observed["complete"] and len(observed["routes"]) == 1 and observed["overflow_requests"] == 0
    assert observed["routes"][0]["requests"] == len(digests) == 1000
    assert observed["routes"][0]["auth_mode"] == "nexus_script_endpoint_claim"
    other = {b"authorization": b"Basic " + base64.b64encode(b"other-user:other-password")}
    stats.record("POST", "/service/rest/v1/script", other, probe_body(), body_group="nexus-script-endpoint")
    assert len(stats.snapshot()["routes"]) == 2


def test_default_body_statistics_do_not_silently_collapse_non_probe_requests():
    from scripts.performance_contracts import HttpRouteStats

    stats = HttpRouteStats(limit=2)
    for index in range(3):
        stats.record("POST", "/ordinary", {}, probe_body(index))
    assert not stats.snapshot()["complete"] and stats.snapshot()["overflow_requests"] == 1


def test_probe_receipts_obey_byte_capacity_and_release_memory_on_consume_and_close():
    body = probe_body()
    ledger = HttpPairWireLedger(body_limit=len(body))
    headers = {b"authorization": b"Basic " + base64.b64encode(b"reader:password")}
    ledger.record(1, "nexus", "POST", "/service/rest/v1/script", headers, body, 405)
    assert ledger.pending_body_bytes == len(body)
    ledger.record(2, "nexus", "POST", "/service/rest/v1/script", headers, body, 405)
    assert ledger.snapshot()["overflow"] == 1 and ledger.pending_body_bytes == len(body)
    assert not ledger.pop(1)["complete"] and ledger.pending_body_bytes == 0
    ledger.record(3, "nexus", "POST", "/service/rest/v1/script", headers, body, 405)
    ledger.close()
    assert ledger.pending_body_bytes == 0
    with pytest.raises(ValueError):
        HttpPairWireLedger(body_limit=0)


@pytest.mark.parametrize("fault", ["missing", "sha", "command", "name", "type", "marker", "unicode"])
def test_corrupt_or_unexpected_probe_body_cannot_pass_as_the_automatic_echo(fault):
    import hashlib

    from scripts.performance_contracts import nexus_probe_body_error

    body = probe_body().decode()
    digest = hashlib.sha256(body.encode()).hexdigest()
    if fault == "missing":
        body = None
    elif fault == "sha":
        digest = "a" * 64
    elif fault == "command":
        body = probe_body(command="id").decode()
    elif fault == "name":
        body = body.replace("redposture-exec-", "other-script-")
    elif fault == "type":
        body = body.replace('"groovy"', '"other"')
    elif fault == "marker":
        body = body.replace("RP_NEXUS_", "OTHER_")
    elif fault == "unicode":
        body = "not json: é"
    if fault not in {"missing", "sha"}:
        digest = hashlib.sha256(body.encode()).hexdigest()
    assert nexus_probe_body_error(body, digest)
