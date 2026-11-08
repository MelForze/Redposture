"""A configured candidate never substitutes for a complete received signature."""

from copy import deepcopy

import pytest

from redposture_core.clients.s3_sigv4 import EMPTY_PAYLOAD_HASH, sign_request
from scripts.performance_contracts import S3WireLedger, credential_summary, wire_s3_record


def headers(user="reader", password="correct", host="qa.local:9000"):
    signed = sign_request(
        method="GET", host=host, path="/", payload_hash=EMPTY_PAYLOAD_HASH, access_key=user, secret_key=password
    )
    return {b"host": host.encode(), **{k.lower().encode(): v.encode() for k, v in signed.items()}}


def product():
    return {
        "service": "minio",
        "is_minio": True,
        "credential_state": "invalid",
        "provided_credentials_ok": False,
        "credential_results": [{"access_key": "reader", "state": "invalid"}],
    }


def receipt(user="reader", password="correct"):
    ledger = S3WireLedger()
    ledger.record(3, "GET", "/", headers(user, password), b"")
    return ledger.pop(3)


def test_single_identity_is_attributed_only_after_complete_independent_signature_proof():
    original = product()
    before = deepcopy(original)
    observed, error = wire_s3_record(original, receipt(), single_pair=("reader", "correct"))
    assert error is None and credential_summary(observed)["invalid"] == 1
    assert observed["attempted_credentials"][0]["password"] == "correct"
    assert original == before and "attempted_credentials" not in original


@pytest.mark.parametrize("wire", [None, {"complete": False, "calls": []}, {"complete": True, "calls": []}])
def test_missing_received_request_is_not_an_attempt_even_if_candidate_is_configured(wire):
    original = product()
    observed, error = wire_s3_record(original, wire, single_pair=("reader", "correct"))
    assert observed is original and error and credential_summary(observed)["attempts_observed"] == 0


@pytest.mark.parametrize("mutation", ["password", "username", "signature", "host", "path", "extra_key", "identity"])
def test_wrong_candidate_tampering_replay_or_changed_product_identity_cannot_pass(mutation):
    original = product()
    wire = receipt()
    pair = ("reader", "correct")
    if mutation == "password":
        pair = ("reader", "wrong")
    if mutation == "username":
        pair = ("another", "correct")
    if mutation == "identity":
        original["credential_results"][0]["access_key"] = "another"
    if mutation == "signature":
        wire["calls"][0]["headers"]["authorization"] += "0"
    if mutation == "host":
        wire["calls"][0]["headers"]["host"] = "another.local"
    if mutation == "path":
        wire["calls"][0]["path"] = "/another"
    if mutation == "extra_key":
        wire["calls"] += receipt("another", "correct")["calls"]
    observed, error = wire_s3_record(original, wire, single_pair=pair)
    assert observed is original and error and "attempted_credentials" not in observed


def test_default_ledger_every_pair_requires_its_own_signature_and_repeated_user_is_preserved():
    ledger = S3WireLedger()
    pairs = [("reader", "one"), ("reader", "two")]
    for u, p in pairs:
        ledger.record(3, "GET", "/", headers(u, p), b"")
    original = {
        "attempted_credentials": [{"username": u, "password": p, "credential_state": "invalid"} for u, p in pairs]
    }
    wire = ledger.pop(3)
    observed, error = wire_s3_record(original, wire)
    assert error is None and observed is original and credential_summary(observed)["attempts_observed"] == 2
    original["attempted_credentials"][1]["password"] = "wrong"
    assert wire_s3_record(original, wire)[1]


def test_inventory_root_reads_are_not_extra_credential_attempts_or_a_substitute_for_a_missing_pair():
    wire = receipt()
    wire["calls"] *= 3
    observed, error = wire_s3_record(product(), wire, single_pair=("reader", "correct"))
    assert error is None and credential_summary(observed)["attempts_observed"] == 1
    row = {
        "attempted_credentials": [
            {"username": "reader", "password": "correct", "credential_state": "invalid"},
            {"username": "reader", "password": "other", "credential_state": "invalid"},
        ]
    }
    assert wire_s3_record(row, wire)[1] == "S3 credential has no received signature proof"


@pytest.mark.parametrize("bounds", [dict(per_target_limit=1), dict(total_limit=1), dict(target_limit=1)])
def test_overflow_is_visible_and_never_treated_as_complete_proof(bounds):
    ledger = S3WireLedger(**bounds)
    ledger.record(1, "GET", "/", headers(), b"")
    ledger.record(2 if "per_target_limit" not in bounds else 1, "GET", "/", headers(), b"")
    assert ledger.pop(1)["complete"] is False and ledger.snapshot()["overflow"] == 1


def test_records_are_consumed_by_destination_and_close_keeps_pending_evidence_visible():
    ledger = S3WireLedger()
    ledger.record(1, "GET", "/", headers(), b"")
    ledger.record(2, "GET", "/", headers(), b"")
    assert len(ledger.pop(1)["calls"]) == 1 and ledger.pop(1)["calls"] == []
    ledger.close()
    assert ledger.snapshot()["pending_calls"] == ledger.snapshot()["pending_targets"] == 1
    with pytest.raises(RuntimeError):
        ledger.pop(2)
    with pytest.raises(RuntimeError):
        ledger.record(3, "GET", "/", headers(), b"")


@pytest.mark.parametrize("bad", [None, [], {"username": [], "password": "wrong"}])
def test_malformed_default_ledger_does_not_crash_or_become_verified(bad):
    row = {"attempted_credentials": [bad]}
    assert wire_s3_record(row, receipt())[1]


def test_sigv4_route_stats_do_not_grow_with_host_bound_signatures():
    from scripts.performance_contracts import HttpRouteStats

    stats = HttpRouteStats(limit=4)
    for index in range(100):
        for user in ("reader", "writer"):
            stats.record("GET", "/", headers(user, "correct", f"127.32.0.{index + 1}:9000"), b"")
    snapshot = stats.snapshot()
    assert snapshot["complete"] is True and snapshot["overflow_requests"] == 0
    assert len(snapshot["routes"]) == 2
    assert all(row["auth_mode"] == "s3_claimed_access_key" and row["requests"] == 100 for row in snapshot["routes"])


def test_sigv4_route_grouping_is_explicitly_not_secret_or_signature_verification():
    from scripts.performance_contracts import HttpRouteStats

    stats = HttpRouteStats()
    for secret in ("correct", "wrong"):
        stats.record("GET", "/", headers("reader", secret), b"")
    snapshot = stats.snapshot()
    assert len(snapshot["routes"]) == 1 and snapshot["routes"][0]["requests"] == 2
    assert snapshot["routes"][0]["auth_mode"] == "s3_claimed_access_key"
    assert wire_s3_record(product(), receipt(password="wrong"), single_pair=("reader", "correct"))[1]
