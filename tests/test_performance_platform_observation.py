"""Root verifier booleans need wire identity, not a guessed CLI token."""

from __future__ import annotations

import pytest

from scripts.performance_contracts import (
    credential_digest,
    credential_summary,
    credential_verdict_errors,
    identity_digest,
    wire_token_record,
)


def root(module, valid):
    common = {"module": module, "status": "valid_credentials" if valid else "auth_required"}
    if module == "consul":
        return {**common, "auth_mode": "token", "auth_valid": valid, "auth_identity": {"ok": valid}}
    if module == "kubeapi":
        return {
            **common,
            "status": "auth_valid" if valid else "auth_failed",
            "auth_mode": "token",
            "auth_valid": valid,
            "auth_verification_method": "self_subject_review",
        }
    if module == "gitlab":
        return {
            **common,
            "status": "valid_credentials" if valid else "invalid_credentials",
            "token_provided": True,
            "token_valid": valid,
        }
    return {
        **common,
        "status": "open_auth" if valid else "auth_required",
        "api_key_provided": True,
        "api_key_access": valid,
        "provided_credentials_ok": valid,
        "credential_state": "valid" if valid else "invalid",
    }


@pytest.mark.parametrize("module", ["consul", "kubeapi", "qdrant", "gitlab"])
@pytest.mark.parametrize("valid", [False, True])
def test_actual_token_verdict_is_normalized_without_changing_product_record(module, valid):
    record = root(module, valid)
    original = dict(record)
    observed = wire_token_record(record, module=module, received_token="wire-token", source="provided")
    assert record == original and "attempted_credentials" not in record
    assert credential_digest(observed) == identity_digest([(None, None, "wire-token")])
    summary = credential_summary(observed)
    assert summary["attempts_observed"] == 1 and summary["accepted_claims"] == int(valid)
    assert summary["invalid"] == int(not valid) and summary["unverified"] == 0
    assert (
        credential_verdict_errors(observed, accepted_identities={(None, None, "wire-token")} if valid else set()) == []
    )
    if valid:
        assert credential_verdict_errors(observed, accepted_identities={(None, None, "different-token")})


@pytest.mark.parametrize("module", ["consul", "kubeapi", "qdrant", "gitlab"])
def test_no_wire_token_or_no_typed_verifier_does_not_fabricate_an_attempt(module):
    record = root(module, True)
    assert wire_token_record(record, module=module, received_token=None, source="provided") is record
    for field in ("auth_valid", "provided_credentials_ok", "token_valid"):
        if field in record:
            record[field] = None
    assert wire_token_record(record, module=module, received_token="wire-token", source="provided") is record


@pytest.mark.parametrize("module", ["consul", "kubeapi", "qdrant", "gitlab"])
def test_wire_adapter_does_not_replace_an_existing_different_ledger(module):
    record = {
        **root(module, True),
        "attempted_credentials": [{"token": "other", "ok": False, "credential_state": "invalid"}],
    }
    assert wire_token_record(record, module=module, received_token="wire-token", source="provided") is record


@pytest.mark.parametrize("module", ["consul", "kubeapi", "qdrant", "gitlab"])
def test_inconsistent_verifier_or_status_does_not_get_rewritten_as_a_pass(module):
    record = {**root(module, True), "status": "auth_failed"}
    assert wire_token_record(record, module=module, received_token="wire-token", source="provided") is record
    if module == "qdrant":
        record = {**root(module, True), "credential_state": "invalid"}
        assert wire_token_record(record, module=module, received_token="wire-token", source="provided") is record
