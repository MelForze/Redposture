"""Known-inconclusive digest controls still require exact full wire/client proof."""

from __future__ import annotations

from copy import deepcopy

import pytest

from scripts import performance_contracts as contracts


def record(module="zookeeper"):
    return {
        "service": module,
        "is_" + module: True,
        "auth_required": True,
        "credential_verification_status": "available",
        "credential_verification_path": "/",
        "anonymous_auth_probe_results": {"/": "noauth"},
        "attempted_credentials": [
            {
                "username": "admin",
                "password": "wrong",
                "status": "auth_required",
                "provided_credentials_ok": None,
                "credential_verdict": "unverified",
                "credential_auth_probe_results": {"/": "noauth"},
                "source": "default",
            }
        ],
    }


def wire():
    return {
        "complete": True,
        "calls": [
            {"kind": "read", "username": None, "password": None, "path": "/", "error": -102},
            {"kind": "digest_ack", "username": "admin", "password": "wrong", "path": None, "error": 0},
            {"kind": "read", "username": "admin", "password": "wrong", "path": "/", "error": -102},
        ],
    }


@pytest.mark.parametrize("module", ["zookeeper", "keeper"])
def test_inconclusive_digest_control_requires_matching_complete_wire_and_client_probe(module):
    verify = getattr(contracts, "wire_coordination_record", None)
    assert callable(verify), "missing distinct inconclusive digest wire contract"
    own = record(module)
    original = deepcopy(own)
    observed, error = verify(own, wire(), module=module)
    assert error is None and own == original and observed == own
    summary = contracts.credential_summary(observed)
    assert summary["attempts_observed"] == summary["unverified"] == 1
    assert summary["accepted_claims"] == summary["invalid"] == 0


@pytest.mark.parametrize(
    "fault",
    [
        "wrong_pair",
        "missing_ack",
        "duplicate_ack",
        "missing_read",
        "unavailable",
        "malformed",
        "access",
        "rejected",
        "no_client_probe",
        "no_anonymous_proof",
        "no_service",
        "no_verifier",
        "missing_anonymous_read",
        "missing_own_boolean",
        "malformed_anonymous_identity",
        "contradictory_status",
    ],
)
def test_unknown_is_never_a_wildcard_for_missing_or_contradictory_evidence(fault):
    verify = getattr(contracts, "wire_coordination_record", None)
    assert callable(verify), "missing distinct inconclusive digest wire contract"
    own, received = record(), wire()
    if fault == "wrong_pair":
        received["calls"][1]["password"] = "other"
    elif fault == "missing_ack":
        received["calls"].pop(1)
    elif fault == "duplicate_ack":
        received["calls"].append(dict(received["calls"][1]))
    elif fault == "missing_read":
        received["calls"].pop()
    elif fault == "unavailable":
        received["complete"] = False
    elif fault == "malformed":
        received["calls"] = ["not evidence"]
    elif fault == "access":
        received["calls"][2]["error"] = 0
    elif fault == "rejected":
        own["attempted_credentials"][0]["provided_credentials_ok"] = False
    elif fault == "no_client_probe":
        own["attempted_credentials"][0]["credential_auth_probe_results"] = {}
    elif fault == "no_anonymous_proof":
        own["anonymous_auth_probe_results"] = {}
    elif fault == "no_service":
        own["is_zookeeper"] = False
    elif fault == "no_verifier":
        own["credential_verification_status"] = "unavailable"
    elif fault == "missing_anonymous_read":
        received["calls"].pop(0)
    elif fault == "missing_own_boolean":
        own["attempted_credentials"][0].pop("provided_credentials_ok")
    elif fault == "malformed_anonymous_identity":
        received["calls"][0].pop("username")
    else:
        own["attempted_credentials"][0]["status"] = "valid_credentials"
    assert verify(own, received, module="zookeeper")[1]


def test_single_result_uses_its_own_full_identity_never_cli_guesses():
    verify = getattr(contracts, "wire_coordination_record", None)
    assert callable(verify)
    own = record()
    attempt = own.pop("attempted_credentials")[0]
    own.update({k: v for k, v in attempt.items() if k not in {"username", "password", "source"}})
    own.update(provided_credentials=True, provided_username="admin", provided_password="wrong")
    observed, error = verify(own, wire(), module="zookeeper")
    assert error is None and "attempted_credentials" not in own
    assert observed["attempted_credentials"][0]["password"] == "wrong"
    own["provided_password"] = "another"
    assert verify(own, wire(), module="zookeeper")[1]


def test_bounded_wire_ledger_retains_actual_values_and_consumes_by_target():
    cls = getattr(contracts, "CoordinationWireLedger", None)
    assert callable(cls), "missing bounded native digest receipt ledger"
    ledger = cls(per_target_limit=2)
    ledger.record(7, "digest_ack", "admin", "wrong", None, 0)
    ledger.record(7, "read", "admin", "wrong", "/", -102)
    assert ledger.pop(7) == {"complete": True, "calls": wire()["calls"][1:]}
    assert ledger.snapshot()["recorded_calls"] == 2 and not ledger.snapshot()["pending_calls"]
    for _ in range(3):
        ledger.record(8, "read", None, None, "/", -102)
    assert not ledger.pop(8)["complete"] and ledger.snapshot()["overflow"] == 1
    ledger.close()
    with pytest.raises(RuntimeError):
        ledger.pop(0)


@pytest.mark.parametrize("module", ["zookeeper", "keeper"])
@pytest.mark.parametrize("mode", ["credentials", "defcreds"])
def test_explicit_digest_profile_is_distinct_from_the_default_invalid_model(monkeypatch, tmp_path, module, mode):
    import sys

    from scripts import profile_module_performance as profile

    seen = []

    def measure(args):
        seen.append((args.module, args.mode, args.auth_surface, args.auth_case))
        return {"module": module, "mode": mode, "model": "mixed", "quality": "PASS", "wall_seconds": 0}

    monkeypatch.setattr(profile, "measure", measure)
    monkeypatch.setattr(profile, "save_instrument_snapshot", lambda _: None)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "profile",
            "--module",
            module,
            "--mode",
            mode,
            "--auth-surface",
            "digest-acl",
            "--output",
            str(tmp_path / "profile.json"),
        ],
    )
    assert profile.main() == 0 and seen == [(module, mode, "digest-acl", "invalid")]


@pytest.mark.parametrize(
    "module,mode,auth_case",
    [
        ("grafana", "credentials", "invalid"),
        ("zookeeper", "detect", "invalid"),
        ("keeper", "actions", "invalid"),
        ("zookeeper", "credentials", "valid"),
    ],
)
def test_digest_profile_cannot_silently_change_another_module_or_auth_model(
    monkeypatch, tmp_path, module, mode, auth_case
):
    import sys

    from scripts import profile_module_performance as profile

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "profile",
            "--module",
            module,
            "--mode",
            mode,
            "--auth-case",
            auth_case,
            "--auth-surface",
            "digest-acl",
            "--output",
            str(tmp_path / "profile.json"),
        ],
    )
    with pytest.raises(SystemExit) as error:
        profile.main()
    assert error.value.code == 2 and not (tmp_path / "profile.json").exists()
