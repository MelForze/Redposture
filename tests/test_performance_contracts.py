"""A green timing sample needs real, complete quality observations."""

from __future__ import annotations

import pytest

from scripts.performance_contracts import (
    HttpRouteStats,
    accepted_claim,
    compare_profiles,
    credential_digest,
    credential_summary,
    credential_verdict_errors,
    grafana_inventory_errors,
    identity_digest,
    matching_case,
    wire_token_record,
)


def test_root_token_observation_uses_received_identity_and_does_not_change_output():
    original = {
        "service": "vault",
        "token_valid": False,
        "provided_credentials_ok": False,
        "credential_state": "invalid",
        "auth_http_status": 403,
    }
    observed = wire_token_record(original, received_token="wire-token", source="provided")
    assert "attempted_credentials" not in original
    assert credential_digest(observed) == identity_digest([(None, None, "wire-token")])
    assert credential_summary(observed)["invalid"] == 1
    assert credential_verdict_errors(observed, accepted_identities=set()) == []


@pytest.mark.parametrize("missing", ["credential_state", "token_valid", "auth_http_status"])
def test_token_on_a_public_route_does_not_invent_a_verifier_result(missing):
    record = {"token_valid": True, "credential_state": "valid", "auth_http_status": 200}
    del record[missing]
    assert (
        credential_summary(wire_token_record(record, received_token="wire-token", source="provided"))[
            "attempts_observed"
        ]
        == 0
    )


def test_ambiguous_wire_identity_or_unknown_verdict_cannot_turn_green():
    row = {"token_valid": None, "credential_state": "unverified", "auth_http_status": 503}
    assert credential_summary(wire_token_record(row, received_token=None, source="provided"))["attempts_observed"] == 0
    observed = wire_token_record(row, received_token="wire-token", source="provided")
    assert credential_summary(observed)["unverified"] == 1
    assert credential_verdict_errors(observed, accepted_identities=set())
    valid = {"token_valid": True, "credential_state": "valid", "auth_http_status": 200}
    observed = wire_token_record(valid, received_token="unexpected-token", source="provided")
    assert credential_verdict_errors(observed, accepted_identities={(None, None, "configured-token")})


def test_wire_identity_never_overwrites_an_existing_credential_ledger():
    record = {
        "token_valid": True,
        "credential_state": "valid",
        "auth_http_status": 200,
        "attempted_credentials": [{"username": "other", "password": "wrong", "status": "valid_credentials"}],
    }
    assert wire_token_record(record, received_token="wire-token", source="provided") is record


@pytest.mark.parametrize("state", ["unknown", "unverified", "verification_unavailable", "skipped", "cancelled"])
def test_seeded_wrong_password_requires_a_real_rejection_not_merely_an_attempt(state):
    row = {"username": "u", "password": "bad", "credential_state": state}
    assert credential_verdict_errors({"attempted_credentials": [row]}, accepted_identities=set())


def test_seeded_valid_pair_cannot_hide_a_false_acceptance_of_another_password():
    rows = [
        {"username": "u", "password": "good", "credential_state": "invalid"},
        {"username": "u", "password": "bad", "credential_state": "valid"},
    ]
    assert credential_summary({"credentials": rows})["accepted_claims"] == 1
    assert credential_verdict_errors({"credentials": rows}, accepted_identities={("u", "good", None)})
    rows[0]["credential_state"] = "valid"
    rows[1]["credential_state"] = "invalid"
    assert credential_verdict_errors({"credentials": rows}, accepted_identities={("u", "good", None)}) == []


def test_seeded_verdict_checks_each_alias_for_conflicting_acceptance():
    row = {"username": "u", "password": "bad", "credential_state": "invalid"}
    record = {"attempted_credentials": [row], "credential_attempts": [dict(row, ok=True)]}
    assert credential_verdict_errors(record, accepted_identities=set())


def test_seeded_verdict_requires_observed_rows_and_checks_full_identity():
    assert credential_verdict_errors({"status": "auth_required"}, accepted_identities=set())
    row = {"username": "u", "password": "good", "token": "another", "credential_state": "valid"}
    assert credential_verdict_errors({"credentials": [row]}, accepted_identities={("u", "good", None)})


@pytest.mark.parametrize("available", ["available", "unavailable", None])
def test_explicit_registry_verifier_availability_separates_rejection_from_transport(available):
    row = {
        "username": "u",
        "password": "bad",
        "status": "auth_required",
        "provided_credentials_ok": False,
        "credential_verification_status": available,
    }
    errors = credential_verdict_errors({"credentials": [row]}, accepted_identities=set())
    assert bool(errors) is (available != "available")


@pytest.mark.parametrize(
    "status", ["auth_required", "auth_failed", "transport_error", "error", None, "vendor_specific"]
)
def test_every_unclassified_observed_attempt_is_counted_as_unverified(status):
    record = {
        "credential_attempts": [
            {"username": "u", "password": "p", "ok": False, "status": status, "error": "verifier unavailable"}
        ]
    }
    summary = credential_summary(record)
    assert summary["attempts_observed"] == summary["unverified"] == 1
    assert summary["accepted_claims"] == summary["invalid"] == summary["skipped"] == 0
    assert credential_verdict_errors(record, accepted_identities=set())


@pytest.mark.parametrize(
    "row",
    [
        {"status": "auth_required", "error": "authentication rejected"},
        {"status": "invalid_credentials_anonymous", "auth_probe_status": "rejected", "auth_probe_http_status": 401},
    ],
)
def test_explicit_rejection_schemas_are_not_called_unverified(row):
    assert credential_verdict_errors({"credentials": [row]}, accepted_identities=set()) == []


@pytest.mark.parametrize("field", ["attempted_credentials", "credential_attempts", "credentials"])
def test_every_supported_ledger_alias_is_checked(field):
    record = {field: [{"username": "wrong", "password": "wrong", "ok": True}]}
    assert credential_summary(record)["accepted_claims"] == 1


@pytest.mark.parametrize("field", ["token_valid", "provided_credentials_ok", "credential_verified", "login_success"])
def test_root_positive_proof_cannot_hide_behind_an_empty_ledger(field):
    assert credential_summary({"attempted_credentials": [], field: True})["accepted_claims"] == 1


def test_overlapping_aliases_do_not_double_attempts_but_each_can_expose_false_acceptance():
    wrong = {"username": "wrong", "password": "wrong", "credential_state": "invalid"}
    record = {"attempted_credentials": [wrong], "credential_attempts": [dict(wrong, ok=True)]}
    assert credential_summary(record) == {
        "attempts_observed": 1,
        "accepted_claims": 1,
        "duplicate_attempts": 0,
        "invalid": 1,
        "unverified": 0,
        "skipped": 0,
        "malformed_attempts": 0,
    }


@pytest.mark.parametrize("legacy", [None, [], 3, "legacy"])
def test_empty_or_invalid_legacy_alias_does_not_hide_typed_attempts(legacy):
    record = {"attempted_credentials": legacy, "credential_attempts": [{"status": "verification_unavailable"}]}
    assert credential_summary(record)["attempts_observed"] == 1
    assert credential_summary(record)["unverified"] == 1


def test_same_login_with_different_passwords_is_not_duplicate():
    first = {"username": "u", "password": "one", "source": "default", "ok": False}
    second = dict(first, password="two")
    assert credential_summary({"credentials": [first, second]})["duplicate_attempts"] == 0
    assert credential_summary({"credentials": [first, first]})["duplicate_attempts"] == 1


def test_missing_attempts_is_not_a_performed_credential_check():
    summary = credential_summary({"status": "auth_required"})
    assert summary["attempts_observed"] == 0
    assert summary["accepted_claims"] == 0


@pytest.mark.parametrize("state,proof,status", [("valid", True, 200), ("invalid", False, 401), ("unknown", None, 503)])
def test_jenkins_single_pair_root_is_an_observed_identity_not_a_bare_flag(state, proof, status):
    record = {
        "service": "jenkins",
        "credential_results": [{"username": "profile-user"}],
        "credential_password": "profile-password",
        "credential_source": "provided",
        "credential_state": state,
        "provided_credentials_ok": proof,
        "auth_http_status": status,
    }
    assert credential_summary(record)["attempts_observed"] == 1
    assert credential_digest(record) == identity_digest([("profile-user", "profile-password", None)])
    assert credential_summary(record)["unverified"] == int(state == "unknown")
    for field in ("credential_state", "auth_http_status", "credential_password", "credential_results"):
        incomplete = dict(record)
        del incomplete[field]
        assert credential_summary(incomplete)["attempts_observed"] == 0


def test_jenkins_root_does_not_replace_the_full_defcreds_ledger():
    first = {"username": "admin", "password": "wrong", "credential_state": "invalid"}
    second = {"username": "dev", "password": "pass", "credential_state": "valid"}
    record = {
        "service": "jenkins",
        "credential_results": [{"username": "dev"}],
        "credential_password": "pass",
        "credential_source": "provided",
        "credential_state": "valid",
        "auth_http_status": 200,
        "attempted_credentials": [first, second],
    }
    assert credential_summary(record)["attempts_observed"] == 2
    assert credential_digest(record) == identity_digest([("admin", "wrong", None), ("dev", "pass", None)])


def test_fixture_routes_separate_auth_identities_and_do_not_drop_overflow():
    stats = HttpRouteStats(limit=2)
    stats.record("GET", "/api/user", {}, b"")
    stats.record("GET", "/api/user", {b"authorization": b"Basic one"}, b"")
    stats.record("GET", "/api/user", {}, b"")
    stats.record("GET", "/api/user", {b"authorization": b"Basic two"}, b"")
    snapshot = stats.snapshot()
    assert len(snapshot["routes"]) == 2
    assert sorted(row["requests"] for row in snapshot["routes"]) == [1, 2]
    assert snapshot["overflow_requests"] == 1 and snapshot["complete"] is False
    assert "Basic one" not in str(snapshot)


def test_route_display_is_bounded_but_hash_separates_different_long_paths():
    stats = HttpRouteStats()
    for suffix in ("one", "two"):
        stats.record("POST", "/" + "a" * 10000 + suffix, {}, suffix.encode())
    routes = stats.snapshot()["routes"]
    assert len(routes) == 2
    assert all(len(row["route"]) == 512 and row["display_truncated"] for row in routes)
    assert len({row["route_identity_sha256"] for row in routes}) == 2


def test_public_anonymous_read_does_not_verify_supplied_credentials():
    assert not accepted_claim({"status": "open_no_auth", "auth_required": False})


def test_conflicting_positive_proof_remains_visible_to_the_quality_gate():
    assert accepted_claim({"status": "verification_unavailable", "ok": True})


def auth_sample(seconds, source="before", **changes):
    return sample(
        seconds,
        source,
        mode="defcreds",
        credential_expected_sha256="a" * 64,
        credential_expectation_per_positive=23,
        credential_identity_digests={"a" * 64: 40},
        credential_count_histogram={"23": 40},
        **changes,
    )


def test_timing_comparison_rejects_a_changed_credential_catalogue_even_when_both_sources_claim_pass():
    before = [auth_sample(10)] * 3
    after = [auth_sample(1, "after") for _ in range(3)]
    for row in after:
        row["credential_expected_sha256"] = "b" * 64
        row["credential_identity_digests"] = {"b" * 64: 40}
    with pytest.raises(ValueError, match="settings"):
        compare_profiles(before, after)


@pytest.mark.parametrize(
    "field",
    [
        "credential_expected_sha256",
        "credential_identity_digests",
        "credential_expectation_per_positive",
        "credential_count_histogram",
    ],
)
def test_auth_timing_without_retained_catalogue_evidence_cannot_pass(field):
    before = [auth_sample(10)] * 3
    after = [auth_sample(1, "after") for _ in range(3)]
    for row in after:
        del row[field]
    try:
        result = compare_profiles(before, after)
    except ValueError:
        return
    assert result["gate"] == "FAIL"


@pytest.mark.parametrize("bad", [{"b" * 64: 40}, {"a" * 64: 39}, {"a" * 64: True}, {"overflow": 40}])
def test_independent_auth_timing_gate_checks_observed_identity_hashes_not_just_quality_pass(bad):
    before = [auth_sample(10)] * 3
    after = [auth_sample(1, "after") for _ in range(3)]
    for row in after:
        row["credential_identity_digests"] = bad
    assert compare_profiles(before, after)["gate"] == "FAIL"


def test_exact_auth_catalogues_can_be_compared():
    assert compare_profiles([auth_sample(10)] * 3, [auth_sample(1, "after")] * 3)["gate"] == "PASS"


@pytest.mark.parametrize("field", ["attempted_credentials", "credential_attempts", "credentials"])
def test_malformed_rows_cannot_be_hidden_by_a_correct_identity_count(field):
    row = {"username": "u", "password": "p", "ok": True, "credential_state": "valid"}
    record = {field: [row, "broken extra row"]}
    summary = credential_summary(record)
    assert summary["malformed_attempts"] == 1
    assert credential_verdict_errors(record, accepted_identities={("u", "p", None)})


@pytest.mark.parametrize("module", [None, "consul", "kubeapi", "qdrant", "gitlab"])
def test_wire_observation_never_overwrites_a_malformed_existing_ledger(module):
    record = {
        "token_valid": True,
        "token_provided": True,
        "credential_state": "valid",
        "auth_http_status": 200,
        "status": "valid_credentials",
        "auth_valid": True,
        "auth_mode": "token",
        "auth_identity": {"ok": True},
        "auth_verification_method": "self_subject_review",
        "api_key_provided": True,
        "provided_credentials_ok": True,
        "attempted_credentials": ["malformed row"],
    }
    if module == "kubeapi":
        record["status"] = "auth_valid"
    if module == "qdrant":
        record["status"] = "open_auth"
    assert wire_token_record(record, module=module, received_token="wire", source="provided") is record


def test_legacy_ok_fields_and_explicit_invalid_errors_are_not_called_unknown():
    rows = [
        {"username": "u", "password": "p", "ok": True},
        {"username": "u", "password": "wrong", "status": "auth_required", "error": "invalid credentials"},
    ]
    summary = credential_summary({"attempted_credentials": rows})
    assert summary["accepted_claims"] == 1
    assert summary["invalid"] == 1
    assert summary["unverified"] == 0


def test_transport_denial_is_not_guessed_to_be_a_wrong_password():
    summary = credential_summary(
        {"attempted_credentials": [{"status": "auth_required", "error": "identity API unavailable", "ok": False}]}
    )
    assert summary["invalid"] == 0


@pytest.mark.parametrize(
    "proof",
    [
        {"credential_verified": False, "credential_verification": "rejected"},
        {"provided_credentials_ok": False, "error": "WRONGPASS invalid username-password pair"},
    ],
)
def test_legacy_root_proof_counts_one_supplied_attempt_without_a_fabricated_ledger(proof):
    record = {"provided_credentials": True, "provided_username": "user", "provided_password": "wrong", **proof}
    summary = credential_summary(record)
    assert summary["attempts_observed"] == summary["invalid"] == 1
    assert summary["accepted_claims"] == 0


def test_legacy_root_without_verdict_or_with_defcreds_does_not_fabricate_attempts():
    record = {"provided_credentials": True, "provided_username": "user", "provided_password": "wrong"}
    assert credential_summary(record)["attempts_observed"] == 0
    record.update(credential_verified=False, defcreds_enabled=True)
    assert credential_summary(record)["attempts_observed"] == 0


def test_full_catalogue_digest_catches_equal_counts_with_missing_and_repeated_pairs():
    rows = [{"username": "u", "password": "one"}, {"username": "u", "password": "two"}]
    expected = identity_digest([("u", "one", None), ("u", "two", None)])
    assert credential_digest({"credential_attempts": rows}) == expected
    assert credential_digest({"credential_attempts": rows[::-1]}) == expected
    assert credential_digest({"credential_attempts": [rows[0], rows[0]]}) != expected
    assert credential_digest({"credential_attempts": [rows[0], {"username": "other", "password": "two"}]}) != expected


def test_legacy_single_pair_identity_is_exact_and_not_just_a_verdict_count():
    record = {
        "provided_credentials": True,
        "provided_username": "u",
        "provided_password": "one",
        "credential_verified": False,
    }
    assert credential_digest(record) == identity_digest([("u", "one", None)])


def test_before_after_comparison_rejects_format_or_tool_change_and_missing_keys():
    before = {key: None for key in matching_case({}, {})}
    after = dict(before)
    assert matching_case(before, after) == []
    after.update(target_style="http", profile_sha256="new tool")
    assert set(matching_case(before, after)) == {"target_style", "profile_sha256"}
    del after["targets"]
    assert "targets" in matching_case(before, after)


def sample(wall, source="before", **overrides):
    row = dict.fromkeys(matching_case({}, {}))
    row.update(
        source_sha256=source,
        result_sha256="exact results",
        wall_seconds=wall,
        quality="PASS",
        cleanup="PASS",
        missing=[],
        extra=[],
        duplicates=0,
        invalid_credentials_accepted=0,
    )
    row.update(overrides)
    return row


def test_repeated_improvement_keeps_broken_baseline_quality_visible():
    before = [sample(t, quality="FAIL", cleanup="FAIL") for t in (70, 71, 69)]
    after = [sample(t, "after") for t in (10, 11, 9)]
    result = compare_profiles(before, after)
    assert result["quality"] == {"before": "FAIL", "after": "PASS"}
    assert result["gate"] == "PASS"
    assert result["timing"] == "IMPROVEMENT"
    assert result["speedup"] == 7


@pytest.mark.parametrize(
    "change",
    [
        {"cleanup": "FAIL"},
        {"missing": [1]},
        {"invalid_credentials_accepted": 1},
        {"negative_target_credential_verdicts": 1},
        {"malformed_credential_rows": 1},
    ],
)
def test_speed_cannot_override_failed_quality(change):
    before = [sample(10) for _ in range(3)]
    after = [sample(1, "after", **change) for _ in range(3)]
    assert compare_profiles(before, after)["gate"] == "FAIL"


def test_fast_but_different_known_results_fail_the_gate():
    result = compare_profiles([sample(10)] * 3, [sample(1, "after", result_sha256="other")] * 3)
    assert result["gate"] == "FAIL"
    assert not result["same_results"]


def test_regression_threshold_accounts_for_measured_spread():
    before = [sample(t) for t in (9, 10, 11)]
    assert compare_profiles(before, [sample(t, "after") for t in (10, 11, 12)])["timing"] == "WITHIN_NOISE"
    assert compare_profiles(before, [sample(t, "after") for t in (20, 21, 22)])["timing"] == "REGRESSION"


def test_single_sample_never_proves_timing_gate():
    result = compare_profiles([sample(10)], [sample(1, "after")])
    assert result["gate"] == "INSUFFICIENT_REPEATS"


@pytest.mark.parametrize("changed", ["source_sha256", "timeout", "delay_ms", "profile_sha256", "target_style"])
def test_comparison_rejects_changed_source_or_settings(changed):
    before = [sample(10)] * 3
    after = [sample(1, "after"), sample(1, "after"), sample(1, "after", **{changed: "changed"})]
    with pytest.raises(ValueError):
        compare_profiles(before, after)


def test_inventory_matcher_checks_actual_objects_and_not_only_count():
    row = {
        "provided_credentials_ok": True,
        "show_datasources": True,
        "datasource_count": 2,
        "datasources": [
            {"name": "Platform metrics", "type": "prometheus", "url": "http://metrics:9090", "access": "proxy"},
            {"name": "Application logs", "type": "loki", "url": "http://logs:3100", "access": "proxy"},
        ],
    }
    assert grafana_inventory_errors(row, limited=False) == []
    row["datasources"][1]["url"] = "http://wrong:3100"
    assert grafana_inventory_errors(row, limited=False)


def test_inventory_denial_needs_confirmed_identity_and_preserved_403_evidence():
    row = {
        "provided_credentials_ok": True,
        "show_datasources": True,
        "datasources": None,
        "datasource_count": None,
        "credential_attempts": [{"ok": True, "credential_capabilities": {"datasource_http_status": 403}}],
    }
    assert grafana_inventory_errors(row, limited=True) == []
    row["credential_attempts"] = []
    assert grafana_inventory_errors(row, limited=True)
