"""Anonymous API access must not be fabricated into credential acceptance."""

from __future__ import annotations

from copy import deepcopy

import pytest

from redposture_core.clients.docker_engine import DockerEngineClient, DockerHTTPResponse
from redposture_core.modules.docker import actions
from scripts.performance_contracts import _credential_catalogue_evidence_ok, matching_case
from scripts.performance_readonly import ReadOnlyWireLedger, docker_inventory_errors, docker_reply, readonly_wire_errors
from scripts.profile_module_performance import module_options, unsupported_auth_reason

CATEGORIES = ["containers", "images", "networks", "volumes", "system"]


@pytest.fixture
def actual_audit(monkeypatch):
    def run(*, access="open", categories=CATEGORIES):
        ledger = ReadOnlyWireLedger()

        def request(self, method, path, **kwargs):
            raw = docker_reply(method, path, access=access)
            fields = {b"host": b"qa.invalid:2375", b"accept": b"application/json"}
            ledger.record_response(0, method, path, fields, b"", raw)
            head, body = raw.split(b"\r\n\r\n", 1)
            code = int(head.split(b" ", 2)[1])
            from redposture_core.clients.docker_engine import DockerEngineHTTPError

            if code >= 400:
                raise DockerEngineHTTPError(code, "Forbidden", body, {})
            return DockerHTTPResponse(code, "OK", {}, body)

        monkeypatch.setattr(DockerEngineClient, "request", request)
        record = actions._audit_docker_host("qa.invalid", 2375, 1, 0, **{"show_" + name: True for name in categories})
        return record, ledger.pop(0)

    return run


@pytest.mark.parametrize("access", ["open", "limited", "denied"])
@pytest.mark.parametrize("categories", [[], ["containers"], CATEGORIES])
def test_full_anonymous_and_denied_reads_are_correlated_with_real_client_actions(actual_audit, access, categories):
    record, wire = actual_audit(access=access, categories=categories)
    assert not docker_inventory_errors(record, wire, access=access, categories=categories)
    assert not record.get("credential_attempts") and not record.get("provided_credentials_ok")


@pytest.mark.parametrize("method", ["POST", "PUT", "DELETE"])
def test_no_mutation_or_container_exec_can_succeed(method):
    for path in ["/containers/create", "/containers/id/exec", "/images/name", "/volumes/create"]:
        assert docker_reply(method, path, access="open").startswith(b"HTTP/1.1 405")


@pytest.mark.parametrize("mode", ["credentials", "defcreds"])
def test_absent_pair_flags_are_not_a_successful_credential_scenario(mode):
    assert unsupported_auth_reason("docker", mode)
    assert "-u" not in module_options("docker", "run", "http://qa:2375", 1)


@pytest.mark.parametrize(
    "fault",
    [
        "missing-wire",
        "corrupt-body",
        "missing-resource",
        "changed-object",
        "wrong-capability",
        "wrong-completion",
        "credential",
        "mutation",
        "malformed-path",
    ],
)
def test_corrupt_evidence_cannot_pass_as_complete_inventory(actual_audit, fault):
    record, wire = actual_audit()
    if fault == "missing-wire":
        wire["calls"].pop()
    elif fault == "corrupt-body":
        wire["calls"][-1]["response_body"] += "wrong"
    elif fault == "missing-resource":
        record["containers"] = []
    elif fault == "changed-object":
        record["containers"][0]["Names"] = ["/other"]
    elif fault == "wrong-capability":
        record["capabilities"]["can_list_images"] = False
    elif fault == "wrong-completion":
        record["data_complete"] = False
    elif fault == "credential":
        wire["calls"][0]["headers"]["authorization"] = "Basic something"
    elif fault == "mutation":
        wire["calls"][0]["method"] = "POST"
    elif fault == "malformed-path":
        wire["calls"][0]["path"] = []
    assert docker_inventory_errors(record, wire, access="open", categories=CATEGORIES)


def test_header_and_body_capacity_are_bounded_and_released():
    ledger = ReadOnlyWireLedger(body_limit=1)
    raw = docker_reply("GET", "/info", access="open")
    ledger.record_response(0, "GET", "/info", {}, b"", raw)
    assert ledger.snapshot()["overflow"] == 1 and not ledger.pop(0)["complete"]
    ledger = ReadOnlyWireLedger()
    ledger.record_response(0, "GET", "/info", {b"host": b"qa"}, b"", raw)
    assert ledger.pending_body_bytes > 0
    assert not readonly_wire_errors(ledger.pop(0)) and ledger.pending_body_bytes == 0
    ledger.close()
    with pytest.raises(RuntimeError):
        ledger.pop(0)


def test_readonly_case_and_credential_applicability_are_comparison_parameters():
    before = {"fixture_access_case": "open", "credential_scenario_applicable": False}
    after = {**before, "fixture_access_case": "limited"}
    assert "fixture_access_case" in matching_case(before, after)
    after = {**before, "credential_scenario_applicable": True}
    assert "credential_scenario_applicable" in matching_case(before, after)


def test_no_credentials_exception_requires_typed_zero_evidence_and_correct_module():
    record = {
        "module": "docker",
        "mode": "actions",
        "fixture_access_case": "open",
        "credential_scenario_applicable": False,
        "credential_quality": "NOT_APPLICABLE",
        "credential_expectation_per_positive": None,
        "credential_expected_sha256": None,
        "credential_identity_digests": {},
        "credential_observations": {
            k: 0
            for k in [
                "attempts_observed",
                "accepted_claims",
                "invalid",
                "unverified",
                "skipped",
                "duplicate_attempts",
                "malformed_attempts",
            ]
        },
    }
    assert _credential_catalogue_evidence_ok(record)
    for field, value in [
        ("module", "grafana"),
        ("mode", "credentials"),
        ("fixture_access_case", []),
        ("credential_quality", "PASS"),
    ]:
        assert not _credential_catalogue_evidence_ok({**record, field: value})
    changed = deepcopy(record)
    changed["credential_observations"]["accepted_claims"] = 1
    assert not _credential_catalogue_evidence_ok(changed)
