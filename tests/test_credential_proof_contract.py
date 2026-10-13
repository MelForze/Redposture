"""Every audit command must distinguish public access from credential proof."""

from __future__ import annotations

import importlib
from types import SimpleNamespace

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from redposture_core.audit_models import AuditRecord
from redposture_core.module_registry import AUDIT_MODULE_NAMES
from redposture_core.stage_runtime import AuditCommandRunner, AuditCredentialRun
from redposture_core.stage_spray import _module_runtime_args


def _runner(module: str) -> AuditCommandRunner:
    parent = SimpleNamespace(
        targets="localhost:49123", timeout=0.1, retries=0, workers=1, proxy=None, debug=False, no_color=True
    )
    args = _module_runtime_args(module, parent, {})
    stage = importlib.import_module(f"redposture_core.modules.{module.replace('-', '_')}.stage")
    spec = getattr(stage, f"build_{module.replace('-', '_')}_spec")(args)
    return AuditCommandRunner(args=args, spec=spec)


@pytest.mark.parametrize("module", AUDIT_MODULE_NAMES)
@pytest.mark.parametrize("status", ("detected", "open_no_auth", "auth_required", "forbidden"))
def test_public_or_ambiguous_result_never_verifies_a_supplied_pair(module: str, status: str) -> None:
    runner = _runner(module)
    record = AuditRecord.from_mapping({"host": "localhost", "port": 49123, "status": status}, module=module)
    accepted, _why = runner._credential_gate(AuditCredentialRun("alice", "secret", source="provided"), record)
    assert accepted is False, module


@pytest.mark.parametrize("module", AUDIT_MODULE_NAMES)
def test_explicit_rejection_vetoes_a_conflicting_success_status(module: str) -> None:
    runner = _runner(module)
    record = AuditRecord.from_mapping(
        {
            "host": "localhost",
            "port": 49123,
            "status": "valid_credentials",
            "provided_credentials_ok": False,
            "credential_state": "invalid",
        },
        module=module,
    )
    accepted, _why = runner._credential_gate(AuditCredentialRun("alice", "wrong", source="provided"), record)
    assert accepted is False, module


def test_default_candidate_is_not_vetoed_by_an_earlier_explicit_rejection() -> None:
    runner = _runner("redis")
    record = AuditRecord.from_mapping(
        {
            "host": "localhost",
            "port": 6379,
            "status": "weak_default_creds",
            "provided_credentials_ok": False,
            "default_credentials": True,
        },
        module="redis",
    )
    assert runner._credential_gate(AuditCredentialRun("redis", "redis", source="default"), record)[0] is True
    assert runner._credential_gate(AuditCredentialRun("alice", "wrong", source="provided"), record)[0] is False


@pytest.mark.parametrize("module", AUDIT_MODULE_NAMES)
def test_verified_product_identity_is_accepted_for_each_module(module: str) -> None:
    runner = _runner(module)
    record = AuditRecord.from_mapping(
        {
            "host": "localhost",
            "port": 49123,
            "status": "auth_valid" if module == "kubeapi" else "valid_credentials",
            "provided_credentials_ok": True,
            "credential_verified": True,
            "auth_valid": True,
            "token_valid": True,
        },
        module=module,
    )
    credential = (
        AuditCredentialRun(token="verified", source="provided")
        if module in {"keycloak", "qdrant", "docker"}
        else AuditCredentialRun("alice", "secret", source="provided")
    )
    accepted, _why = runner._credential_gate(credential, record)
    assert accepted is True, module


@pytest.mark.parametrize("module", AUDIT_MODULE_NAMES)
def test_low_privilege_cve_gate_rejects_conflicting_or_unknown_proof(module: str) -> None:
    runner = _runner(module)
    runner.args.username = "alice"
    runner.args.password = "secret"
    assert runner._record_reports_verified_credentials({"status": "open_no_auth"}) is False
    assert runner._record_reports_verified_credentials({"status": "auth_valid"}) is False
    assert (
        runner._record_reports_verified_credentials({"status": "auth_valid", "provided_credentials_ok": False}) is False
    )
    assert (
        runner._record_reports_verified_credentials({"status": "auth_valid", "credential_state": "unverified"}) is False
    )
    assert (
        runner._record_reports_verified_credentials({"status": "auth_valid", "provided_credentials_ok": True}) is True
    )


@settings(max_examples=250, deadline=None)
@given(
    module=st.sampled_from(AUDIT_MODULE_NAMES),
    status=st.sampled_from(("open_no_auth", "auth_required", "valid_credentials", "auth_valid", "token_ok")),
    rejected_field=st.sampled_from(
        ("provided_credentials_ok", "credential_verified", "auth_valid", "token_valid", "credentials_valid")
    ),
    credential_state=st.sampled_from(("invalid", "unknown", "unverified", "verification_unavailable")),
)
def test_conflicting_or_ambiguous_proof_never_verifies_credentials(
    module: str, status: str, rejected_field: str, credential_state: str
) -> None:
    runner = _runner(module)
    credential = AuditCredentialRun("alice", "secret", source="provided")
    record = AuditRecord.from_mapping(
        {
            "host": "localhost",
            "port": 49123,
            "status": status,
            "provided_credentials_ok": True,
            rejected_field: False,
            "credential_state": credential_state,
        },
        module=module,
    )
    assert runner._credential_gate(credential, record)[0] is False
