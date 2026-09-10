from __future__ import annotations

from redposture_core.audit_models import AuditRecord
from redposture_core.cli_args import parse_args
from redposture_core.modules.airflow import stage


def test_build_airflow_spec_wires_hooks():
    spec = stage.build_airflow_spec(parse_args(["airflow", "-t", "127.0.0.1"]))
    assert spec.module == "airflow" and spec.label == "AIRFLOW"
    assert spec.detect is not None and spec.auth is not None and spec.capabilities is not None
    assert spec.data is None  # Phase 1 has no enumeration
    assert "credential_password" in spec.structured_output_redact_fields


def test_defcreds_makes_spec_exhaustive():
    spec = stage.build_airflow_spec(parse_args(["airflow", "-t", "127.0.0.1", "--defcreds"]))
    assert spec.continue_after_credential_success is True
    assert spec.continue_after_credential_error is True
    plain = stage.build_airflow_spec(parse_args(["airflow", "-t", "127.0.0.1"]))
    assert plain.continue_after_credential_success is False


def test_credential_gate_reads_provided_ok():
    ok = AuditRecord(host="h", port=8080, service="airflow", status="detected", extra={"provided_credentials_ok": True})
    no = AuditRecord(
        host="h", port=8080, service="airflow", status="detected", extra={"provided_credentials_ok": False}
    )
    assert stage._airflow_credential_gate(None, ok)[0] is True
    assert stage._airflow_credential_gate(None, no)[0] is False
