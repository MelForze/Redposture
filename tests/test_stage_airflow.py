from __future__ import annotations

import pytest

from redposture_core.audit_models import AuditRecord
from redposture_core.cli_args import parse_args
from redposture_core.modules.airflow import stage


def test_build_airflow_spec_wires_hooks():
    spec = stage.build_airflow_spec(parse_args(["airflow", "-t", "127.0.0.1"]))
    assert spec.module == "airflow" and spec.label == "AIRFLOW"
    assert spec.detect is not None and spec.auth is not None and spec.capabilities is not None
    assert spec.data is not None  # Discovery is gated by --discover inside the data hook.
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


@pytest.mark.parametrize(
    ("target", "port_args", "expected_ports"),
    [
        ("http://airflow.example/app", (), (80,)),
        ("https://airflow.example/app", (), (443,)),
        ("https://airflow.example:18443/app", (), (18443,)),
        ("airflow.example", (), (8080, 8081, 18080, 28080, 8443)),
        ("http://airflow.example/app", ("--port", "18080"), (18080,)),
        ("https://airflow.example/app", ("--ports", "8080,8443"), (8080, 8443)),
    ],
)
def test_airflow_url_and_explicit_port_precedence(
    target: str, port_args: tuple[str, ...], expected_ports: tuple[int, ...]
) -> None:
    plan = stage.build_airflow_plan(parse_args(["airflow", "-t", target, *port_args]))

    targets = [(port, spec) for _index, _host, port, spec in plan.iter_target_specs()]
    assert tuple(port for port, _spec in targets) == expected_ports
    assert plan.target_count == len(expected_ports)
    if target.startswith("http"):
        assert all(spec is not None and spec.path == "/app" for _port, spec in targets)


def test_airflow_mixed_target_file_keeps_url_and_bare_host_semantics(tmp_path) -> None:
    targets = tmp_path / "airflow-targets.txt"
    targets.write_text(
        "http://web.example/airflow\nhttps://secure.example/airflow\n"
        "http://custom.example:18080/airflow\nbare.example\n",
        encoding="utf-8",
    )
    plan = stage.build_airflow_plan(parse_args(["airflow", "-t", str(targets)]))

    pairs = {(host, port) for _index, host, port, _spec in plan.iter_target_specs()}
    assert pairs == {
        ("web.example", 80),
        ("secure.example", 443),
        ("custom.example", 18080),
        *(("bare.example", port) for port in (8080, 8081, 18080, 28080, 8443)),
    }
    assert plan.target_count == len(pairs) == 8
