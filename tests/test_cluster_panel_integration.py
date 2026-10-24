"""Cross-command contracts for independent Spark, YARN and Portainer surfaces."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from redposture_core.audit_models import AuditRecord
from redposture_core.cli_args import build_parser, parse_args
from redposture_core.cve import resolve_products
from redposture_core.data_discovery import DISCOVERY_MODULES, discovery_fields, inspect_record, project_discovery_output
from redposture_core.module_registry import AUDIT_MODULE_NAMES
from redposture_core.stage_spray import Candidate, _supported


@pytest.mark.parametrize("module", ["spark", "yarn", "portainer"])
def test_new_commands_have_independent_registry_help_and_discovery(module: str) -> None:
    assert module in AUDIT_MODULE_NAMES
    args = parse_args([module, "-t", "http://localhost:8080/prefix", "--discover", "--enum-cve"])
    assert args.command == module and args.discover and args.enum_cve
    assert module in DISCOVERY_MODULES and discovery_fields(module)
    assert module in build_parser().format_help()


@pytest.mark.parametrize(
    "module,product", [("spark", "apache_spark"), ("yarn", "apache_hadoop_yarn"), ("portainer", "portainer")]
)
def test_cve_routing_keeps_products_and_versions_separate(module: str, product: str) -> None:
    payload = {"version": "3.1.3", f"is_{module}": True}
    if module == "portainer":
        payload.update(surface="ui", ui_product="portainer", ui={"version": "2.45.0"}, server_version="28.0.0")
    products = resolve_products(module, payload)
    assert len(products) == 1 and products[0].product_key == product
    assert products[0].version == ("2.45.0" if module == "portainer" else "3.1.3")


@pytest.mark.parametrize("module", ["spark", "yarn"])
@pytest.mark.parametrize("candidate", [Candidate("pair", "admin", "admin"), Candidate("token", token="candidate")])
def test_cluster_managers_do_not_claim_password_or_token_verifiers(module: str, candidate: Candidate) -> None:
    record = AuditRecord.from_mapping(
        {"host": "localhost", "port": 8080, "status": "open_no_auth", f"is_{module}": True}
    )
    assert not _supported(module, candidate, record)


@pytest.mark.parametrize("kind", ["pair", "token"])
def test_portainer_spray_supports_only_its_own_confirmed_surface(kind: str) -> None:
    candidate = Candidate(kind, "admin", "password") if kind == "pair" else Candidate(kind, token="ptr_candidate")
    record = AuditRecord.from_mapping(
        {
            "host": "localhost",
            "port": 9000,
            "status": "auth_required",
            "surface": "ui",
            "ui_product": "portainer",
            "credential_verification_status": "available",
        }
    )
    assert _supported("portainer", candidate, record)
    assert not _supported("docker", Candidate("token", token="candidate"), record)


@pytest.mark.parametrize(
    "module,field", [("spark", "spark_metadata"), ("yarn", "app_specs"), ("portainer", "portainer_metadata")]
)
def test_shared_discovery_reads_new_content_and_hides_raw_scan_input(module: str, field: str) -> None:
    args = SimpleNamespace(command=module, discover=True)
    record = {"host": "localhost", "port": 8080, field: {"password": "warehouse-test-secret-827341"}}
    inspected = inspect_record(module, record)
    assert inspected["findings"]
    assert field not in project_discovery_output(args, record)


def test_docker_command_no_longer_probes_portainer_or_accepts_panel_credentials() -> None:
    from redposture_core import web_panels
    from redposture_core.modules.docker.stage import build_docker_plan

    assert "docker" not in web_panels.MODULE_PRODUCTS
    args = parse_args(["docker", "-t", "127.0.0.1"])
    assert not {9000, 9443}.intersection(build_docker_plan(args).ports)
    with pytest.raises(SystemExit):
        parse_args(["docker", "-t", "127.0.0.1", "--defcreds"])
    assert not _supported(
        "docker", Candidate("pair", "admin", "admin"), AuditRecord.from_mapping({"status": "open_no_auth"})
    )


@pytest.mark.parametrize(
    "product,cve,affected,fixed",
    [
        ("apache_spark", "CVE-2022-33891", "3.1.3", "3.1.4"),
        ("apache_spark", "CVE-2022-33891", "3.2.1", "3.2.2"),
        ("apache_hadoop_yarn", "CVE-2021-25642", "2.10.1", "2.10.2"),
        ("apache_hadoop_yarn", "CVE-2021-25642", "3.2.3", "3.2.4"),
        ("apache_hadoop_yarn", "CVE-2021-25642", "3.3.3", "3.3.4"),
        ("portainer", "CVE-2026-72533", "2.39.6", "2.39.7"),
        ("portainer", "CVE-2026-72533", "2.44.0", "2.45.0"),
    ],
)
def test_reviewed_catalog_versions_use_vendor_branch_boundaries(product, cve, affected, fixed) -> None:
    from redposture_core.cve import load_catalog, version_in_range

    entry = next(e for e in load_catalog().entries if e["product"] == product and e["id"] == cve)
    assert any(version_in_range(affected, item) for item in entry["affected"])
    assert not any(version_in_range(fixed, item) for item in entry["affected"])


def test_portainer_spray_does_not_invent_a_second_backend_surface(monkeypatch, tmp_path) -> None:
    from argparse import Namespace

    from redposture_core import stage_spray as spray
    from redposture_core.stage_runtime import ModuleAuditSpec
    from redposture_core.targeting import ScanTargetSpec

    calls = []

    def detect(ctx):
        calls.append("detect")
        return AuditRecord.from_mapping(
            {
                "host": "qa",
                "port": 9000,
                "status": "auth_required",
                "is_portainer": True,
                "surface": "ui",
                "ui_product": "portainer",
                "credential_verification_status": "available",
            }
        )

    def auth(ctx, prior):
        calls.append("auth")
        return AuditRecord.from_mapping(
            {
                **prior.to_dict(),
                "status": "invalid_credentials",
                "credential_state": "invalid",
                "provided_credentials_ok": False,
            }
        )

    spec = ModuleAuditSpec(
        module="portainer",
        label="PORTAINER",
        default_port=9000,
        detect=detect,
        auth=auth,
        is_detected=lambda rec: rec.extra.get("is_portainer") is True,
    )
    monkeypatch.setattr(
        spray.importlib, "import_module", lambda name: SimpleNamespace(build_portainer_spec=lambda args: spec)
    )
    journal = spray.AttemptJournal(str(tmp_path / "checkpoint.sqlite3"), "same", False)
    try:
        assert spray._run_target(
            "portainer",
            Namespace(),
            "qa",
            9000,
            ScanTargetSpec("qa", scheme="http", explicit_port=9000, raw="http://qa:9000"),
            (Candidate("pair", "admin", "wrong"),),
            journal,
            spray.RateGate(1000, 0.001),
            None,
        )
        assert calls == ["detect", "auth"]
        assert len(list(journal.rows())) == 2
    finally:
        journal.close()


def test_portainer_spray_keeps_ui_version_and_one_ui_suffix() -> None:
    from redposture_core.stage_spray import _record_version, _render_rows

    record = AuditRecord.from_mapping({"surface": "ui", "ui_product": "portainer", "ui": {"version": "2.39.7"}})
    assert _record_version(record) == "2.39.7"
    rows = [("portainer", "qa", 9000, 0, "valid", "Portainer UI: identity verified; surface:ui", "(UI)")]
    assert _render_rows(rows, (Candidate("pair", "admin", "secret"),), "txt")[0].count("(UI)") == 1
