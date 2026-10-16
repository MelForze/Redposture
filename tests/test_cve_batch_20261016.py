from __future__ import annotations

import pytest

from redposture_core.console import Console
from redposture_core.cve import (
    enumerate_record,
    load_catalog,
    render_finding_lines,
    resolve_products,
    version_in_range,
)
from redposture_core.rendering import render_colored_marker_line


@pytest.mark.parametrize(
    ("cve_id", "product", "affected", "fixed"),
    [
        ("CVE-2026-2603", "keycloak", "26.4.9", "26.4.10"),
        ("CVE-2026-2092", "keycloak", "26.4.7", "26.4.8"),
        ("CVE-2026-11403", "nexus_repository", "3.92.9", "3.93.0"),
        ("CVE-2024-41110", "docker_engine", "27.1.0", "27.1.1"),
        ("CVE-2026-11933", "mongodb", "8.3.3", "8.3.4"),
        ("CVE-2025-47889", "jenkins_plugin_wso2id_oauth", "1.0", "1.1"),
    ],
)
def test_new_catalog_entries_match_boundaries(cve_id: str, product: str, affected: str, fixed: str) -> None:
    entry = next(item for item in load_catalog().entries if item["id"] == cve_id and item["product"] == product)
    assert any(version_in_range(affected, version_range) is True for version_range in entry["affected"])
    assert all(version_in_range(fixed, version_range) is False for version_range in entry["affected"])


@pytest.mark.parametrize(
    ("cve_id", "product", "affected", "fixed"),
    [
        ("CVE-2026-2603", "keycloak", "26.2.13", "26.2.14"),
        ("CVE-2026-2603", "keycloak", "26.5.4", "26.5.5"),
        ("CVE-2026-2092", "keycloak", "26.2.5", "26.2.6"),
        ("CVE-2026-2092", "keycloak", "26.5.4", "26.5.5"),
        ("CVE-2024-41110", "docker_engine", "23.0.14", "23.0.15"),
        ("CVE-2024-41110", "docker_engine", "25.0.5", "25.0.6"),
        ("CVE-2024-41110", "docker_engine", "26.1.4", "26.1.5"),
        ("CVE-2026-11933", "mongodb", "4.4.30", "4.4.31"),
        ("CVE-2026-11933", "mongodb", "5.0.33", "5.0.34"),
        ("CVE-2026-11933", "mongodb", "6.0.28", "6.0.29"),
        ("CVE-2026-11933", "mongodb", "7.0.36", "7.0.37"),
        ("CVE-2026-11933", "mongodb", "8.0.25", "8.0.26"),
        ("CVE-2026-11933", "mongodb", "8.2.10", "8.2.11"),
    ],
)
def test_vendor_branch_fixes_exclude_patched_builds(cve_id: str, product: str, affected: str, fixed: str) -> None:
    entry = next(item for item in load_catalog().entries if item["id"] == cve_id and item["product"] == product)
    assert any(version_in_range(affected, item) is True for item in entry["affected"])
    assert all(version_in_range(fixed, item) is False for item in entry["affected"])


@pytest.mark.parametrize(
    ("module", "field", "version", "cve_id"),
    [
        ("keycloak", "version", "26.4.9", "CVE-2026-2603"),
        ("docker", "server_version", "27.1.0", "CVE-2024-41110"),
        ("mongodb", "server_version", "8.3.3", "CVE-2026-11933"),
    ],
)
def test_new_low_privilege_findings_require_verified_access(module: str, field: str, version: str, cve_id: str) -> None:
    catalog = load_catalog()
    no_access = enumerate_record(module, {field: version, "auth_required": True}, catalog=catalog, confirmed=True)
    with_access = enumerate_record(
        module,
        {field: version, "auth_required": True},
        catalog=catalog,
        confirmed=True,
        credentials_provided=True,
    )
    assert cve_id not in {finding["id"] for finding in no_access["findings"]}
    assert cve_id in {finding["id"] for finding in with_access["findings"]}


def test_wso2_plugin_never_inherits_jenkins_core_version() -> None:
    catalog = load_catalog()
    absent_inventory = {"version": "2.541.3", "plugins_access": "denied"}
    products = resolve_products("jenkins", absent_inventory)
    plugin = next(product for product in products if product.product_key == "jenkins_plugin_wso2id_oauth")
    assert plugin.version is None
    assert plugin.confidence == "inferred"
    possible = enumerate_record("jenkins", absent_inventory, catalog=catalog, confirmed=True)
    finding = next(item for item in possible["findings"] if item["id"] == "CVE-2025-47889")
    assert finding["version_assessment"] == "unknown"
    assert finding["product_presence"] == "unverified"

    absent_plugin = {"version": "2.541.3", "plugins": [], "plugins_count": 0, "plugins_access": "allowed"}
    assert "CVE-2025-47889" not in {
        item["id"] for item in enumerate_record("jenkins", absent_plugin, catalog=catalog, confirmed=True)["findings"]
    }

    installed = {
        "version": "2.541.3",
        "plugins": [{"short_name": "wso2id-oauth", "version": "1.0", "active": True}],
        "plugins_count": 1,
        "plugins_access": "allowed",
    }
    matched = enumerate_record("jenkins", installed, catalog=catalog, confirmed=True)
    installed_finding = next(item for item in matched["findings"] if item["id"] == "CVE-2025-47889")
    assert installed_finding.get("version_assessment") != "unknown"
    assert installed_finding["detected_version"] == "1.0"

    inactive = {**installed, "plugins": [{**installed["plugins"][0], "active": False}]}
    assert "CVE-2025-47889" not in {
        item["id"] for item in enumerate_record("jenkins", inactive, catalog=catalog, confirmed=True)["findings"]
    }


def test_speculative_plugin_line_uses_existing_yellow_and_no_ansi_saved_text(
    capsys: pytest.CaptureFixture[str],
) -> None:
    result = enumerate_record(
        "jenkins",
        {"version": "2.541.3", "plugins_access": "denied"},
        catalog=load_catalog(),
        confirmed=True,
    )
    lines = render_finding_lines({"cve_enumeration": result}, label="JENKINS", host="host", port=8080)
    plugin_line = next(line for line in lines if "CVE-2025-47889" in line)
    assert "[!] Possibly CVE-2025-47889" in plugin_line
    assert "only if installed" in plugin_line
    console = Console(no_color=True)
    assert render_colored_marker_line(console, plugin_line, tag="JENKINS")
    assert "\x1b[" not in capsys.readouterr().out
    assert "\x1b[" not in plugin_line
