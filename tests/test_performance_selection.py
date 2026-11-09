"""Short selection remains explainable and cannot silently drop missing phase fixtures."""

import pytest

from scripts.performance_selection import selection


def inventory():
    from redposture_core.module_registry import AUDIT_MODULE_NAMES

    return {
        "audit_modules": [
            {
                "module": name,
                "discover": name != "grpc",
                "auth_flags": ["--token"],
                "inventory_flags": ["--show-items"],
                "companion_surfaces": ["ui-" + name],
                "additional_surfaces": [],
            }
            for name in AUDIT_MODULE_NAMES
        ]
    }


def test_every_module_and_ui_stays_in_catalog_even_if_not_selected():
    plan = selection(inventory(), [])
    assert len(plan["catalog"]) == 32 and not plan["modules"]
    assert all(r["surfaces"] for r in plan["catalog"])
    assert not plan["missing_data_recipes"]
    assert "redis" in plan["adapter_only_data_modules"]
    redis = next(row for row in plan["catalog"] if row["module"] == "redis")
    assert redis["data"]["transport_boundary"] and redis["data"]["adapter_instrument"]
    assert plan["full_ci_qa_required"]


@pytest.mark.parametrize(
    "package,expected",
    [
        ("keycloak", {"keycloak"}),
        ("docker_registry", {"docker-registry"}),
        ("registry", {"harbor", "nexus", "docker-registry"}),
    ],
)
def test_direct_paths_and_shared_registry_fan_out(package, expected):
    plan = selection(inventory(), [f"redposture_core/modules/{package}/actions.py"])
    assert {r["module"] for r in plan["modules"]} == expected
    assert set(plan["discover_routes"]) == expected


def test_shared_scanner_selects_every_discover_route_without_claiming_network_coverage():
    plan = selection(inventory(), ["redposture_core/secret_detection.py"])
    assert len(plan["discover_routes"]) == 31 and plan["shared_processing"]
    assert not plan["modules"]


def test_runtime_selects_protocol_representatives_and_exporter_workflows():
    plan = selection(inventory(), ["redposture_core/async_detection.py"])
    assert {r["module"] for r in plan["modules"]} == {"redis", "postgres", "kafka", "grafana"}
    assert plan["workflows"] == ["collect", "trigger", "spray"]


def test_all_is_explicit_and_duplicate_catalog_is_rejected():
    plan = selection(inventory(), [], all_modules=True)
    assert len(plan["modules"]) == 32 and len(plan["discover_routes"]) == 31
    data = inventory()
    data["audit_modules"].append(data["audit_modules"][0])
    with pytest.raises(ValueError, match="duplicate module"):
        selection(data, [])
