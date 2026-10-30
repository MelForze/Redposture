"""A plain diagnostic label is not a malformed nested JSON document."""

from types import SimpleNamespace

import pytest

from redposture_core.data_discovery import _scan_portioned_value
from redposture_core.discovery_values import DiskBackedText
from redposture_core.storage_discovery import DiscoveryCollector


@pytest.mark.parametrize("disk", [False, True])
@pytest.mark.parametrize(
    "warning", ["[DEPRECATION NOTICE]: API is accessible without encryption.", "{NOTICE}: ordinary status."]
)
def test_diagnostic_bracket_labels_are_fully_inspected_plaintext(disk, warning):
    value = warning
    if disk:
        value = DiskBackedText()
        value.append_text(warning)
        value.finish()
    try:
        matches, size, covered = _scan_portioned_value({"Warnings": [value]}, "$.info", 65536)
        assert covered
        assert size >= len(warning)
        assert list(matches) == []
    finally:
        if disk:
            value.close()


def test_portainer_docker_warning_does_not_report_a_removed_byte_budget():
    collector = DiscoveryCollector(
        "portainer", SimpleNamespace(args=SimpleNamespace(discover_time=30)), {"status": "valid_credentials"}
    )
    collector.add("portainer/inventory/system", [{"info": {"Warnings": ["[DEPRECATION NOTICE]: API is accessible."]}}])
    assert collector.result()["status"] == "complete"


def test_real_malformed_nested_json_keeps_prefix_and_reports_its_actual_reason():
    collector = DiscoveryCollector(
        "portainer", SimpleNamespace(args=SimpleNamespace(discover_time=30)), {"status": "valid_credentials"}
    )
    collector.add("config", {"content": '{"password":"finished-secret","tail":'})
    result = collector.result()
    assert result["status"] == "partial"
    assert [row["value"] for row in result["findings"]] == ["finished-secret"]
    assert result["partial_reasons"] == ["config: invalid_json"]
