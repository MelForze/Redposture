"""Observed Grafana redaction is a sentinel, not an available password."""

from __future__ import annotations

import pytest

from redposture_core.discovery_engine import _scan_portioned_value
from redposture_core.discovery_values import DiskBackedText
from scripts.discovery_accuracy import MODULES, READERS, scan


@pytest.mark.parametrize("route", (*MODULES, *READERS))
def test_grafana_redacted_marker_never_becomes_a_secret_on_existing_adapter_routes(route):
    findings, status = scan(route, {"password": "[REDACTED]"}, portion=3)
    assert status == "complete"
    assert not findings, findings


@pytest.mark.parametrize("value", ["[REDACTED]", " [redacted] ", "\n[ReDaCtEd]\t"])
def test_redacted_marker_disk_scalar_uses_same_semantics(value):
    with DiskBackedText() as disk:
        for offset in range(0, len(value), 3):
            disk.append_text(value[offset : offset + 3])
        disk.finish()
        matches, _, complete = _scan_portioned_value({"password": disk}, "$", 3)
        assert complete
        assert not list(matches)


@pytest.mark.parametrize(
    "value", ["real-[REDACTED]-keep!42", "[REDACTED]suffix!42", "prefix[REDACTED]", "[REDACTED]-αβ!42"]
)
def test_sensitive_values_containing_marker_are_not_filtered(value):
    findings, status = scan("common", {"password": value}, portion=3)
    assert status == "complete"
    assert [f["value"] for f in findings] == [value]
