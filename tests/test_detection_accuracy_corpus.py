"""Run the frozen evaluation split against actual detectors, serially per module."""

from __future__ import annotations

import pytest

from redposture_core.module_registry import AUDIT_MODULE_NAMES
from scripts.detection_accuracy import classify, module_cases, panel_cases, special_cases


@pytest.mark.parametrize("module", AUDIT_MODULE_NAMES)
def test_module_accuracy_reference_and_holdout(module):
    rows = module_cases(module)
    summary = classify(rows)
    failures = [r for r in rows if r.get("error_type") or r.get("detected") != r["expected"]]
    assert summary["status"] == "PASS", (module, summary, failures)
    assert {r["provenance"] for r in rows} == {"synthetic-protocol-reference", "holdout-v2"}
    assert all(r.get("wire_exchanges", 0) > 0 for r in rows), (module, rows)


def test_ui_cross_product_identity_parity():
    rows = panel_cases()
    summary = classify(rows)
    assert summary["status"] == "PASS", (
        summary,
        [r for r in rows if r.get("error_type") or r.get("detected") != r["expected"]],
    )
    assert len({r["surface"] for r in rows}) == 9


def test_additional_http_and_grpc_surfaces():
    rows = special_cases()
    summary = classify(rows)
    assert summary["status"] == "PASS", (
        summary,
        [r for r in rows if r.get("error_type") or r.get("detected") != r["expected"]],
    )
    assert len({r["id"] for r in rows if r["expected"]}) == 10
