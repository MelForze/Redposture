"""Gate integrity: wrong results and broken runs must never look green."""

from __future__ import annotations

import json

import pytest

from redposture_core.module_registry import AUDIT_MODULE_NAMES
from scripts import detection_accuracy as gate


def pair(expected=True, detected=True):
    return [dict(id="control", mode=mode, expected=expected, detected=detected) for mode in ("sync", "async")]


def test_reference_covers_every_module_and_holdout_is_locked():
    assert len(gate.PRODUCTS) == 32 and set(gate.PRODUCTS) == set(AUDIT_MODULE_NAMES)
    holdout = gate.load_holdout()
    assert len(holdout["cases"]) == 14
    assert {c["expected"] for c in holdout["cases"]} == {False}


def test_modified_holdout_requires_explicit_review(tmp_path, monkeypatch):
    p = tmp_path / "holdout.json"
    p.write_text(json.dumps({"cases": []}))
    monkeypatch.setattr(gate, "CORPUS", p)
    with pytest.raises(ValueError, match="holdout changed"):
        gate.load_holdout()


@pytest.mark.parametrize("expected,detected,key", [(True, False, "fn"), (False, True, "fp")])
def test_wrong_identity_is_a_gate_failure(expected, detected, key):
    summary = gate.classify(pair(expected, detected))
    assert summary["status"] == "FAIL" and summary[key] == 2


def test_protocol_unavailable_is_not_a_successful_positive():
    rows = pair(True, False)
    for row in rows:
        row["detection_status"] = "transport_failure"
    summary = gate.classify(rows)
    assert summary["fn"] == 2 and summary["unconfirmed"] == 2 and summary["status"] == "FAIL"


@pytest.mark.parametrize("rows", [[], [dict(id="control", error_type="TimeoutError")], pair()[:1], pair()[:1] * 2])
def test_empty_crashed_missing_or_duplicate_mode_fails(rows):
    assert gate.classify(rows)["status"] == "FAIL"


def test_different_sync_async_decisions_fail_even_with_individual_labels():
    rows = pair(False, False)
    rows[1].update(expected=True, detected=True)
    summary = gate.classify(rows)
    assert summary["status"] == "FAIL" and summary["parity_mismatches"] == ["control"]


def test_fallback_is_counted_separately_and_never_relabels_expectations():
    rows = pair()
    rows[1]["fallback"] = True
    summary = gate.classify(rows)
    assert summary["status"] == "PASS" and summary["tp"] == 2 and summary["async_fallbacks"] == 1


def test_missing_whole_case_pair_is_not_hidden_by_other_passes():
    summary = gate.classify(pair(), {"control", "missing-positive"})
    assert summary["status"] == "FAIL"
    assert summary["missing_cases"] == ["missing-positive"]


def test_positive_ui_labels_cover_every_supported_surface():
    from redposture_core import web_panels

    assert set(gate.PANEL_PRODUCTS.values()) == {
        product for products in web_panels.MODULE_PRODUCTS.values() for product in products
    }


def test_other_kafka_http_surfaces_have_reference_labels():
    from redposture_core.modules.kafka import http_surfaces

    assert set(http_surfaces._PRODUCTS) | {"provectus", "kafbat"} == {
        product for module, product in gate.SPECIAL_SURFACES.values() if module == "kafka"
    }


def test_wrong_ui_subtype_cannot_hide_behind_correct_module():
    rows = pair()
    for row in rows:
        row.update(expected_product="pgadmin", product="postgrest")
    assert gate.classify(rows)["status"] == "FAIL"


@pytest.mark.parametrize("kind", [RuntimeError, ValueError, OSError])
def test_peer_thread_exception_is_a_gate_error(kind):
    import socket

    def broken(*args):
        raise kind("deliberate fixture failure")

    with pytest.raises(RuntimeError, match="accuracy peer"):
        with gate.response_peer({}, broken) as (port, requests):
            with socket.create_connection(("127.0.0.1", port), timeout=1) as connection:
                connection.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                assert connection.recv(1) == b""
