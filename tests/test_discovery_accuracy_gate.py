"""Known answers are fixture labels, never values inferred from detector output."""

from __future__ import annotations

import json

import pytest

from scripts.discovery_accuracy import COMMON, CORPUS, MODULES, load_corpus, measure, scan


def test_gate_rejects_value_prefix_wrong_type_wrong_place_and_duplicates():
    expected = [{"type": "password", "value": "full-password!42", "path": "$.db.password"}]
    assert measure(expected, expected)["tp"] == 1
    for field, replacement in [("value", "full"), ("type", "high_entropy"), ("path", "$.other.password")]:
        result = measure(expected, [{**expected[0], field: replacement}])
        assert result["fn"] == result["fp"] == 1
    duplicate = measure(expected, expected * 2)
    assert duplicate["duplicates"] == duplicate["fp"] == 1


def test_gate_locks_corpus_and_rejects_changed_labels(tmp_path):
    assert load_corpus()["cases"]
    copy = tmp_path / "modified.json"
    data = json.loads(CORPUS.read_bytes())
    data["cases"][0]["expected"] = []
    copy.write_text(json.dumps(data))
    with pytest.raises(ValueError, match="holdout changed"):
        load_corpus(copy)


@pytest.mark.parametrize("route", ["common", "disk-json", "stream-json", "elastic", "proxmox"])
def test_random_version_metadata_does_not_become_an_entropy_candidate(route):
    value = "qR7xN2pV5tC8fK3sM9zD6aL4bE1"
    actual, status = scan(route, {"version": value, "nested": {"version": value}, "password": value})
    assert status == "complete"
    assert {row["path"] for row in actual} == {"$.password"}


@pytest.mark.parametrize("route", MODULES)
@pytest.mark.parametrize("split", ["development", "holdout"])
def test_locked_known_answer_corpus_per_adapter(route, split):
    from scripts.discovery_accuracy import expected_rows, load_holdout

    for case in (load_holdout() if split == "holdout" else load_corpus())["cases"]:
        actual, status = scan(route, case["body"])
        result = measure(expected_rows(case, route), actual)
        assert status == case["status"], (route, case["id"], status)
        assert not any(result[k] for k in ("fn", "fp", "duplicates", "confidence_mismatch")), (
            route,
            case["id"],
            result,
            actual,
        )


def test_gate_includes_every_existing_discover_command():
    from redposture_core.cli_args import parse_args
    from redposture_core.module_registry import AUDIT_MODULE_NAMES

    expected = {name for name in AUDIT_MODULE_NAMES if hasattr(parse_args([name, "-t", "127.0.0.1"]), "discover")}
    assert len(MODULES) == len(set(MODULES)) == 31
    assert set(MODULES) == expected
    assert len(COMMON) == 22


@pytest.mark.parametrize("module", MODULES)
def test_adapter_preserves_simple_known_value_type_and_path(module):
    actual, status = scan(module, {"db": {"password": "ordinary-inactive-secret!42"}})
    result = measure([{"type": "password", "value": "ordinary-inactive-secret!42", "path": "$.db.password"}], actual)
    assert status == "complete"
    assert result["tp"] == 1 and result["fn"] == result["fp"] == result["duplicates"] == 0


@pytest.mark.parametrize("module", MODULES)
def test_repeated_adapter_scan_does_not_retain_findings_from_previous_or_modified_source(module):
    # This proves DTO/detector state isolation, not network snapshot consistency.
    for value in ("inactive-before!42", "inactive-before!42", "inactive-after!42"):
        rows, status = scan(module, {"db": {"password": value}})
        assert status == "complete"
        result = measure([{"type": "password", "value": value, "path": "$.db.password"}], rows)
        assert result["tp"] == 1 and result["fn"] == result["fp"] == result["duplicates"] == 0


@pytest.mark.parametrize("streamed", [False, True])
def test_proxmox_retains_ordinary_low_confidence_candidate(streamed):
    import time

    from redposture_core.clients.http_api import HttpResponse
    from redposture_core.modules.proxmox.actions import _scan_endpoint_payload
    from redposture_core.modules.proxmox.discovery import stream_proxmox_response

    value = "qR7xN2pV5tC8fK3sM9zD6aL4bE1"
    raw = json.dumps({"data": {"message": f"received {value} completed"}}).encode()
    if streamed:

        class Pool:
            def request_stream(self, _method, _url, *, on_response, on_chunk, **_kwargs):
                on_response(200, {})
                for i in range(0, len(raw), 7):
                    on_chunk(raw[i : i + 7])
                return HttpResponse(200, b"", {})

        _, payload, headers, error = stream_proxmox_response(
            Pool(),
            "http://accuracy.invalid/api2/json/nodes/qa/config",
            "/nodes/qa/config",
            headers={},
            timeout=1,
            deadline=time.monotonic() + 30,
        )
        assert error is None and "x-redposture-discovery-error" not in headers
        rows = list(payload.findings)
    else:
        rows = []
        assert _scan_endpoint_payload("/nodes/qa/config", raw, rows, set())
    assert [(r["type"], r["sample"], r["path"], r["confidence"]) for r in rows] == [
        ("high_entropy", value, "$.message", "low")
    ]
