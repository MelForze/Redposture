"""The QA oracle compares complete typed credential objects, not repr strings."""

from __future__ import annotations

import json

import pytest

from scripts import verify_postrun as verifier


@pytest.mark.parametrize("mode", ["same", "stringified", "missing", "changed", "extra"])
def test_postrun_checks_whole_object_value_and_its_json_type(tmp_path, monkeypatch, mode):
    value = {"client_id": "qa-app", "client_secret": "inactive-client-secret-42"}
    location = {"source_kind": "document", "object": "corpus/one", "index": "corpus", "id": "one", "path": "/oauth"}
    expected = {"secret_type": "oauth_credentials", "value": value, "locations": [location]}
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({"findings": [expected], "expected_secret_types": ["oauth_credentials"]}))
    actual: object = dict(reversed(list(value.items())))
    if mode == "stringified":
        actual = json.dumps(value)
    elif mode == "missing":
        actual = {"client_secret": value["client_secret"]}
    elif mode == "changed":
        actual = {**value, "client_secret": "different-secret-84"}
    elif mode == "extra":
        actual = {**value, "refresh_token": "unrelated-token-84"}
    record = {
        "vendor": "qa",
        "status": "open_no_auth",
        "is_elastic": True,
        "discover": True,
        "discover_schema_version": 2,
        "discover_findings": [
            {
                **expected,
                "value": actual,
                "fingerprint": "sha256:expected",
                "score": 99,
                "confidence": "high",
                "occurrence_count": 1,
            }
        ],
        "discover_coverage": {
            "status": "complete",
            "complete": True,
            "indices_scanned": 1,
            "documents_scanned": 1,
            "surfaces": {},
        },
    }
    artifact = tmp_path / "audit.json"
    artifact.write_text(json.dumps(record))
    monkeypatch.setitem(verifier._DISCOVER_LAB_CONTRACTS, "qa_objects", {"vendor": "qa"})
    rows = [{"label": "qa_objects", "exit_code": "0", "json_path": str(artifact)}]
    if mode == "same":
        verifier._validate_discover_lab_contracts(rows, manifest_path=manifest)
    else:
        with pytest.raises(SystemExit, match="corpus mismatch"):
            verifier._validate_discover_lab_contracts(rows, manifest_path=manifest)


def test_kube_golden_ignores_runtime_pod_status_byte_count_only():
    # Real K3s system pods changed Pending -> Running between fresh stands;
    # their raw responses differed by 274 bytes with identical audit findings.
    first = {"content_discovery": {"bytes_read": 57250, "status": "complete", "findings": []}}
    second = {"content_discovery": {"bytes_read": 57524, "status": "complete", "findings": []}}

    def normalize(value):
        return verifier._normalize_for_golden(value, module="kubeapi", label="kubeapi_open")

    assert normalize(first) == normalize(second)
    assert normalize(first) != normalize(
        {"content_discovery": {"bytes_read": 57524, "status": "partial", "findings": []}}
    )
    assert verifier._normalize_for_golden(first, module="redis") != verifier._normalize_for_golden(
        second, module="redis"
    )
