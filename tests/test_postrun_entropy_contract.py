"""QA accepts the ordinary low-candidate list while keeping strict corpus checks."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from scripts import verify_postrun as postrun


def verify(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, candidate: dict[str, Any]) -> None:
    location = {"source_kind": "document", "object": "corpus/one", "index": "corpus", "id": "one"}
    expected = {"secret_type": "password", "value": "inactive-postrun-password!42", "locations": [location]}
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({"findings": [expected], "expected_secret_types": ["password"]}))
    finding = {**expected, "fingerprint": "sha256:expected", "score": 90, "confidence": "high", "occurrence_count": 1}
    record = {
        "vendor": "qa",
        "status": "open_no_auth",
        "is_elastic": True,
        "discover": True,
        "discover_schema_version": 2,
        "discover_findings": [finding, candidate],
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
    monkeypatch.setitem(postrun._DISCOVER_LAB_CONTRACTS, "qa_entropy", {"vendor": "qa"})
    postrun._validate_discover_lab_contracts(
        [{"label": "qa_entropy", "exit_code": "0", "json_path": str(artifact)}], manifest_path=manifest
    )


def low_candidate() -> dict[str, Any]:
    return {
        "fingerprint": "sha256:candidate",
        "value": "random-audit-resource-id-0123",
        "secret_type": "high_entropy",
        "confidence": "low",
        "score": 55,
        "detectors": ["entropy_candidate"],
        "occurrence_count": 1,
        "locations": [{"source_kind": "document", "object": "audit/two", "index": "audit", "id": "two"}],
    }


def test_postrun_accepts_low_entropy_in_an_unrelated_audit_document(tmp_path, monkeypatch):
    verify(tmp_path, monkeypatch, low_candidate())


@pytest.mark.parametrize(
    "field,value", [("confidence", "unknown"), ("secret_type", "password"), ("detectors", []), ("score", 90)]
)
def test_low_candidate_must_keep_its_explicit_evidence_class(tmp_path, monkeypatch, field, value):
    candidate = low_candidate()
    candidate[field] = value
    with pytest.raises(SystemExit, match="confidence|low-confidence"):
        verify(tmp_path, monkeypatch, candidate)


def test_low_candidate_cannot_hide_an_unexpected_finding_inside_the_labelled_corpus(tmp_path, monkeypatch):
    candidate = low_candidate()
    candidate["locations"] = [{"source_kind": "document", "object": "corpus/extra", "index": "corpus", "id": "extra"}]
    with pytest.raises(SystemExit, match="corpus mismatch"):
        verify(tmp_path, monkeypatch, copy.deepcopy(candidate))
