from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from redposture_core.modules.elastic.discover import FindingAccumulator, scan_value_tree
from scripts.verify_elastic_discover_corpus import verify_records

ROOT = Path(__file__).resolve().parents[1]
CORPUS_DIR = ROOT / "tests/fixtures/elastic_discover"


def _load_corpus() -> list[tuple[str, str, dict[str, Any]]]:
    lines = (CORPUS_DIR / "discover_corpus.ndjson").read_text(encoding="utf-8").splitlines()
    assert len(lines) % 2 == 0
    documents: list[tuple[str, str, dict[str, Any]]] = []
    for offset in range(0, len(lines), 2):
        action = json.loads(lines[offset])
        document = json.loads(lines[offset + 1])
        documents.append((action["index"]["_index"], action["index"]["_id"], document))
    return documents


def _manifest() -> dict[str, Any]:
    return json.loads((CORPUS_DIR / "discover_corpus_expected.json").read_text(encoding="utf-8"))


def test_shared_discover_corpus_covers_all_exported_types_and_document_locations() -> None:
    manifest = _manifest()
    accumulator = FindingAccumulator()
    suppressed = 0
    negative_detections = []
    for index, document_id, document in _load_corpus():
        result = scan_value_tree(
            document,
            source_kind="document",
            object_name=f"{index}/{document_id}",
            index=index,
            document_id=document_id,
        )
        suppressed += result.suppressed_indicators
        if document_id == "negative-controls":
            negative_detections = result.detections
        for detection, location in result.detections:
            accumulator.add(detection, location)

    findings = accumulator.findings()
    by_key = {(finding.secret_type, finding.value): finding for finding in findings}
    expected_documents = [
        item
        for item in manifest["findings"]
        if any(location.get("source_kind") == "document" for location in item.get("locations", []))
    ]
    for expected in expected_documents:
        key = (expected["secret_type"], expected["value"])
        assert key in by_key
        finding = by_key[key]
        for expected_location in expected["locations"]:
            assert any(
                all(location.to_dict().get(name) == value for name, value in expected_location.items())
                for location in finding.locations
            )
        assert finding.occurrence_count >= expected.get("occurrence_count_min", 1)

    assert {finding.secret_type for finding in findings} == set(manifest["expected_secret_types"])
    assert negative_detections == []
    assert suppressed >= 3
    assert not set(manifest["forbidden_values"]) & {finding.value for finding in findings}


def test_shared_corpus_mapping_and_seed_are_vendor_neutral_and_fail_closed() -> None:
    mapping = json.loads((CORPUS_DIR / "discover_corpus_mapping.json").read_text(encoding="utf-8"))
    seed = (CORPUS_DIR / "seed_elastic.sh").read_text(encoding="utf-8")

    assert mapping["mappings"]["_meta"]["client_secret"] == "CorpusMappingMetaSecret!2026"
    assert "dynamic_templates" in mapping["mappings"]
    assert '"errors":false' in seed
    assert 'bulk_file "${CORPUS_DIR}/discover_corpus.ndjson"' in seed
    assert 'SEARCH_VENDOR}" = "opensearch"' in seed
    assert '"derived"' in seed
    assert '"runtime"' in seed
    assert "search.insights.top_queries.latency.enabled" in seed
    assert "touch /tmp/redposture-search-seed-ready" in seed


def test_search_lab_compose_ports_are_bound_to_loopback() -> None:
    for service in ("elastic", "opensearch"):
        compose_file = CORPUS_DIR / f"{service}-compose.yml"
        published = re.findall(
            r'^\s+- "([^"\s]+:\d+:\d+)"\s*$',
            compose_file.read_text(encoding="utf-8"),
            flags=re.MULTILINE,
        )
        assert published
        assert all(port.startswith("127.0.0.1:") for port in published)


def test_corpus_verifier_checks_locations_negatives_types_and_surface_coverage() -> None:
    finding = {
        "secret_type": "password",
        "value": "CorpusVerifierPassword!2026",
        "occurrence_count": 1,
        "locations": [
            {
                "source_kind": "document",
                "object": "redposture-discover-corpus-v2/doc-1",
                "index": "redposture-discover-corpus-v2",
                "id": "doc-1",
                "path": "/password",
            }
        ],
    }
    record = {
        "discover_findings": [finding],
        "discover_coverage": {
            "surfaces": {
                "index_inventory": {
                    "status": "complete",
                    "objects_scanned": 1,
                }
            }
        },
    }
    manifest = {
        "corpus_index": "redposture-discover-corpus-v2",
        "expected_secret_types": ["password"],
        "findings": [
            {
                "secret_type": "password",
                "value": "CorpusVerifierPassword!2026",
                "locations": [{"source_kind": "document", "index": "redposture-discover-corpus-v2"}],
                "vendors": ["opensearch"],
            }
        ],
        "forbidden_values": ["REDACTED"],
        "expected_surfaces": {
            "index_inventory": {
                "allowed_statuses": ["complete"],
                "objects_scanned_min": 1,
            }
        },
    }

    assert verify_records([record], manifest, vendor="opensearch") == []

    finding["value"] = "REDACTED"
    errors = verify_records([record], manifest, vendor="opensearch")
    assert any(error.startswith("missing finding:") for error in errors)
    assert any(error.startswith("forbidden negative control exported:") for error in errors)
