#!/usr/bin/env python3
"""Verify discover-v2 JSONL against the shared Elasticsearch/OpenSearch corpus."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = ROOT / "tests/fixtures/elastic_discover/discover_corpus_expected.json"


def _load_json_records(path: Path) -> list[dict[str, Any]]:
    text = path.read_text(encoding="utf-8").strip()
    if not text:
        return []
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        records: list[dict[str, Any]] = []
        for line_number, line in enumerate(text.splitlines(), start=1):
            if not line.strip():
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid JSONL at line {line_number}: {exc}") from exc
            if not isinstance(item, dict):
                raise ValueError(f"JSONL line {line_number} is not an object") from None
            records.append(item)
        return records
    if isinstance(payload, dict):
        return [payload]
    if isinstance(payload, list) and all(isinstance(item, dict) for item in payload):
        return list(payload)
    raise ValueError("discover output must be a JSON object, JSON array, or JSONL objects")


def _matches_location(actual: Mapping[str, Any], expected: Mapping[str, Any]) -> bool:
    return all(actual.get(key) == value for key, value in expected.items())


def _finding_key(item: Mapping[str, Any]) -> tuple[str, str]:
    return str(item.get("secret_type") or ""), str(item.get("value") or "")


def _is_corpus_scoped(item: Mapping[str, Any], corpus_index: str) -> bool:
    if "Corpus" in str(item.get("value") or "") or "Q29ycHVz" in str(item.get("value") or ""):
        return True
    locations = item.get("locations")
    if not isinstance(locations, list):
        return False
    for location in locations:
        if not isinstance(location, Mapping):
            continue
        index = str(location.get("index") or "")
        object_name = str(location.get("object") or "")
        if index == corpus_index or object_name.startswith((corpus_index, "redposture-corpus-")):
            return True
    return False


def verify_records(
    records: Sequence[Mapping[str, Any]],
    manifest: Mapping[str, Any],
    *,
    vendor: str,
) -> list[str]:
    """Return deterministic contract violations; an empty list means success."""

    errors: list[str] = []
    discover_records = [record for record in records if isinstance(record.get("discover_findings"), list)]
    if not discover_records:
        return ["no record contains discover_findings"]
    findings = [
        finding
        for record in discover_records
        for finding in record.get("discover_findings", [])
        if isinstance(finding, Mapping)
    ]
    actual_by_key: dict[tuple[str, str], Mapping[str, Any]] = {}
    for finding in findings:
        key = _finding_key(finding)
        if key in actual_by_key:
            errors.append(f"duplicate serialized finding: {key[0]} value={key[1]!r}")
        actual_by_key[key] = finding

    raw_expected = manifest.get("findings")
    if not isinstance(raw_expected, list):
        return ["manifest findings must be a list"]
    expected = [
        item
        for item in raw_expected
        if isinstance(item, Mapping)
        and vendor in {str(value) for value in item.get("vendors", []) if isinstance(value, str)}
    ]
    expected_keys = {_finding_key(item) for item in expected}
    for item in expected:
        key = _finding_key(item)
        actual = actual_by_key.get(key)
        if actual is None:
            errors.append(f"missing finding: {key[0]} value={key[1]!r}")
            continue
        expected_locations = item.get("locations")
        actual_locations = actual.get("locations")
        if isinstance(expected_locations, list) and expected_locations:
            if not isinstance(actual_locations, list):
                errors.append(f"finding has no locations: {key[0]} value={key[1]!r}")
            else:
                for location in expected_locations:
                    if isinstance(location, Mapping) and not any(
                        isinstance(candidate, Mapping) and _matches_location(candidate, location)
                        for candidate in actual_locations
                    ):
                        errors.append(
                            f"missing location for {key[0]} value={key[1]!r}: "
                            f"{json.dumps(dict(location), sort_keys=True)}"
                        )
        minimum = int(item.get("occurrence_count_min") or 1)
        if int(actual.get("occurrence_count") or 0) < minimum:
            errors.append(
                f"occurrence_count for {key[0]} value={key[1]!r} is "
                f"{actual.get('occurrence_count')!r}, expected >= {minimum}"
            )

    corpus_index = str(manifest.get("corpus_index") or "")
    unexpected = sorted(
        key for key, item in actual_by_key.items() if _is_corpus_scoped(item, corpus_index) and key not in expected_keys
    )
    for secret_type, value in unexpected:
        errors.append(f"unexpected corpus finding: {secret_type} value={value!r}")

    forbidden = {str(value) for value in manifest.get("forbidden_values", [])}
    for secret_type, value in actual_by_key:
        if value in forbidden:
            errors.append(f"forbidden negative control exported: {secret_type} value={value!r}")

    expected_types = {str(value) for value in manifest.get("expected_secret_types", [])}
    found_expected_types = {key[0] for key in expected_keys if key in actual_by_key}
    if found_expected_types != expected_types:
        missing = sorted(expected_types - found_expected_types)
        extra = sorted(found_expected_types - expected_types)
        errors.append(f"secret type coverage mismatch: missing={missing} extra={extra}")

    coverage_records: list[Mapping[str, Any]] = []
    for record in discover_records:
        coverage_item = record.get("discover_coverage")
        if isinstance(coverage_item, Mapping):
            coverage_records.append(coverage_item)
    if not coverage_records:
        errors.append("no record contains discover_coverage")
        return errors
    coverage = coverage_records[0]
    surfaces = coverage.get("surfaces")
    if not isinstance(surfaces, Mapping):
        errors.append("discover_coverage.surfaces is missing")
        return errors
    expected_surfaces = manifest.get("expected_surfaces")
    if isinstance(expected_surfaces, Mapping):
        for name, contract in expected_surfaces.items():
            actual = surfaces.get(name)
            if not isinstance(actual, Mapping) or not isinstance(contract, Mapping):
                errors.append(f"coverage surface missing: {name}")
                continue
            allowed = {str(value) for value in contract.get("allowed_statuses", [])}
            status = str(actual.get("status") or "")
            if allowed and status not in allowed:
                errors.append(f"surface {name} status={status!r}, expected one of {sorted(allowed)}")
            minimum = int(contract.get("objects_scanned_min") or 0)
            if int(actual.get("objects_scanned") or 0) < minimum:
                errors.append(
                    f"surface {name} objects_scanned={actual.get('objects_scanned')!r}, expected >= {minimum}"
                )
    return errors


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path, help="redposture elastic --discover JSON/JSONL output")
    parser.add_argument("--vendor", required=True, choices=("elasticsearch", "opensearch"))
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    args = _parser().parse_args(list(argv) if argv is not None else None)
    try:
        records = _load_json_records(args.output)
        manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"discover corpus verification failed: {exc}", file=sys.stderr)
        return 2
    if not isinstance(manifest, dict):
        print("discover corpus verification failed: manifest root is not an object", file=sys.stderr)
        return 2
    errors = verify_records(records, manifest, vendor=args.vendor)
    if errors:
        print("discover corpus verification failed:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    expected_count = sum(
        1
        for item in manifest.get("findings", [])
        if isinstance(item, Mapping) and args.vendor in item.get("vendors", [])
    )
    print(f"discover corpus verified vendor={args.vendor} expected_findings={expected_count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
