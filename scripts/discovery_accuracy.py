"""Locked known-answer secret gate. Local DTO/readers only; never contacts targets.

Labels describe authored, inactive examples, not production prevalence. The
holdout is frozen before measurement; it is not externally or blindly reviewed.
Actual enumeration, authentication and UI availability require separate tests.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import resource
import sys
import time
from collections import Counter
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

from redposture_core.data_discovery import inspect_record
from redposture_core.discovery_engine import _scan_portioned_value
from redposture_core.discovery_values import CredentialObject, DiskBackedText, iter_json_chunks
from redposture_core.storage_discovery import DiscoveryCollector

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "tests/fixtures/discovery_accuracy/holdout-v3.json"
CORPUS_SHA256 = "55296c01675172090dd9874c593844e4c4a974067d16807c59182c6a002494f8"
COMMON = {
    "docker": ("docker_metadata", "$.docker_metadata[0]", "list"),
    "rabbitmq": ("rabbitmq_metadata", "$.rabbitmq_metadata[0]", "list"),
    "grafana": ("grafana_metadata", "$.grafana_metadata[0]", "list"),
    "keycloak": ("keycloak_metadata", "$.keycloak_metadata[0]", "list"),
    "redis": ("key_value_entries", "$.key_value_entries.corpus.corpus", "kv"),
    "etcd": ("key_value_entries", "$.key_value_entries.corpus.corpus", "kv"),
    "consul": ("kv_dump_items", "$.kv_dump_items.corpus.corpus", "kv"),
    "vault": ("kv_dump_items", "$.kv_dump_items.corpus.corpus", "kv"),
    "postgres": ("table_dumps", "$.table.qa.corpus[0]", "table"),
    "mongodb": ("documents", "$.qa.corpus", "document"),
    "oracle": ("rows", "$.table.qa.corpus", "row"),
    "qdrant": ("payload_discovery_items", "$.collection.corpus[0]", "points"),
    "kubeapi": ("configmaps", "$.configmaps.qa.corpus", "configmap"),
    "jenkins": ("job_configs", "$.job.corpus.config", "config"),
    "kafka": ("dump_results", "$.topic.corpus[0]", "topic"),
    "zookeeper": ("znode_values", "$.znode./corpus.corpus", "znode"),
    "keeper": ("znode_values", "$.znode./corpus.corpus", "znode"),
    "nomad": ("job_specs", "$.job_specs[0]", "list"),
    "jupyter": ("notebook_contents", "$.notebook_contents[0]", "list"),
    "spark": ("spark_metadata", "$.spark_metadata[0]", "list"),
    "yarn": ("app_specs", "$.app_specs[0]", "list"),
    "portainer": ("portainer_metadata", "$.portainer_metadata[0]", "list"),
}
STORAGE = ("gitlab", "harbor", "nexus", "docker-registry")
MODULES = (*COMMON, *STORAGE, "airflow", "elastic", "minio", "proxmox", "clickhouse")
READERS = ("common", "disk-json", "stream-json")
LEGACY_HOLDOUT = ROOT / "tests/fixtures/discovery_accuracy/locked-holdout-v1.json"
LEGACY_HOLDOUT_SHA256 = "d282119afc054eaeedbcceac34897dedcd0feb02152f25515a7d985be81962f8"
HOLDOUT = ROOT / "tests/fixtures/discovery_accuracy/locked-holdout-v3.json"
HOLDOUT_SHA256 = "f815a09e00ec24f19a358cbabcc63b63d4f84908c0a53bf0fced2bcc530fd88c"


def full(value: Any) -> str:
    return "".join(value.iter_text_chunks()) if isinstance(value, DiskBackedText) else str(value)


def load_corpus(path: Path = CORPUS) -> dict[str, Any]:
    return _load_locked(path, CORPUS_SHA256)


def load_holdout(path: Path = HOLDOUT) -> dict[str, Any]:
    return _load_locked(path, HOLDOUT_SHA256)


def _load_locked(path: Path, expected_sha256: str) -> dict[str, Any]:
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise ValueError("holdout changed: create and review a new version, never update labels from actual results")
    corpus = json.loads(raw)
    cases = corpus["cases"]
    if len({row["id"] for row in cases}) != len(cases):
        raise ValueError("duplicate case id")
    for row in cases:
        # The label author encodes JSON solely to avoid publishing raw
        # provider-token-shaped fixture literals. This lossless codec knows no
        # detection rules and never derives expected answers from the scanner.
        if "body_json_base64" in row:
            if "body" in row:
                raise ValueError("ambiguous fixture body")
            row["body"] = json.loads(base64.b64decode(row.pop("body_json_base64"), validate=True).decode("utf-8"))
        for finding in row["expected"]:
            if "value_json_base64" in finding:
                if "value" in finding:
                    raise ValueError("ambiguous fixture value")
                finding["value"] = json.loads(
                    base64.b64decode(finding.pop("value_json_base64"), validate=True).decode("utf-8")
                )
            if not finding["path"].startswith("$") or not finding["value"]:
                raise ValueError("invalid independent label")
    return corpus


def record_input(module: str, body: Any) -> tuple[dict[str, Any], str]:
    field, prefix, kind = COMMON[module]
    wrappers = {
        "kv": lambda: [{"key": "corpus", "value": body}],
        "table": lambda: [{"database": "qa", "table": "corpus", "rows": [body]}],
        "document": lambda: [{"database": "qa", "collection": "corpus", "document": body}],
        "row": lambda: [{"schema": "qa", "table": "corpus", "row": body}],
        "points": lambda: [{"collection": "corpus", "points": [body]}],
        "configmap": lambda: [{"namespace": "qa", "name": "corpus", "data": body}],
        "config": lambda: [{"job": "corpus", "config": body}],
        "topic": lambda: {"corpus": [body]},
        "znode": lambda: ["/corpus:" + json.dumps(body, ensure_ascii=False)],
        "list": lambda: [body],
    }
    return {"status": "open_no_auth", field: wrappers[kind]()}, prefix


def compact_rows(rows: Any, *, prefix: str = "$") -> list[dict[str, str]]:
    result = []
    for row in rows:
        # A path outside the declared adapter envelope remains visible and fails
        # the gate, rather than being stripped with an arbitrary suffix match.
        locations = row.get("locations") or [{"object_path": row["object_path"]}]
        for location in locations:
            path = full(location.get("object_path", row["object_path"]))
            if path == prefix or path.startswith(prefix + ".") or path.startswith(prefix + "["):
                path = "$" + path[len(prefix) :]
            result.append(
                {
                    "value": full(row["value"]),
                    "value_kind": "object" if isinstance(row["value"], CredentialObject) else "string",
                    "type": row["type"],
                    "path": path,
                    "confidence": row.get("confidence", "unspecified"),
                }
            )
    return result


def scan(route: str, body: Any, *, portion: int = 37) -> tuple[list[dict[str, str]], str]:
    """Use real adapter entrypoints, with explicit transport/evidence scope."""
    if route in COMMON:
        payload, prefix = record_input(route, body)
        report = inspect_record(route, payload)
        return compact_rows(report["findings"], prefix=prefix), report["status"]
    if route in STORAGE or route == "stream-json":
        collector = DiscoveryCollector(
            route if route in STORAGE else "gitlab",
            SimpleNamespace(host="accuracy.invalid", port=443, args=SimpleNamespace(discover_time=30)),
            {"status": "open_no_auth"},
        )
        if route == "stream-json":
            raw = json.dumps(body, ensure_ascii=False).encode()
            collector.scan_json_chunks("corpus", (raw[i : i + portion] for i in range(0, len(raw), portion)))
        else:
            # This harness represents an HTTP 200 content read. An empty value
            # is authorized content; merely constructing a collector is not.
            collector.mark_accessible_source()
            collector.add("corpus", body)
        report = collector.result()
        return compact_rows(report["findings"], prefix="$.corpus"), report["status"]
    if route in {"common", "disk-json"}:
        with DiskBackedText() as disk:
            disk.append_text(json.dumps(body, ensure_ascii=False))
            disk.finish()
            matches, _, complete = _scan_portioned_value(disk if route == "disk-json" else body, "$", portion)
            rows = [
                {"value": m.value, "type": m.detector, "object_path": m.object_path, "confidence": m.confidence}
                for m in matches
            ]
            return compact_rows(rows), "complete" if complete else "partial"
    if route == "elastic":
        from redposture_core.modules.elastic.discover import FindingAccumulator, scan_value_tree

        result = scan_value_tree(body, source_kind="document", object_name="qa/corpus")
        accumulator = FindingAccumulator()
        for match, location in result.detections:
            accumulator.add(match, location)
        rows = []
        for finding in accumulator.findings():
            for location in finding.locations:
                pointer = full(location.path)
                # Fixtures contain only simple object keys. Keep unusual JSON
                # pointers literal: unsupported conversion must not hide a miss.
                path = "$" + ".".join(["", *pointer.lstrip("/").split("/")]) if pointer else "$"
                rows.append(
                    {
                        "value": full(finding.value),
                        "value_kind": "object" if isinstance(finding.value, CredentialObject) else "string",
                        "type": finding.secret_type,
                        "path": path,
                        "confidence": finding.confidence,
                    }
                )
        return rows, "partial" if result.truncated_reasons else "complete"
    if route == "minio":
        from redposture_core.clients.minio_api import MinioResponse
        from redposture_core.modules.minio.discover import Budget, discover_secrets
        from redposture_core.modules.minio.enumerate import ObjectInfo

        raw = json.dumps(body, ensure_ascii=False).encode()

        class Reader:
            def get_object_range(
                self, _bucket: str, _key: str, *, start: int, length: int, signed: bool
            ) -> MinioResponse:
                return MinioResponse(206, {}, raw[start : start + length])

        minio_report = discover_secrets(
            Reader(), [ObjectInfo("qa", "corpus.json", len(raw))], budget=Budget(chunk_size=portion)
        )
        return compact_rows(minio_report.findings), "complete" if minio_report.coverage_complete else "partial"
    if route == "proxmox":
        from redposture_core.modules.proxmox.actions import _scan_endpoint_payload

        findings: list[dict[str, Any]] = []
        complete = _scan_endpoint_payload("/nodes/qa/config", json.dumps({"data": body}).encode(), findings, set())
        rows = [
            {
                "value": r["sample"],
                "type": r["reason"],
                "object_path": r["path"],
                "confidence": r.get("confidence", "unspecified"),
            }
            for r in findings
        ]
        return compact_rows(rows), "complete" if complete else "partial"
    if route == "clickhouse":
        from redposture_core.modules.clickhouse.discover.engine import _scan_rows
        from redposture_core.modules.clickhouse.discover.findings import FindingStore
        from redposture_core.modules.clickhouse.discover.models import ScanChunk
        from redposture_core.secret_detection import detector_names

        column_findings = FindingStore()
        coverage = {"qa.corpus.config": {"rows_scanned": 0, "bytes_scanned": 0}}
        complete = _scan_rows(
            [[body]],
            ScanChunk("qa", "corpus", ("config",), None, 0, 1),
            column_findings,
            coverage,
            enabled=detector_names(),
            redact=False,
        )
        return compact_rows(column_findings.values()), "complete" if complete else "partial"
    if route == "airflow":
        from redposture_core.clients.airflow_api import AirflowClient, AirflowResponse
        from redposture_core.modules.airflow.discover import DiscoverConfig, discover_task_logs

        class Client:
            def get(self, path: str, **_kwargs: Any) -> AirflowResponse:
                data: Any = (
                    {"variables": [{"key": "config", "value": body}], "total_entries": 1}
                    if "/variables?" in path
                    else {"dags": [], "total_entries": 0}
                )
                return AirflowResponse(200, {}, json.dumps(data).encode())

        report = discover_task_logs(cast(AirflowClient, Client()), "v1", DiscoverConfig(include_variables=True))
        return compact_rows(report["findings"], prefix="$.config"), report["status"]
    raise ValueError(f"unknown accuracy route: {route}")


def measure(expected: list[dict[str, str]], actual: list[dict[str, str]]) -> dict[str, int]:
    """Do not collapse duplicates or accept a matching prefix as a correct value."""

    def value_key(row: dict[str, str]) -> tuple[str, str]:
        return hashlib.sha256(row["value"].encode()).hexdigest(), row.get("value_kind", "string")

    def key(row: dict[str, str]) -> tuple[tuple[str, str], str, str]:
        return value_key(row), row["type"], row["path"]

    want, got = Counter(map(key, expected)), Counter(map(key, actual))
    want_values = {value_key(r) for r in expected}
    got_values = {value_key(r) for r in actual}
    return {
        "tp": sum((want & got).values()),
        "fn": sum((want - got).values()),
        "fp": sum((got - want).values()),
        "duplicates": sum(n - 1 for n in got.values() if n > 1),
        "value_missing": len(want_values - got_values),
        "value_extra": len(got_values - want_values),
        "low_confidence": sum(r.get("confidence") == "low" for r in actual),
        "confidence_mismatch": sum(
            1
            for want_row in expected
            if "confidence" in want_row
            and any(
                key(got_row) == key(want_row) and got_row.get("confidence") != want_row["confidence"]
                for got_row in actual
            )
        ),
    }


def expected_rows(case: dict[str, Any], route: str) -> list[dict[str, str]]:
    # JSON-field location and a parser's subfield locator are both precise but
    # different published contracts. Labels declare both, not a suffix wildcard.
    return [
        {
            **row,
            "value": json.dumps(row["value"], sort_keys=True, ensure_ascii=False, separators=(",", ":"))
            if isinstance(row["value"], dict)
            else row["value"],
            "value_kind": "object" if isinstance(row["value"], dict) else row.get("value_kind", "string"),
            "path": row.get("embedded_path", row["path"]) if route != "elastic" else row["path"],
        }
        for row in case["expected"]
    ]


def run(routes: list[str], *, split: str = "holdout") -> dict[str, Any]:
    corpus = (
        load_holdout()
        if split == "holdout"
        else _load_locked(LEGACY_HOLDOUT, LEGACY_HOLDOUT_SHA256)
        if split == "legacy-holdout"
        else load_corpus()
    )
    rows = []
    for route in routes:  # deliberately serial, no sockets or stands
        for case in corpus["cases"]:
            start = time.monotonic()
            start_cpu = time.process_time()
            expected = expected_rows(case, route)
            try:
                actual, status = scan(route, case["body"])
                metrics = measure(expected, actual)
                error = None
            except Exception as exc:
                actual, status, metrics, error = [], "error", measure(expected, []), repr(exc)
            rows.append(
                {
                    "route": route,
                    "case": case["id"],
                    "metrics": metrics,
                    "status": status,
                    "expected_status": case["status"],
                    "wall_seconds": time.monotonic() - start,
                    "cpu_seconds": time.process_time() - start_cpu,
                    "actual": actual,
                    "error": error,
                }
            )
    failed = [
        r
        for r in rows
        if r["error"]
        or r["status"] != r["expected_status"]
        or any(r["metrics"][k] for k in ("fn", "fp", "duplicates", "confidence_mismatch"))
    ]
    totals: Counter[str] = Counter()
    for row in rows:
        totals.update(row["metrics"])
    return {
        "status": "FAIL" if failed else "PASS",
        "corpus_sha256": HOLDOUT_SHA256
        if split == "holdout"
        else LEGACY_HOLDOUT_SHA256
        if split == "legacy-holdout"
        else CORPUS_SHA256,
        "split": split,
        "scope": "authored locked DTO/reader holdout, not live-product or production accuracy",
        "routes": routes,
        "cases": len(corpus["cases"]),
        "failures": len(failed),
        "totals": dict(totals),
        "wall_seconds": sum(row["wall_seconds"] for row in rows),
        "cpu_seconds": sum(row["cpu_seconds"] for row in rows),
        "results": rows,
        "peak_rss_bytes": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        * (1 if sys.platform == "darwin" else 1024),
        "first_finding_seconds": None,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--route", action="append", choices=(*READERS, *MODULES))
    parser.add_argument("--split", choices=("development", "holdout", "legacy-holdout"), default="holdout")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    result = run(args.route or [*READERS, *MODULES], split=args.split)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text("".join(iter_json_chunks(result)) + "\n")
    print(json.dumps({k: result[k] for k in ("status", "cases", "failures", "scope")}))
    return int(result["status"] != "PASS")


if __name__ == "__main__":
    sys.exit(main())
