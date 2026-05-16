#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

_EXPECTED_MODULES = (
    "exporters",
    "registry",
    "grafana",
    "gitlab",
    "consul",
    "kubeapi",
    "postgres",
    "mongodb",
    "docker",
    "clickhouse",
    "redis",
    "etcd",
    "qdrant",
    "elastic",
    "grpc",
    "kafka",
    "zookeeper",
    "proxmox",
)

_EXPECTED_LABELS = (
    "exporters_scan",
    "exporters_collect",
    "exporters_trigger",
    "exporters_scan_url_http",
    "exporters_scan_url_https_reject",
    "exporters_collect_url_http",
    "exporters_collect_url_https_reject",
    "exporters_trigger_url_http",
    "exporters_trigger_url_https_reject",
    "registry_open",
    "registry_auth",
    "registry_harbor",
    "registry_gitlab",
    "registry_nexus",
    "registry_url_http",
    "registry_url_https_reject",
    "registry_multi_instance_urls",
    "grafana_default",
    "grafana_url_http",
    "grafana_url_https_reject",
    "grafana_ssrf_edge",
    "grafana_multi_instance_urls",
    "gitlab_public",
    "gitlab_analyst",
    "gitlab_url_override_http",
    "gitlab_multi_instance_urls",
    "consul_open",
    "consul_acl_read",
    "consul_acl_mgmt",
    "consul_url_hint_http",
    "consul_multi_instance_urls",
    "kubeapi_open",
    "kubeapi_auditor",
    "kubeapi_admin",
    "kubeapi_url_override_https",
    "kubeapi_multi_instance_urls",
    "postgres_default",
    "postgres_multi_ports",
    "mongodb_open",
    "mongodb_auth",
    "mongodb_defcreds",
    "mongodb_multi_ports",
    "mongodb_query_dump",
    "mongodb_debug_smoke",
    "docker_open",
    "docker_tls",
    "docker_multi_ports",
    "docker_inventory",
    "docker_exec",
    "docker_debug_smoke",
    "clickhouse_native_open",
    "clickhouse_http_open",
    "clickhouse_native_auth",
    "clickhouse_http_auth",
    "clickhouse_multi_ports",
    "redis_default",
    "redis_multi_ports",
    "etcd_open",
    "etcd_auth",
    "etcd_url_http",
    "etcd_url_https_reject",
    "etcd_multi_instance_urls",
    "qdrant_default",
    "qdrant_url_http",
    "qdrant_url_https_reject",
    "qdrant_multi_instance_urls",
    "elastic_open",
    "elastic_auth",
    "elastic_url_hint_https",
    "elastic_plugins_edge",
    "elastic_multi_instance_urls",
    "grpc_open",
    "grpc_auth_token",
    "grpc_auth_defcreds",
    "grpc_multi_ports",
    "grpc_debug_smoke",
    "grpc_invoke_health",
    "grpc_proto_invoke",
    "grpc_protoset_invoke",
    "grpc_openapi_export",
    "grpc_web_detect",
    "kafka_open",
    "kafka_auth",
    "kafka_multi_ports",
    "zookeeper_default",
    "zookeeper_multi_ports",
    "proxmox_audit",
    "proxmox_admin",
    "proxmox_url_override_https",
    "proxmox_multi_instance_urls",
)

_PROGRESS_EXPECTED_TARGETS = {
    "exporters_scan": 48,
    "registry_multi_instance_urls": 5,
    "grafana_multi_instance_urls": 5,
    "gitlab_multi_instance_urls": 5,
    "consul_multi_instance_urls": 5,
    "kubeapi_multi_instance_urls": 5,
    "postgres_multi_ports": 5,
    "mongodb_multi_ports": 5,
    "docker_multi_ports": 5,
    "clickhouse_multi_ports": 5,
    "redis_multi_ports": 5,
    "etcd_multi_instance_urls": 5,
    "qdrant_multi_instance_urls": 5,
    "elastic_multi_instance_urls": 5,
    "grpc_multi_ports": 5,
    "kafka_multi_ports": 5,
    "zookeeper_multi_ports": 5,
    "proxmox_multi_instance_urls": 5,
}

_PROGRESS_LINE_RE = re.compile(r"Running redposture against (\d+) targets?")


def _parse_status_file(path: Path) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    with path.open(encoding="utf-8") as fh:
        header = fh.readline().strip()
        if header not in {
            "module\tlabel\texit_code\tjson_path\tlog_path",
            "module\tlabel\texpected_exit\texit_code\tjson_path\tlog_path",
        }:
            raise SystemExit("matrix status header is invalid")
        has_expected_exit = header.startswith("module\tlabel\texpected_exit\t")
        for raw in fh:
            raw = raw.rstrip("\n")
            if not raw:
                continue
            parts = raw.split("\t")
            if has_expected_exit and len(parts) != 6:
                raise SystemExit(f"invalid matrix status row: {raw}")
            if not has_expected_exit and len(parts) != 5:
                raise SystemExit(f"invalid matrix status row: {raw}")
            if has_expected_exit:
                module, label, expected_exit, exit_code, json_path, log_path = parts
            else:
                module, label, exit_code, json_path, log_path = parts
                expected_exit = "0"
            rows.append(
                {
                    "module": module,
                    "label": label,
                    "expected_exit": expected_exit,
                    "exit_code": exit_code,
                    "json_path": json_path,
                    "log_path": log_path,
                }
            )
    return rows


def _validate_expected_exits(rows: list[dict[str, str]]) -> None:
    for row in rows:
        label = row["label"]
        try:
            expected_exit = int(row["expected_exit"])
        except (TypeError, ValueError) as exc:
            raise SystemExit(f"invalid expected_exit for label '{label}': {row['expected_exit']}") from exc
        try:
            exit_code = int(row["exit_code"])
        except (TypeError, ValueError) as exc:
            raise SystemExit(f"invalid exit_code for label '{label}': {row['exit_code']}") from exc
        if exit_code != expected_exit:
            raise SystemExit(f"label '{label}' exit mismatch: expected={expected_exit} actual={exit_code}")


def _validate_expected_labels(rows: list[dict[str, str]]) -> None:
    seen_labels = {row["label"] for row in rows}
    missing = sorted(label for label in _EXPECTED_LABELS if label not in seen_labels)
    if missing:
        raise SystemExit(f"matrix status is missing expected labels: {', '.join(missing)}")


def _validate_json_artifacts(rows: list[dict[str, str]]) -> Counter[str]:
    successful_modules: Counter[str] = Counter()

    for row in rows:
        log_path = Path(row["log_path"])
        if not log_path.exists():
            raise SystemExit(f"missing run log file: {log_path}")

        if row["exit_code"] != "0":
            continue

        json_path = row["json_path"]
        if json_path in {"", "-"}:
            successful_modules[row["module"]] += 1
            continue

        artifact = Path(json_path)
        if not artifact.exists() or artifact.stat().st_size == 0:
            raise SystemExit(f"missing or empty JSON artifact for successful run: {artifact}")

        try:
            with artifact.open("r", encoding="utf-8") as fh:
                payload = json.load(fh)
            if not isinstance(payload, (dict, list)):
                raise SystemExit(f"unexpected JSON payload type in {artifact}: {type(payload).__name__}")
        except json.JSONDecodeError:
            # Some module outputs are JSONL streams; treat as valid when each non-empty line is valid JSON.
            lines = [line for line in artifact.read_text(encoding="utf-8").splitlines() if line.strip()]
            if not lines:
                raise SystemExit(f"empty JSONL artifact for successful run: {artifact}") from None
            for idx, line in enumerate(lines, start=1):
                try:
                    payload_line = json.loads(line)
                except Exception as exc:  # pragma: no cover - surfaced via SystemExit
                    raise SystemExit(f"invalid JSONL artifact {artifact} at line {idx}: {exc}") from exc
                if not isinstance(payload_line, (dict, list)):
                    raise SystemExit(
                        f"unexpected JSONL payload type in {artifact} at line {idx}: {type(payload_line).__name__}"
                    ) from None
        except Exception as exc:  # pragma: no cover - surfaced via SystemExit
            raise SystemExit(f"invalid JSON artifact {artifact}: {exc}") from exc

        successful_modules[row["module"]] += 1

    return successful_modules


def _progress_counts_from_log(text: str) -> list[int]:
    return [int(match.group(1)) for match in _PROGRESS_LINE_RE.finditer(text)]


def _infer_target_count_from_jsonl(text: str) -> int:
    seen: set[tuple[str, int]] = set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        host = payload.get("host")
        port = payload.get("port")
        if isinstance(host, str) and isinstance(port, int):
            seen.add((host, port))
    return len(seen)


def _validate_output_sanity(rows: list[dict[str, str]]) -> None:
    for row in rows:
        log_path = Path(row["log_path"])
        if not log_path.exists():
            raise SystemExit(f"missing run log file: {log_path}")
        log_text = log_path.read_text(encoding="utf-8", errors="replace")
        label = row["label"]
        module = row["module"]
        is_debug_run = "debug" in label

        # Non-debug regressions: debug trace markers must not leak into default runs.
        if not is_debug_run and "stage_trace " in log_text:
            raise SystemExit(f"unexpected debug stage_trace in non-debug run log for label '{label}'")

        # Noise regression: agreed modules should not print noisy connection-failed row in successful default runs.
        if row["exit_code"] == "0" and module in {"redis", "etcd", "kafka"} and not is_debug_run:
            if "[!] connection failed err=" in log_text:
                raise SystemExit(f"unexpected noisy connection failed line in non-debug log for label '{label}'")

        expected_targets = _PROGRESS_EXPECTED_TARGETS.get(label)
        if expected_targets is None or row["exit_code"] != "0":
            continue
        counts = _progress_counts_from_log(log_text)
        if not counts:
            # Some json/jsonl flows intentionally stream structured rows without rendering progress.
            inferred_targets = _infer_target_count_from_jsonl(log_text)
            if inferred_targets == expected_targets:
                continue
            raise SystemExit(f"missing progress row in log for label '{label}'")
        if expected_targets not in counts:
            raise SystemExit(
                f"progress target count mismatch for label '{label}': expected {expected_targets}, got {counts}"
            )
        if expected_targets > 1 and 1 in counts:
            raise SystemExit(f"progress regressed to single-target batches in label '{label}': counts={counts}")
        if any(count != expected_targets for count in counts):
            raise SystemExit(
                f"progress target count mismatch for label '{label}': expected {expected_targets}, got {counts}"
            )


def _validate_openapi_artifacts(out_dir: Path, rows: list[dict[str, str]]) -> None:
    labels = {row["label"] for row in rows if row["exit_code"] == "0"}
    if "grpc_openapi_export" not in labels:
        return
    path = out_dir / "json" / "grpc_openapi.json"
    if not path.exists() or path.stat().st_size == 0:
        raise SystemExit(f"missing grpc OpenAPI artifact: {path}")
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"invalid grpc OpenAPI artifact {path}: {exc}") from exc
    if document.get("openapi") != "3.1.0":
        raise SystemExit(f"grpc OpenAPI artifact has unexpected version: {document.get('openapi')}")
    paths = document.get("paths")
    if not isinstance(paths, dict) or "/grpc.health.v1.Health/Check" not in paths:
        raise SystemExit("grpc OpenAPI artifact does not contain /grpc.health.v1.Health/Check")
    operation = (
        paths["/grpc.health.v1.Health/Check"].get("post")
        if isinstance(paths.get("/grpc.health.v1.Health/Check"), dict)
        else None
    )
    if not isinstance(operation, dict):
        raise SystemExit("grpc OpenAPI health path does not contain a post operation")
    for key in ("x-grpc-service", "x-grpc-method", "x-grpc-input-type", "x-grpc-output-type", "x-grpc-streaming"):
        if key not in operation:
            raise SystemExit(f"grpc OpenAPI operation is missing {key}")


def _run_cli_check(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "redposture.py", *args],
        capture_output=True,
        text=True,
        check=False,
    )


def _cli_smoke_checks() -> None:
    checks = [
        ("--help",),
        ("registry", "-h"),
        ("exporters", "scan", "-h"),
        ("postgres", "-h"),
        ("elastic", "-h"),
        ("grpc", "-h"),
    ]
    for args in checks:
        result = _run_cli_check(*args)
        if result.returncode != 0:
            raise SystemExit(f"cli smoke failed: redposture.py {' '.join(args)}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify lab matrix outputs and artifacts.")
    parser.add_argument("--status-file", required=True)
    parser.add_argument("--out-dir", required=True)
    args = parser.parse_args()

    status_path = Path(args.status_file)
    if not status_path.exists():
        raise SystemExit(f"status file not found: {status_path}")

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    checks_dir = out_dir / "postrun_checks"
    checks_dir.mkdir(parents=True, exist_ok=True)

    rows = _parse_status_file(status_path)
    if not rows:
        raise SystemExit("matrix status file is empty")

    _validate_expected_exits(rows)
    _validate_expected_labels(rows)

    successful_modules = _validate_json_artifacts(rows)
    if not successful_modules:
        raise SystemExit("no successful runs were recorded")

    seen_modules = {row["module"] for row in rows}
    missing_modules = sorted(module for module in _EXPECTED_MODULES if module not in seen_modules)
    if missing_modules:
        raise SystemExit(f"matrix status is missing expected modules: {', '.join(missing_modules)}")

    _validate_output_sanity(rows)
    _validate_openapi_artifacts(out_dir, rows)

    missing_success = sorted(module for module in _EXPECTED_MODULES if successful_modules.get(module, 0) == 0)
    if missing_success:
        raise SystemExit(f"no successful run recorded for modules: {', '.join(missing_success)}")

    _cli_smoke_checks()

    summary = {
        "total_rows": len(rows),
        "successful_modules": dict(successful_modules),
        "expected_modules": list(_EXPECTED_MODULES),
        "expected_labels": list(_EXPECTED_LABELS),
    }
    (checks_dir / "summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
