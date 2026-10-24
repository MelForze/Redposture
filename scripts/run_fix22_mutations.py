#!/usr/bin/env python3
"""Sequential behavioral mutations for the 22 fixes from 2026-10-22.

Only a private temporary source tree is changed. Each mutant has its own green
control; import errors, timeouts and collection errors never count as kills.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# id, source, old fragment, mutant, behavioral test (parametrizations included).
CASES = (
    (
        1,
        "exporters/discovery_logic.py",
        "if runner_up is not None else 0",
        "if runner_up is not None else -1",
        "test_expansion_protocol_state.py::test_exporter_single_weak_marker_without_fingerprint_remains_unconfirmed",
    ),
    (
        2,
        "modules/clickhouse/actions.py",
        "return output, _friendly_error_from_exception(exc)",
        "return [], _friendly_error_from_exception(exc)",
        "test_expansion_clickhouse.py::test_sql_stream_error_retains_rows_already_received",
    ),
    (
        3,
        "modules/redis/actions.py",
        "if pending:\n            _flush_page(pending)",
        "if False and pending:\n            _flush_page(pending)",
        "test_expansion_native.py::test_redis_scan_failure_flushes_already_discovered_pending_keys",
    ),
    (
        4,
        "clients/kafka.py",
        "count = reader.read_i32()\n        if count < 0:",
        "count = reader.read_i32() if reader.remaining() >= 4 else 0\n        if count < 0:",
        "test_expansion_native.py::test_kafka_apiversions_rejects_missing_array_length",
    ),
    (
        5,
        "web_panel_export.py",
        'first_id = rows[0].get("_id") if isinstance(rows[0], dict) else None',
        'first_id = rows[0].get("_id")',
        "test_expansion_web_export.py::test_dashboard_malformed_scroll_hit_reports_incomplete_instead_of_crashing",
    ),
    (
        6,
        "modules/kafka/ui.py",
        "or isinstance(partition, bool)",
        "or False",
        "test_expansion_kafka_ui.py::test_message_stream_rejects_boolean_positions[partition]",
    ),
    (
        7,
        "modules/qdrant/actions.py",
        "if not isinstance(point, dict):\n                partial = True",
        "if not isinstance(point, dict):\n                pass",
        "test_expansion_http_qdrant_scroll.py::test_scroll_invalid_point_cannot_claim_complete_inventory",
    ),
    (
        8,
        "modules/qdrant/actions.py",
        "remaining = 1000 - len(points)",
        "remaining = len(page_points)",
        "test_expansion_http_qdrant_scroll.py::test_scroll_enforces_documented_thousand_point_cap",
    ),
    (
        9,
        "clients/http_api.py",
        'completed = rest.startswith(b"\\r\\n") or b"\\r\\n\\r\\n" in rest',
        "completed = True",
        "test_expansion_transport.py::test_complete_chunk_decoder_rejects_missing_crlf_or_trailer_terminator",
    ),
    (
        10,
        "clients/http_session.py",
        "except Exception as exc:\n",
        "except Exception as exc:\n",
        "test_expansion_transport.py::test_pool_single_hop_normalizes_proxy_connection_acquisition_errors",
    ),
    (
        11,
        "clients/grpc.py",
        "try:\n        context = _grpc_ssl_context(tls_config, alpn_h2=True)",
        "context = _grpc_ssl_context(tls_config, alpn_h2=True)\n    try:",
        "test_expansion_clients.py::test_grpc_tls_context_failure_closes_already_opened_tcp_socket[_open_grpc_socket]",
    ),
    (
        12,
        "clients/grpc.py",
        'while True:\n        header_blob, sep, body = raw.partition(b"\\r\\n\\r\\n")',
        'return raw\n    while True:\n        header_blob, sep, body = raw.partition(b"\\r\\n\\r\\n")',
        "test_expansion_clients.py::test_grpc_web_accepts_final_response_after_informational_headers",
    ),
    (
        13,
        "stage_spray.py",
        "bool(args.users) != (args.passwords is not None)",
        "bool(args.users) != bool(args.passwords)",
        "test_expansion_shared.py::test_spray_explicit_empty_literal_password_is_a_candidate",
    ),
    (
        14,
        "web_panel_export.py",
        'if isinstance(value, dict) and "objects" in value and objects is None:',
        "if False:",
        "test_expansion_web_export.py::test_minio_real_empty_bucket_does_not_abort_remaining_buckets",
    ),
    (
        15,
        "modules/elastic/discover.py",
        "if not inventory_fields or any(not isinstance(parsed[name], list) for name in inventory_fields):",
        "if False:",
        "test_expansion2_elastic_discovery.py::test_invalid_resolve_inventory_cannot_claim_complete_empty_scan",
    ),
    (
        16,
        "modules/consul/actions.py",
        'anonymous.get("ok") is False\n            and _unauthorized_status(anonymous.get("status"))\n            and authenticated.get("ok") is True',
        'authenticated.get("ok") is True',
        "test_campaign22_fault_contracts.py::test_consul_unknown_anonymous_probe_cannot_prove_basic_credentials",
    ),
    (
        17,
        "modules/kafka/ui.py",
        "if position not in seen_positions and position not in page_positions:",
        "if True:",
        "test_campaign22_pagination.py::test_kafka_bounded_dump_deduplicates_overlapping_cursor_pages",
    ),
    (
        18,
        "scripts/run_qa_handoff.py",
        "_stop_process_group(child, signal.SIGINT)",
        "child.wait()",
        "test_campaign22_qa_lifecycle.py::test_logged_command_ctrl_c_must_stop_descendant_that_ignores_sigint",
    ),
    (
        19,
        "modules/elastic/discover.py",
        "for match in _SQL_IDENTIFIED_BY_RE.finditer(text):",
        'for match in _SQL_IDENTIFIED_BY_RE.finditer(""):',
        "test_campaign22_discover_corpus.py::test_identified_by_sql_cleartext_secret_recall_limitation",
    ),
    (
        20,
        "modules/kafka/stage.py",
        "max_messages = int(explicit_max) if explicit_max is not None else dump_limit if dump else 10",
        "max_messages = int(explicit_max if explicit_max is not None else dump_limit if dump_limit is not None else 10)",
        "test_campaign22_kafka_full_dump.py::test_native_bare_dump_must_not_silently_cap_at_ten_and_claim_complete",
    ),
    (
        21,
        "modules/kafka/ui.py",
        'payload["ui_topics"].extend(',
        'payload.setdefault("_discarded_topics", []).extend(',
        "test_campaign22_kafka_full_dump.py::test_ui_full_dump_preserves_requested_inventory[show_topics-ui_topics-expected0-True]",
    ),
    (
        22,
        "modules/kafka/ui.py",
        "next_offsets = dict(offsets) if offsets is not None else None",
        'if not done or error:\n                                raise _FullIncomplete("incomplete page")\n                            next_offsets = dict(offsets) if offsets is not None else None',
        "test_campaign22_kafka_full_dump.py::test_ui_interrupted_sse_page_preserves_already_decoded_messages",
    ),
)


def verdict(code: int, report: Path) -> str:
    if not report.exists():
        return "ERROR"
    root = ET.parse(report).getroot()
    tests = root.findall(".//testcase")
    if any(t.find("error") is not None for t in tests) or not tests:
        return "ERROR"
    failures = sum(t.find("failure") is not None for t in tests)
    skipped = sum(t.find("skipped") is not None for t in tests)
    if code == 0 and failures == skipped == 0:
        return "PASS"
    return "KILLED" if code == 1 and failures and not skipped else "ERROR"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--timeout", type=float, default=60)
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    results = []
    with tempfile.TemporaryDirectory(prefix="rp-fix22-mutants-") as name:
        temp = Path(name)
        for directory in ("redposture_core", "scripts", "tests"):
            shutil.copytree(
                ROOT / directory, temp / directory, ignore=shutil.ignore_patterns("__pycache__", ".pytest_cache")
            )
        shutil.copy2(ROOT / "pyproject.toml", temp / "pyproject.toml")
        shutil.copy2(ROOT / "redposture.py", temp / "redposture.py")
        for number, source, old, new, test in CASES:
            path = temp / (source if source.startswith("scripts/") else "redposture_core/" + source)
            original = path.read_text()
            # Acquisition must fail outside the normalization block again.
            if number == 10:
                old = "        try:\n            connection, reused = self._acquire(key, timeout)"
                new = "        connection, reused = self._acquire(key, timeout)\n        try:"
            if old == new or old not in original:
                raise RuntimeError(f"missing/non-mutating anchor {number}: {old!r}")
            runs = {}
            for phase in ("control", "mutant"):
                path.write_text(original if phase == "control" else original.replace(old, new, 1))
                xml = out / f"{number:02}-{phase}.xml"
                cmd = [
                    sys.executable,
                    "-B",
                    "-m",
                    "pytest",
                    "-o",
                    "addopts=",
                    "--import-mode=importlib",
                    "-q",
                    "--tb=short",
                    "--junitxml=" + str(xml),
                    "tests/" + test,
                ]
                started = time.monotonic()
                process = subprocess.Popen(
                    cmd,
                    cwd=temp,
                    env={**os.environ, "PYTHONPATH": str(temp), "PYTHONDONTWRITEBYTECODE": "1"},
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    start_new_session=True,
                )
                try:
                    stdout, _ = process.communicate(timeout=args.timeout)
                    status = verdict(process.returncode, xml)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    stdout, _ = process.communicate(timeout=5)
                    status = "TIMEOUT"
                (out / f"{number:02}-{phase}.log").write_bytes(stdout)
                runs[phase] = {"status": status, "code": process.returncode, "seconds": time.monotonic() - started}
            path.write_text(original)
            row = {"id": number, "source": str(path.relative_to(temp)), "test": test, **runs}
            row["status"] = (
                "PASS" if runs["control"]["status"] == "PASS" and runs["mutant"]["status"] == "KILLED" else "FAIL"
            )
            results.append(row)
            (out / "result.json").write_text(json.dumps(results, indent=2))
            print(number, row["status"], runs, flush=True)
    return int(any(row["status"] != "PASS" for row in results))


if __name__ == "__main__":
    raise SystemExit(main())
