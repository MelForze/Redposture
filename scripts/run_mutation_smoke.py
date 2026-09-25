#!/usr/bin/env python3
"""Run a small deterministic mutation suite over critical security decisions."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class Mutation:
    name: str
    source: str
    original: str
    replacement: str
    tests: tuple[str, ...]


MUTATIONS = (
    Mutation(
        name="CVE fixed-version boundary becomes inclusive",
        source="redposture_core/cve.py",
        original="if fixed is not None and _compare_versions(parsed, fixed) >= 0:",
        replacement="if fixed is not None and _compare_versions(parsed, fixed) > 0:",
        tests=("tests/test_cve_catalog_properties.py",),
    ),
    Mutation(
        name="large scan threshold moves above 1000",
        source="redposture_core/stage_runtime.py",
        original="_LARGE_AUDIT_PLAN_ENDPOINTS = 1_000",
        replacement="_LARGE_AUDIT_PLAN_ENDPOINTS = 1_001",
        tests=("tests/test_stage_runtime.py::test_cli_audit_worker_profile_uses_expanded_endpoint_count",),
    ),
    Mutation(
        name="HTTPS-required classifier accepts the wrong status",
        source="redposture_core/clients/http_api.py",
        original="if int(status) != 400:",
        replacement="if int(status) != 401:",
        tests=("tests/test_code_review_regressions.py::test_https_required_response_classifier_is_strict",),
    ),
    Mutation(
        name="Keycloak redirect loses its provider fingerprint",
        source="redposture_core/auth_detection.py",
        original='return "keycloak", "oidc"',
        replacement='return "generic_sso", "oidc"',
        tests=("tests/test_auth_detection.py::test_detects_keycloak_from_redirect_url_and_page",),
    ),
    Mutation(
        name="mutating POST becomes replay-safe after an ambiguous failure",
        source="redposture_core/clients/http_api.py",
        original='replay_safe = str(request.method or "GET").upper() in {"GET", "HEAD"}',
        replacement='replay_safe = str(request.method or "GET").upper() in {"GET", "HEAD", "POST"}',
        tests=(
            "tests/test_mutating_retry_safety.py::test_mutating_http_requests_are_never_replayed_after_ambiguous_transport_failure",
        ),
    ),
    Mutation(
        name="redirect hop ceiling silently increases",
        source="redposture_core/clients/http_redirects.py",
        original="MAX_REDIRECTS = 5",
        replacement="MAX_REDIRECTS = 6",
        tests=("tests/test_redirect_matrix_contract.py::test_redirect_limit_and_signature_preparer_cover_every_hop",),
    ),
    Mutation(
        name="MinIO discovery worker limit drifts",
        source="redposture_core/modules/minio/discover.py",
        original="DISCOVER_WORKERS = 8",
        replacement="DISCOVER_WORKERS = 7",
        tests=(
            "tests/test_discovery_parallel_invariants.py::test_fixed_discovery_limits_match_the_command_wide_contract",
        ),
    ),
    Mutation(
        name="ClickHouse discovery worker limit drifts",
        source="redposture_core/modules/clickhouse/discover/engine.py",
        original="DISCOVER_WORKERS = 4",
        replacement="DISCOVER_WORKERS = 3",
        tests=(
            "tests/test_discovery_parallel_invariants.py::test_fixed_discovery_limits_match_the_command_wide_contract",
        ),
    ),
    Mutation(
        name="normal text starts emitting unconfirmed services",
        source="redposture_core/stage_runtime.py",
        original="suppress_undetected_records_in_text: bool = True",
        replacement="suppress_undetected_records_in_text: bool = False",
        tests=(
            "tests/test_release_quality_contracts.py::test_every_audit_module_obeys_mixed_target_output_contract[airflow]",
        ),
    ),
    Mutation(
        name="CVE findings switch from newest-first to oldest-first",
        source="redposture_core/cve.py",
        original='return (-int(year), -int(sequence), str(item.get("product") or ""))',
        replacement='return (int(year), int(sequence), str(item.get("product") or ""))',
        tests=("tests/test_cve.py::test_multiple_ranges_and_stable_newest_first_order",),
    ),
    Mutation(
        name="discovery compact output leaks severity labels",
        source="redposture_core/discovery_rendering.py",
        original="return f\"{module}\\t{host or '?'}\\t{int(port or 0)}\\t [!] {kind} Value={encoded_value} Place={encoded_place}\"",
        replacement="return f\"{module}\\t{host or '?'}\\t{int(port or 0)}\\t [!] {severity} {kind} Value={encoded_value} Place={encoded_place}\"",
        tests=("tests/test_discovery_rendering.py::test_common_discovery_line_escapes_value_and_place",),
    ),
    Mutation(
        name="completed discovery headings lose semantic status colors",
        source="redposture_core/discovery_rendering.py",
        original='if payload.startswith(("Discover Secrets", "Discover Complete")):',
        replacement='if payload.startswith(("Discover Secrets",)):',
        tests=(
            "tests/test_discovery_rendering.py::test_discovery_section_keeps_title_white_and_colors_status_and_findings",
        ),
    ),
)


def _mutated_source(mutation: Mutation) -> str:
    source = (ROOT / mutation.source).read_text(encoding="utf-8")
    occurrences = source.count(mutation.original)
    if occurrences < 1:
        raise RuntimeError(f"mutation anchor is missing: {mutation.name}")
    return source.replace(mutation.original, mutation.replacement, 1)


def run_mutation(mutation: Mutation) -> tuple[bool, str]:
    with tempfile.TemporaryDirectory(prefix="redposture-mutation-") as raw_temp:
        temp = Path(raw_temp)
        shutil.copytree(ROOT / "redposture_core", temp / "redposture_core")
        mutated_path = temp / mutation.source
        mutated_path.write_text(_mutated_source(mutation), encoding="utf-8")
        (temp / "pytest.ini").write_text("[pytest]\naddopts = -q\n", encoding="utf-8")

        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(temp)
        command = [
            sys.executable,
            "-m",
            "pytest",
            "--rootdir",
            str(temp),
            *(str(ROOT / test) for test in mutation.tests),
        ]
        completed = subprocess.run(
            command,
            cwd=temp,
            env=environment,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        output = (completed.stdout + completed.stderr).strip()
        return completed.returncode != 0, output


def main() -> int:
    survivors: list[str] = []
    for mutation in MUTATIONS:
        killed, output = run_mutation(mutation)
        if killed:
            print(f"[killed] {mutation.name}")
            continue
        survivors.append(mutation.name)
        print(f"[survived] {mutation.name}")
        if output:
            print(output)
    if survivors:
        print(f"mutation smoke failed: {len(survivors)} mutation(s) survived", file=sys.stderr)
        return 1
    print(f"mutation smoke passed: {len(MUTATIONS)} mutation(s) killed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
