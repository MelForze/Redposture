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
        tests=("tests/test_concurrency_stress.py::test_dynamic_workers_process_full_plan_without_exceeding_limit",),
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
