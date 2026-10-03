#!/usr/bin/env python3
"""Require branch-aware coverage of the QA expansion's high-risk files."""

from __future__ import annotations

import json
import sys
from collections.abc import Sequence
from pathlib import Path

from scripts.check_coverage_per_file import CoverageDataError, measured_file_coverage

TARGETS = (
    "redposture_core/clients/kafka.py",
    "redposture_core/modules/kafka/policy.py",
    "redposture_core/modules/registry/actions.py",
    "redposture_core/modules/airflow/discover.py",
    "redposture_core/modules/clickhouse/discover/inventory.py",
    "redposture_core/modules/proxmox/actions.py",
    "redposture_core/exporters/http_pool.py",
    "redposture_core/stage_trigger.py",
)
MINIMUM = 85


def check_report(report: object) -> list[str]:
    measured = {item.path: item.percent_covered for item in measured_file_coverage(report)}
    failures: list[str] = []
    for path in TARGETS:
        percent = measured.get(path)
        if percent is None:
            failures.append(f"{path}: absent from coverage report")
        elif percent < MINIMUM:
            failures.append(f"{path}: {percent}% < {MINIMUM}%")
    return failures


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if len(arguments) != 1:
        print("usage: check_quality_coverage.py COVERAGE_JSON", file=sys.stderr)
        return 2
    try:
        report = json.loads(Path(arguments[0]).read_text(encoding="utf-8"))
        failures = check_report(report)
    except (OSError, ValueError, CoverageDataError) as exc:
        print(f"focused coverage gate: {exc}", file=sys.stderr)
        return 2
    if failures:
        print("focused coverage gate failed:", *failures, sep="\n  ", file=sys.stderr)
        return 1
    print(f"focused coverage gate passed: {len(TARGETS)} files >= {MINIMUM}%")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
