#!/usr/bin/env python3
"""Enforce a minimum coverage percentage for each measured production module."""

from __future__ import annotations

import argparse
import json
import posixpath
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from pathlib import Path, PurePosixPath

DEFAULT_MINIMUM = Decimal("70")
PROJECT_ROOT = Path(__file__).resolve().parents[1]
PRODUCTION_ROOT = PROJECT_ROOT / "redposture_core"


class CoverageDataError(ValueError):
    """Raised when a coverage JSON report cannot be checked safely."""


@dataclass(frozen=True)
class FileCoverage:
    path: str
    percent_covered: Decimal


def _parse_json_constant(value: str) -> None:
    raise ValueError(f"non-finite number {value!r}")


def load_coverage_json(path: Path) -> object:
    try:
        with path.open(encoding="utf-8") as coverage_file:
            return json.load(
                coverage_file,
                parse_float=Decimal,
                parse_int=Decimal,
                parse_constant=_parse_json_constant,
            )
    except OSError as exc:
        raise CoverageDataError(f"cannot read {path}: {exc}") from exc
    except (json.JSONDecodeError, ValueError) as exc:
        raise CoverageDataError(f"{path} is not valid JSON: {exc}") from exc


def _production_path(raw_path: str) -> str | None:
    """Return a stable project-relative path for measured production Python files."""

    platform_path = Path(raw_path)
    if platform_path.is_absolute():
        try:
            relative_path = platform_path.resolve().relative_to(PRODUCTION_ROOT.resolve())
        except ValueError:
            return None
        if relative_path.suffix != ".py":
            return None
        return (PurePosixPath("redposture_core") / PurePosixPath(relative_path.as_posix())).as_posix()

    normalized = posixpath.normpath(raw_path.replace("\\", "/"))
    relative_posix_path = PurePosixPath(normalized)
    if (
        len(relative_posix_path.parts) < 2
        or relative_posix_path.parts[0] != "redposture_core"
        or relative_posix_path.suffix != ".py"
    ):
        return None
    return relative_posix_path.as_posix()


def _as_percentage(value: object, *, path: str) -> Decimal:
    if isinstance(value, bool) or not isinstance(value, (Decimal, int, float)):
        raise CoverageDataError(f"{path}: summary.percent_covered must be a number")

    try:
        percentage = value if isinstance(value, Decimal) else Decimal(str(value))
    except (InvalidOperation, ValueError) as exc:
        raise CoverageDataError(f"{path}: summary.percent_covered must be a number") from exc

    if not percentage.is_finite() or percentage < 0 or percentage > 100:
        raise CoverageDataError(f"{path}: summary.percent_covered must be between 0 and 100")
    return percentage


def measured_file_coverage(report: object) -> list[FileCoverage]:
    if not isinstance(report, dict):
        raise CoverageDataError("coverage report must be a JSON object")

    files = report.get("files")
    if not isinstance(files, dict):
        raise CoverageDataError("coverage report field 'files' must be a JSON object")

    measured: list[FileCoverage] = []
    seen_paths: set[str] = set()
    for raw_path, file_data in files.items():
        if not isinstance(raw_path, str):
            raise CoverageDataError("coverage report file names must be strings")
        path = _production_path(raw_path)
        if path is None:
            continue
        if path in seen_paths:
            raise CoverageDataError(f"coverage report contains duplicate production path: {path}")
        seen_paths.add(path)

        if not isinstance(file_data, dict):
            raise CoverageDataError(f"{path}: file coverage entry must be a JSON object")
        summary = file_data.get("summary")
        if not isinstance(summary, dict):
            raise CoverageDataError(f"{path}: field 'summary' must be a JSON object")
        if "percent_covered" not in summary:
            raise CoverageDataError(f"{path}: summary.percent_covered is missing")

        measured.append(
            FileCoverage(
                path=path,
                percent_covered=_as_percentage(summary["percent_covered"], path=path),
            )
        )

    if not measured:
        raise CoverageDataError("coverage report contains no measured Python files under redposture_core")
    return sorted(measured, key=lambda item: item.path)


def below_minimum(report: object, minimum: Decimal) -> list[FileCoverage]:
    return [item for item in measured_file_coverage(report) if item.percent_covered < minimum]


def _percentage_argument(value: str) -> Decimal:
    try:
        percentage = Decimal(value)
    except InvalidOperation as exc:
        raise argparse.ArgumentTypeError("must be a number between 0 and 100") from exc
    if not percentage.is_finite() or percentage < 0 or percentage > 100:
        raise argparse.ArgumentTypeError("must be a number between 0 and 100")
    return percentage


def _format_percentage(value: Decimal) -> str:
    return format(value, "f")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Fail if any measured redposture_core Python file is below the coverage threshold."
    )
    parser.add_argument("coverage_json", type=Path, help="path to coverage.py's JSON report")
    parser.add_argument(
        "--min",
        dest="minimum",
        type=_percentage_argument,
        default=DEFAULT_MINIMUM,
        metavar="PERCENT",
        help=f"minimum percent_covered required per file (default: {DEFAULT_MINIMUM})",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        report = load_coverage_json(args.coverage_json)
        measured = measured_file_coverage(report)
    except CoverageDataError as exc:
        print(f"per-file coverage error: {exc}", file=sys.stderr)
        return 2

    failures = [item for item in measured if item.percent_covered < args.minimum]
    minimum = _format_percentage(args.minimum)
    if failures:
        print(
            f"per-file coverage failed: {len(failures)} of {len(measured)} measured "
            f"redposture_core Python files are below {minimum}%.",
            file=sys.stderr,
        )
        for failure in failures:
            print(
                f"  {failure.path}: {_format_percentage(failure.percent_covered)}%",
                file=sys.stderr,
            )
        return 1

    print(
        f"per-file coverage passed: all {len(measured)} measured redposture_core "
        f"Python files are at or above {minimum}%."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
