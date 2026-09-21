#!/usr/bin/env python3
"""Fail closed when a RedPosture wheel misses runtime data or CLI metadata."""

from __future__ import annotations

import argparse
import json
import re
import zipfile
from email.parser import Parser
from pathlib import Path

_VERSION_RE = re.compile(r'^version\s*=\s*["\']([^"\']+)["\']\s*$', re.MULTILINE)


def _project_version(root: Path) -> str:
    match = _VERSION_RE.search((root / "pyproject.toml").read_text(encoding="utf-8"))
    if match is None:
        raise ValueError("project version is missing from pyproject.toml")
    return match.group(1)


def verify_wheel(path: Path, *, expected_version: str) -> None:
    if not path.is_file() or path.suffix != ".whl":
        raise ValueError(f"wheel does not exist: {path}")
    with zipfile.ZipFile(path) as archive:
        names = set(archive.namelist())
        metadata_names = sorted(name for name in names if name.endswith(".dist-info/METADATA"))
        entry_point_names = sorted(name for name in names if name.endswith(".dist-info/entry_points.txt"))
        record_names = sorted(name for name in names if name.endswith(".dist-info/RECORD"))
        if len(metadata_names) != 1 or len(entry_point_names) != 1 or len(record_names) != 1:
            raise ValueError("wheel must contain exactly one METADATA, entry_points.txt and RECORD")
        required = {
            "redposture_core/cli.py",
            "redposture_core/module_registry.py",
            "redposture_core/cve.py",
            "redposture_core/data/cve_catalog.json",
        }
        missing = sorted(required - names)
        if missing:
            raise ValueError(f"wheel is missing runtime files: {', '.join(missing)}")

        metadata = Parser().parsestr(archive.read(metadata_names[0]).decode("utf-8"))
        if metadata.get("Name", "").casefold() != "redposture":
            raise ValueError("wheel project name is not redposture")
        if metadata.get("Version") != expected_version:
            raise ValueError(
                f"wheel version {metadata.get('Version')!r} does not match pyproject version {expected_version!r}"
            )
        entry_points = archive.read(entry_point_names[0]).decode("utf-8")
        if "redposture = redposture_core.cli:main" not in entry_points:
            raise ValueError("wheel does not expose the redposture console script")

        catalog = json.loads(archive.read("redposture_core/data/cve_catalog.json"))
        if not isinstance(catalog, dict) or not catalog.get("catalog_version"):
            raise ValueError("bundled CVE catalog has no catalog_version")
        entries = catalog.get("entries")
        if not isinstance(entries, list) or not entries:
            raise ValueError("bundled CVE catalog has no entries")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("wheels", nargs="+", type=Path)
    args = parser.parse_args(argv)
    root = Path(__file__).resolve().parents[1]
    expected_version = _project_version(root)
    for wheel in args.wheels:
        verify_wheel(wheel, expected_version=expected_version)
        print(f"[+] verified release wheel: {wheel}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
