#!/usr/bin/env python3
"""Remove only Compose image references absent before a local QA stand started."""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path


def missing_images(references: list[str]) -> list[str]:
    missing = []
    for reference in sorted(set(references)):
        if not reference:
            continue
        present = subprocess.run(
            ["docker", "image", "inspect", reference],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        if present.returncode:
            missing.append(reference)
    return missing


def compose_images(compose: list[str]) -> list[str]:
    result = subprocess.run([*compose, "config", "--images"], capture_output=True, text=True, check=True, timeout=60)
    return sorted(set(result.stdout.splitlines()))


def remove_images(references: list[str]) -> list[str]:
    """Leave in-use images untouched; never prune unrelated Docker state."""
    errors = []
    for reference in sorted(set(references)):
        if not reference:
            continue
        result = subprocess.run(
            ["docker", "image", "rm", reference], capture_output=True, text=True, check=False, timeout=120
        )
        if result.returncode:
            message = result.stderr.strip() or result.stdout.strip()
            # A failed pull may never have created the reference. Other errors
            # (including a stopped Docker daemon) must remain visible.
            if "No such image" not in message and "No such object" not in message:
                errors.append(f"{reference}: {message}")
        else:
            print(f"[qa-image-cleanup] removed {reference}", flush=True)
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="mode", required=True)
    snapshot = subparsers.add_parser("snapshot")
    snapshot.add_argument("output", type=Path)
    snapshot.add_argument("compose", nargs=argparse.REMAINDER)
    snapshot_refs = subparsers.add_parser("snapshot-refs")
    snapshot_refs.add_argument("output", type=Path)
    snapshot_refs.add_argument("images", nargs="+")
    cleanup = subparsers.add_parser("cleanup")
    cleanup.add_argument("snapshot", type=Path)
    args = parser.parse_args()
    if args.mode == "snapshot":
        compose = args.compose[1:] if args.compose[:1] == ["--"] else args.compose
        if not compose or compose[0] != "docker":
            parser.error("snapshot expects -- docker compose ...")
        references = missing_images(compose_images(compose))
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(references, indent=2) + "\n", encoding="utf-8")
        print(f"[qa-image-cleanup] captured {len(references)} new image reference(s)", flush=True)
        return 0
    if args.mode == "snapshot-refs":
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(missing_images(args.images), indent=2) + "\n", encoding="utf-8")
        return 0
    references = json.loads(args.snapshot.read_text(encoding="utf-8"))
    if not isinstance(references, list) or not all(isinstance(item, str) for item in references):
        parser.error("image snapshot must be a JSON list of references")
    errors = remove_images(references)
    for error in errors:
        print(f"[qa-image-cleanup] {error}", flush=True)
    return int(bool(errors))


if __name__ == "__main__":
    raise SystemExit(main())
