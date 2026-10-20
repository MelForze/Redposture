"""Collision-resistant local names and exclusive download destinations."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path


def identity_component(value: str) -> str:
    """Retain exact identity even when readable filesystem slugs coincide."""
    label = re.sub(r"[^a-zA-Z0-9._-]+", "_", value).strip("._-")[:64] or "item"
    return f"{label}-{hashlib.sha256(value.encode('utf-8')).hexdigest()}"


def write_unique_file(destination: str, body: bytes) -> str:
    path = Path(destination)
    path.parent.mkdir(parents=True, exist_ok=True)
    for suffix in range(1, 1000000):
        candidate = path if suffix == 1 else path.with_name(f"{path.name}-{suffix}")
        try:
            with candidate.open("xb") as handle:
                handle.write(body)
            return str(candidate)
        except FileExistsError:
            continue
    raise OSError("download destination suffix limit exceeded")


def unique_directory(destination: str) -> str:
    path = Path(destination)
    path.parent.mkdir(parents=True, exist_ok=True)
    for suffix in range(1, 1000000):
        candidate = path if suffix == 1 else path.with_name(f"{path.name}-{suffix}")
        try:
            candidate.mkdir()
            return str(candidate)
        except FileExistsError:
            continue
    raise OSError("download destination suffix limit exceeded")
