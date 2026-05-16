"""Filesystem artifact helpers for exporter collect flows."""

from __future__ import annotations

import os
import re
from typing import Any


def safe_fs_part(value: str, fallback: str) -> str:
    clean = re.sub(r"[^A-Za-z0-9._-]+", "_", (value or "").strip())
    clean = clean.strip("._-")
    if not clean:
        return fallback
    return clean[:96]


def endpoint_slug(endpoint: str) -> str:
    raw = (endpoint or "").strip()
    if not raw:
        return "root"
    raw = raw.lstrip("/")
    if not raw:
        return "root"
    raw = raw.replace("/", "__").replace("?", "__q__").replace("&", "__and__").replace("=", "__")
    return safe_fs_part(raw, "endpoint")


def save_collect_body(
    save_dir: str,
    record: dict[str, Any],
) -> tuple[str | None, int]:
    body = str(record.get("body") or "")
    host = safe_fs_part(str(record.get("host") or ""), "host")
    exporter = safe_fs_part(str(record.get("exporter") or ""), "exporter")
    port = str(record.get("port") or "-")
    endpoint = str(record.get("endpoint") or "")
    slug = endpoint_slug(endpoint)

    rel_path = os.path.join(host, exporter, f"{port}_{slug}.txt")
    abs_path = os.path.join(save_dir, rel_path)
    os.makedirs(os.path.dirname(abs_path), exist_ok=True)
    with open(abs_path, "w", encoding="utf-8") as fh:
        fh.write(body)

    return rel_path, len(body.encode("utf-8"))


__all__ = [
    "endpoint_slug",
    "safe_fs_part",
    "save_collect_body",
]
