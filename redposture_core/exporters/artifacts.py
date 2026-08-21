"""Filesystem artifact helpers for exporter collect flows."""

from __future__ import annotations

import os
import re
from hashlib import sha256
from typing import Any


def safe_fs_part(value: str, fallback: str) -> str:
    clean = re.sub(r"[^A-Za-z0-9._-]+", "_", (value or "").strip())
    clean = clean.strip("._-")
    if not clean:
        return fallback
    return clean[:96]


def endpoint_slug(endpoint: str) -> str:
    source_raw = (endpoint or "").strip()
    raw = source_raw
    if not raw:
        return "root"
    raw = raw.lstrip("/")
    if not raw:
        return "root"
    raw = raw.replace("/", "__").replace("?", "__q__").replace("&", "__and__").replace("=", "__")
    # Keep the unbounded sanitised value long enough to detect truncation.
    # Looking only at ``readable`` loses that information and made endpoints
    # with the same first 96 characters overwrite one another.
    sanitised = re.sub(r"[^A-Za-z0-9._-]+", "_", raw.strip()).strip("._-")
    readable = safe_fs_part(raw, "endpoint")
    # Sanitisation is deliberately lossy (`/a/b` and `/a__b` used to map to
    # the same path).  A digest of the original endpoint makes the mapping
    # collision-resistant while keeping filenames recognisable to operators.
    # Keep the historic readable shape where it is already one-to-one.  Raw
    # underscores and characters collapsed by ``safe_fs_part`` are the
    # ambiguous cases and receive a digest suffix.
    ambiguous = (
        "_" in source_raw
        or source_raw.startswith("//")
        or len(sanitised) > 96
        or any(not (char.isascii() and (char.isalnum() or char in "/.?&=-")) for char in source_raw)
    )
    if not ambiguous:
        return readable
    digest = sha256(str(endpoint).encode("utf-8", errors="surrogatepass")).hexdigest()[:12]
    return f"{readable[:83]}-{digest}"


def _artifact_is_binary(record: dict[str, Any], raw: bytes) -> bool:
    endpoint = str(record.get("endpoint") or "")
    endpoint_path, _separator, endpoint_query = endpoint.partition("?")
    binary_pprof_paths = {
        "/debug/pprof/allocs",
        "/debug/pprof/block",
        "/debug/pprof/heap",
        "/debug/pprof/mutex",
        "/debug/pprof/profile",
        "/debug/pprof/threadcreate",
        "/debug/pprof/trace",
    }
    if endpoint_path in binary_pprof_paths and "debug=" not in endpoint_query:
        return True
    content_type = str(record.get("content_type") or "").split(";", 1)[0].strip().lower()
    if content_type and (
        content_type.startswith("text/")
        or content_type in {"application/json", "application/javascript", "application/xml"}
        or content_type.endswith("+json")
        or content_type.endswith("+xml")
    ):
        return False
    if content_type in {
        "application/octet-stream",
        "application/x-gzip",
        "application/gzip",
        "application/x-protobuf",
        "application/protobuf",
    }:
        return True
    try:
        raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return True
    return False


def save_collect_body(
    save_dir: str,
    record: dict[str, Any],
) -> tuple[str | None, int]:
    raw_value = record.get("raw_body")
    if isinstance(raw_value, bytes):
        raw = raw_value
    else:
        raw = str(record.get("body") or "").encode("utf-8")
    host = safe_fs_part(str(record.get("host") or ""), "host")
    exporter = safe_fs_part(str(record.get("exporter") or ""), "exporter")
    port = str(record.get("port") or "-")
    endpoint = str(record.get("endpoint") or "")
    slug = endpoint_slug(endpoint)

    binary = _artifact_is_binary(record, raw)
    extension = ".bin" if binary else ".txt"
    rel_path = os.path.join(host, exporter, f"{port}_{slug}{extension}")
    abs_path = os.path.join(save_dir, rel_path)
    os.makedirs(os.path.dirname(abs_path), exist_ok=True)
    with open(abs_path, "wb") as fh:
        fh.write(raw)

    return rel_path, len(raw)


__all__ = [
    "endpoint_slug",
    "safe_fs_part",
    "save_collect_body",
]
