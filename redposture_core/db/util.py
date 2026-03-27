"""Utility helpers for DB subsystem."""

from __future__ import annotations

import gzip
import hashlib
import json
from datetime import datetime, timezone
from typing import Any


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def parse_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    text = str(value).strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    return datetime.fromisoformat(text)


def stable_hash(*parts: str | None) -> str:
    payload = "|".join(str(part or "") for part in parts)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def compress_json_payload(payload: Any) -> tuple[bytes, str, int, str]:
    raw = json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
    compressed = gzip.compress(raw)
    return compressed, "gzip", len(compressed), hashlib.sha256(compressed).hexdigest()
