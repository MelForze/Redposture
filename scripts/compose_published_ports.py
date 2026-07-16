#!/usr/bin/env python3
"""Print published host ports from normalized Docker Compose JSON."""

from __future__ import annotations

import json
import sys
from collections.abc import Iterable, Mapping
from typing import Any


def _expand_port(value: Any) -> Iterable[int]:
    text = str(value or "").strip()
    if not text:
        return ()
    if "-" not in text:
        try:
            port = int(text)
        except ValueError:
            return ()
        return (port,) if 1 <= port <= 65535 else ()
    start_text, end_text = text.split("-", 1)
    try:
        start = int(start_text)
        end = int(end_text)
    except ValueError:
        return ()
    if not (1 <= start <= end <= 65535):
        return ()
    return range(start, end + 1)


def published_ports(payload: Mapping[str, Any]) -> list[int]:
    ports: set[int] = set()
    services = payload.get("services")
    if not isinstance(services, Mapping):
        return []
    for service in services.values():
        if not isinstance(service, Mapping):
            continue
        entries = service.get("ports")
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if isinstance(entry, Mapping):
                ports.update(_expand_port(entry.get("published")))
                continue
            # Compatibility with non-normalized Compose payloads used by unit
            # tests and older Compose implementations.
            text = str(entry or "").rsplit("/", 1)[0]
            published = text.split(":")[-2] if ":" in text else text
            ports.update(_expand_port(published))
    return sorted(ports)


def main() -> int:
    payload = json.load(sys.stdin)
    if not isinstance(payload, Mapping):
        raise ValueError("Compose config must be a JSON object")
    for port in published_ports(payload):
        print(port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
