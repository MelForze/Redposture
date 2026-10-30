"""Bounded, explicit onboarding of the disposable Redis Insight QA fixture."""

from __future__ import annotations

import argparse
import json
import time
import urllib.request
from typing import Any


def request(base: str, path: str, value: Any = None, *, method: str | None = None) -> Any:
    payload = json.dumps(value).encode() if value is not None else None
    call = urllib.request.Request(
        base.rstrip("/") + path, payload, headers={"Content-Type": "application/json"}, method=method
    )
    with urllib.request.urlopen(call, timeout=5) as response:
        raw = response.read()
    try:
        return json.loads(raw)
    except ValueError:
        return raw.decode(errors="replace")


def onboard_redisinsight(base: str, *, host: str = "redis", password: str = "reader-pass-22") -> str:
    spec = request(base, "/api/settings/agreements/spec")
    agreements = spec.get("agreements") if isinstance(spec, dict) else None
    if not isinstance(agreements, dict) or "eula" not in agreements:
        raise RuntimeError("Redis Insight agreement schema is unavailable; onboarding was not confirmed")
    request(base, "/api/settings", {"agreements": {key: key == "eula" for key in agreements}}, method="PATCH")
    databases = request(base, "/api/databases")
    if not isinstance(databases, list):
        raise RuntimeError("Redis Insight connection listing is unavailable")
    existing = next(
        (row for row in databases if row.get("host") == host and row.get("port") == 6379 and row.get("db") == 0), None
    )
    connection = existing or request(
        base,
        "/api/databases",
        {"name": "qa", "host": host, "port": 6379, "username": "default", "password": password, "db": 0},
    )
    identifier = connection.get("id") if isinstance(connection, dict) else None
    if not identifier:
        raise RuntimeError("Redis Insight connection creation was not confirmed")
    return str(identifier)


def wait_api(base: str, path: str, seconds: float = 180) -> None:
    deadline = time.monotonic() + seconds
    last: object = "no response"
    while time.monotonic() < deadline:
        try:
            request(base, path)
            return
        except (OSError, ValueError) as exc:
            last = str(exc)
        time.sleep(min(0.5, max(0, deadline - time.monotonic())))
    raise TimeoutError(f"API {path} unavailable after {seconds}s: {last}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("base")
    parser.add_argument("--host", default="redis")
    parser.add_argument("--timeout", type=float, default=180)
    args = parser.parse_args()
    wait_api(args.base, "/api/info", args.timeout)
    onboard_redisinsight(args.base, host=args.host)
    print("Redis Insight QA agreements and connection configured; use inventory/dump to verify data access")


if __name__ == "__main__":
    main()
