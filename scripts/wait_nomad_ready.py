"""Wait externally for a leader and a ready, eligible raw_exec client."""

from __future__ import annotations

import argparse
import json
import time
import urllib.error
import urllib.request
from typing import Any


def ready_client(nodes: Any) -> bool:
    return isinstance(nodes, list) and any(
        isinstance(node, dict)
        and node.get("Status") == "ready"
        and node.get("SchedulingEligibility") == "eligible"
        and (node.get("Drivers", {}).get("raw_exec", {}).get("Healthy") is True)
        for node in nodes
    )


def wait_ready(base: str, seconds: float = 120) -> None:
    deadline = time.monotonic() + seconds
    last: object = "no response"

    def get(path: str) -> Any:
        with urllib.request.urlopen(
            base.rstrip("/") + path, timeout=min(5, max(0.01, deadline - time.monotonic()))
        ) as response:
            return json.load(response)

    while time.monotonic() < deadline:
        try:
            leader = get("/v1/status/leader")
            if isinstance(leader, str) and leader and ready_client(get("/v1/nodes")):
                return
            last = "leader or eligible raw_exec client missing"
        except (OSError, ValueError, urllib.error.URLError) as exc:
            last = str(exc)
        time.sleep(min(0.25, max(0, deadline - time.monotonic())))
    raise TimeoutError(f"Nomad not ready within {seconds}s: {last}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("base")
    parser.add_argument("--timeout", type=float, default=120)
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    wait_ready(args.base, args.timeout)
    print("Nomad leader and eligible raw_exec client ready")


if __name__ == "__main__":
    main()
