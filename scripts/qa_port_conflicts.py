"""Check QA host ports using one read-only snapshot of running containers."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any


def find_conflicts(containers: object, ports: set[int]) -> list[tuple[int, str, str]]:
    if not isinstance(containers, list):
        raise ValueError("Docker inspect did not return a list")
    conflicts: set[tuple[int, str, str]] = set()
    for container in containers:
        if not isinstance(container, dict) or not isinstance(container.get("NetworkSettings"), dict):
            raise ValueError("Docker inspect returned invalid container network settings")
        network = container["NetworkSettings"]
        bindings = network.get("Ports")
        if bindings is None and "Ports" in network:
            bindings = {}  # A nil port map has no published bindings.
        if not isinstance(bindings, dict):
            raise ValueError("Docker inspect returned invalid published ports")
        for entries in bindings.values():
            if entries is None:
                continue  # Exposed container-only ports do not occupy a host port.
            if not isinstance(entries, list):
                raise ValueError("Docker inspect returned invalid port bindings")
            for entry in entries:
                if not isinstance(entry, dict):
                    raise ValueError("Docker inspect returned an invalid port binding")
                try:
                    port = int(entry["HostPort"])
                except (KeyError, ValueError, TypeError) as exc:
                    raise ValueError("Docker inspect returned an invalid host port") from exc
                if not 1 <= port <= 65535:
                    raise ValueError("Docker inspect returned a host port outside 1..65535")
                if port in ports:
                    conflicts.add(
                        (
                            port,
                            str(container.get("Id") or "unknown")[:12],
                            str(container.get("Name") or "unknown").removeprefix("/"),
                        )
                    )
    return sorted(conflicts)


def inspect_running() -> list[dict[str, Any]]:
    ids = subprocess.run(["docker", "ps", "-q"], check=True, text=True, capture_output=True, timeout=30)
    if not ids.stdout.split():
        return []
    result = subprocess.run(
        ["docker", "inspect", *ids.stdout.split()], check=True, text=True, capture_output=True, timeout=30
    )
    payload = json.loads(result.stdout)
    if not isinstance(payload, list) or not all(isinstance(item, dict) for item in payload):
        raise ValueError("Docker inspect did not return container objects")
    return payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ports-file", type=Path, required=True)
    parser.add_argument("--snapshot", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        ports = {int(line) for line in args.ports_file.read_text().splitlines() if line.strip()}
        if not ports or any(not 1 <= port <= 65535 for port in ports):
            raise ValueError("QA published port set is empty or invalid")
        containers = inspect_running()
        conflicts = find_conflicts(containers, ports)
        snapshot = [
            {
                "Id": item.get("Id"),
                "Name": item.get("Name"),
                "NetworkSettings": {"Ports": item["NetworkSettings"].get("Ports")},
            }
            for item in containers
        ]
        args.snapshot.write_text(json.dumps(snapshot, indent=2) + "\n")
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        print(f"[error] cannot verify QA published ports: {exc}", file=sys.stderr)
        return 2
    for port, container, name in conflicts:
        print(f"[error] lab port conflict: port={port} container={container} name={name}", file=sys.stderr)
    if conflicts:
        print(
            f"[error] refusing to remove {len(conflicts)} external port occupant(s); stop or reconfigure them first",
            file=sys.stderr,
        )
        return 2
    print(f"[preflight] {len(ports)} host ports checked using one running-container snapshot")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
