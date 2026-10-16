"""Give QA Compose services project-scoped container names.

The local fixture Compose files have fixed ``container_name`` values so they
can be used by hand. A QA run must not collide with another stopped or running
fixture project that happens to use those names.
"""

from __future__ import annotations

import argparse
import json
import re
import sys


def build_override(config: object, project: str) -> dict[str, object]:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", project):
        raise ValueError("invalid QA Compose project name")
    if not isinstance(config, dict) or not isinstance(config.get("services"), dict):
        raise ValueError("Compose config has no services")
    services = {
        service: {"container_name": f"{project}-{name}"}
        for service, details in config["services"].items()
        if isinstance(service, str)
        and isinstance(details, dict)
        and isinstance(name := details.get("container_name"), str)
        and name
    }
    return {"services": services}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--project", required=True)
    args = parser.parse_args()
    try:
        result = build_override(json.load(sys.stdin), args.project)
    except (ValueError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    json.dump(result, sys.stdout)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
