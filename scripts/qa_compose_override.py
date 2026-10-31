"""Give QA Compose services project-scoped container names.

The local fixture Compose files have fixed ``container_name`` values so they
can be used by hand. A QA run must not collide with another stopped or running
fixture project that happens to use those names.
"""

from __future__ import annotations

import argparse
import copy
import json
import re
import sys
from pathlib import Path


def build_override(config: object, project: str) -> dict[str, dict[str, dict[str, str]]]:
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
    parser.add_argument("--config-output", type=Path)
    args = parser.parse_args()
    try:
        config = json.load(sys.stdin)
        result = build_override(config, args.project)
        if args.config_output is not None:
            merged = copy.deepcopy(config)
            for service, override in result["services"].items():
                merged["services"][service].update(override)
            temporary = args.config_output.with_suffix(".tmp")
            temporary.write_text(json.dumps(merged) + "\n", encoding="utf-8")
            temporary.replace(args.config_output)
    except (ValueError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    json.dump(result, sys.stdout)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
