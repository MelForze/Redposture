"""Give QA Compose services isolated names and deterministic fixture settings.

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


def build_override(config: object, project: str) -> dict[str, dict[str, dict[str, object]]]:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", project):
        raise ValueError("invalid QA Compose project name")
    if not isinstance(config, dict) or not isinstance(config.get("services"), dict):
        raise ValueError("Compose config has no services")
    services: dict[str, dict[str, object]] = {
        service: {"container_name": f"{project}-{name}"}
        for service, details in config["services"].items()
        if isinstance(service, str)
        and isinstance(details, dict)
        and isinstance(name := details.get("container_name"), str)
        and name
    }
    for service, details in config["services"].items():
        if service not in services:
            continue
        name = str(details.get("container_name") or "")
        image = str(details.get("image") or "").split("@", 1)[0].split(":", 1)[0]
        if not re.fullmatch(r"redposture-lab-grafana(?:-\d+)?", name) or image not in {
            "grafana/grafana",
            "grafana/grafana-oss",
            "grafana/grafana-enterprise",
        }:
            continue
        # Independent auth cases and pair-specific controls share this fixture.
        # Prevent earlier cases from locking only the first replica before the
        # multi-target check. Normal/manual labs keep their original policy.
        # Include the full environment: --config-output caches a shallow merge.
        environment = details.get("environment")
        services[service]["environment"] = {
            **(environment if isinstance(environment, dict) else {}),
            "GF_SECURITY_BRUTE_FORCE_LOGIN_PROTECTION_MAX_ATTEMPTS": "1000",
        }
    airflow = config["services"].get("airflow-auth")
    if isinstance(airflow, dict) and airflow.get("container_name") == "redposture-lab-airflow-auth":
        target = "/opt/airflow/webserver_config.py"
        services["airflow-auth"]["volumes"] = [
            mount
            for mount in airflow.get("volumes", [])
            if not isinstance(mount, dict) or mount.get("target") != target
        ] + [
            {
                "type": "bind",
                "source": str(
                    Path(__file__).resolve().parents[1] / "tests/fixtures/airflow_golden_lab/webserver_config.py"
                ),
                "target": target,
                "read_only": True,
            }
        ]
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
