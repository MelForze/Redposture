"""Explainable short-gate selection; full CI/QA and all-module profiles remain separate."""

from __future__ import annotations

import sys
from collections.abc import Iterable
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.profile_native_data_performance import MODULES as NATIVE_DATA_MODULES  # noqa: E402

REPRESENTATIVES = ("postgres", "redis", "grafana", "kafka")
# These commands have independently seeded action-result matchers in the wire
# profiler. An absent entry is a missing short recipe, not product N/A and
# not a claim that no other fixture exists in the larger profile suite.
ACTIONS = {
    "airflow": ["--show-dags", "--show-keys", "--show-connections"],
    "grafana": ["--show-datasources"],
    "jenkins": ["--show-jobs"],
    "keycloak": ["--show-realms", "--show-clients"],
    "rabbitmq": ["--show-queues"],
    "vault": ["--show-mounts"],
    "nomad": ["--show-jobs"],
    "jupyter": ["--show-kernels"],
    "proxmox": ["--show-nodes", "--show-users"],
    "minio": ["--show-buckets"],
    "portainer": ["--show-containers", "--show-images"],
    "elastic": ["--show-cluster", "--show-user"],
    "etcd": ["--dump"],
    "harbor": ["--show-images"],
    "docker-registry": ["--show-images"],
    "nexus": [
        "--show-repositories",
        "--show-assets",
        "--repository",
        "release-assets",
        "--asset",
        "release-notes/stable/artifact.bin",
    ],
    "gitlab": ["--project", "team/app"],
    "consul": ["--services"],
    "qdrant": ["--dump"],
    "kubeapi": ["--namespaces"],
    "docker": ["--containers", "--images"],
    "spark": ["--show-workers", "--show-apps"],
    "yarn": ["--show-apps", "--show-nodes"],
    "kafka": ["--show-topics"],
    "grpc": ["--analyze"],
}
ACTION_SETTINGS = {
    **{name: {"access_case": "open", "auth_case": "invalid"} for name in ("docker", "spark", "yarn")},
    "kafka": {"auth_surface": "provectus-ui"},
    "grpc": {"auth_surface": "grpc-auth", "native_peer": "process"},
}


def selection(inventory: dict[str, Any], changed: Iterable[str], *, all_modules: bool = False) -> dict[str, Any]:
    rows = inventory["audit_modules"]
    by_name = {row["module"]: row for row in rows}
    if len(by_name) != len(rows):
        raise ValueError("duplicate module in inventory")
    selected: dict[str, set[str]] = {}
    changed = sorted(set(changed))
    discover_changed = False
    runtime_changed = False
    workflows_changed = False

    def choose(module: str, reason: str) -> None:
        selected.setdefault(module, set()).add(reason)

    for name in changed:
        if name.startswith("redposture_core/modules/"):
            package = name.split("/")[2]
            for module in by_name:
                if (
                    module.replace("-", "_") == package
                    or package == "registry"
                    and module in {"harbor", "nexus", "docker-registry"}
                ):
                    choose(module, "direct module path: " + name)
        if name.startswith("redposture_core/") and "/modules/" not in name:
            if any(part in name for part in ("discovery", "secret_")):
                discover_changed = True
            else:
                runtime_changed = True
        if "/exporters/" in name or name.startswith("redposture_core/spray"):
            workflows_changed = True
    if runtime_changed or all_modules:
        for module in by_name if all_modules else REPRESENTATIVES:
            if module in by_name:
                choose(module, "all modules requested" if all_modules else "representative of shared runtime")
    discover_routes = (
        [r["module"] for r in rows if r["discover"]]
        if discover_changed or all_modules
        else [m for m in selected if by_name[m]["discover"]]
    )
    catalog = []
    for row in rows:
        module = row["module"]
        catalog.append(
            {
                "module": module,
                "surfaces": row["companion_surfaces"] + row["additional_surfaces"],
                "detect": {"available": True, "instrument": "profile_module_performance.py --mode detect"},
                "auth": {
                    "available": bool(set(row["auth_flags"]) & {"--token", "--api-key"})
                    or {"-u", "-p"} <= set(row["auth_flags"]),
                    "transport_auth_flags": [flag for flag in row["auth_flags"] if flag == "--tls-cert"],
                    "instrument": "profile_module_performance.py --mode credentials",
                    "scope": "invalid supplied identity; positive identity requires a seeded protocol/surface recipe",
                },
                "data": {
                    "available": bool(row["inventory_flags"]),
                    "seeded_action_recipe": ACTIONS.get(module),
                    "adapter_instrument": "profile_native_data_performance.py --module " + module
                    if module in NATIVE_DATA_MODULES
                    else None,
                    "transport_boundary": "SDK/session/network data transport is outside the short adapter profile"
                    if module in NATIVE_DATA_MODULES
                    else None,
                    "fixture_status": "SEEDED"
                    if module in ACTIONS
                    else "SEEDED_ADAPTER"
                    if module in NATIVE_DATA_MODULES
                    else "MISSING_ACTION_RECIPE"
                    if row["inventory_flags"]
                    else "NO_INVENTORY_FLAGS",
                },
                "discover": {
                    "available": row["discover"],
                    "instrument": "discovery_accuracy.py --route " + module if row["discover"] else None,
                    "scope": "DTO/reader known-answer processing, not authentication or full network traversal",
                },
            }
        )
    return {
        "scope": "short selection, not all-API or production coverage",
        "changed_paths": changed,
        "modules": [{"module": m, "reasons": sorted(selected[m])} for m in sorted(selected)],
        "discover_routes": sorted(discover_routes),
        "shared_processing": discover_changed or all_modules,
        "workflows": ["collect", "trigger", "spray"] if workflows_changed or runtime_changed or all_modules else [],
        "catalog": catalog,
        "missing_data_recipes": [
            r["module"] for r in catalog if r["data"]["fixture_status"] == "MISSING_ACTION_RECIPE"
        ],
        "adapter_only_data_modules": [r["module"] for r in catalog if r["data"]["fixture_status"] == "SEEDED_ADAPTER"],
        "full_ci_qa_required": True,
    }


def main() -> int:
    import argparse
    import json
    import subprocess

    from scripts.profile_module_performance import inventory

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--changed-file", action="append")
    parser.add_argument("--all-modules", action="store_true")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("output must be new")
    changed = args.changed_file
    if changed is None:
        changed = []
        for command in (
            ["git", "diff", "--name-only", "-z", "HEAD", "--"],
            ["git", "ls-files", "--others", "--exclude-standard", "-z"],
        ):
            changed.extend(
                name for name in subprocess.check_output(command, cwd=args.source).decode().split("\0") if name
            )
    plan = selection(inventory(args.source.resolve()), changed, all_modules=args.all_modules)
    plan["status"] = "PLAN_ONLY"
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(plan, indent=2) + "\n")
    print(
        json.dumps(
            {
                "status": plan["status"],
                "modules": len(plan["modules"]),
                "discover_routes": len(plan["discover_routes"]),
                "missing_data_recipes": plan["missing_data_recipes"],
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
