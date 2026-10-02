"""Plain Docker Registry audit entrypoint backed by the shared OCI client."""

from __future__ import annotations

from typing import Any

from ..registry.stage import build_registry_plan, build_registry_spec, run_docker_registry_stage


def build_docker_registry_plan(args: Any):
    return build_registry_plan(args, product="docker-registry")


def build_docker_registry_spec(args: Any):
    return build_registry_spec(args, product="docker-registry")


__all__ = ["build_docker_registry_plan", "build_docker_registry_spec", "run_docker_registry_stage"]
