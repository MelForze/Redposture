"""Nexus audit entrypoint backed by the shared OCI client."""

from __future__ import annotations

from typing import Any

from ..registry.stage import build_registry_plan, build_registry_spec, run_nexus_stage


def build_nexus_plan(args: Any):
    return build_registry_plan(args, product="nexus")


def build_nexus_spec(args: Any):
    return build_registry_spec(args, product="nexus")


__all__ = ["build_nexus_plan", "build_nexus_spec", "run_nexus_stage"]
