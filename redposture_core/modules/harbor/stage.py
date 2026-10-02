"""Harbor audit entrypoint backed by the shared OCI client."""

from __future__ import annotations

from typing import Any

from ..registry.stage import build_registry_plan, build_registry_spec, run_harbor_stage


def build_harbor_plan(args: Any):
    return build_registry_plan(args, product="harbor")


def build_harbor_spec(args: Any):
    return build_registry_spec(args, product="harbor")


__all__ = ["build_harbor_plan", "build_harbor_spec", "run_harbor_stage"]
