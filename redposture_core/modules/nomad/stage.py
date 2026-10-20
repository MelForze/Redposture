"""Nomad audit lifecycle."""

from typing import Any

from ...audit_config import AuditConfig
from ...console import Console
from ...stage_runtime import run_basic_host_audit
from ..token_api import build_plan, build_spec
from . import actions, policy, render


def build_nomad_plan(args: Any) -> Any:
    return build_plan(args, "nomad", 4646)


def build_nomad_spec(args: Any) -> Any:
    return build_spec(args, "nomad", 4646, actions, render)


def run_nomad_stage(args: Any, logger: Any) -> int:
    return run_basic_host_audit(
        args,
        logger,
        console=Console(debug=AuditConfig.from_namespace(args).debug),
        label="NOMAD",
        validate=policy.validate_args,
        build_plan=build_nomad_plan,
        build_spec=build_nomad_spec,
    )
