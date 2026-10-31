"""Nomad audit lifecycle."""

from dataclasses import replace
from typing import Any

from ...audit_config import AuditConfig
from ...audit_models import AuditRecord
from ...console import Console
from ...stage_runtime import run_basic_host_audit
from ..execution_api import finish, run_os_shell
from ..rce_probe import probe_execution
from ..token_api import build_plan, build_spec
from . import actions, execution, policy, render


def build_nomad_plan(args: Any) -> Any:
    return build_plan(args, "nomad", 4646)


def build_nomad_spec(args: Any) -> Any:
    spec = build_spec(args, "nomad", 4646, actions, render)

    def _rce_probe(ctx: Any, record: AuditRecord) -> AuditRecord:
        def _execute(current_ctx: Any, prior: dict[str, Any], _state: Any) -> dict[str, Any]:
            return {"execution": execution.execute(current_ctx, prior)}

        return probe_execution(ctx, record, None, _execute, stateful=False)

    spec = replace(spec, rce_probe=_rce_probe)
    if bool(getattr(args, "os_shell", False)) and spec.data is not None:

        def _shell(ctx: Any, record: AuditRecord) -> AuditRecord:
            def execute_once(current_ctx: Any, prior: dict[str, Any], _state: Any) -> dict[str, Any]:
                output = finish(
                    execution.execute(current_ctx, prior),
                    max_bytes=int(getattr(current_ctx.args, "execute_max_bytes", 1048576)),
                )
                return {**prior, "execution": output, "execute_verified": output.get("executed") is True}

            run_os_shell(
                ctx,
                record,
                ctx.lifecycle_state,
                module="nomad",
                surface="selected allocation/task" if getattr(ctx.args, "allocation", None) else "temporary Nomad job",
                execute_once=execute_once,
                cache_fields=(),
            )
            return record

        return replace(spec, data=_shell)
    return spec


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
