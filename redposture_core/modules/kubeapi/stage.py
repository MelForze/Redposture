"""Runtime entrypoint for the kubeapi audit module."""

from __future__ import annotations

from typing import Any

from ...audit_config import AuditConfig
from ...audit_models import AuditRecord
from ...console import Console
from ...stage_runtime import (
    AuditCommandPlan,
    AuditCommandRunner,
    ModuleAuditSpec,
    build_basic_audit_plan,
)
from . import actions, policy, render

_DEFAULT_PORT = 6443
_DEFAULT_PORTS: tuple[int, ...] | None = (6443, 16443)
_PRODUCTION_HOST_STAGE = actions.host_stage
_PRODUCTION_AUDIT_HOST = actions._audit_kubeapi_host


def build_kubeapi_plan(args: Any) -> AuditCommandPlan:
    return build_basic_audit_plan(args, default_port=_DEFAULT_PORT, default_ports=_DEFAULT_PORTS)


def _build_kubeapi_host_stage_options(args: Any) -> dict[str, Any]:
    return {
        "show_namespaces": bool(getattr(args, "namespaces", False)),
        "show_pods": bool(getattr(args, "pods", False)),
        "show_secrets": bool(getattr(args, "secrets", False)),
        "namespace_filters": actions._normalize_namespace_filters(getattr(args, "namespace", None)),
        "exec_pod": str(getattr(args, "pod", "") or "").strip() or None,
        "exec_command": str(getattr(args, "exec_command", "") or "").strip() or None,
    }


def build_kubeapi_spec(args: Any) -> ModuleAuditSpec:
    options = _build_kubeapi_host_stage_options(args)
    resolved_host_stage = getattr(actions, _PRODUCTION_HOST_STAGE.__name__, _PRODUCTION_HOST_STAGE)
    use_lifecycle_hooks = (
        actions.host_stage is _PRODUCTION_HOST_STAGE
        and resolved_host_stage is _PRODUCTION_HOST_STAGE
        and actions._audit_kubeapi_host is _PRODUCTION_AUDIT_HOST
    )

    def _detect(ctx: Any) -> AuditRecord:
        return AuditRecord.from_mapping(actions.detect_kubeapi(ctx, options), module="kubeapi", service="kubeapi")

    def _auth(ctx: Any, record: Any) -> AuditRecord:
        return AuditRecord.from_mapping(
            actions.authenticate_kubeapi(ctx, record, options),
            module="kubeapi",
            service="kubeapi",
        )

    def _data(ctx: Any, record: Any) -> AuditRecord:
        return AuditRecord.from_mapping(
            actions.collect_kubeapi_data(ctx, record, options),
            module="kubeapi",
            service="kubeapi",
        )

    return ModuleAuditSpec(
        module="kubeapi",
        label="KUBEAPI",
        default_port=_DEFAULT_PORT,
        host_stage=actions.host_stage,
        host_stage_options=options,
        detect=_detect if use_lifecycle_hooks else None,
        auth=_auth if use_lifecycle_hooks else None,
        data=_data if use_lifecycle_hooks else None,
        lifecycle_state_factory=(lambda _ctx: actions.KubeApiLifecycleState()) if use_lifecycle_hooks else None,
        render_module=render,
        colorize=render._render_colored_kubeapi_line,
        # E3 opt-in: kubeapi anon-open (system:anonymous binding, common on
        # dev/testing clusters) is confirmed by the detect probe.
        keep_anonymous_open_no_auth=True,
    )


def run_kubeapi_stage(args: Any, logger: Any) -> int:
    cfg = AuditConfig.from_namespace(args)
    console = Console(debug=cfg.debug)
    if hasattr(console, "set_structured_output"):
        console.set_structured_output(cfg.output_format == "json")
    validation_rc = policy.validate_args(args, console)
    if validation_rc is not None:
        return int(validation_rc)
    if getattr(args, "token", None) and (
        getattr(args, "username", None) is not None or getattr(args, "password", None) is not None
    ):
        if hasattr(console, "warn"):
            console.warn("--token is set; Basic auth credentials are ignored")
        args.username = None
        args.password = None
    try:
        plan = build_kubeapi_plan(args)
    except ValueError as exc:
        console.error(str(exc))
        return 2
    if cfg.debug and not getattr(args, "debug_emit", None):
        args.debug_emit = console.info
    if cfg.debug:
        suffix = f" format={cfg.output_format}"
        if cfg.output:
            suffix += f" output={args.output}"
        auth_mode = (
            "token"
            if getattr(args, "token", None)
            else ("basic" if getattr(args, "username", None) is not None else "none")
        )
        console.info(f"kubeapi audit started: auth={auth_mode}" + suffix)
    try:
        runner = AuditCommandRunner(args=args, spec=build_kubeapi_spec(args), logger=logger, console=console)
        result = runner.run_plan(plan)
    except ValueError as exc:
        console.error(str(exc))
        return 2
    except OSError as exc:
        console.error(f"failed to process kubeapi output: {exc}")
        return 2
    if cfg.debug and result.detected_count == 0 and hasattr(console, "warn"):
        console.warn("all kubeapi targets are unreachable")
    return 0


__all__ = [
    "_build_kubeapi_host_stage_options",
    "build_kubeapi_plan",
    "build_kubeapi_spec",
    "run_kubeapi_stage",
]
