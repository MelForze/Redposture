"""Jenkins audit entrypoint and phase-aware hooks."""

from __future__ import annotations

from dataclasses import replace
from itertools import islice
from typing import Any

from ...audit_config import AuditConfig
from ...audit_models import AuditRecord
from ...clients.http_api import http_target_context
from ...clients.http_session import HttpSessionPool
from ...clients.scoped_http import HttpLifecycleState
from ...console import Console
from ...detection_steps import with_async_http_detection
from ...stage_runtime import (
    AuditCommandPlan,
    AuditCredentialRun,
    ModuleAuditSpec,
    build_basic_audit_plan,
    merge_audit_credential_runs,
    run_basic_host_audit,
    sort_default_audit_credential_runs,
)
from ..execution_api import run_os_shell
from ..rce_probe import probe_execution
from . import actions, execution, policy, render

_DEFAULT_PORTS = (8080, 8443, 18080)


def _emit_discovery_inventory(ctx: Any, payload: dict[str, Any]) -> None:
    emit = getattr(ctx, "live_emit", None)
    if (
        not getattr(ctx.args, "discover", False)
        or getattr(ctx.args, "output_format", "txt") != "txt"
        or not callable(emit)
    ):
        return
    lines = iter(render._iter_inventory_records(payload))
    while batch := list(islice(lines, 256)):
        emit(batch)
    payload["_jenkins_inventory_emitted"] = True


_DEFAULT_CREDENTIALS = (
    ("admin", "admin"),
    ("admin", "changeme"),
    ("admin", "jenkins"),
    ("admin", "password"),
    ("admin", "admin123"),
    ("admin", "12345678"),
    ("jenkins", "jenkins"),
    ("jenkins", "password"),
    ("jenkins", "changeme"),
    ("jenkins", "admin"),
    ("root", "root"),
    ("root", "password"),
    ("user", "user"),
    ("user", "password"),
    ("test", "test"),
    ("dev", "dev"),
    ("guest", "guest"),
    ("service", "service"),
)


def _normalize_target_aliases(plan: Any) -> Any:
    """Normalize equivalent URL prefixes without expanding streamed IP ranges."""
    entries: list[Any] = []
    seen: set[tuple[Any, ...]] = set()
    removed = 0
    no_port_count = plan.no_port_count
    explicit_counts = dict(plan.explicit_port_counts)
    bare_counts = dict(plan.bare_explicit_port_counts)
    for entry in plan._entries:
        if not hasattr(entry, "specs"):
            entries.append(entry)
            continue
        specs = []
        for original in entry.specs:
            spec = (
                replace(original, path=original.path.rstrip("/"), fragment="", normalized_key=None)
                if original.scheme
                else original
            )
            key = (spec.host, spec.scheme, spec.explicit_port, spec.path, spec.query, spec.fragment)
            if key in seen:
                removed += 1
                if spec.explicit_port is None:
                    no_port_count -= 1
                else:
                    explicit_counts[spec.explicit_port] -= 1
                    if spec.scheme is None:
                        bare_counts[spec.explicit_port] -= 1
                continue
            seen.add(key)
            specs.append(spec)
        if specs:
            entries.append(replace(entry, specs=tuple(specs)))
    return replace(
        plan,
        _entries=tuple(entries),
        target_count=plan.target_count - removed,
        no_port_count=no_port_count,
        explicit_port_counts={port: count for port, count in explicit_counts.items() if count},
        bare_explicit_port_counts={port: count for port, count in bare_counts.items() if count},
        explicit_ports=tuple(port for port in plan.explicit_ports if explicit_counts.get(port)),
    )


def build_jenkins_plan(args: Any) -> AuditCommandPlan:
    plan = build_basic_audit_plan(args, default_port=8080, default_ports=_DEFAULT_PORTS)
    explicit_port = getattr(args, "port", None) is not None or bool(str(getattr(args, "ports", "") or "").strip())
    if not explicit_port and plan.target_plan is not None:
        plan = replace(plan, target_plan=plan.target_plan.with_scheme_default_ports({"http": 80, "https": 443}))
    if plan.target_plan is not None:
        plan = replace(plan, target_plan=_normalize_target_aliases(plan.target_plan))
    token = getattr(args, "_jenkins_api_token", None)
    provided = (
        (AuditCredentialRun(username=args.username, password=token, source="api_token"),)
        if token
        else plan.credential_runs
    )
    defaults = (
        sort_default_audit_credential_runs(
            AuditCredentialRun(username=username, password=password, source="default")
            for username, password in _DEFAULT_CREDENTIALS
        )
        if getattr(args, "defcreds", False)
        else ()
    )
    return replace(plan, credential_runs=merge_audit_credential_runs(provided, defaults))


def build_jenkins_spec(args: Any) -> ModuleAuditSpec:
    def _state(ctx: Any) -> HttpLifecycleState:
        return HttpLifecycleState(
            HttpSessionPool(
                timeout=float(getattr(ctx.args, "timeout", 5.0) or 5.0),
                retries=int(getattr(ctx.args, "retries", 0) or 0),
                proxy=getattr(ctx.args, "_proxy_config", None),
                insecure=True,
            )
        )

    def _phase(ctx: Any, action: Any, record: AuditRecord | None = None) -> AuditRecord:
        with http_target_context(
            ctx.target,
            route_state=getattr(ctx, "lifecycle_state", None),
            api_prefixes=("/api", "/login", "/whoAmI", "/job", "/pluginManager", "/computer", "/queue"),
        ):
            value = action(ctx) if record is None else action(ctx, record.to_dict())
        return AuditRecord.from_mapping(value, module="jenkins", service="jenkins")

    def _data(ctx: Any, record: AuditRecord) -> AuditRecord:
        if bool(getattr(ctx.args, "os_shell", False)):
            run_os_shell(
                ctx,
                record,
                ctx.lifecycle_state,
                module="jenkins",
                surface="Jenkins Script Console",
                execute_once=execution.collect,
            )
            return record
        payload = execution.collect(ctx, record.to_dict(), ctx.lifecycle_state)
        if getattr(ctx.args, "execute", None) is not None and (
            not payload.get("execute_verified")
            or not any(
                getattr(ctx.args, key, False)
                for key in (
                    "show_jobs",
                    "show_builds",
                    "show_plugins",
                    "show_nodes",
                    "show_queue",
                    "show_artifacts",
                    "discover",
                )
            )
        ):
            return AuditRecord.from_mapping(payload, module="jenkins", service="jenkins")
        record = _phase(
            ctx, actions.data_record, AuditRecord.from_mapping(payload, module="jenkins", service="jenkins")
        )
        payload = record.to_dict()
        _emit_discovery_inventory(ctx, payload)
        return AuditRecord.from_mapping(payload, module="jenkins", service="jenkins")

    def _rce_probe(ctx: Any, record: AuditRecord) -> AuditRecord:
        return probe_execution(ctx, record, ctx.lifecycle_state, execution.collect)

    spec = ModuleAuditSpec(
        module="jenkins",
        label="JENKINS",
        default_port=8080,
        lifecycle_state_factory=_state,
        lifecycle_state_close=lambda state: state.close(),
        detect=lambda ctx: _phase(ctx, actions.detect_record),
        auth=lambda ctx, record: _phase(ctx, actions.auth_record, record),
        data=_data,
        render_module=render,
        colorize=render._render_colored_jenkins_line,
        is_detected=lambda record: record.extra.get("is_jenkins") is True,
        rce_probe=_rce_probe,
        credential_gate=lambda _credential, record: (
            record.extra.get("provided_credentials_ok") is True,
            "Jenkins identity verified"
            if record.extra.get("provided_credentials_ok") is True
            else "identity not verified",
        ),
        record_skipped_credential_attempts=bool(getattr(args, "defcreds", False)),
        credential_attempt_detail_fields=(
            "credential_state",
            "credential_verification_reason",
            "auth_http_status",
            "auth_error_detail",
            "auth_response_body",
            "auth_retry_after",
            "credential_stop_reason",
            "credential_jobs_access",
            "credential_jobs_count",
            "credential_source",
        ),
        logical_target_key=lambda record: str(record.extra.get("api_endpoint") or "").rstrip("/") or None,
        phase_output_key=lambda record, line: (
            "jenkins-detection:" + str(record.extra.get("api_endpoint") or f"{record.host}:{record.port}")
            if " [*] Jenkins (auth required:" in line
            else line
        ),
        continue_after_credential_error=bool(getattr(args, "defcreds", False)),
        continue_after_credential_success=bool(getattr(args, "defcreds", False)),
        defer_detect_output_until_auth=True,
        live_phase_output=True,
    )

    return with_async_http_detection(
        spec, actions, api_prefixes=("/api", "/login", "/whoAmI", "/job", "/pluginManager", "/computer", "/queue")
    )


def run_jenkins_stage(args: Any, logger: Any) -> int:
    cfg = AuditConfig.from_namespace(args)
    return run_basic_host_audit(
        args,
        logger,
        console=Console(debug=cfg.debug),
        label="JENKINS",
        validate=policy.validate_args,
        build_plan=build_jenkins_plan,
        build_spec=build_jenkins_spec,
    )


__all__ = ["build_jenkins_plan", "build_jenkins_spec", "run_jenkins_stage"]
