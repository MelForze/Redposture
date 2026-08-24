"""Runtime entrypoint for the proxmox audit module."""

from __future__ import annotations

import time
from dataclasses import dataclass, field, replace
from typing import Any

from ...audit_config import AuditConfig
from ...audit_models import AuditRecord
from ...clients.http_api import http_target_context
from ...clients.http_session import HttpSessionPool
from ...console import Console
from ...stage_runtime import (
    AuditCommandPlan,
    AuditCredentialRun,
    AuditHookContext,
    ModuleAuditSpec,
    build_basic_audit_plan,
    build_basic_credential_runs,
    merge_audit_credential_runs,
    run_basic_host_audit,
    sort_default_audit_credential_runs,
)
from . import actions, policy, render

_DEFAULT_PORT = 8006
_DEFAULT_PORTS: tuple[int, ...] | None = (8006, 18006)
_PROXMOX_HOST_STAGE = actions.host_stage
_PROXMOX_HOST_STAGE_NAME = actions.host_stage.__name__
_PROXMOX_HOST_STAGE_IMPL = getattr(actions, _PROXMOX_HOST_STAGE_NAME, actions.host_stage)
_PROXMOX_AUDIT_HOST_IMPL = actions._audit_proxmox_host


@dataclass
class _ProxmoxLifecycleState:
    detect_record: AuditRecord | None = None
    auth_attempts: list[dict[str, str]] = field(default_factory=list)
    resolved_auth: tuple[dict[str, str], str, str | None, str | None, list[dict[str, str]]] | None = None
    deep_record: AuditRecord | None = None
    http: HttpSessionPool | None = None

    def close(self) -> None:
        if self.http is not None:
            self.http.close()
            self.http = None


def build_proxmox_plan(args: Any) -> AuditCommandPlan:
    plan = build_basic_audit_plan(args, default_port=_DEFAULT_PORT, default_ports=_DEFAULT_PORTS)
    explicit_port = getattr(args, "port", None) is not None or bool(str(getattr(args, "ports", "") or "").strip())
    if not explicit_port and plan.target_plan is not None:
        plan = replace(plan, target_plan=plan.target_plan.with_scheme_default_ports({"http": 80, "https": 443}))
    return plan


def _proxmox_lifecycle_state_factory(ctx: AuditHookContext) -> _ProxmoxLifecycleState:
    return _ProxmoxLifecycleState(
        http=HttpSessionPool(
            timeout=float(getattr(ctx.args, "timeout", 1.0)),
            insecure=bool(getattr(ctx.args, "insecure", False)),
            proxy=_proxmox_proxy(ctx.args),
        )
    )


def _activate_transport(ctx: AuditHookContext) -> None:
    state = ctx.lifecycle_state if isinstance(ctx.lifecycle_state, _ProxmoxLifecycleState) else None
    actions.activate_proxmox_transport(state.http if state is not None else None)


def _proxmox_record(payload: AuditRecord | dict[str, Any]) -> AuditRecord:
    if isinstance(payload, AuditRecord):
        return payload
    return AuditRecord.from_mapping(dict(payload), module="proxmox", service="proxmox")


def _proxmox_apply_credential_source(record: AuditRecord, credential: AuditCredentialRun) -> AuditRecord:
    if (
        credential.source != "default"
        or str(record.status or "") != "token_ok"
        or str(record.extra.get("auth_method") or "") != "password"
    ):
        return record
    payload = record.to_dict()
    payload.update({"status": "weak_default_creds", "defcreds_enabled": True})
    return _proxmox_record(payload)


def _resolved_proxmox_host_stage() -> Any:
    if actions.host_stage is not _PROXMOX_HOST_STAGE:
        return actions.host_stage
    return getattr(actions, _PROXMOX_HOST_STAGE_NAME, actions.host_stage)


def _proxmox_host_stage_is_replaced() -> bool:
    return (
        _resolved_proxmox_host_stage() is not _PROXMOX_HOST_STAGE_IMPL
        or actions._audit_proxmox_host is not _PROXMOX_AUDIT_HOST_IMPL
    )


def _proxmox_use_https(ctx: AuditHookContext) -> bool:
    target_scheme = str(ctx.target.scheme or "").lower() if ctx.target is not None else ""
    if target_scheme in {"http", "https"}:
        return target_scheme == "https"
    return bool(getattr(ctx.args, "https", True))


def _proxmox_proxy(args: Any) -> Any | None:
    if hasattr(args, "_proxy_config"):
        return args._proxy_config
    return getattr(args, "proxy", None)


def _proxmox_requested_action_fields(args: Any) -> dict[str, Any]:
    """Fields that describe the requested CLI actions, even when auth gates them."""

    return {
        "discover_creds": bool(getattr(args, "discover_creds", False)),
        "show_nodes": bool(getattr(args, "nodes", False) or getattr(args, "show_nodes", False)),
        "show_users": bool(getattr(args, "users", False) or getattr(args, "show_users", False)),
        "add_user": str(getattr(args, "add_user", "") or "").strip() or None,
        "grant_role": str(getattr(args, "grant_role", "") or "").strip() or None,
        "grant_path": str(getattr(args, "grant_path", "/") or "/").strip(),
        "grant_propagate": bool(getattr(args, "grant_propagate", True)),
    }


def _proxmox_with_action_contract(record: AuditRecord, args: Any) -> AuditRecord:
    payload = record.to_dict()
    payload.update(_proxmox_requested_action_fields(args))
    return _proxmox_record(payload)


def _proxmox_detect(ctx: AuditHookContext) -> AuditRecord:
    """Classify the API anonymously before any token/password is applied."""

    _activate_transport(ctx)
    cfg = AuditConfig.from_namespace(ctx.args)
    use_https = _proxmox_use_https(ctx)
    if _proxmox_host_stage_is_replaced():
        record = _proxmox_record(
            _resolved_proxmox_host_stage()(
                host=ctx.host,
                port=ctx.port,
                timeout=cfg.timeout,
                retries=cfg.retries,
                pve_api_token="",
                use_https=use_https,
                insecure=bool(getattr(ctx.args, "insecure", False)),
                proxy=_proxmox_proxy(ctx.args),
                username=None,
                password=None,
                defcreds=False,
                discover_creds=False,
                show_nodes=False,
                show_users=False,
                add_user=None,
                run_deep_checks=False,
                debug=cfg.debug,
                debug_emit=ctx.debug_emit,
                on_status_ready=None,
                on_discovered_url=None,
                on_credential_finding=None,
            )
        )
        record = _proxmox_with_action_contract(record, ctx.args)
        if isinstance(ctx.lifecycle_state, _ProxmoxLifecycleState):
            ctx.lifecycle_state.detect_record = record
        return record
    started = time.monotonic()
    status, payload, response_headers, error = actions._proxmox_request(
        ctx.host,
        ctx.port,
        "/access",
        cfg.timeout,
        cfg.retries,
        pve_api_token="",
        use_https=use_https,
        insecure=bool(getattr(ctx.args, "insecure", False)),
        proxy=_proxmox_proxy(ctx.args),
        auth_headers={},
    )
    detected = actions._looks_like_proxmox_response(status, payload, response_headers)
    if error:
        record_status = "fail"
        detected = False
        error_text = error
    elif not detected:
        record_status = "fail"
        error_text = "service is not proxmox"
    elif status == 200:
        record_status = "open_no_auth"
        error_text = None
    elif status in {401, 403}:
        record_status = "auth_failed"
        error_text = actions._extract_error_message(payload) or "authentication required"
    else:
        record_status = "fail"
        error_text = f"unexpected HTTP {status} from /access"
    record = _proxmox_record(
        {
            "timestamp": actions.utc_now_iso(),
            "host": ctx.host,
            "port": ctx.port,
            "service": "proxmox",
            "module": "proxmox",
            "is_proxmox": detected,
            "status": record_status,
            "auth_required": detected and status in {401, 403},
            "auth_method": "anonymous",
            "auth_attempts": [],
            "use_https": use_https,
            "checked_endpoints": 1,
            "successful_endpoints": int(status == 200),
            "endpoint_results": [{"path": "/access", "status": status, "error": error, "method": "GET"}],
            "elapsed_ms": int((time.monotonic() - started) * 1000),
            "error": error_text,
        }
    )
    record = _proxmox_with_action_contract(record, ctx.args)
    if isinstance(ctx.lifecycle_state, _ProxmoxLifecycleState):
        ctx.lifecycle_state.detect_record = record
    return record


def _proxmox_auth(ctx: AuditHookContext, detect_record: AuditRecord) -> AuditRecord:
    _activate_transport(ctx)
    cfg = AuditConfig.from_namespace(ctx.args)
    state = ctx.lifecycle_state if isinstance(ctx.lifecycle_state, _ProxmoxLifecycleState) else None
    credential = ctx.credential
    token = str(
        credential.token
        or (
            getattr(ctx.args, "pve_api_token", None)
            if credential.username is None and credential.password is None
            else None
        )
        or ""
    ).strip()
    use_https = _proxmox_use_https(ctx)
    payload = detect_record.to_dict()
    payload.update(
        {
            "host": ctx.host,
            "port": ctx.port,
            "module": "proxmox",
            "service": "proxmox",
            "is_proxmox": True,
            "use_https": use_https,
            **_proxmox_requested_action_fields(ctx.args),
        }
    )

    if _proxmox_host_stage_is_replaced():
        options = _build_proxmox_host_stage_options(ctx.args)
        deep_record = _proxmox_apply_credential_source(
            _proxmox_record(
                _resolved_proxmox_host_stage()(
                    host=ctx.host,
                    port=ctx.port,
                    timeout=cfg.timeout,
                    retries=cfg.retries,
                    pve_api_token=token,
                    use_https=use_https,
                    insecure=bool(getattr(ctx.args, "insecure", False)),
                    proxy=_proxmox_proxy(ctx.args),
                    username=credential.username,
                    password=credential.password,
                    defcreds=False,
                    discover_creds=bool(options["discover_creds"]),
                    show_nodes=bool(options["show_nodes"]),
                    show_users=bool(options["show_users"]),
                    add_user=options["add_user"],
                    grant_role=options["grant_role"],
                    grant_path=options["grant_path"],
                    grant_propagate=options["grant_propagate"],
                    run_deep_checks=True,
                    debug=cfg.debug,
                    debug_emit=ctx.debug_emit,
                    on_status_ready=options["on_status_ready"],
                    on_discovered_url=options["on_discovered_url"],
                    on_credential_finding=options["on_credential_finding"],
                )
            ),
            credential,
        )
        if (
            state is not None
            and state.deep_record is None
            and str(deep_record.status or "")
            in {
                "token_ok",
                "weak_default_creds",
                "insufficient_privileges",
            }
        ):
            state.deep_record = deep_record
        return deep_record

    if (
        str(detect_record.status or "") == "open_no_auth"
        and not token
        and credential.username is None
        and credential.password is None
    ):
        anonymous_resolved: tuple[
            dict[str, str],
            str,
            str | None,
            str | None,
            list[dict[str, str]],
        ] = ({}, "anonymous", None, None, [])
        if state is not None:
            state.resolved_auth = anonymous_resolved
        payload.update(
            {
                "status": "open_no_auth",
                "auth_required": False,
                "auth_method": "anonymous",
                "auth_username": None,
                "auth_password": None,
                "auth_attempts": [],
                "error": None,
            }
        )
        return _proxmox_record(payload)

    if token:
        auth_headers = actions._proxmox_auth_headers(token)
        status, token_payload, _headers, token_error = actions._proxmox_request(
            ctx.host,
            ctx.port,
            "/access",
            cfg.timeout,
            cfg.retries,
            pve_api_token="",
            use_https=use_https,
            insecure=bool(getattr(ctx.args, "insecure", False)),
            proxy=_proxmox_proxy(ctx.args),
            auth_headers=auth_headers,
        )
        error_message = token_error or actions._extract_error_message(token_payload)
        if status not in {200, 403}:
            payload.update(
                {
                    "status": "auth_failed",
                    "auth_required": True,
                    "auth_method": "pveapitoken",
                    "auth_username": None,
                    "auth_password": None,
                    "auth_attempts": [],
                    "error": error_message or f"unexpected HTTP {status} from /access",
                }
            )
            return _proxmox_record(payload)
        token_resolved: tuple[dict[str, str], str, str | None, str | None, list[dict[str, str]]] = (
            auth_headers,
            "pveapitoken",
            None,
            None,
            [],
        )
        if state is not None and state.resolved_auth is None:
            state.resolved_auth = token_resolved
        payload.update(
            {
                "status": "token_ok" if status == 200 else "insufficient_privileges",
                "auth_required": True,
                "auth_method": "pveapitoken",
                "auth_username": None,
                "auth_password": None,
                "auth_attempts": [],
                "error": error_message if status == 403 else None,
            }
        )
        return _proxmox_record(payload)

    username = credential.username
    password = credential.password
    if username is None or password is None:
        payload.update(
            {
                "status": "auth_failed",
                "auth_required": True,
                "auth_method": "password",
                "auth_username": username,
                "auth_password": password,
                "error": "username and password are required",
            }
        )
        return _proxmox_record(payload)

    headers, login_error = actions._login_proxmox_password(
        ctx.host,
        ctx.port,
        cfg.timeout,
        cfg.retries,
        username=username,
        password=password,
        use_https=use_https,
        insecure=bool(getattr(ctx.args, "insecure", False)),
        proxy=_proxmox_proxy(ctx.args),
    )
    attempt = {
        "username": username,
        "password": password,
        "source": "defcreds" if credential.source == "default" else credential.source,
        "ok": str(headers is not None),
    }
    auth_attempts = state.auth_attempts if state is not None else []
    auth_attempts.append(attempt)
    if headers is None:
        payload.update(
            {
                "status": "auth_failed",
                "auth_required": True,
                "auth_method": "password",
                "auth_username": username,
                "auth_password": password,
                "auth_attempts": [dict(item) for item in auth_attempts],
                "error": login_error or "authentication failed",
            }
        )
        return _proxmox_record(payload)

    password_resolved: tuple[
        dict[str, str],
        str,
        str | None,
        str | None,
        list[dict[str, str]],
    ] = (dict(headers), "password", username, password, auth_attempts)
    if state is not None and state.resolved_auth is None:
        state.resolved_auth = password_resolved
    payload.update(
        {
            "status": "weak_default_creds" if credential.source == "default" else "token_ok",
            "auth_required": True,
            "auth_method": "password",
            "auth_username": username,
            "auth_password": password,
            "auth_attempts": [dict(item) for item in auth_attempts],
            "error": None,
        }
    )
    return _proxmox_record(payload)


def _proxmox_data(ctx: AuditHookContext, record: AuditRecord) -> AuditRecord:
    _activate_transport(ctx)
    state = ctx.lifecycle_state if isinstance(ctx.lifecycle_state, _ProxmoxLifecycleState) else None
    if state is not None and state.deep_record is not None:
        return state.deep_record
    if state is None or state.resolved_auth is None:
        return record
    cfg = AuditConfig.from_namespace(ctx.args)
    options = _build_proxmox_host_stage_options(ctx.args)
    started = time.monotonic()
    if actions._audit_proxmox_host is not _PROXMOX_AUDIT_HOST_IMPL:
        raw_record = _resolved_proxmox_host_stage()(
            host=ctx.host,
            port=ctx.port,
            timeout=cfg.timeout,
            retries=cfg.retries,
            pve_api_token=str(ctx.credential.token or ""),
            use_https=_proxmox_use_https(ctx),
            insecure=bool(getattr(ctx.args, "insecure", False)),
            proxy=_proxmox_proxy(ctx.args),
            username=ctx.credential.username,
            password=ctx.credential.password,
            defcreds=False,
            discover_creds=bool(options["discover_creds"]),
            show_nodes=bool(options["show_nodes"]),
            show_users=bool(options["show_users"]),
            add_user=options["add_user"],
            grant_role=options["grant_role"],
            grant_path=options["grant_path"],
            grant_propagate=options["grant_propagate"],
            run_deep_checks=True,
            debug=cfg.debug,
            debug_emit=ctx.debug_emit,
            on_status_ready=options["on_status_ready"],
            on_discovered_url=options["on_discovered_url"],
            on_credential_finding=options["on_credential_finding"],
        )
        return _proxmox_apply_credential_source(_proxmox_record(raw_record), ctx.credential)
    raw_record = actions._audit_proxmox_host(
        ctx.host,
        ctx.port,
        cfg.timeout,
        cfg.retries,
        str(ctx.credential.token or ""),
        _proxmox_use_https(ctx),
        bool(getattr(ctx.args, "insecure", False)),
        _proxmox_proxy(ctx.args),
        username=ctx.credential.username,
        password=ctx.credential.password,
        defcreds=False,
        discover_creds=bool(options["discover_creds"]),
        show_nodes=bool(options["show_nodes"]),
        show_users=bool(options["show_users"]),
        add_user=options["add_user"],
        grant_role=options["grant_role"],
        grant_path=options["grant_path"],
        grant_propagate=options["grant_propagate"],
        on_status_ready=options["on_status_ready"],
        on_discovered_url=options["on_discovered_url"],
        on_credential_finding=options["on_credential_finding"],
        _resolved_auth=state.resolved_auth,
    )
    return _proxmox_apply_credential_source(
        _proxmox_record(
            actions._attach_proxmox_stage_telemetry(
                raw_record,
                host=ctx.host,
                port=ctx.port,
                retries=cfg.retries,
                run_deep_checks=True,
                debug=cfg.debug,
                debug_emit=ctx.debug_emit,
                started=started,
            )
        ),
        ctx.credential,
    )


def _prepare_proxmox_credential_runs(args: Any) -> None:
    token = str(getattr(args, "pve_api_token", "") or "").strip()
    token_runs = (AuditCredentialRun(token=token, source="provided"),) if token else ()
    supplied_runs = build_basic_credential_runs(args)
    default_runs = (
        sort_default_audit_credential_runs(
            AuditCredentialRun(username=username, password=password, source="default")
            for username, password in actions._PROXMOX_DEFAULT_CREDENTIALS
        )
        if bool(getattr(args, "defcreds", False))
        else ()
    )
    args._audit_credential_runs = merge_audit_credential_runs(token_runs, supplied_runs, default_runs)


def _build_proxmox_host_stage_options(args: Any) -> dict[str, Any]:
    callbacks: dict[str, Any] = {}
    for name in ("on_status_ready", "on_discovered_url", "on_credential_finding"):
        callback = getattr(args, name, None)
        if callback is not None and not callable(callback):
            raise ValueError(f"{name} must be callable")
        callbacks[name] = callback
    return {
        **_proxmox_requested_action_fields(args),
        **callbacks,
    }


def build_proxmox_spec(args: Any) -> ModuleAuditSpec:
    full_credential_sweep = bool(getattr(args, "defcreds", False))

    def _detect_with_target(ctx: AuditHookContext) -> AuditRecord:
        with http_target_context(ctx.target, api_prefixes=("/api2/json",)):
            return _proxmox_detect(ctx)

    def _auth_with_target(ctx: AuditHookContext, record: AuditRecord) -> AuditRecord:
        with http_target_context(ctx.target, api_prefixes=("/api2/json",)):
            return _proxmox_auth(ctx, record)

    def _data_with_target(ctx: AuditHookContext, record: AuditRecord) -> AuditRecord:
        with http_target_context(ctx.target, api_prefixes=("/api2/json",)):
            return _proxmox_data(ctx, record)

    return ModuleAuditSpec(
        module="proxmox",
        label="PROXMOX",
        default_port=_DEFAULT_PORT,
        host_stage=actions.host_stage,
        host_stage_options=_build_proxmox_host_stage_options(args),
        detect=_detect_with_target,
        auth=_auth_with_target,
        data=_data_with_target,
        lifecycle_state_factory=_proxmox_lifecycle_state_factory,
        lifecycle_state_close=lambda state: state.close(),
        record_all_credential_attempts=full_credential_sweep,
        continue_after_credential_success=full_credential_sweep,
        continue_after_credential_error=full_credential_sweep,
        credential_attempt_detail_fields=("auth_method",),
        render_module=render,
        colorize=render._render_colored_proxmox_line,
        keep_anonymous_open_no_auth=False,
    )


def _validate_and_prepare_proxmox_args(args: Any, console: Any) -> int | None:
    validation_rc = policy.validate_args(args, console)
    if validation_rc is not None:
        return int(validation_rc)
    try:
        _prepare_proxmox_credential_runs(args)
    except ValueError as exc:
        console.error(str(exc))
        return 2
    return None


def run_proxmox_stage(args: Any, logger: Any) -> int:
    cfg = AuditConfig.from_namespace(args)
    console = Console(debug=cfg.debug)
    return run_basic_host_audit(
        args,
        logger,
        console=console,
        label="PROXMOX",
        validate=_validate_and_prepare_proxmox_args,
        build_plan=build_proxmox_plan,
        build_spec=build_proxmox_spec,
    )


__all__ = [
    "_build_proxmox_host_stage_options",
    "_prepare_proxmox_credential_runs",
    "build_proxmox_plan",
    "build_proxmox_spec",
    "run_proxmox_stage",
]
