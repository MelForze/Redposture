"""Runtime entrypoint for the gitlab audit module."""

from __future__ import annotations

import os
from dataclasses import dataclass, replace
from types import SimpleNamespace
from typing import Any

from ...audit_config import AuditConfig
from ...audit_models import AuditRecord
from ...clients.http_api import http_target_context, infer_http_base_path
from ...console import Console
from ...stage_runtime import (
    AuditCommandPlan,
    AuditCredentialRun,
    ModuleAuditSpec,
    build_basic_audit_plan,
    merge_audit_credential_runs,
    run_basic_host_audit,
)
from ..registry import actions as oci_actions
from ..registry import stage as oci_stage
from . import actions, policy, render

_DEFAULT_PORT = 80
_DEFAULT_PORTS = None
_PRODUCTION_HOST_STAGE = actions.host_stage
_PRODUCTION_AUDIT_HOST = actions._audit_gitlab_host
_GITLAB_BASIC_PAIRS = (
    ("root", "root"),
    ("root", "password"),
    ("root", "admin"),
    ("admin", "admin"),
    ("admin", "password"),
    ("gitlab", "gitlab"),
    ("user", "user"),
    ("test", "test"),
)


@dataclass
class GitLabCombinedState:
    web: actions.GitLabLifecycleState
    registry: oci_actions.RegistryLifecycleState

    def close(self) -> None:
        self.web.close()
        self.registry.close()


def gitlab_combined_state_factory(ctx: Any) -> GitLabCombinedState:
    registry = oci_actions.registry_lifecycle_state_factory(ctx)
    registry.base_path = infer_http_base_path(
        str(getattr(getattr(ctx, "target", None), "path", "") or ""),
        ("/api/v4", "/users/sign_in", "/-", "/v2", "/jwt/auth"),
    )
    return GitLabCombinedState(
        web=actions.gitlab_lifecycle_state_factory(ctx),
        registry=registry,
    )


def _surface_ctx(ctx: Any, state: Any, *, token: str | None = None, anonymous: bool = False) -> Any:
    credential = ctx.credential
    if anonymous:
        credential = AuditCredentialRun(source="anonymous")
    elif token is not None:
        credential = AuditCredentialRun(token=token, source="registry_token")
    try:
        return replace(ctx, lifecycle_state=state, credential=credential)
    except TypeError:
        return SimpleNamespace(**{**vars(ctx), "lifecycle_state": state, "credential": credential})


def build_gitlab_plan(args: Any) -> AuditCommandPlan:
    explicit_port = getattr(args, "port", None) is not None or bool(str(getattr(args, "ports", "") or "").strip())
    default_port = 443 if bool(getattr(args, "https", False)) else _DEFAULT_PORT
    plan = build_basic_audit_plan(args, default_port=default_port, default_ports=_DEFAULT_PORTS)
    if not explicit_port and plan.target_plan is not None:
        plan = replace(
            plan,
            target_plan=plan.target_plan.with_scheme_default_ports(
                {
                    "http": 80,
                    "https": 443,
                }
            ),
        )
    runs = list(plan.credential_runs)
    web_token = str(getattr(args, "token", "") or "")
    registry_token = str(getattr(args, "registry_token", "") or "")
    if web_token:
        runs = [
            AuditCredentialRun(token=item.token, source="both_token" if registry_token == web_token else "web_token")
            if item.token == web_token
            else item
            for item in runs
        ]
    if registry_token and registry_token != web_token:
        runs.append(AuditCredentialRun(token=registry_token, source="registry_token"))
    defaults = (
        tuple(
            AuditCredentialRun(username=user, password=password, source="default")
            for user, password in _GITLAB_BASIC_PAIRS
        )
        if bool(getattr(args, "defcreds", False))
        else ()
    )
    plan = replace(plan, credential_runs=merge_audit_credential_runs(runs, defaults))
    return plan


def _build_gitlab_host_stage_options(args: Any) -> dict[str, Any]:
    clone_dir = str(getattr(args, "clone_dir", actions._DEFAULT_CLONE_DIR) or actions._DEFAULT_CLONE_DIR).strip()
    clone_dir = clone_dir or actions._DEFAULT_CLONE_DIR
    project_values = getattr(args, "project", None)
    if project_values is None:
        project_values = getattr(args, "project_filters", None)
    return {
        "project_filters": actions._normalize_project_filters(project_values),
        "clone": bool(getattr(args, "clone", False)),
        "clone_dir": os.path.abspath(os.path.expanduser(clone_dir)),
    }


def build_gitlab_spec(args: Any) -> ModuleAuditSpec:
    options = _build_gitlab_host_stage_options(args)
    registry_spec = oci_stage.build_registry_spec(args, product="gitlab")
    resolved_host_stage = getattr(actions, _PRODUCTION_HOST_STAGE.__name__, _PRODUCTION_HOST_STAGE)
    use_lifecycle_hooks = (
        actions.host_stage is _PRODUCTION_HOST_STAGE
        and resolved_host_stage is _PRODUCTION_HOST_STAGE
        and actions._audit_gitlab_host is _PRODUCTION_AUDIT_HOST
    )

    def _detect(ctx: Any) -> AuditRecord:
        state = ctx.lifecycle_state
        if not isinstance(state, GitLabCombinedState):
            raise TypeError("GitLab combined lifecycle state is unavailable")
        with http_target_context(ctx.target, route_state=state.web, api_prefixes=("/api/v4", "/users/sign_in", "/-")):
            web = actions.detect_gitlab(_surface_ctx(ctx, state.web), options)
        if registry_spec.detect is None:
            raise RuntimeError("GitLab registry detector is unavailable")
        registry = registry_spec.detect(_surface_ctx(ctx, state.registry)).to_dict()
        web_ok = web.get("is_gitlab") is True
        registry_ok = registry.get("is_registry") is True and registry.get("is_gitlab") is True
        if web_ok:
            result = dict(web)
            result["gitlab_surface"] = "web_and_registry" if registry_ok else "web"
        elif registry_ok:
            result = dict(registry)
            result.update(
                {
                    "is_gitlab": True,
                    "status": "detected",
                    "login_page": False,
                    "version": (registry.get("gitlab_info") or {}).get("version"),
                    "gitlab_surface": "container_registry",
                }
            )
        else:
            result = dict(web)
            result["gitlab_surface"] = "none"
        result["container_registry"] = registry if registry_ok else None
        return AuditRecord.from_mapping(result, module="gitlab", service="gitlab")

    def _auth(ctx: Any, record: Any) -> AuditRecord:
        state = ctx.lifecycle_state
        if not isinstance(state, GitLabCombinedState):
            raise TypeError("GitLab combined lifecycle state is unavailable")
        prior = record.to_dict()
        surface = str(prior.get("gitlab_surface") or "web")
        source = str(getattr(ctx.credential, "source", ""))
        token_candidate = ctx.credential.token is not None
        web_allowed = surface in {"web", "web_and_registry"} and (
            not token_candidate or source in {"web_token", "both_token", "anonymous", "provided"}
        )
        registry_allowed = surface in {"container_registry", "web_and_registry"} and (
            not token_candidate or source in {"registry_token", "both_token"}
        )
        result = dict(prior)
        web_ok: bool | None = None
        registry_ok: bool | None = None
        if web_allowed:
            if ctx.credential.username is not None:
                with http_target_context(
                    ctx.target, route_state=state.web, api_prefixes=("/api/v4", "/users/sign_in", "/-")
                ):
                    web_ok, web_reason = actions.verify_gitlab_web_credentials(
                        _surface_ctx(ctx, state.web),
                        str(ctx.credential.username),
                        str(ctx.credential.password or ""),
                    )
                result["web_credential_reason"] = web_reason
                result["status"] = (
                    "valid_credentials" if web_ok is True else "invalid_credentials" if web_ok is False else "detected"
                )
                result["provided_credentials_ok"] = web_ok
            else:
                with http_target_context(
                    ctx.target, route_state=state.web, api_prefixes=("/api/v4", "/users/sign_in", "/-")
                ):
                    result = actions.authenticate_gitlab(_surface_ctx(ctx, state.web), record, options)
                web_ok = result.get("token_valid")
        if registry_allowed and registry_spec.auth is not None and isinstance(prior.get("container_registry"), dict):
            registry_record = AuditRecord.from_mapping(prior["container_registry"], module="gitlab", service="gitlab")
            token = str(getattr(ctx.args, "registry_token", "") or "") if token_candidate else None
            registry_ctx = (
                _surface_ctx(ctx, state.registry, token=token) if token else _surface_ctx(ctx, state.registry)
            )
            checked = registry_spec.auth(registry_ctx, registry_record).to_dict()
            checked.pop("provided_password", None)
            result["container_registry"] = checked
            registry_ok = checked.get("provided_credentials_ok")
        if web_ok is True or registry_ok is True:
            result["status"] = "valid_credentials"
            result["provided_credentials_ok"] = True
        elif (web_ok is False or registry_ok is False) and web_ok is not None and registry_ok is not None:
            result["status"] = "invalid_credentials"
            result["provided_credentials_ok"] = False
        elif web_ok is False and not registry_allowed:
            result["status"] = "invalid_credentials"
            result["provided_credentials_ok"] = False
        elif registry_ok is False and not web_allowed:
            result["status"] = "invalid_credentials"
            result["provided_credentials_ok"] = False
        elif web_ok is None or registry_ok is None:
            result["provided_credentials_ok"] = None
        result["credentials_source"] = source
        result["provided_username"] = ctx.credential.username
        result["provided_password"] = ctx.credential.password
        return AuditRecord.from_mapping(result, module="gitlab", service="gitlab")

    def _data(ctx: Any, record: Any) -> AuditRecord:
        state = ctx.lifecycle_state
        if not isinstance(state, GitLabCombinedState):
            raise TypeError("GitLab combined lifecycle state is unavailable")
        prior = record.to_dict()
        result = dict(prior)
        source = str(getattr(ctx.credential, "source", ""))
        if prior.get("gitlab_surface") in {"web", "web_and_registry"}:
            with http_target_context(
                ctx.target, route_state=state.web, api_prefixes=("/api/v4", "/users/sign_in", "/-")
            ):
                result = actions.collect_gitlab_data(
                    _surface_ctx(ctx, state.web, anonymous=source == "registry_token"), record, options
                )
        if prior.get("gitlab_surface") in {"container_registry", "web_and_registry"} and registry_spec.data is not None:
            registry_payload = prior.get("container_registry")
            if isinstance(registry_payload, dict):
                registry_record = AuditRecord.from_mapping(registry_payload, module="gitlab", service="gitlab")
                updated_registry = registry_spec.data(
                    _surface_ctx(ctx, state.registry, anonymous=source == "web_token"), registry_record
                ).to_dict()
                updated_registry.pop("provided_password", None)
                result["container_registry"] = updated_registry
        result["gitlab_surface"] = prior.get("gitlab_surface")
        return AuditRecord.from_mapping(result, module="gitlab", service="gitlab")

    return ModuleAuditSpec(
        module="gitlab",
        label="GITLAB",
        default_port=_DEFAULT_PORT,
        host_stage=actions.host_stage,
        host_stage_options=options,
        detect=_detect if use_lifecycle_hooks else None,
        auth=_auth if use_lifecycle_hooks else None,
        data=_data if use_lifecycle_hooks else None,
        lifecycle_state_factory=gitlab_combined_state_factory if use_lifecycle_hooks else None,
        lifecycle_state_close=(lambda state: state.close()) if use_lifecycle_hooks else None,
        deep_gate=(
            lambda record: (
                str(record.status or "") in {"detected", "valid_credentials", "invalid_credentials"},
                f"status={record.status}",
            )
        )
        if use_lifecycle_hooks
        else None,
        render_module=render,
        defer_detect_output_until_auth=True,
        structured_output_redact_fields=("provided_password",),
        colorize=render._render_colored_gitlab_line,
        is_detected=lambda record: record.extra.get("is_gitlab") is True,
        suppress_undetected_records_in_text=True,
        credential_gate=lambda _credential, record: (
            record.extra.get("provided_credentials_ok") is True or record.extra.get("token_valid") is True,
            "GitLab identity verified"
            if record.extra.get("provided_credentials_ok") is True
            else "GitLab credentials unverified",
        ),
        continue_after_credential_error=bool(getattr(args, "defcreds", False)),
        continue_after_credential_success=bool(getattr(args, "defcreds", False)),
    )


def run_gitlab_stage(args: Any, logger: Any) -> int:
    cfg = AuditConfig.from_namespace(args)
    console = Console(debug=cfg.debug)
    return run_basic_host_audit(
        args,
        logger,
        console=console,
        label="GITLAB",
        validate=policy.validate_args,
        build_plan=build_gitlab_plan,
        build_spec=build_gitlab_spec,
    )


__all__ = [
    "_build_gitlab_host_stage_options",
    "build_gitlab_plan",
    "build_gitlab_spec",
    "run_gitlab_stage",
]
