"""Shared transport and lifecycle plumbing for read-only token API audits."""

from __future__ import annotations

import time
from dataclasses import replace
from pathlib import Path
from typing import Any
from urllib.parse import quote

from ..audit_models import AuditRecord
from ..clients.http_api import HttpResponse, build_http_target_url, current_http_target_binding, http_target_context
from ..clients.http_session import HttpSessionPool
from ..clients.scoped_http import HttpLifecycleState, ScopedHttpClient
from ..discovery_options import validate_discovery_budget
from ..stage_runtime import AuditCredentialRun, ModuleAuditSpec, build_basic_audit_plan

CAP = 4 * 1024 * 1024


def client(ctx: Any) -> ScopedHttpClient:
    return ScopedHttpClient(ctx.lifecycle_state.http, CAP)


def json_value(response: HttpResponse) -> Any:
    if response.error or response.truncated or not response.status:
        return None
    try:
        return response.json()
    except (ValueError, UnicodeError, RecursionError):
        return None


def bases(ctx: Any) -> tuple[str, str]:
    scheme = current_http_target_binding().scheme or ("https" if ctx.port in {443, 8443} else "http")
    return tuple(
        build_http_target_url(ctx.host, ctx.port, "/", default_scheme=value, override_bound_scheme=True).rstrip("/")
        for value in (scheme, "https" if scheme == "http" else "http")
    )  # type: ignore[return-value]


def request(
    ctx: Any, base: str, path: str, *, header: str, token: str | None = None, method: str = "GET"
) -> HttpResponse:
    headers = {"Accept": "application/json"}
    if token:
        headers[header] = f"token {token}" if header == "Authorization" else token
    return client(ctx).request(method, base + path, headers=headers)


def path_value(value: str) -> str:
    return quote(value, safe="")


def safe_path(value: Any) -> bool:
    if not isinstance(value, str) or len(value) > 4096:
        return False
    try:
        encoded = value.encode("utf-8")
    except UnicodeError:
        return False
    return (
        len(encoded) <= 4096
        and len(value.split("/")) <= 128
        and "//" not in value
        and not any(c in value for c in "\\\r\n\x00?#")
        and all(part not in {".", ".."} for part in value.strip("/").split("/"))
    )


def verdict(prior: dict[str, Any], response: HttpResponse, valid: bool, invalid: bool) -> dict[str, Any]:
    state = "valid" if valid else "invalid" if invalid else "unverified"
    return {
        **prior,
        "token_valid": True if valid else False if invalid else None,
        "provided_credentials_ok": True if valid else False if invalid else None,
        "credential_state": state,
        "auth_http_status": response.status,
        "credential_verification_reason": "product token verified"
        if valid
        else "product rejected token"
        if invalid
        else "token could not be verified",
        "status": "valid_credentials"
        if valid
        else "invalid_credentials"
        if invalid
        else "rate_limited"
        if response.status == 429
        else prior.get("status", "detected"),
    }


def access(response: HttpResponse, valid_shape: bool) -> str:
    return (
        "allowed"
        if response.status == 200 and valid_shape
        else "denied"
        if response.status in {401, 403}
        else "rate_limited"
        if response.status == 429
        else "unknown"
    )


class ReadBudget:
    """Global request, byte and time caps, including unsuccessful traversal."""

    def __init__(self, args: Any) -> None:
        self.deadline = time.monotonic() + float(getattr(args, "discover_time", None) or 300)
        self.remaining = int(getattr(args, "discover_max_bytes", None) or 50 * 1024 * 1024)
        self.calls = 0
        self.partial = False

    def allowed(self) -> bool:
        allowed = self.calls < 10000 and self.remaining > 0 and time.monotonic() < self.deadline
        self.partial |= not allowed
        return allowed

    def consume(self, response: HttpResponse) -> bool:
        self.calls += 1
        self.remaining -= len(response.body)
        self.partial |= bool(response.error or response.truncated or self.remaining < 0)
        return not (response.error or response.truncated or self.remaining < 0)


def validate_token_args(args: Any, console: Any, module: str) -> int | None:
    if (error := validate_discovery_budget(args, console)) is not None:
        return error
    token = getattr(args, "token", None)
    if getattr(args, "token_file", None):
        try:
            token = Path(args.token_file).read_text(encoding="utf-8").strip()
        except (OSError, UnicodeError):
            console.error("cannot read --token-file")
            return 2
    if token is not None and (
        not token or not token.isascii() or any(ord(c) <= 32 or ord(c) == 127 for c in token) or len(token) > 16384
    ):
        console.error(
            "token must be nonempty ASCII, at most 16384 characters, without whitespace or control characters"
        )
        return 2
    if bool(getattr(args, "tls_cert", None)) != bool(getattr(args, "tls_key", None)):
        console.error("--tls-cert and --tls-key must be supplied together")
        return 2
    setattr(args, f"_{module}_token", token)
    return None


def build_plan(args: Any, module: str, port: int, *, default_token: str | None = None) -> Any:
    plan = build_basic_audit_plan(args, default_port=port, default_ports=(port,))
    if plan.target_plan is not None and getattr(args, "port", None) is None and not getattr(args, "ports", None):
        plan = replace(plan, target_plan=plan.target_plan.with_scheme_default_ports({"http": 80, "https": 443}))
    credentials: tuple[AuditCredentialRun, ...]
    token = getattr(args, f"_{module}_token", None)
    if token:
        credentials = (AuditCredentialRun(token=token, source="provided"),)
    elif getattr(args, "defcreds", False) and default_token:
        credentials = (AuditCredentialRun(token=default_token, source="default"),)
    else:
        credentials = ()
    return replace(plan, credential_runs=credentials)


def build_spec(args: Any, module: str, port: int, actions: Any, render: Any) -> ModuleAuditSpec:
    def state(ctx: Any) -> HttpLifecycleState:
        return HttpLifecycleState(
            HttpSessionPool(
                timeout=float(getattr(ctx.args, "timeout", 5) or 5),
                retries=int(getattr(ctx.args, "retries", 0) or 0),
                proxy=getattr(ctx.args, "_proxy_config", None),
                insecure=not bool(getattr(ctx.args, "tls_ca", None)),
                ca_file=getattr(ctx.args, "tls_ca", None),
                cert_file=getattr(ctx.args, "tls_cert", None),
                key_file=getattr(ctx.args, "tls_key", None),
            )
        )

    def phase(ctx: Any, action: Any, record: AuditRecord | None = None) -> AuditRecord:
        with http_target_context(
            ctx.target,
            route_state=ctx.lifecycle_state,
            api_prefixes=("/v1",) if module != "jupyter" else ("/api", "/login", "/lab", "/tree"),
        ):
            value = action(ctx) if record is None else action(ctx, record.to_dict())
        return AuditRecord.from_mapping(value, module=module, service=module)

    return ModuleAuditSpec(
        module=module,
        label=module.upper(),
        default_port=port,
        lifecycle_state_factory=state,
        lifecycle_state_close=lambda value: value.close(),
        detect=lambda ctx: phase(ctx, actions.detect_record),
        auth=lambda ctx, rec: phase(ctx, actions.auth_record, rec),
        data=lambda ctx, rec: phase(ctx, actions.data_record, rec),
        render_module=render,
        colorize=getattr(render, f"_render_colored_{module}_line"),
        is_detected=lambda rec: rec.extra.get(f"is_{module}") is True,
        credential_gate=lambda _cred, rec: (rec.extra.get("provided_credentials_ok") is True, "token identity check"),
        structured_output_redact_fields=("attempted_credentials", "credential_results"),
        defer_detect_output_until_auth=True,
        live_phase_output=True,
    )
