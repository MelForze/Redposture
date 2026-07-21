"""gRPC audit stage."""

from __future__ import annotations

import base64
import json
import re
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from google.protobuf import descriptor_pb2

from ...clients import transport
from ...clients.grpc import (
    _build_auth_header,
    _build_basic_auth_header,
    _compile_proto_files,
    _decode_grpc_frames,
    _decode_grpc_web_frames,
    _dedup_descriptor_bytes,
    _descriptor_bytes_from_protoset,
    _descriptor_bytes_to_pool,
    _encode_grpc_frame,
    _extract_descriptors,
    _find_method_descriptor,
    _generate_openapi_document,
    _grpc_call,
    _grpc_health_payload,
    _grpc_reflection_list_payload,
    _grpc_reflection_symbol_payload,
    _grpc_status_name,
    _grpc_web_call,
    _grpc_web_health_check_call,
    _GrpcCallResult,
    _GrpcH2Session,
    _GrpcWebCallResult,
    _health_check_call,
    _HealthResult,
    _http2_headers_to_map,
    _invoke_unary_method,
    _InvokeResult,
    _load_explicit_descriptor_bytes,
    _metadata_value,
    _open_grpc_socket,
    _open_http_socket,
    _parse_health_message,
    _parse_http1_response,
    _parse_json_payload_source,
    _parse_metadata_items,
    _reflection_capability_call,
    _reflection_file_descriptors_call,
    _reflection_list_services_call,
    _ReflectionCapabilityResult,
    _ReflectionDescriptorResult,
    _ReflectionListResult,
    _split_grpc_method_path,
    _write_openapi_document,
)
from ...console import Console
from ...proto import grpc_health_pb2, grpc_reflection_pb2
from ...rendering import RegexColorRule, collect_color_spans, render_colored_marker_line, render_tagged_detail_line
from ...stage_runtime import (
    merge_stage_records,
)
from ...utils import (
    as_list,
    utc_now_iso,
)

# Connection-error classification + framed reads are shared via the transport layer.
_is_connection_refused_error = transport.is_connection_refused


@dataclass
class GrpcLifecycleState:
    detect_result: dict[str, Any] | None = None
    deep_records: dict[tuple[str | None, str | None, str | None, str], dict[str, Any]] = field(default_factory=dict)
    sessions: dict[tuple[str, int, bool], _GrpcH2Session] = field(default_factory=dict)
    health_auth_used: dict[str, Any] | None = None
    reflection_auth_used: dict[str, Any] | None = None
    health_deep_auth_required: bool = False
    reflection_deep_auth_required: bool = False

    def session_for(self, host: str, port: int, *, timeout: float, use_tls: bool) -> _GrpcH2Session:
        key = (str(host), int(port), bool(use_tls))
        session = self.sessions.get(key)
        if session is None:
            session = _GrpcH2Session(key[0], key[1], timeout=timeout, use_tls=key[2])
            self.sessions[key] = session
        return session

    def close(self) -> None:
        sessions = list(self.sessions.values())
        self.sessions.clear()
        for session in sessions:
            session.close()


def _grpc_lifecycle_key(ctx: Any) -> tuple[str | None, str | None, str | None, str]:
    credential = ctx.credential
    return credential.username, credential.password, credential.token, str(credential.source or "anonymous")


_is_connection_refused_fail_record = transport.is_connection_refused_fail_record
_is_connection_timeout_error = transport.is_connection_timeout

__all__ = [
    "descriptor_pb2",
    "grpc_health_pb2",
    "grpc_reflection_pb2",
    "_GrpcCallResult",
    "_GrpcH2Session",
    "_GrpcWebCallResult",
    "_HealthResult",
    "_InvokeResult",
    "_ReflectionDescriptorResult",
    "_ReflectionCapabilityResult",
    "_ReflectionListResult",
    "_build_auth_header",
    "_build_basic_auth_header",
    "_compile_proto_files",
    "_decode_grpc_frames",
    "_decode_grpc_web_frames",
    "_descriptor_bytes_from_protoset",
    "_descriptor_bytes_to_pool",
    "_encode_grpc_frame",
    "_extract_descriptors",
    "_find_method_descriptor",
    "_generate_openapi_document",
    "_grpc_call",
    "_grpc_health_payload",
    "_grpc_reflection_list_payload",
    "_grpc_reflection_symbol_payload",
    "_grpc_status_name",
    "_grpc_web_call",
    "_grpc_web_health_check_call",
    "_health_check_call",
    "_http2_headers_to_map",
    "_invoke_unary_method",
    "_load_explicit_descriptor_bytes",
    "_metadata_value",
    "_open_grpc_socket",
    "_open_http_socket",
    "_parse_health_message",
    "_parse_http1_response",
    "_parse_json_payload_source",
    "_parse_metadata_items",
    "_reflection_capability_call",
    "_reflection_file_descriptors_call",
    "_reflection_list_services_call",
    "_split_grpc_method_path",
    "_write_openapi_document",
]

_GRPC_TAG = "GRPC"
_CONNECTION_REFUSED_PREFIX = "connection refused"
_CONNECTION_TIMEOUT_PREFIX = "connection timeout"

_STAGE_DETECT_PROTOCOL = "detect_protocol"
_STAGE_AUTH_INFERENCE = "auth_inference_credentials"
_STAGE_ACCESS_CAPABILITIES = "access_capabilities"
_STAGE_DATA = "data"

_THREAD_LOCAL_DEBUG_EMIT = threading.local()

_DEFAULT_BASIC_CREDENTIALS: tuple[tuple[str, str], ...] = (
    ("admin", "admin"),
    ("admin", "password"),
    ("root", "root"),
    ("root", "admin"),
    ("grpc", "grpc"),
    ("service", "service"),
    ("test", "test"),
    ("user", "password"),
)
_DEFAULT_BEARER_TOKENS: tuple[str, ...] = (
    "admin",
    "token",
    "secret",
    "changeme",
    "grpc",
    "default-token",
)

_GRPC_AUTH_CODES = {7, 16}
_GRPC_OK = 0
_GRPC_UNIMPLEMENTED = 12

_ACCESS_ANONYMOUS = "anonymous"
_ACCESS_AUTHENTICATED = "authenticated"
_ACCESS_AUTH_REQUIRED = "auth_required"
_ACCESS_MIXED = "mixed"
_ACCESS_NOT_TESTED = "not_tested"
_ACCESS_UNKNOWN = "unknown"
_ACCESS_UNSUPPORTED = "unsupported"

_ACCESS_COLORS: dict[str, str] = {
    _ACCESS_ANONYMOUS: "red",
    _ACCESS_AUTHENTICATED: "bright_green",
    _ACCESS_AUTH_REQUIRED: "bright_green",
    _ACCESS_MIXED: "orange",
    _ACCESS_NOT_TESTED: "yellow",
    _ACCESS_UNKNOWN: "yellow",
    _ACCESS_UNSUPPORTED: "yellow",
}


def _clip(text: str, width: int = 96) -> str:
    if len(text) <= width:
        return text
    if width <= 3:
        return text[:width]
    return text[: width - 3] + "..."


def _retry_delay(attempt_index: int) -> float:
    return min(1.50, 0.20 * (2**attempt_index))


def _get_thread_debug_emitter() -> Callable[[str], None] | None:
    callback = getattr(_THREAD_LOCAL_DEBUG_EMIT, "callback", None)
    if callable(callback):
        return callback
    return None


def _friendly_error_text(value: str) -> str:
    from ...utils import friendly_error_text

    return friendly_error_text(value)


def _friendly_error_from_exception(exc: BaseException) -> str:
    from ...utils import friendly_error_from_exception

    return friendly_error_from_exception(exc)


def _is_retryable_stage_error(value: Any) -> bool:
    text = str(value or "").strip().lower()
    if not text:
        return False
    return text.startswith(_CONNECTION_TIMEOUT_PREFIX) or text.startswith(_CONNECTION_REFUSED_PREFIX)


def _is_suppressed_fail_record(record: dict[str, Any]) -> bool:
    return str(record.get("status") or "") == "fail"


def grpc_deep_gate(record: Any) -> tuple[bool, str]:
    """Keep trying credentials until the requested gRPC action is usable."""

    if isinstance(record, dict):
        payload = record
        status = str(payload.get("status") or "unknown")
    else:
        extra = getattr(record, "extra", {})
        payload = extra if isinstance(extra, dict) else {}
        status = str(getattr(record, "status", None) or payload.get("status") or "unknown")

    action_access_satisfied = payload.get("action_access_satisfied")
    if action_access_satisfied is True:
        return True, "grpc action access satisfied"
    if action_access_satisfied is False:
        return False, "grpc action access unresolved"

    allowed = {
        "ok",
        "open",
        "open_no_auth",
        "anonymous_access",
        "detected",
        "token_ok",
        "valid_credentials",
        "auth_valid",
        "weak_default_creds",
        "invalid_credentials_anonymous",
        "valid_token",
        "token_accepted",
        "insufficient_privileges",
    }
    if status in allowed:
        return True, f"status={status}"
    if status.startswith("not_"):
        return False, status
    return False, f"status={status}"


def _auth_required_from_grpc_status(grpc_status: int | None) -> bool | None:
    if grpc_status in _GRPC_AUTH_CODES:
        return True
    if grpc_status is None:
        return None
    return False


def _effective_grpc_status(result: dict[str, Any]) -> int | None:
    """Prefer a Reflection response's embedded status over transport OK."""

    embedded = result.get("embedded_error_code")
    if isinstance(embedded, int) and not isinstance(embedded, bool):
        return embedded
    grpc_status = result.get("grpc_status")
    if isinstance(grpc_status, int) and not isinstance(grpc_status, bool):
        return grpc_status
    return None


def _access_from_grpc_status(
    grpc_status: int | None,
    *,
    supported: bool | None = None,
    used_credentials: bool = False,
) -> str:
    """Classify access to one concrete gRPC capability.

    This deliberately does not infer endpoint-wide authentication policy.  A
    successful Health or Reflection call only proves access to that service.
    """

    if grpc_status in _GRPC_AUTH_CODES:
        return _ACCESS_AUTH_REQUIRED
    if supported is False or grpc_status == _GRPC_UNIMPLEMENTED:
        return _ACCESS_UNSUPPORTED
    if grpc_status is None:
        return _ACCESS_UNKNOWN
    return _ACCESS_AUTHENTICATED if used_credentials else _ACCESS_ANONYMOUS


def _merge_access(current: str, observed: str) -> str:
    """Merge per-call observations without widening anonymous access."""

    current = str(current or _ACCESS_UNKNOWN)
    observed = str(observed or _ACCESS_UNKNOWN)
    if current == observed:
        return current
    ignored = {_ACCESS_UNKNOWN, _ACCESS_NOT_TESTED}
    if current in ignored:
        return observed
    if observed in ignored:
        return current
    # An anonymous auth challenge followed by a successful credentialed call
    # is one capability transitioning to authenticated access, not mixed ACLs.
    if current == _ACCESS_AUTH_REQUIRED and observed == _ACCESS_AUTHENTICATED:
        return _ACCESS_AUTHENTICATED
    if current == _ACCESS_UNSUPPORTED:
        return observed
    if observed == _ACCESS_UNSUPPORTED:
        return current
    return _ACCESS_MIXED


def _detect_grpc_target(
    host: str,
    port: int,
    *,
    timeout: float,
    preferred_scheme: str | None,
    _session_state: GrpcLifecycleState | None = None,
) -> dict[str, Any]:
    scheme_hint = str(preferred_scheme or "").strip().lower()
    if scheme_hint == "http":
        transport_order = [False, True]
    elif scheme_hint == "https":
        transport_order = [True, False]
    else:
        transport_order = [True, False]

    calls: list[dict[str, Any]] = []
    transport_errors: list[str] = []
    non_grpc_seen = False

    for use_tls in transport_order:
        session = (
            _session_state.session_for(host, port, timeout=timeout, use_tls=use_tls)
            if _session_state is not None
            else None
        )
        health = _health_check_call(
            host,
            port,
            timeout=timeout,
            use_tls=use_tls,
            authorization=None,
            service_name="",
            session=session,
        )
        calls.append(health)
        health_call = health["call"]
        if bool(health_call.get("is_grpc")):
            # Reflection availability belongs to the lightweight fingerprint.
            # Only the full service/descriptor inventory is gated by --analyze.
            reflection = _reflection_capability_call(
                host,
                port,
                timeout=timeout,
                use_tls=use_tls,
                authorization=None,
                session=session,
            )
            calls.append(reflection)
            raw_reflection_call = reflection.get("call")
            reflection_call: dict[str, Any] = raw_reflection_call if isinstance(raw_reflection_call, dict) else {}
            return {
                "is_grpc": True,
                "protocol_flavor": "grpc",
                "grpc_web_detected": False,
                "transport_mode": "tls" if use_tls else "plaintext",
                # Health is a separate gRPC service.  Its public availability
                # cannot establish endpoint-wide anonymous access.
                "auth_required": None,
                "health_access": _access_from_grpc_status(
                    health.get("grpc_status"), supported=health.get("health_supported")
                ),
                "reflection_access": _access_from_grpc_status(
                    _effective_grpc_status(reflection), supported=reflection.get("reflection_enabled")
                ),
                "invoke_access": _ACCESS_NOT_TESTED,
                "health_supported": health.get("health_supported"),
                "reflection_enabled": reflection.get("reflection_enabled"),
                "reflection_version": reflection.get("reflection_version"),
                "detect_error": health.get("error"),
                "detect_probe_trace": [
                    {
                        "probe": "health",
                        "scheme": "https" if use_tls else "http",
                        "http_status": health_call.get("http_status"),
                        "grpc_status": health.get("grpc_status"),
                        "access": _access_from_grpc_status(
                            health.get("grpc_status"), supported=health.get("health_supported")
                        ),
                        "error": health.get("error"),
                    },
                    {
                        "probe": "reflection",
                        "scheme": "https" if use_tls else "http",
                        "http_status": reflection_call.get("http_status"),
                        "grpc_status": reflection.get("grpc_status"),
                        "access": _access_from_grpc_status(
                            _effective_grpc_status(reflection), supported=reflection.get("reflection_enabled")
                        ),
                        "error": reflection.get("error"),
                    },
                ],
            }

        if health_call.get("transport_ok"):
            non_grpc_seen = True
        if health.get("error"):
            transport_errors.append(str(health.get("error")))

        reflection = _reflection_capability_call(
            host,
            port,
            timeout=timeout,
            use_tls=use_tls,
            authorization=None,
            session=session,
        )
        calls.append(reflection)
        reflection_call = reflection["call"]
        if bool(reflection_call.get("is_grpc")):
            return {
                "is_grpc": True,
                "protocol_flavor": "grpc",
                "grpc_web_detected": False,
                "transport_mode": "tls" if use_tls else "plaintext",
                "auth_required": None,
                "health_access": _access_from_grpc_status(
                    health.get("grpc_status"), supported=health.get("health_supported")
                ),
                "reflection_access": _access_from_grpc_status(
                    _effective_grpc_status(reflection), supported=reflection.get("reflection_enabled")
                ),
                "invoke_access": _ACCESS_NOT_TESTED,
                "health_supported": health.get("health_supported"),
                "reflection_enabled": reflection.get("reflection_enabled"),
                "reflection_version": reflection.get("reflection_version"),
                "detect_error": reflection.get("error"),
                "detect_probe_trace": [
                    {
                        "probe": "health",
                        "scheme": "https" if use_tls else "http",
                        "http_status": health_call.get("http_status"),
                        "grpc_status": health.get("grpc_status"),
                        "access": _access_from_grpc_status(
                            health.get("grpc_status"), supported=health.get("health_supported")
                        ),
                        "error": health.get("error"),
                    },
                    {
                        "probe": "reflection",
                        "scheme": "https" if use_tls else "http",
                        "http_status": reflection_call.get("http_status"),
                        "grpc_status": reflection.get("grpc_status"),
                        "access": _access_from_grpc_status(
                            _effective_grpc_status(reflection), supported=reflection.get("reflection_enabled")
                        ),
                        "error": reflection.get("error"),
                    },
                ],
            }

        if reflection_call.get("transport_ok"):
            non_grpc_seen = True
        if reflection.get("error"):
            transport_errors.append(str(reflection.get("error")))

    for use_tls in transport_order:
        web_health = _grpc_web_health_check_call(
            host,
            port,
            timeout=timeout,
            use_tls=use_tls,
            authorization=None,
            service_name="",
        )
        calls.append(web_health)
        web_call = web_health["call"]
        if bool(web_call.get("is_grpc_web")):
            return {
                "is_grpc": True,
                "protocol_flavor": "grpc-web",
                "grpc_web_detected": True,
                "transport_mode": "tls" if use_tls else "plaintext",
                "auth_required": None,
                "health_access": _access_from_grpc_status(
                    web_health.get("grpc_status"), supported=web_health.get("health_supported")
                ),
                "reflection_access": _ACCESS_NOT_TESTED,
                "invoke_access": _ACCESS_NOT_TESTED,
                "health_supported": web_health.get("health_supported"),
                # Native server reflection was not probed on the gRPC-Web
                # endpoint. Do not present "not probed" as securely disabled.
                "reflection_enabled": None,
                "reflection_version": None,
                "detect_error": web_health.get("error"),
                "detect_probe_trace": [
                    {
                        "probe": "grpc-web-health",
                        "scheme": "https" if use_tls else "http",
                        "http_status": web_call.get("http_status"),
                        "grpc_status": web_health.get("grpc_status"),
                        "access": _access_from_grpc_status(
                            web_health.get("grpc_status"), supported=web_health.get("health_supported")
                        ),
                        "error": web_health.get("error"),
                    }
                ],
            }
        if web_call.get("transport_ok"):
            non_grpc_seen = True
        if web_health.get("error"):
            transport_errors.append(str(web_health.get("error")))

    if non_grpc_seen:
        return {
            "is_grpc": False,
            "protocol_flavor": None,
            "grpc_web_detected": False,
            "status": "not_grpc",
            "transport_mode": None,
            "auth_required": None,
            "health_access": _ACCESS_UNKNOWN,
            "reflection_access": _ACCESS_UNKNOWN,
            "invoke_access": _ACCESS_NOT_TESTED,
            "health_supported": None,
            "reflection_enabled": None,
            "reflection_version": None,
            "detect_error": "not a gRPC endpoint",
            "detect_probe_trace": [
                {
                    "probe": "health",
                    "scheme": "https" if item.get("call", {}).get("use_tls") else "http",
                    "http_status": item.get("call", {}).get("http_status"),
                    "grpc_status": item.get("grpc_status"),
                    "error": item.get("error"),
                }
                for item in calls
            ],
        }

    error_text = "; ".join(dict.fromkeys(err for err in transport_errors if err.strip())) or "connection failed"
    return {
        "is_grpc": False,
        "protocol_flavor": None,
        "grpc_web_detected": False,
        "status": "fail",
        "transport_mode": None,
        "auth_required": None,
        "health_access": _ACCESS_UNKNOWN,
        "reflection_access": _ACCESS_UNKNOWN,
        "invoke_access": _ACCESS_NOT_TESTED,
        "health_supported": None,
        "reflection_enabled": None,
        "reflection_version": None,
        "detect_error": error_text,
        "detect_probe_trace": [
            {
                "probe": "health",
                "scheme": "https" if item.get("call", {}).get("use_tls") else "http",
                "http_status": item.get("call", {}).get("http_status"),
                "grpc_status": item.get("grpc_status"),
                "error": item.get("error"),
            }
            for item in calls
        ],
    }


def _credential_label(entry: dict[str, Any]) -> str:
    auth_type = str(entry.get("type") or "").strip()
    if auth_type == "token":
        return "token"
    if auth_type == "basic":
        username = str(entry.get("username") or "user").strip() or "user"
        password = str(entry.get("password") or "")
        if password == "":
            password = "<empty>"
        return f"{username}:{password}"
    return "credentials"


def _credential_auth_header(candidate: dict[str, Any] | None) -> str | None:
    if not isinstance(candidate, dict):
        return None
    return _build_auth_header(
        token=str(candidate.get("token") or "") if candidate.get("type") == "token" else None,
        username=str(candidate.get("username") or "") if candidate.get("type") == "basic" else None,
        password=str(candidate.get("password") or "") if candidate.get("type") == "basic" else None,
    )


def _provided_credential_type(*, token: str | None, username: str | None, password: str | None) -> str | None:
    if token:
        return "token"
    if username is not None and password is not None:
        return "basic"
    return None


def _auth_attempt_entries(
    *,
    token: str | None,
    username: str | None,
    password: str | None,
    defcreds: bool,
) -> list[dict[str, Any]]:
    attempts: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()

    def _add_token(value: str, source: str) -> None:
        key = ("token", value, "")
        if key in seen:
            return
        seen.add(key)
        attempts.append({"type": "token", "token": value, "source": source})

    def _add_basic(user: str, pwd: str, source: str) -> None:
        key = ("basic", user, pwd)
        if key in seen:
            return
        seen.add(key)
        attempts.append({"type": "basic", "username": user, "password": pwd, "source": source})

    if token:
        _add_token(token, "provided")
    elif username is not None and password is not None:
        _add_basic(username, password, "provided")

    if defcreds:
        for value in _DEFAULT_BEARER_TOKENS:
            _add_token(value, "defcreds")
        for user, pwd in _DEFAULT_BASIC_CREDENTIALS:
            _add_basic(user, pwd, "defcreds")

    return attempts


def _auth_attempt_success(grpc_status: int | None, is_grpc: bool) -> bool:
    if not is_grpc:
        return False
    if grpc_status in _GRPC_AUTH_CODES:
        return False
    if grpc_status is None:
        return False
    return True


def _try_credentials(
    host: str,
    port: int,
    *,
    timeout: float,
    use_tls: bool,
    protocol_flavor: str,
    candidates: list[dict[str, Any]],
    health_access: str = _ACCESS_AUTH_REQUIRED,
    reflection_access: str = _ACCESS_AUTH_REQUIRED,
    required_capability: str = "any",
    session: _GrpcH2Session | None = None,
) -> tuple[bool, dict[str, Any] | None, dict[str, Any] | None]:
    last_attempt: dict[str, Any] | None = None
    health_candidate: dict[str, Any] | None = None
    reflection_candidate: dict[str, Any] | None = None
    for candidate in candidates:
        auth_header = _credential_auth_header(candidate)
        if protocol_flavor == "grpc-web":
            health = _grpc_web_health_check_call(
                host,
                port,
                timeout=timeout,
                use_tls=use_tls,
                authorization=auth_header,
                service_name="",
            )
        else:
            health = _health_check_call(
                host,
                port,
                timeout=timeout,
                use_tls=use_tls,
                authorization=auth_header,
                service_name="",
                session=session,
            )
        last_attempt = {
            "candidate": candidate,
            "health": health,
        }
        health_ok = health_access == _ACCESS_AUTH_REQUIRED and _auth_attempt_success(
            health.get("grpc_status"), bool(health.get("call", {}).get("is_grpc"))
        )
        if health_ok and health_candidate is None:
            health_candidate = dict(candidate)

        if protocol_flavor == "grpc-web":
            reflection = None
            reflection_ok = False
        else:
            reflection = _reflection_capability_call(
                host,
                port,
                timeout=timeout,
                use_tls=use_tls,
                authorization=auth_header,
                session=session,
            )
            reflection_ok = reflection_access == _ACCESS_AUTH_REQUIRED and _auth_attempt_success(
                _effective_grpc_status(reflection), bool(reflection.get("call", {}).get("is_grpc"))
            )
            if reflection_ok and reflection_candidate is None:
                reflection_candidate = dict(candidate)

        last_attempt = {
            "candidate": candidate,
            "health": health,
            "reflection": reflection,
            "health_ok": health_ok,
            "reflection_ok": reflection_ok,
            "health_candidate": health_candidate,
            "reflection_candidate": reflection_candidate,
        }
        if required_capability == "health":
            candidate_ok = health_ok
        elif required_capability == "reflection":
            candidate_ok = reflection_ok
        else:
            candidate_ok = health_ok or reflection_ok
        if candidate_ok:
            return True, candidate, last_attempt

    return False, None, last_attempt


def _format_status_label(status: str) -> str:
    if status == "open_no_auth":
        return "anonymous access"
    if status == "valid_credentials":
        return "valid credentials"
    if status == "auth_required":
        return "authentication required"
    if status == "invalid_credentials_anonymous":
        return "invalid credentials (anonymous works)"
    if status == "invalid_credentials":
        return "invalid credentials"
    if status == "not_grpc":
        return "not grpc"
    if status == "fail":
        return "fail"
    return status


def _audit_grpc_host(
    host: str,
    port: int,
    timeout: float,
    retries: int,
    *,
    token: str | None,
    username: str | None,
    password: str | None,
    defcreds: bool,
    preferred_scheme: str | None,
    run_deep_checks: bool,
    analyze: bool = True,
    schema_descriptor_bytes: list[bytes] | None = None,
    invoke_path: str | None = None,
    invoke_request_json: dict[str, Any] | None = None,
    metadata: list[tuple[str, str]] | None = None,
    _lifecycle_detect_result: dict[str, Any] | None = None,
    _session_state: GrpcLifecycleState | None = None,
) -> dict[str, Any]:
    if _session_state is None:
        owned_session_state = GrpcLifecycleState()
        try:
            return _audit_grpc_host(
                host,
                port,
                timeout,
                retries,
                token=token,
                username=username,
                password=password,
                defcreds=defcreds,
                preferred_scheme=preferred_scheme,
                run_deep_checks=run_deep_checks,
                analyze=analyze,
                schema_descriptor_bytes=schema_descriptor_bytes,
                invoke_path=invoke_path,
                invoke_request_json=invoke_request_json,
                metadata=metadata,
                _lifecycle_detect_result=_lifecycle_detect_result,
                _session_state=owned_session_state,
            )
        finally:
            owned_session_state.close()

    attempts = max(1, retries + 1)
    provided_credentials = bool(token or (username is not None and password is not None))
    provided_credential_type = _provided_credential_type(token=token, username=username, password=password)
    auth_candidates = _auth_attempt_entries(token=token, username=username, password=password, defcreds=defcreds)

    last_error: str | None = None
    detect_probe_trace: list[dict[str, Any]] = []

    detect_duration_ms = 0
    auth_duration_ms = 0
    capability_duration_ms = 0
    data_duration_ms = 0
    stage_attempts_used = 1
    perform_analysis = bool(run_deep_checks and analyze)

    detect_result: dict[str, Any] = dict(_lifecycle_detect_result or {})

    if _lifecycle_detect_result is None:
        for attempt in range(attempts):
            stage_attempts_used = attempt + 1
            detect_started = time.monotonic()
            detect_result = _detect_grpc_target(
                host,
                port,
                timeout=timeout,
                preferred_scheme=preferred_scheme,
                _session_state=_session_state,
            )
            detect_duration_ms = int((time.monotonic() - detect_started) * 1000)
            detect_probe_trace = list(detect_result.get("detect_probe_trace") or [])

            if detect_result.get("status") == "fail":
                last_error = str(detect_result.get("detect_error") or "connection failed")
                if attempt >= attempts - 1 or not _is_retryable_stage_error(last_error):
                    break
                time.sleep(_retry_delay(attempt))
                continue

            break
    else:
        detect_probe_trace = list(detect_result.get("detect_probe_trace") or [])
        last_error = str(detect_result.get("detect_error") or "") or None

    if detect_result.get("status") == "fail":
        return {
            "timestamp": utc_now_iso(),
            "host": host,
            "port": port,
            "is_grpc": False,
            "transport_mode": None,
            "protocol_flavor": detect_result.get("protocol_flavor"),
            "grpc_web_detected": bool(detect_result.get("grpc_web_detected")),
            "status": "fail",
            "auth_required": None,
            "health_access": _ACCESS_UNKNOWN,
            "reflection_access": _ACCESS_UNKNOWN,
            "invoke_access": _ACCESS_NOT_TESTED,
            "provided_credentials": provided_credentials,
            "provided_credential_type": provided_credential_type,
            "provided_username": username,
            "provided_password": password if username is not None and password is not None else None,
            "provided_credentials_ok": None,
            "auth_used": None,
            "defcreds_used": bool(defcreds),
            "reflection_enabled": None,
            "reflection_version": None,
            "analysis_performed": False,
            "health_supported": None,
            "services": None,
            "methods": None,
            "descriptors": None,
            "health_checks": None,
            "invoke_result": None,
            "descriptor_protos_b64": None,
            "detect_probe_trace": detect_probe_trace,
            "error": last_error or str(detect_result.get("detect_error") or "connection failed"),
            "stage_detect_ms": detect_duration_ms,
            "stage_auth_ms": auth_duration_ms,
            "stage_capabilities_ms": capability_duration_ms,
            "stage_data_ms": data_duration_ms,
            "stage_attempts_used": stage_attempts_used,
        }

    if not bool(detect_result.get("is_grpc")):
        return {
            "timestamp": utc_now_iso(),
            "host": host,
            "port": port,
            "is_grpc": False,
            "transport_mode": None,
            "protocol_flavor": detect_result.get("protocol_flavor"),
            "grpc_web_detected": bool(detect_result.get("grpc_web_detected")),
            "status": "not_grpc",
            "auth_required": None,
            "health_access": _ACCESS_UNKNOWN,
            "reflection_access": _ACCESS_UNKNOWN,
            "invoke_access": _ACCESS_NOT_TESTED,
            "provided_credentials": provided_credentials,
            "provided_credential_type": provided_credential_type,
            "provided_username": username,
            "provided_password": password if username is not None and password is not None else None,
            "provided_credentials_ok": None,
            "auth_used": None,
            "defcreds_used": bool(defcreds),
            "reflection_enabled": None,
            "reflection_version": None,
            "analysis_performed": False,
            "health_supported": None,
            "services": None,
            "methods": None,
            "descriptors": None,
            "health_checks": None,
            "invoke_result": None,
            "descriptor_protos_b64": None,
            "detect_probe_trace": detect_probe_trace,
            "error": str(detect_result.get("detect_error") or "not a gRPC endpoint"),
            "stage_detect_ms": detect_duration_ms,
            "stage_auth_ms": auth_duration_ms,
            "stage_capabilities_ms": capability_duration_ms,
            "stage_data_ms": data_duration_ms,
            "stage_attempts_used": stage_attempts_used,
        }

    transport_mode = str(detect_result.get("transport_mode") or "plaintext")
    protocol_flavor = str(detect_result.get("protocol_flavor") or "grpc")
    use_tls = transport_mode == "tls"
    native_session = (
        _session_state.session_for(host, port, timeout=timeout, use_tls=use_tls)
        if _session_state is not None and protocol_flavor != "grpc-web"
        else None
    )

    health_supported = detect_result.get("health_supported")
    reflection_enabled = detect_result.get("reflection_enabled")
    reflection_version = detect_result.get("reflection_version")
    legacy_auth_required = detect_result.get("auth_required")
    raw_health_access = detect_result.get("health_access")
    if isinstance(raw_health_access, str) and raw_health_access:
        health_access = raw_health_access
    elif legacy_auth_required is True:
        health_access = _ACCESS_AUTH_REQUIRED
    elif legacy_auth_required is False:
        # Compatibility for old callers: narrow the legacy endpoint-wide value
        # to the Health probe instead of perpetuating the unsafe inference.
        health_access = _ACCESS_ANONYMOUS
    else:
        health_access = _ACCESS_UNKNOWN
    raw_reflection_access = detect_result.get("reflection_access")
    reflection_access = (
        str(raw_reflection_access)
        if isinstance(raw_reflection_access, str) and raw_reflection_access
        else _ACCESS_UNKNOWN
    )
    raw_invoke_access = detect_result.get("invoke_access")
    invoke_access = (
        str(raw_invoke_access) if isinstance(raw_invoke_access, str) and raw_invoke_access else _ACCESS_NOT_TESTED
    )
    health_auth_used = _session_state.health_auth_used
    reflection_auth_used = _session_state.reflection_auth_used
    if health_auth_used is not None and health_access == _ACCESS_AUTH_REQUIRED:
        health_access = _ACCESS_AUTHENTICATED
    if reflection_auth_used is not None and reflection_access == _ACCESS_AUTH_REQUIRED:
        reflection_access = _ACCESS_AUTHENTICATED

    auth_started = time.monotonic()
    # This legacy field is endpoint-wide.  Health and Reflection can never set
    # it: only an explicitly requested application method may provide evidence.
    auth_required: bool | None = None
    provided_credentials_ok: bool | None = None
    auth_used: dict[str, Any] | None = None
    auth_error: str | None = None

    if perform_analysis and protocol_flavor != "grpc-web" and reflection_access == _ACCESS_AUTH_REQUIRED:
        required_credential_capability = "reflection"
    elif health_access == _ACCESS_AUTH_REQUIRED:
        required_credential_capability = "health"
    elif reflection_access == _ACCESS_AUTH_REQUIRED:
        required_credential_capability = "reflection"
    else:
        required_credential_capability = "any"

    protected_probe_seen = _ACCESS_AUTH_REQUIRED in {health_access, reflection_access}
    should_try_auth = bool(auth_candidates) and protected_probe_seen
    if should_try_auth:
        success, matched_candidate, last_attempt = _try_credentials(
            host,
            port,
            timeout=timeout,
            use_tls=use_tls,
            protocol_flavor=protocol_flavor,
            candidates=auth_candidates,
            health_access=health_access,
            reflection_access=reflection_access,
            required_capability=required_credential_capability,
            session=native_session,
        )
        if isinstance(last_attempt, dict):
            attempted_health_candidate = last_attempt.get("health_candidate")
            attempted_reflection_candidate = last_attempt.get("reflection_candidate")
            if isinstance(attempted_health_candidate, dict):
                health_auth_used = dict(attempted_health_candidate)
                _session_state.health_auth_used = dict(attempted_health_candidate)
                health_access = _ACCESS_AUTHENTICATED
            if isinstance(attempted_reflection_candidate, dict):
                reflection_auth_used = dict(attempted_reflection_candidate)
                _session_state.reflection_auth_used = dict(attempted_reflection_candidate)
                reflection_access = _ACCESS_AUTHENTICATED
        if success:
            provided_credentials_ok = True
            auth_used = matched_candidate
        else:
            provided_credentials_ok = False if bool(auth_candidates) else None
            if isinstance(last_attempt, dict):
                health = last_attempt.get("health")
                reflection = last_attempt.get("reflection")
                if isinstance(health, dict) and health.get("error"):
                    auth_error = str(health.get("error"))
                if not auth_error and isinstance(reflection, dict) and reflection.get("error"):
                    auth_error = str(reflection.get("error"))

    auth_duration_ms = int((time.monotonic() - auth_started) * 1000)

    if provided_credentials_ok is True:
        status = "valid_credentials"
    elif provided_credentials_ok is False:
        status = "invalid_credentials"
    else:
        status = "detected"

    services: list[str] = []
    methods: list[dict[str, Any]] = []
    descriptors: list[dict[str, Any]] = []
    health_checks: list[dict[str, Any]] = []
    descriptor_blobs: list[bytes] = _dedup_descriptor_bytes(list(schema_descriptor_bytes or []))
    invoke_result: dict[str, Any] | None = None

    # Invoke is the only probe that can validate access to the selected
    # application method. Pass the current explicit/default credential even
    # when public Health/Reflection could not validate it first.
    allow_unvalidated_invoke = bool(invoke_path and provided_credentials)
    analysis_performed = bool(
        perform_analysis and (status in {"detected", "valid_credentials"} or allow_unvalidated_invoke)
    )
    reflection_analysis_satisfied = False
    health_analysis_satisfied = False
    reflection_deep_challenge_seen = False
    health_deep_challenge_seen = False
    if analysis_performed:
        cap_started = time.monotonic()
        current_auth_candidate = auth_used
        if current_auth_candidate is None and auth_candidates:
            current_auth_candidate = auth_candidates[0]
        reflection_provisional_auth = (
            current_auth_candidate
            if _session_state.reflection_deep_auth_required and current_auth_candidate is not None
            else None
        )
        health_provisional_auth = (
            current_auth_candidate
            if (
                protocol_flavor == "grpc-web"
                and _session_state.health_deep_auth_required
                and current_auth_candidate is not None
            )
            else None
        )
        health_deep_auth_used = health_provisional_auth or health_auth_used
        reflection_deep_auth_used = reflection_provisional_auth or reflection_auth_used
        health_auth_header = _credential_auth_header(health_deep_auth_used)
        reflection_auth_header = _credential_auth_header(reflection_deep_auth_used)
        invoke_auth_used = auth_used
        if invoke_auth_used is None and allow_unvalidated_invoke and auth_candidates:
            invoke_auth_used = auth_candidates[0]
        invoke_auth_header = _credential_auth_header(invoke_auth_used)

        if protocol_flavor == "grpc-web":
            reflection_enabled = None
            reflection_version = None
        else:
            reflection = _reflection_list_services_call(
                host,
                port,
                timeout=timeout,
                use_tls=use_tls,
                authorization=reflection_auth_header,
                session=native_session,
            )
            reflection_enabled = reflection.get("reflection_enabled")
            reflection_version = reflection.get("reflection_version")
            reflection_status = _effective_grpc_status(reflection)
            reflection_observation = _access_from_grpc_status(
                reflection_status,
                supported=reflection_enabled,
                used_credentials=bool(
                    reflection_auth_header
                    and (reflection_access != _ACCESS_ANONYMOUS or reflection_provisional_auth is not None)
                ),
            )
            reflection_access = _merge_access(reflection_access, reflection_observation)
            reflection_analysis_satisfied = reflection_observation in {
                _ACCESS_ANONYMOUS,
                _ACCESS_AUTHENTICATED,
                _ACCESS_UNSUPPORTED,
            }
            if reflection_status in _GRPC_AUTH_CODES:
                reflection_deep_challenge_seen = True
                _session_state.reflection_deep_auth_required = True
                _session_state.reflection_auth_used = None
            services = list(reflection.get("services") or [])

        if protocol_flavor == "grpc-web":
            primary_health = _grpc_web_health_check_call(
                host,
                port,
                timeout=timeout,
                use_tls=use_tls,
                authorization=health_auth_header,
                service_name="",
            )
        else:
            primary_health = _health_check_call(
                host,
                port,
                timeout=timeout,
                use_tls=use_tls,
                authorization=health_auth_header,
                service_name="",
                session=native_session,
            )
        health_supported = primary_health.get("health_supported")
        primary_health_status = primary_health.get("grpc_status")
        primary_health_access = _access_from_grpc_status(
            primary_health_status,
            supported=health_supported,
            used_credentials=bool(
                health_auth_header and (health_access != _ACCESS_ANONYMOUS or health_provisional_auth is not None)
            ),
        )
        health_access = _merge_access(health_access, primary_health_access)
        health_analysis_satisfied = primary_health_access in {
            _ACCESS_ANONYMOUS,
            _ACCESS_AUTHENTICATED,
            _ACCESS_UNSUPPORTED,
        }
        if protocol_flavor == "grpc-web" and primary_health_status in _GRPC_AUTH_CODES:
            health_deep_challenge_seen = True
            _session_state.health_deep_auth_required = True
            _session_state.health_auth_used = None
        health_checks.append(
            {
                "service": "",
                "grpc_status": primary_health.get("grpc_status"),
                "grpc_status_name": primary_health.get("grpc_status_name"),
                "serving_status": primary_health.get("serving_status"),
                "access": primary_health_access,
                "error": primary_health.get("error"),
            }
        )

        capability_duration_ms = int((time.monotonic() - cap_started) * 1000)

        data_started = time.monotonic()
        if protocol_flavor != "grpc-web" and reflection_enabled is True and services:
            for service_name in services:
                response = _reflection_file_descriptors_call(
                    host,
                    port,
                    timeout=timeout,
                    use_tls=use_tls,
                    authorization=reflection_auth_header,
                    symbol=service_name,
                    session=native_session,
                )
                descriptor_status = _effective_grpc_status(response)
                descriptor_access = _access_from_grpc_status(
                    descriptor_status,
                    used_credentials=bool(reflection_auth_header),
                )
                reflection_access = _merge_access(reflection_access, descriptor_access)
                reflection_analysis_satisfied = reflection_analysis_satisfied and descriptor_access in {
                    _ACCESS_ANONYMOUS,
                    _ACCESS_AUTHENTICATED,
                    _ACCESS_UNSUPPORTED,
                }
                if descriptor_status in _GRPC_AUTH_CODES:
                    reflection_deep_challenge_seen = True
                    _session_state.reflection_deep_auth_required = True
                    _session_state.reflection_auth_used = None
                descriptor_blobs.extend(
                    blob for blob in response.get("descriptor_bytes") or [] if isinstance(blob, bytes)
                )

        descriptor_blobs = _dedup_descriptor_bytes(descriptor_blobs)
        methods, descriptors = _extract_descriptors(descriptor_blobs)
        if not services and methods:
            services = sorted({str(method.get("service") or "") for method in methods if method.get("service")})

        if services:
            for service_name in services:
                if protocol_flavor == "grpc-web":
                    health_entry = _grpc_web_health_check_call(
                        host,
                        port,
                        timeout=timeout,
                        use_tls=use_tls,
                        authorization=health_auth_header,
                        service_name=service_name,
                    )
                else:
                    health_entry = _health_check_call(
                        host,
                        port,
                        timeout=timeout,
                        use_tls=use_tls,
                        authorization=health_auth_header,
                        service_name=service_name,
                        session=native_session,
                    )
                service_health_access = _access_from_grpc_status(
                    health_entry.get("grpc_status"),
                    supported=health_entry.get("health_supported"),
                    used_credentials=bool(health_auth_header),
                )
                health_access = _merge_access(health_access, service_health_access)
                health_analysis_satisfied = health_analysis_satisfied and service_health_access in {
                    _ACCESS_ANONYMOUS,
                    _ACCESS_AUTHENTICATED,
                    _ACCESS_UNSUPPORTED,
                }
                if protocol_flavor == "grpc-web" and health_entry.get("grpc_status") in _GRPC_AUTH_CODES:
                    health_deep_challenge_seen = True
                    _session_state.health_deep_auth_required = True
                    _session_state.health_auth_used = None
                health_checks.append(
                    {
                        "service": service_name,
                        "grpc_status": health_entry.get("grpc_status"),
                        "grpc_status_name": health_entry.get("grpc_status_name"),
                        "serving_status": health_entry.get("serving_status"),
                        "access": service_health_access,
                        "error": health_entry.get("error"),
                    }
                )

        if reflection_provisional_auth is not None:
            if reflection_analysis_satisfied:
                reflection_auth_used = dict(reflection_provisional_auth)
                _session_state.reflection_auth_used = dict(reflection_provisional_auth)
                _session_state.reflection_deep_auth_required = False
                provided_credentials_ok = True
                auth_used = dict(reflection_provisional_auth)
                status = "valid_credentials"
            elif reflection_deep_challenge_seen:
                provided_credentials_ok = False
                status = "invalid_credentials"

        if health_provisional_auth is not None:
            if health_analysis_satisfied:
                health_auth_used = dict(health_provisional_auth)
                _session_state.health_auth_used = dict(health_provisional_auth)
                _session_state.health_deep_auth_required = False
                provided_credentials_ok = True
                auth_used = dict(health_provisional_auth)
                status = "valid_credentials"
            elif health_deep_challenge_seen:
                provided_credentials_ok = False
                status = "invalid_credentials"

        if invoke_path:
            invoke_result = _invoke_unary_method(
                host,
                port,
                timeout=timeout,
                use_tls=use_tls,
                protocol_flavor=protocol_flavor,
                authorization=invoke_auth_header,
                metadata=list(metadata or []),
                descriptor_bytes=descriptor_blobs,
                invoke_path=invoke_path,
                request_json=dict(invoke_request_json or {}),
                session=native_session,
            )
            if str(invoke_result.get("status") or "") == "unsupported":
                invoke_access = _ACCESS_UNSUPPORTED
            else:
                invoke_access = _access_from_grpc_status(
                    invoke_result.get("grpc_status"),
                    used_credentials=bool(invoke_auth_header),
                )
            if invoke_access == _ACCESS_AUTH_REQUIRED:
                if invoke_auth_header:
                    provided_credentials_ok = False
                    status = "invalid_credentials"
            elif invoke_access == _ACCESS_AUTHENTICATED:
                provided_credentials_ok = True
                auth_used = invoke_auth_used
                status = "valid_credentials"

        data_duration_ms = int((time.monotonic() - data_started) * 1000)

    resolved_access = {_ACCESS_ANONYMOUS, _ACCESS_AUTHENTICATED, _ACCESS_UNSUPPORTED}
    if invoke_path:
        action_access_satisfied = invoke_access in resolved_access
    elif perform_analysis and protocol_flavor == "grpc-web":
        action_access_satisfied = analysis_performed and health_analysis_satisfied
    elif perform_analysis:
        action_access_satisfied = analysis_performed and reflection_analysis_satisfied
    else:
        action_access_satisfied = provided_credentials_ok is not False

    if not action_access_satisfied and reflection_access == _ACCESS_MIXED:
        _session_state.reflection_auth_used = None
    if not action_access_satisfied and health_access == _ACCESS_MIXED:
        _session_state.health_auth_used = None

    error_parts: list[str] = []
    if detect_result.get("detect_error") and status in {"fail", "not_grpc"}:
        error_parts.append(str(detect_result.get("detect_error")))
    if auth_error and status in {"auth_required", "invalid_credentials", "invalid_credentials_anonymous"}:
        error_parts.append(auth_error)

    return {
        "timestamp": utc_now_iso(),
        "host": host,
        "port": port,
        "is_grpc": True,
        "transport_mode": transport_mode,
        "protocol_flavor": protocol_flavor,
        "grpc_web_detected": protocol_flavor == "grpc-web",
        "status": status,
        "auth_required": auth_required,
        "health_access": health_access,
        "reflection_access": reflection_access,
        "invoke_access": invoke_access,
        "provided_credentials": provided_credentials,
        "provided_credential_type": provided_credential_type,
        "provided_username": username,
        "provided_password": password if username is not None and password is not None else None,
        "provided_credentials_ok": provided_credentials_ok,
        "auth_used": auth_used,
        "defcreds_used": bool(defcreds),
        "reflection_enabled": reflection_enabled,
        "reflection_version": reflection_version,
        "analysis_performed": analysis_performed,
        "action_access_satisfied": action_access_satisfied,
        "health_supported": health_supported,
        "services": services or None,
        "methods": methods or None,
        "descriptors": descriptors or None,
        "health_checks": health_checks or None,
        "invoke_result": invoke_result,
        "descriptor_protos_b64": [
            base64.b64encode(blob).decode("ascii") for blob in _dedup_descriptor_bytes(descriptor_blobs)
        ]
        or None,
        "detect_probe_trace": detect_probe_trace,
        "error": "; ".join(dict.fromkeys(part for part in error_parts if part.strip())) or None,
        "stage_detect_ms": detect_duration_ms,
        "stage_auth_ms": auth_duration_ms,
        "stage_capabilities_ms": capability_duration_ms,
        "stage_data_ms": data_duration_ms,
        "stage_attempts_used": stage_attempts_used,
    }


def _nxc_prefix(record: dict[str, Any]) -> str:
    host = _clip(str(record.get("host") or "-"), 64)
    port = str(record.get("port") or "-")
    return f"{_GRPC_TAG:<8}\t{host}\t{port}\t"


def _auth_required_text(value: Any) -> str:
    if value is True:
        return "True"
    if value is False:
        return "False"
    return "unknown"


def _reflection_status_text(value: Any) -> str:
    if value is True:
        return "enabled"
    if value is False:
        return "disable"
    return "unknown"


def _access_text(value: Any, *, default: str = _ACCESS_UNKNOWN) -> str:
    text = str(value or "").strip().lower()
    if text in {
        _ACCESS_ANONYMOUS,
        _ACCESS_AUTHENTICATED,
        _ACCESS_AUTH_REQUIRED,
        _ACCESS_MIXED,
        _ACCESS_NOT_TESTED,
        _ACCESS_UNKNOWN,
        _ACCESS_UNSUPPORTED,
    }:
        return text
    return default if default in {_ACCESS_NOT_TESTED, _ACCESS_UNKNOWN} else _ACCESS_UNKNOWN


def _format_detect_record(record: dict[str, Any], output_format: str) -> str:
    status = str(record.get("status") or "fail")
    if output_format == "json":
        return json.dumps(
            {
                "timestamp": record.get("timestamp"),
                "type": "detect",
                "host": record.get("host"),
                "port": record.get("port"),
                "service": "grpc",
                "detected": bool(record.get("is_grpc")),
                "status": status,
                "auth_required": record.get("auth_required"),
                "health_access": _access_text(record.get("health_access")),
                "reflection_access": _access_text(record.get("reflection_access")),
                "invoke_access": _access_text(record.get("invoke_access"), default=_ACCESS_NOT_TESTED),
                "transport_mode": record.get("transport_mode"),
                "protocol_flavor": record.get("protocol_flavor"),
                "grpc_web_detected": bool(record.get("grpc_web_detected")),
                "reflection_enabled": record.get("reflection_enabled"),
                "reflection_version": record.get("reflection_version"),
            },
            ensure_ascii=False,
        )

    prefix = _nxc_prefix(record)
    if status == "fail":
        err = _clip(str(record.get("error") or "-"), 72)
        if err != "-":
            return f"{prefix} [!] connection failed err={err}"
        return f"{prefix} [!] connection failed"
    if status == "not_grpc":
        return f"{prefix} [-] not a gRPC service"

    transport = str(record.get("transport_mode") or "-")
    protocol = str(record.get("protocol_flavor") or "grpc")
    return (
        f"{prefix} [*] gRPC Service (transport:{transport}) (protocol:{protocol}) "
        f"(reflection:{_reflection_status_text(record.get('reflection_enabled'))}) "
        f"(health_access:{_access_text(record.get('health_access'))}) "
        f"(reflection_access:{_access_text(record.get('reflection_access'))}) "
        f"(invoke_access:{_access_text(record.get('invoke_access'), default=_ACCESS_NOT_TESTED)})"
    )


def _format_record(record: dict[str, Any], output_format: str) -> str:
    if output_format == "json":
        return json.dumps(record, ensure_ascii=False)

    status = str(record.get("status") or "fail")
    prefix = _nxc_prefix(record)
    err = _clip(str(record.get("error") or "-"), 72)

    services_count = len(record.get("services") or []) if isinstance(record.get("services"), list) else 0
    methods_count = len(record.get("methods") or []) if isinstance(record.get("methods"), list) else 0
    reflection_enabled = record.get("reflection_enabled")
    health_supported = record.get("health_supported")
    _ = (services_count, methods_count, reflection_enabled, health_supported)

    if status in {"detected", "open_no_auth"}:
        return ""

    if status in {"invalid_credentials", "invalid_credentials_anonymous"}:
        if record.get("provided_credential_type") == "token":
            source = str(record.get("provided_credential_source") or "provided").strip() or "provided"
            return f"{prefix} [-] token (source:{source})"
        username = str(record.get("provided_username") or "user").strip() or "user"
        provided_password = record.get("provided_password")
        password_text = "<empty>" if provided_password == "" else str(provided_password or "")
        return f"{prefix} [-] {username}:{password_text}"

    if status == "valid_credentials":
        auth_used = record.get("auth_used")
        if isinstance(auth_used, dict):
            label = _credential_label(auth_used)
        else:
            label = "credentials"
        return f"{prefix} [+] {label}"

    if status == "auth_required":
        if record.get("provided_credentials"):
            if record.get("provided_credential_type") == "token":
                source = str(record.get("provided_credential_source") or "provided").strip() or "provided"
                base = f"{prefix} [-] token (source:{source})"
            else:
                username = str(record.get("provided_username") or "user").strip() or "user"
                provided_password = record.get("provided_password")
                password_text = "<empty>" if provided_password == "" else str(provided_password or "")
                base = f"{prefix} [-] {username}:{password_text}"
        else:
            base = f"{prefix} [-] authentication required"
        if err != "-":
            return f"{base} err={err}"
        return base

    if status == "not_grpc":
        return f"{prefix} [-] not a gRPC service"

    line = f"{prefix} [!] connection failed"
    if err != "-":
        return f"{line} err={err}"
    return line


def _format_detail_records(record: dict[str, Any], output_format: str) -> list[str]:
    if str(record.get("status") or "") not in {
        "detected",
        "invalid_credentials",
        "open_no_auth",
        "valid_credentials",
    }:
        return []
    if record.get("analysis_performed") is False:
        return []

    services = [str(item).strip() for item in (record.get("services") or []) if str(item).strip()]
    methods_raw = as_list(record.get("methods"))
    methods = [item for item in methods_raw if isinstance(item, dict)]
    descriptors_raw = as_list(record.get("descriptors"))
    descriptors = [item for item in descriptors_raw if isinstance(item, dict)]
    health_checks_raw = as_list(record.get("health_checks"))
    health_checks = [item for item in health_checks_raw if isinstance(item, dict)]
    invoke_result = record.get("invoke_result") if isinstance(record.get("invoke_result"), dict) else None
    reflection_enabled = record.get("reflection_enabled")
    health_supported = record.get("health_supported")

    if output_format == "json":
        lines: list[str] = []
        lines.append(
            json.dumps(
                {
                    "timestamp": record.get("timestamp"),
                    "type": "grpc_reflection_services",
                    "service": "grpc",
                    "host": record.get("host"),
                    "port": record.get("port"),
                    "reflection_enabled": record.get("reflection_enabled"),
                    "reflection_version": record.get("reflection_version"),
                    "reflection_access": _access_text(record.get("reflection_access")),
                    "services": services,
                },
                ensure_ascii=False,
            )
        )
        lines.append(
            json.dumps(
                {
                    "timestamp": record.get("timestamp"),
                    "type": "grpc_methods",
                    "service": "grpc",
                    "host": record.get("host"),
                    "port": record.get("port"),
                    "methods": methods,
                },
                ensure_ascii=False,
            )
        )
        lines.append(
            json.dumps(
                {
                    "timestamp": record.get("timestamp"),
                    "type": "grpc_descriptors",
                    "service": "grpc",
                    "host": record.get("host"),
                    "port": record.get("port"),
                    "descriptors": descriptors,
                },
                ensure_ascii=False,
            )
        )
        lines.append(
            json.dumps(
                {
                    "timestamp": record.get("timestamp"),
                    "type": "grpc_health_checks",
                    "service": "grpc",
                    "host": record.get("host"),
                    "port": record.get("port"),
                    "health_supported": record.get("health_supported"),
                    "health_access": _access_text(record.get("health_access")),
                    "checks": health_checks,
                },
                ensure_ascii=False,
            )
        )
        if invoke_result is not None:
            lines.append(
                json.dumps(
                    {
                        "timestamp": record.get("timestamp"),
                        "type": "grpc_invoke_result",
                        "service": "grpc",
                        "host": record.get("host"),
                        "port": record.get("port"),
                        "invoke_access": _access_text(record.get("invoke_access"), default=_ACCESS_NOT_TESTED),
                        "result": invoke_result,
                    },
                    ensure_ascii=False,
                )
            )
        return lines

    prefix = _nxc_prefix(record)
    lines = []

    if reflection_enabled is True:
        if services:
            lines.append(f"{prefix} [*] {len(services)} Services")
            for service_name in services:
                lines.append(f"{prefix} service={service_name}")
        else:
            lines.append(f"{prefix} <no services>")

    if methods:
        lines.append(f"{prefix} [*] {len(methods)} Methods")
        for method in methods:
            full_method = str(method.get("full_method") or "")
            input_type = str(method.get("input_type") or "-")
            output_type = str(method.get("output_type") or "-")
            client_streaming = bool(method.get("client_streaming"))
            server_streaming = bool(method.get("server_streaming"))
            lines.append(
                f"{prefix} {full_method} input={input_type} output={output_type} "
                f"client_stream={client_streaming} server_stream={server_streaming}"
            )

    if descriptors:
        lines.append(f"{prefix} [*] {len(descriptors)} Descriptors")
        for descriptor in descriptors:
            file_name = str(descriptor.get("file") or "-")
            package_name = str(descriptor.get("package") or "-")
            service_list = as_list(descriptor.get("services"))
            lines.append(f"{prefix} file={file_name} package={package_name} services={len(service_list)}")

    lines.append(f"{prefix} [*] Health (supported:{_auth_required_text(health_supported)})")
    if health_checks:
        lines.append(f"{prefix} [*] {len(health_checks)} Health Checks")
        for entry in health_checks:
            service_name = str(entry.get("service") or "") or "<overall>"
            serving = str(entry.get("serving_status") or "-")
            grpc_status_name = str(entry.get("grpc_status_name") or "-")
            err = str(entry.get("error") or "").strip()
            access = _access_text(entry.get("access"))
            line = f"{prefix} service={service_name} grpc={grpc_status_name} status={serving} access={access}"
            if err:
                line = f"{line} err={_clip(err, 60)}"
            lines.append(line)
    else:
        lines.append(f"{prefix} <no health data>")

    if invoke_result is not None:
        lines.append(f"{prefix} [*] Invoke")
        invoke_path = str(invoke_result.get("path") or "-")
        status = str(invoke_result.get("status") or "-")
        grpc_status_name = str(invoke_result.get("grpc_status_name") or "-")
        elapsed_ms = invoke_result.get("elapsed_ms")
        line = (
            f"{prefix} method={invoke_path} result={status} grpc={grpc_status_name} "
            f"access={_access_text(record.get('invoke_access'), default=_ACCESS_NOT_TESTED)}"
        )
        if elapsed_ms is not None:
            line = f"{line} elapsed_ms={elapsed_ms}"
        lines.append(line)
        if invoke_result.get("response") is not None:
            response_json = json.dumps(invoke_result.get("response"), ensure_ascii=False, sort_keys=True)
            lines.append(f"{prefix} response={response_json}")
        if invoke_result.get("error"):
            lines.append(f"{prefix} err={_clip(str(invoke_result.get('error')), 120)}")

    return lines


def _grpc_marker_color_spans(payload: str) -> list[tuple[int, int, str]]:
    return collect_color_spans(
        payload,
        literals=(
            ("(auth required:True)", "bright_green"),
            ("(auth required:False)", "red"),
            ("(auth required:unknown)", "yellow"),
            ("(enabled:True)", "red"),
            ("(enabled:False)", "bright_green"),
            ("(enabled:unknown)", "yellow"),
            ("(supported:True)", "bright_green"),
            ("(supported:False)", "yellow"),
            ("(supported:unknown)", "yellow"),
            ("(transport:tls)", "bright_green"),
            ("(transport:plaintext)", "yellow"),
            ("(transport:-)", "yellow"),
            ("(protocol:grpc)", "bright_green"),
            ("(protocol:grpc-web)", "orange"),
            ("(reflection:enabled)", "red"),
            ("(reflection:disable)", "bright_green"),
            ("(reflection:unknown)", "yellow"),
            ("authentication required", "red"),
        )
        + tuple(
            (f"({field}:{access})", color)
            for field in ("health_access", "reflection_access", "invoke_access")
            for access, color in _ACCESS_COLORS.items()
        ),
        regexes=(
            RegexColorRule(r"\((services|methods|descriptors|checks):(\d+)\)", "orange", skip_zero_group=2),
            RegexColorRule(r"\bservice=[^\s]+", "orange"),
            RegexColorRule(r"\bfile=[^\s]+", "orange"),
            RegexColorRule(r"\bmethod=/[^\s]+", "orange"),
            RegexColorRule(r"(?<!\S)/[A-Za-z0-9_.]+/[A-Za-z0-9_]+", "orange"),
            RegexColorRule(r"(?<=\bstatus=)SERVING\b", "orange"),
            RegexColorRule(r"(?<=\bgrpc=)OK\b", "orange"),
            RegexColorRule(r"(?<=\bresult=)ok\b", "orange"),
            RegexColorRule(r"(?<=\bstatus=)[A-Z_]+\b", "yellow"),
            RegexColorRule(r"(?<=\bgrpc=)[A-Z_]+\b", "yellow"),
            RegexColorRule(r"(?<=\bresult=)unsupported\b", "yellow"),
            RegexColorRule(r"\berr=[^\s].*", "yellow"),
            RegexColorRule(r"\b(response=\{.*)", "orange"),
            RegexColorRule(r"\bOpenAPI exported\b.*", "orange"),
        ),
    )


def _grpc_detail_color_spans(payload: str) -> list[tuple[int, int, str]]:
    return collect_color_spans(
        payload,
        regexes=(
            RegexColorRule(r"^\s*service=[^\s]+\s+grpc=[A-Z_]+\s+status=[A-Z_]+.*", "orange"),
            RegexColorRule(r"^\s*/[A-Za-z0-9_.]+/[A-Za-z0-9_]+.*", "orange"),
            RegexColorRule(r"^\s*file=[^\s]+.*", "orange"),
            RegexColorRule(r"^\s*method=/[^\s]+.*", "orange"),
            RegexColorRule(r"^\s*response=\{.*", "orange"),
            RegexColorRule(r"^\s*OpenAPI exported\b.*", "orange"),
            RegexColorRule(r"\bservice=[^\s]+", "orange"),
            RegexColorRule(r"\bfile=[^\s]+", "orange"),
            RegexColorRule(r"(?<!\S)/[A-Za-z0-9_.]+/[A-Za-z0-9_]+", "orange"),
            RegexColorRule(r"\bmethod=/[^\s]+", "orange"),
            RegexColorRule(r"\bresponse=\{.*", "orange"),
            RegexColorRule(r"\berr=.*", "yellow"),
            RegexColorRule(r"(?<=\bgrpc=)OK\b", "orange"),
            RegexColorRule(r"(?<=\bstatus=)SERVING\b", "orange"),
            RegexColorRule(r"(?<=\bresult=)ok\b", "orange"),
            RegexColorRule(r"(?<=\bgrpc=)[A-Z_]+\b", "yellow"),
            RegexColorRule(r"(?<=\bstatus=)[A-Z_]+\b", "yellow"),
            RegexColorRule(r"(?<=\bresult=)unsupported\b", "yellow"),
        ),
    )


def _render_colored_grpc_line(console: Console, line: str) -> bool:
    if not line.startswith(_GRPC_TAG):
        return False

    if render_colored_marker_line(
        console,
        line,
        tag=_GRPC_TAG,
        include_auth_required=False,
        extra_spans=lambda _marker, payload: _grpc_marker_color_spans(payload),
    ):
        return True

    if "\t" in line:
        _left, right = line.rsplit("\t", 1)
        if re.search(r"^\s*(service=|file=|/|method=|response=|err=)|\b(status=SERVING|grpc=OK)\b", right):
            return render_tagged_detail_line(console, line, tag=_GRPC_TAG, spans=_grpc_detail_color_spans(right))

    return False


def _call_audit_grpc_host_with_thread_debug(
    host: str,
    port: int,
    timeout: float,
    retries: int,
    *,
    token: str | None,
    username: str | None,
    password: str | None,
    defcreds: bool,
    preferred_scheme: str | None,
    debug: bool,
    run_deep_checks: bool,
    analyze: bool = True,
    schema_descriptor_bytes: list[bytes] | None = None,
    invoke_path: str | None = None,
    invoke_request_json: dict[str, Any] | None = None,
    metadata: list[tuple[str, str]] | None = None,
    debug_emit: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    with _thread_debug_context(debug_emit):
        return _call_audit_grpc_host_with_stage_debug(
            host,
            port,
            timeout,
            retries,
            token=token,
            username=username,
            password=password,
            defcreds=defcreds,
            preferred_scheme=preferred_scheme,
            debug=debug,
            run_deep_checks=run_deep_checks,
            analyze=analyze,
            schema_descriptor_bytes=schema_descriptor_bytes,
            invoke_path=invoke_path,
            invoke_request_json=invoke_request_json,
            metadata=metadata,
            debug_emit=debug_emit,
        )


def _thread_debug_context(debug_emit: Callable[[str], None] | None):
    class _Ctx:
        def __enter__(self_inner):
            _THREAD_LOCAL_DEBUG_EMIT.callback = debug_emit

        def __exit__(self_inner, exc_type, exc, tb):
            try:
                del _THREAD_LOCAL_DEBUG_EMIT.callback
            except AttributeError:
                pass

    return _Ctx()


def _call_audit_grpc_host_with_stage_debug(
    host: str,
    port: int,
    timeout: float,
    retries: int,
    *,
    token: str | None,
    username: str | None,
    password: str | None,
    defcreds: bool,
    preferred_scheme: str | None,
    debug: bool,
    run_deep_checks: bool,
    analyze: bool = True,
    schema_descriptor_bytes: list[bytes] | None = None,
    invoke_path: str | None = None,
    invoke_request_json: dict[str, Any] | None = None,
    metadata: list[tuple[str, str]] | None = None,
    debug_emit: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    started = time.monotonic()
    effective_deep_checks = bool(run_deep_checks and analyze)
    session_state = GrpcLifecycleState()
    try:
        record = _audit_grpc_host(
            host,
            port,
            timeout,
            retries,
            token=token,
            username=username,
            password=password,
            defcreds=defcreds,
            preferred_scheme=preferred_scheme,
            run_deep_checks=effective_deep_checks,
            analyze=analyze,
            schema_descriptor_bytes=schema_descriptor_bytes,
            invoke_path=invoke_path,
            invoke_request_json=invoke_request_json,
            metadata=metadata,
            _session_state=session_state,
        )
    finally:
        session_state.close()

    result: dict[str, Any] = dict(record)
    debug_events: list[str] = []

    def _debug(message: str) -> None:
        if not debug:
            return
        debug_events.append(message)
        if debug_emit is not None:
            debug_emit(f"{host}:{port} {message}")

    status = str(result.get("status") or "fail")
    attempts = max(1, retries + 1)
    attempts_used = int(result.get("stage_attempts_used") or 1)

    if attempts_used > 1 and status == "fail":
        _debug(
            f"retry_decision stage={_STAGE_DETECT_PROTOCOL} attempt=1/{attempts} "
            f"backoff={_retry_delay(0):.2f}s reason=error"
        )

    stage_entries: list[dict[str, Any]] = [
        {
            "stage_name": _STAGE_DETECT_PROTOCOL,
            "attempt": attempts_used,
            "duration_ms": int(result.get("stage_detect_ms") or 0),
            "result": "ok" if status not in {"fail", "not_grpc"} else ("skip" if status == "not_grpc" else "error"),
            "error": result.get("error") if status == "fail" else None,
        },
        {
            "stage_name": _STAGE_AUTH_INFERENCE,
            "attempt": attempts_used,
            "duration_ms": int(result.get("stage_auth_ms") or 0),
            "result": "ok"
            if status
            in {
                "detected",
                "open_no_auth",
                "valid_credentials",
                "auth_required",
                "invalid_credentials",
                "invalid_credentials_anonymous",
            }
            else "skip",
            "error": None,
        },
        {
            "stage_name": _STAGE_ACCESS_CAPABILITIES,
            "attempt": 1,
            "duration_ms": int(result.get("stage_capabilities_ms") or 0),
            "result": "ok" if effective_deep_checks and bool(result.get("analysis_performed")) else "skip",
            "error": None,
        },
        {
            "stage_name": _STAGE_DATA,
            "attempt": 1,
            "duration_ms": int(result.get("stage_data_ms") or 0),
            "result": "ok" if effective_deep_checks and bool(result.get("analysis_performed")) else "skip",
            "error": None,
        },
    ]

    for stage_entry in stage_entries:
        _debug(
            f"stage_trace stage_name={stage_entry['stage_name']} attempt={stage_entry['attempt']} "
            f"duration_ms={stage_entry['duration_ms']} result={stage_entry['result']} "
            f"error={stage_entry['error'] or '-'}"
        )

    stage_failed_at: str | None = None
    for stage_entry in stage_entries:
        if str(stage_entry.get("result") or "") == "error":
            stage_failed_at = str(stage_entry.get("stage_name") or "")
            break

    stage_durations_ms = {str(item["stage_name"]): int(item["duration_ms"]) for item in stage_entries}
    stage_attempts = {str(item["stage_name"]): int(item["attempt"]) for item in stage_entries}

    total_ms = int((time.monotonic() - started) * 1000)
    _debug(
        f"stage_timing_summary status={status} attempts={attempts_used}/{attempts} "
        f"detect_ms={stage_durations_ms.get(_STAGE_DETECT_PROTOCOL, 0)} "
        f"auth_ms={stage_durations_ms.get(_STAGE_AUTH_INFERENCE, 0)} "
        f"capabilities_ms={stage_durations_ms.get(_STAGE_ACCESS_CAPABILITIES, 0)} "
        f"data_ms={stage_durations_ms.get(_STAGE_DATA, 0)} total_ms={total_ms}"
    )

    result["stages"] = stage_entries
    result["stage_failed_at"] = stage_failed_at
    result["stage_durations_ms"] = stage_durations_ms
    result["stage_attempts"] = stage_attempts
    result["debug_events"] = debug_events
    result["debug_events_streamed"] = bool(debug and debug_emit is not None)
    result["elapsed_ms"] = total_ms
    result["detect_confidence"] = "high" if bool(result.get("is_grpc")) else "low"
    result["transport_mode"] = result.get("transport_mode")
    result["health_supported"] = result.get("health_supported")
    result["reflection_enabled"] = result.get("reflection_enabled")
    result["health_access"] = _access_text(result.get("health_access"))
    result["reflection_access"] = _access_text(result.get("reflection_access"))
    result["invoke_access"] = _access_text(result.get("invoke_access"), default=_ACCESS_NOT_TESTED)
    return result


def _merge_stage2_record(detect_record: dict[str, Any], deep_record: dict[str, Any]) -> dict[str, Any]:
    return merge_stage_records(detect_record, deep_record)


def _grpc_lifecycle_audit(
    ctx: Any,
    options: dict[str, Any],
    *,
    run_deep_checks: bool,
) -> dict[str, Any]:
    state = ctx.lifecycle_state
    if not isinstance(state, GrpcLifecycleState) or state.detect_result is None:
        raise TypeError("grpc lifecycle state is unavailable")
    credential = ctx.credential
    record = _audit_grpc_host(
        str(ctx.host),
        int(ctx.port),
        float(getattr(ctx.args, "timeout", 5.0)),
        int(getattr(ctx.args, "retries", 0) or 0),
        token=credential.token,
        username=credential.username,
        password=credential.password,
        defcreds=False,
        preferred_scheme=(str(ctx.target.scheme) if ctx.target is not None and ctx.target.scheme else None),
        run_deep_checks=run_deep_checks,
        analyze=bool(options.get("analyze", False)),
        schema_descriptor_bytes=list(options["schema_descriptor_bytes"]),
        invoke_path=options["invoke_path"],
        invoke_request_json=options["invoke_request_json"],
        metadata=list(options["metadata"]),
        _lifecycle_detect_result=state.detect_result,
        _session_state=state,
    )
    credential_source = str(credential.source or "anonymous")
    if credential_source == "anonymous" and (
        credential.token or (credential.username is not None and credential.password is not None)
    ):
        credential_source = "provided"
    record["provided_credential_source"] = credential_source
    if credential_source == "default":
        record["defcreds_used"] = True
        auth_used = record.get("auth_used")
        if isinstance(auth_used, dict):
            auth_used["source"] = "defcreds"
    return record


def detect_grpc(ctx: Any, options: dict[str, Any]) -> dict[str, Any]:
    state = ctx.lifecycle_state
    if not isinstance(state, GrpcLifecycleState):
        raise TypeError("grpc lifecycle state is unavailable")
    attempts = max(1, int(getattr(ctx.args, "retries", 0) or 0) + 1)
    for attempt in range(attempts):
        result = _detect_grpc_target(
            str(ctx.host),
            int(ctx.port),
            timeout=float(getattr(ctx.args, "timeout", 5.0)),
            preferred_scheme=(str(ctx.target.scheme) if ctx.target is not None and ctx.target.scheme else None),
            _session_state=state,
        )
        state.detect_result = dict(result)
        error = str(result.get("detect_error") or "")
        if result.get("status") != "fail" or attempt >= attempts - 1 or not _is_retryable_stage_error(error):
            break
        time.sleep(_retry_delay(attempt))
    anonymous_ctx = type("_AnonymousGrpcContext", (), {})()
    anonymous_ctx.args = ctx.args
    anonymous_ctx.host = ctx.host
    anonymous_ctx.port = ctx.port
    anonymous_ctx.target = ctx.target
    anonymous_ctx.lifecycle_state = state
    anonymous_ctx.credential = type(
        "_AnonymousCredential",
        (),
        {"username": None, "password": None, "token": None, "source": "anonymous"},
    )()
    return _grpc_lifecycle_audit(anonymous_ctx, options, run_deep_checks=False)


def authenticate_grpc(ctx: Any, _detect_record: Any, options: dict[str, Any]) -> dict[str, Any]:
    state = ctx.lifecycle_state
    if not isinstance(state, GrpcLifecycleState):
        raise TypeError("grpc lifecycle state is unavailable")
    run_deep_checks = bool(options.get("analyze", False))
    reflection_challenge_before = state.reflection_deep_auth_required
    health_challenge_before = state.health_deep_auth_required
    record = _grpc_lifecycle_audit(ctx, options, run_deep_checks=run_deep_checks)

    credential = ctx.credential
    has_credentials = bool(credential.token or (credential.username is not None and credential.password is not None))
    protocol_flavor = str(record.get("protocol_flavor") or "grpc")
    if protocol_flavor == "grpc-web":
        new_action_challenge = not health_challenge_before and state.health_deep_auth_required
    else:
        new_action_challenge = not reflection_challenge_before and state.reflection_deep_auth_required

    # A public lightweight probe can reveal the protected deep operation only
    # during this credential's sole runtime run. Retry exactly once, now with
    # that credential; a merely public success never enables this path.
    if (
        run_deep_checks
        and options.get("invoke_path") is None
        and has_credentials
        and record.get("action_access_satisfied") is False
        and new_action_challenge
    ):
        record = _grpc_lifecycle_audit(ctx, options, run_deep_checks=True)
    state.deep_records[_grpc_lifecycle_key(ctx)] = record
    return record


def collect_grpc_data(ctx: Any, _record: Any, options: dict[str, Any]) -> dict[str, Any]:
    state = ctx.lifecycle_state
    if not isinstance(state, GrpcLifecycleState):
        raise TypeError("grpc lifecycle state is unavailable")
    cached = state.deep_records.get(_grpc_lifecycle_key(ctx))
    if cached is not None:
        return cached
    return _grpc_lifecycle_audit(ctx, options, run_deep_checks=bool(options.get("analyze", False)))


# Typed runner boundary -----------------------------------------------------
host_stage = _call_audit_grpc_host_with_stage_debug
