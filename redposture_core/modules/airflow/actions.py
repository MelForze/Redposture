"""Airflow detection, authentication and resource-access actions (REST API, read-only)."""

from __future__ import annotations

from typing import Any

from ...auth_detection import detect_browser_sso
from ...clients.airflow_api import AirflowClient, AirflowResponse
from ...clients.http_api import http_response_origin, http_response_requires_https, http_scheme_candidates
from ...clients.http_session import HttpSessionPool
from ...discovery_rendering import format_discovery_finding_line
from .discover import DiscoverConfig, discover_task_logs, list_connections, list_variable_keys
from .types import AirflowCapabilities, AirflowDetection, AnonymousResult, CredentialResult, ResourceAccess

# Модуль использует detect/auth хуки, а не монолитный host_stage; None корректно и
# удовлетворяет architecture-guard (наличие имени `host_stage = `).
host_stage = None

# Per-generation endpoint map. `/version` and `/health` are Public (no auth), so
# detection + version + generation come from one unauthenticated probe.
_ENDPOINTS = {
    "v1": {  # Airflow 2.x
        "version": "/api/v1/version",
        "health": "/api/v1/health",
        "dags": "/api/v1/dags",
        "keys": "/api/v1/variables",
        "connections": "/api/v1/connections",
    },
    "v2": {  # Airflow 3.x
        "version": "/api/v2/version",
        "health": "/api/v2/monitor/health",
        "dags": "/api/v2/dags",
        "keys": "/api/v2/variables",
        "connections": "/api/v2/connections",
    },
}
_AUTH_TOKEN_PATH = "/auth/token"  # Airflow 3.x JWT exchange

_DEFAULT_CREDENTIALS: tuple[tuple[str, str], ...] = (
    ("airflow", "airflow"),  # real Airflow default
    ("admin", "admin"),
    ("admin", "airflow"),
    ("airflow", "admin"),
    ("airflow", "password"),
    ("airflow", "changeme"),
    ("airflow", "airflow123"),
    ("admin", "password"),
    ("admin", "changeme"),
    ("admin", "airflow123"),
    ("root", "root"),
    ("root", "password"),
    ("user", "user"),
    ("user", "password"),
    ("test", "test"),
    ("dev", "dev"),
    ("service", "service"),
    ("guest", "guest"),
)


# --- detection -------------------------------------------------------------


def detect_airflow(client: AirflowClient) -> AirflowDetection:
    """Probe the public version endpoint (v2 then v1) to confirm Airflow, capture the
    version, and pin the API generation used for later auth."""
    evidence: dict[str, Any] = {}
    transport_failures = 0
    for generation in ("v2", "v1"):
        resp = client.get(_ENDPOINTS[generation]["version"], authed=False)
        if resp.transport_error:
            transport_failures += 1
            evidence[f"{generation}_transport_error"] = resp.transport_error
            continue
        evidence[f"{generation}_version_status"] = resp.http_status
        data = resp.json()
        if resp.http_status == 200 and isinstance(data, dict) and data.get("version"):
            return AirflowDetection(
                status="confirmed",
                api_generation=generation,
                version=str(data.get("version")),
                api_endpoint=client.base_url,
                evidence={**evidence, "git_version": data.get("git_version")},
            )
    if transport_failures == 2:
        return AirflowDetection(status="transport_failure", api_endpoint=client.base_url, evidence=evidence)
    # Version endpoint did not answer with a version. Fall back to health as a weak
    # signal (auth-gated version, or an Airflow behind a stricter config).
    for generation in ("v2", "v1"):
        health = client.get(_ENDPOINTS[generation]["health"], authed=False)
        if not health.transport_error and health.http_status == 200 and _looks_like_health(health):
            return AirflowDetection(
                status="probable",
                api_generation=generation,
                api_endpoint=client.base_url,
                evidence={**evidence, f"{generation}_health": True},
            )
    return AirflowDetection(status="not_airflow", api_endpoint=client.base_url, evidence=evidence)


def _looks_like_health(resp: AirflowResponse) -> bool:
    data = resp.json()
    return isinstance(data, dict) and ("metadatabase" in data or "scheduler" in data)


def _looks_like_dag_collection(resp: AirflowResponse) -> bool:
    data = resp.json()
    if not isinstance(data, dict) or not isinstance(data.get("dags"), list):
        return False
    dags = data["dags"]
    total_entries = data.get("total_entries")
    return (
        all(isinstance(item, dict) for item in dags)
        and isinstance(total_entries, int)
        and not isinstance(total_entries, bool)
        and total_entries >= len(dags)
    )


def _looks_like_airflow_problem(resp: AirflowResponse, status: int) -> bool:
    data = resp.json()
    if not isinstance(data, dict):
        return False
    response_status = data.get("status")
    return (
        isinstance(response_status, int)
        and not isinstance(response_status, bool)
        and response_status == status
        and isinstance(data.get("detail"), str)
        and bool(str(data.get("detail") or "").strip())
        and isinstance(data.get("title"), str)
        and bool(str(data.get("title") or "").strip())
    )


# --- anonymous access ------------------------------------------------------


def classify_anonymous(client: AirflowClient, generation: str) -> AnonymousResult:
    """Confirm anonymous DAG access only from a valid Airflow collection response."""
    endpoints = _ENDPOINTS.get(generation, _ENDPOINTS["v1"])
    viewer = client.get(endpoints["dags"], authed=False)
    sso = detect_browser_sso(
        final_url=viewer.final_url,
        redirect_history=viewer.redirect_history,
        headers=viewer.headers,
        body=viewer.body,
    )
    if sso is not None:
        return AnonymousResult(
            reachable=True,
            auth_required=True,
            dags_allowed=False,
            auth_method="sso",
            sso_provider=sso.provider,
            sso_protocol=sso.protocol,
            sso_evidence=sso.evidence,
        )
    if viewer.transport_error:
        return AnonymousResult(reachable=False)
    if viewer.http_status in {401, 403}:
        return AnonymousResult(reachable=True, auth_required=True, dags_allowed=False, auth_method="native")
    if viewer.http_status != 200:
        return AnonymousResult(reachable=True, auth_required=None, dags_allowed=None)
    if not _looks_like_dag_collection(viewer):
        # A reverse proxy or an unrecognized login page may answer 200. Only an
        # Airflow DAG collection proves anonymous DAG access.
        return AnonymousResult(reachable=True, auth_required=None, dags_allowed=None)
    return AnonymousResult(reachable=True, auth_required=False, dags_allowed=True, auth_method="anonymous")


# --- credentials -----------------------------------------------------------


def verify_credential(pool_client_factory: Any, generation: str, username: str, password: str) -> CredentialResult:
    """Verify one credential for the pinned generation.

    2.x: HTTP Basic against the DAG collection (200 valid / 401 invalid / 403
    valid_but_restricted). 3.x: POST /auth/token (200 + access_token valid / 401
    invalid); the issued JWT is kept for the resource-access probes.
    """
    if generation == "v2":
        client = pool_client_factory()
        resp = client.post_json(_AUTH_TOKEN_PATH, {"username": username, "password": password})
        if resp.transport_error:
            return CredentialResult(state="transient_failure", username=username)
        if resp.http_status in {401, 403}:
            return CredentialResult(state="invalid", username=username, error_code=str(resp.http_status))
        data = resp.json()
        token = data.get("access_token") if isinstance(data, dict) else None
        if resp.http_status == 200 and token:
            return CredentialResult(state="valid", username=username, bearer_token=str(token))
        return CredentialResult(state="transient_failure", username=username, error_code=str(resp.http_status))

    client = pool_client_factory(basic_user=username, basic_password=password)
    resp = client.get(_ENDPOINTS["v1"]["dags"], authed=True)
    if resp.transport_error:
        return CredentialResult(state="transient_failure", username=username)
    if resp.http_status == 401 and _looks_like_airflow_problem(resp, 401):
        return CredentialResult(state="invalid", username=username, error_code="401")
    if resp.http_status == 403 and _looks_like_airflow_problem(resp, 403):
        return CredentialResult(state="valid_but_restricted", username=username, error_code="403")
    if resp.http_status == 200 and _looks_like_dag_collection(resp):
        return CredentialResult(state="valid", username=username)
    return CredentialResult(state="verification_unavailable", username=username, error_code=str(resp.http_status))


# --- authenticated resource access ----------------------------------------


def _resource_access(client: AirflowClient, path: str, collection_key: str) -> ResourceAccess:
    """Return an exact collection count only for a validated Airflow response."""

    resp = client.get(f"{path}?limit=1&offset=0", authed=True)
    if resp.transport_error:
        return ResourceAccess(status="unknown", error="transport_error")
    if resp.http_status in {401, 403}:
        return ResourceAccess(status="denied", http_status=resp.http_status)
    if resp.http_status != 200:
        return ResourceAccess(status="unknown", http_status=resp.http_status, error=f"http_{resp.http_status}")
    if resp.truncated:
        return ResourceAccess(status="unknown", http_status=200, error="response_truncated")
    payload = resp.json()
    if not isinstance(payload, dict):
        return ResourceAccess(status="unknown", http_status=200, error="invalid_collection")
    items = payload.get(collection_key)
    total = payload.get("total_entries")
    if (
        not isinstance(items, list)
        or any(not isinstance(item, dict) for item in items)
        or not isinstance(total, int)
        or isinstance(total, bool)
        or total < 0
        or len(items) > 1
        or len(items) > total
    ):
        return ResourceAccess(status="unknown", http_status=200, error="invalid_collection")
    return ResourceAccess(status="allowed", count=total, http_status=200)


def classify_capabilities(client: AirflowClient, generation: str) -> AirflowCapabilities:
    """Measure authenticated read access without inferring an Airflow role."""

    endpoints = _ENDPOINTS.get(generation, _ENDPOINTS["v1"])
    return AirflowCapabilities(
        dags=_resource_access(client, endpoints["dags"], "dags"),
        keys=_resource_access(client, endpoints["keys"], "variables"),
        connections=_resource_access(client, endpoints["connections"], "connections"),
    )


# --- lifecycle + client ----------------------------------------------------


class AirflowLifecycleState:
    """One HttpSessionPool per target (pool reuse) + the transport scheme resolved
    for the target and the JWT held for a 3.x credential. Certificates are always
    accepted: this audits exposure, not trust."""

    def __init__(self, args: Any, host: str, port: int, *, scheme: str | None = None) -> None:
        self.host = str(host)
        self.port = int(port)
        if scheme not in {None, "http", "https"}:
            raise ValueError("airflow supports HTTP/HTTPS targets only")
        self.preferred_scheme: str | None = scheme
        self.resolved_scheme: str | None = None
        self.bearer_token: str | None = None
        self.bearer_tokens: dict[tuple[str, str], str] = {}
        self.pool = HttpSessionPool(
            timeout=float(getattr(args, "timeout", 5.0) or 5.0),
            insecure=True,
            retries=int(getattr(args, "retries", 0) or 0),
        )

    def _probe_scheme(self, scheme: str) -> AirflowResponse:
        client = AirflowClient(self.pool, scheme=scheme, host=self.host, port=self.port)
        return client.get(_ENDPOINTS["v2"]["version"], authed=False)

    def resolve_scheme(self) -> str:
        """Resolve and retain the effective origin used by the Airflow API."""
        if self.resolved_scheme is not None:
            return self.resolved_scheme
        candidates = http_scheme_candidates(self.preferred_scheme, self.port, tls_ports=frozenset({443, 8443}))
        selected = candidates[0]
        for index, candidate in enumerate(candidates):
            resp = self._probe_scheme(candidate)
            mismatch = bool(resp.transport_error and _transport_mismatch(candidate, resp.transport_error))
            tls_required = candidate == "http" and http_response_requires_https(resp.http_status, resp.body)
            selected = candidate
            if resp.transport_error and not mismatch and index == 0:
                continue
            if mismatch or tls_required:
                continue
            selected, self.host, self.port = http_response_origin(
                resp,
                fallback_scheme=candidate,
                fallback_host=self.host,
                fallback_port=self.port,
            )
            break
        self.resolved_scheme = selected
        return selected

    def close(self) -> None:
        self.pool.close()


_HTTPS_ON_PLAINTEXT = ("wrong_version_number", "record layer", "unknown protocol", "sslv3_alert", "http_request")
_HTTP_ON_TLS = ("badstatusline", "remotedisconnected", "connectionreset", "connection reset", "reset by peer")


def _transport_mismatch(scheme: str, transport_error: str) -> bool:
    err = transport_error.lower()
    markers = _HTTPS_ON_PLAINTEXT if scheme == "https" else _HTTP_ON_TLS
    return any(marker in err for marker in markers)


def airflow_lifecycle_state_factory(ctx: Any) -> AirflowLifecycleState:
    target = getattr(ctx, "target", None)
    scheme = getattr(target, "scheme", None)
    return AirflowLifecycleState(ctx.args, ctx.host, ctx.port, scheme=scheme)


def _client_for(
    ctx: Any,
    *,
    basic_user: str | None = None,
    basic_password: str | None = None,
    bearer_token: str | None = None,
) -> AirflowClient:
    state = getattr(ctx, "lifecycle_state", None)
    if isinstance(state, AirflowLifecycleState):
        scheme = state.resolve_scheme()
        pool = state.pool
        host = state.host
        port = state.port
    else:
        scheme = "https" if int(ctx.port) in {443, 8443} else "http"
        pool = HttpSessionPool(timeout=float(getattr(ctx.args, "timeout", 5.0) or 5.0), insecure=True)
        host = str(ctx.host)
        port = int(ctx.port)
    return AirflowClient(
        pool,
        scheme=scheme,
        host=host,
        port=port,
        basic_user=basic_user,
        basic_password=basic_password,
        bearer_token=bearer_token,
    )


# --- hooks -----------------------------------------------------------------


def detect_record(ctx: Any) -> dict[str, Any]:
    client = _client_for(ctx)
    detection = detect_airflow(client)
    status_word = {
        "confirmed": "detected",
        "probable": "probable",
        "not_airflow": "not_service",
        "transport_failure": "fail",
    }[detection.status]
    record: dict[str, Any] = {
        "host": str(ctx.host),
        "port": int(ctx.port),
        "status": status_word,
        "detection_status": detection.status,
        "api_generation": detection.api_generation,
        "api_endpoint": detection.api_endpoint,
        "detection": detection.evidence,
        "credential_verification_status": "available" if detection.status == "confirmed" else "unavailable",
    }
    if detection.version:
        record["version"] = detection.version
    if detection.status == "confirmed" and detection.api_generation:
        anon = classify_anonymous(client, detection.api_generation)
        record["auth_required"] = anon.auth_required
        record["dags_allowed"] = anon.dags_allowed
        record["anonymous_dags_allowed"] = anon.dags_allowed
        record["auth_method"] = anon.auth_method
        if anon.auth_required is False:
            # A public DAG endpoint returns the same successful response with
            # or without Basic credentials.  Treating that response as proof of
            # a password would create false positives for every --defcreds pair.
            record["status"] = "open_no_auth"
            record["credential_verification_status"] = "unavailable"
        if anon.sso_provider:
            record["sso_provider"] = anon.sso_provider
            record["sso_protocol"] = anon.sso_protocol
            record["sso_evidence"] = list(anon.sso_evidence)
            # A default Basic/JWT catalog cannot verify a browser SSO flow.
            # Explicit credentials remain available for installations that
            # expose native API auth alongside the browser login.
            args = getattr(ctx, "args", None)
            explicit_auth = bool(
                getattr(args, "username", None) is not None or getattr(args, "password", None) is not None
            )
            if not explicit_auth:
                record["credential_verification_status"] = "unavailable"
    if bool(getattr(getattr(ctx, "args", None), "discover", False)):
        record["discover_requested"] = True
        if detection.status != "confirmed":
            record["discover_report"] = {
                "status": "unavailable",
                "finding_count": 0,
                "findings": [],
                "partial_reasons": ["api_generation_unconfirmed"],
            }
    if bool(getattr(getattr(ctx, "args", None), "show_keys", False)):
        record["show_keys_requested"] = True
        if detection.status != "confirmed":
            record["variable_keys_error"] = "api_generation_unconfirmed"
    if bool(getattr(getattr(ctx, "args", None), "show_connections", False)):
        record["show_connections_requested"] = True
        if detection.status != "confirmed":
            record["connections_error"] = "api_generation_unconfirmed"
    return record


def auth_record(ctx: Any, prior: dict[str, Any]) -> dict[str, Any]:
    credential = ctx.credential
    username = getattr(credential, "username", None)
    password = getattr(credential, "password", None)
    if not (username and password is not None):
        return dict(prior)
    generation = str(prior.get("api_generation") or "v1")
    merged = dict(prior)

    def factory(basic_user: str | None = None, basic_password: str | None = None) -> AirflowClient:
        return _client_for(ctx, basic_user=basic_user, basic_password=basic_password)

    result = verify_credential(factory, generation, str(username), str(password))
    state = getattr(ctx, "lifecycle_state", None)
    if result.bearer_token and isinstance(state, AirflowLifecycleState):
        state.bearer_token = result.bearer_token
        state.bearer_tokens[(str(username), str(password))] = result.bearer_token
    anonymous_open = prior.get("auth_required") is False
    credential_state = result.state
    error_code = result.error_code
    if anonymous_open and credential_state in {"valid", "valid_but_restricted"}:
        credential_state = "verification_unavailable"
        error_code = "anonymous_access_already_succeeded"
    merged["credential_state"] = credential_state
    merged["credential_results"] = [{"username": result.username, "state": credential_state, "error_code": error_code}]
    merged["_credential_capabilities_pending"] = credential_state in {"valid", "valid_but_restricted"}
    # Echoed on the TXT accepted line as user:pass; redacted from JSON output.
    if credential_state in {"valid", "valid_but_restricted"}:
        merged["credential_password"] = str(password)
    merged["provided_credentials_ok"] = (
        True
        if credential_state in {"valid", "valid_but_restricted"}
        else False
        if credential_state == "invalid"
        else None
    )
    merged["default_credentials"] = getattr(credential, "source", "") == "default" and merged["provided_credentials_ok"]
    return merged


def capabilities_record(ctx: Any, prior: dict[str, Any]) -> dict[str, Any]:
    merged = dict(prior)
    if str(prior.get("credential_state") or "") not in {"valid", "valid_but_restricted"}:
        merged.pop("_credential_capabilities_pending", None)
        return merged
    generation = str(prior.get("api_generation") or "v1")
    credential = ctx.credential
    if generation == "v2":
        state = getattr(ctx, "lifecycle_state", None)
        token = (
            state.bearer_tokens.get((str(credential.username), str(credential.password)), state.bearer_token)
            if isinstance(state, AirflowLifecycleState)
            else None
        )
        client = _client_for(ctx, bearer_token=token)
    else:
        client = _client_for(
            ctx, basic_user=getattr(credential, "username", None), basic_password=getattr(credential, "password", None)
        )
    capabilities = classify_capabilities(client, generation)
    for name, access in (
        ("dags", capabilities.dags),
        ("keys", capabilities.keys),
        ("connections", capabilities.connections),
    ):
        merged[f"authenticated_{name}_access"] = access.status
        merged[f"authenticated_{name}_count"] = access.count
        merged[f"authenticated_{name}_http_status"] = access.http_status
        if access.error:
            merged[f"authenticated_{name}_error"] = access.error
    merged.pop("_credential_capabilities_pending", None)
    return merged


def discover_record(ctx: Any, prior: dict[str, Any]) -> dict[str, Any]:
    merged = dict(prior)
    discover_requested = bool(getattr(ctx.args, "discover", False))
    show_keys_value = getattr(ctx.args, "show_keys", False)
    show_keys_requested = bool(show_keys_value)
    show_connections_value = getattr(ctx.args, "show_connections", False)
    show_connections_requested = bool(show_connections_value)
    if not discover_requested and not show_keys_requested and not show_connections_requested:
        return merged
    if discover_requested:
        merged["discover_requested"] = True
    if show_keys_requested:
        merged["show_keys_requested"] = True
    if show_connections_requested:
        merged["show_connections_requested"] = True
    generation = str(prior.get("api_generation") or "")
    if prior.get("detection_status") != "confirmed" or generation not in {"v1", "v2"}:
        return merged
    credential = ctx.credential
    credential_ok = prior.get("provided_credentials_ok") is True
    if generation == "v2":
        state = getattr(ctx, "lifecycle_state", None)
        token = (
            state.bearer_tokens.get((str(credential.username), str(credential.password)))
            if isinstance(state, AirflowLifecycleState) and credential_ok
            else None
        )
        if credential_ok and token is None:
            merged["discover_report"] = {
                "status": "unavailable",
                "finding_count": 0,
                "findings": [],
                "partial_reasons": ["bearer_token_unavailable"],
            }
            return merged
        client = _client_for(ctx, bearer_token=token)
    else:
        client = _client_for(
            ctx,
            basic_user=str(credential.username) if credential_ok else None,
            basic_password=str(credential.password) if credential_ok else None,
        )

    show_keys_limit = (
        int(show_keys_value) if isinstance(show_keys_value, int) and not isinstance(show_keys_value, bool) else None
    )
    show_connections_limit = (
        int(show_connections_value)
        if isinstance(show_connections_value, int) and not isinstance(show_connections_value, bool)
        else None
    )
    if not discover_requested:
        if show_keys_requested:
            keys = list_variable_keys(client, generation, limit=show_keys_limit)
            merged["variable_keys"] = keys["keys"]
            merged["variable_keys_count"] = keys["count"]
            merged["variable_keys_total"] = keys["total"]
            merged["variable_keys_truncated"] = keys["truncated"]
            if keys.get("error"):
                merged["variable_keys_error"] = keys["error"]
        if show_connections_requested:
            connections = list_connections(client, generation, limit=show_connections_limit)
            merged["airflow_connections"] = connections["connections"]
            merged["airflow_connections_count"] = connections["count"]
            merged["airflow_connections_total"] = connections["total"]
            merged["airflow_connections_truncated"] = connections["truncated"]
            if connections.get("error"):
                merged["connections_error"] = connections["error"]
        return merged

    config = DiscoverConfig(
        max_bytes=int(getattr(ctx.args, "discover_max_bytes", 50 * 1024 * 1024)),
        max_seconds=getattr(ctx.args, "discover_time", None),
        include_dag_sources=True,
        include_variables=True,
        include_connections=True,
    )
    live_emit = getattr(ctx, "live_emit", None)

    if discover_requested and callable(live_emit):
        live_emit([f"AIRFLOW\t{ctx.host}\t{int(ctx.port)}\t [*] Discover Secrets"])

    def _on_finding(finding: dict[str, Any]) -> None:
        if not callable(live_emit):
            return
        place = str(finding.get("place") or _legacy_discovery_place(finding))
        live_emit(
            [
                format_discovery_finding_line(
                    "AIRFLOW",
                    ctx.host,
                    ctx.port,
                    severity=finding.get("confidence"),
                    finding_type=finding.get("type"),
                    value=finding.get("value") or finding.get("masked_value"),
                    place=place,
                )
            ]
        )

    report = (
        discover_task_logs(client, generation, config, on_finding=_on_finding)
        if callable(live_emit)
        else discover_task_logs(client, generation, config)
    )
    merged["discover_report"] = report
    if show_keys_requested:
        raw_variable_keys = report.get("variable_keys")
        all_keys: list[Any] = raw_variable_keys if isinstance(raw_variable_keys, list) else []
        shown_keys = all_keys if show_keys_limit is None else all_keys[:show_keys_limit]
        merged["variable_keys"] = shown_keys
        merged["variable_keys_count"] = len(shown_keys)
        merged["variable_keys_total"] = len(all_keys)
        merged["variable_keys_truncated"] = show_keys_limit is not None and len(all_keys) > show_keys_limit
        if report.get("variables_error"):
            merged["variable_keys_error"] = report["variables_error"]
    if show_connections_requested:
        connections = list_connections(client, generation, limit=show_connections_limit)
        merged["airflow_connections"] = connections["connections"]
        merged["airflow_connections_count"] = connections["count"]
        merged["airflow_connections_total"] = connections["total"]
        merged["airflow_connections_truncated"] = connections["truncated"]
        if connections.get("error"):
            merged["connections_error"] = connections["error"]
    if callable(live_emit):
        merged["_discover_findings_streamed"] = True
    return merged


def _legacy_discovery_place(finding: dict[str, Any]) -> str:
    return (
        f"{finding.get('dag_id', '?')}/{finding.get('dag_run_id', '?')}/"
        f"{finding.get('task_id', '?')}/try:{finding.get('try_number', '?')}"
        f"/map:{finding.get('map_index', -1)}{finding.get('object_path', '$')}"
    )


def _build_credential_candidates(
    username: str | None, password: str | None, defcreds: bool
) -> list[tuple[str, str, str]]:
    candidates: list[tuple[str, str, str]] = []
    seen: set[tuple[str, str]] = set()
    if password is not None:
        user = (username or "").strip()
        candidates.append((user, password, "provided"))
        seen.add((user, password))
    if defcreds:
        for user, pw in _DEFAULT_CREDENTIALS:
            if (user, pw) in seen:
                continue
            seen.add((user, pw))
            candidates.append((user, pw, "default"))
    return candidates


__all__ = [
    "detect_airflow",
    "classify_anonymous",
    "verify_credential",
    "classify_capabilities",
    "detect_record",
    "auth_record",
    "capabilities_record",
    "discover_record",
    "AirflowLifecycleState",
    "airflow_lifecycle_state_factory",
    "host_stage",
]
