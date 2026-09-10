"""Airflow detection / anonymous / auth / role actions (REST API, read-only)."""

from __future__ import annotations

from typing import Any

from ...clients.airflow_api import AirflowClient, AirflowResponse
from ...clients.http_session import HttpSessionPool
from .types import AirflowDetection, AnonymousResult, CredentialResult, RoleCapability

# Модуль использует detect/auth хуки, а не монолитный host_stage; None корректно и
# удовлетворяет architecture-guard (наличие имени `host_stage = `).
host_stage = None

# Per-generation endpoint map. `/version` and `/health` are Public (no auth), so
# detection + version + generation come from one unauthenticated probe.
_ENDPOINTS = {
    "v1": {  # Airflow 2.x
        "version": "/api/v1/version",
        "health": "/api/v1/health",
        "viewer": "/api/v1/dags",
        "op": "/api/v1/pools",
        "admin": "/api/v1/eventLogs",
    },
    "v2": {  # Airflow 3.x
        "version": "/api/v2/version",
        "health": "/api/v2/monitor/health",
        "viewer": "/api/v2/dags",
        "op": "/api/v2/pools",
        "admin": "/api/v2/eventLogs",
    },
}
_AUTH_TOKEN_PATH = "/auth/token"  # Airflow 3.x JWT exchange
_ROLE_RUNGS = ("viewer", "op", "admin")

_DEFAULT_CREDENTIALS: tuple[tuple[str, str], ...] = (
    ("airflow", "airflow"),  # real Airflow default
    ("admin", "admin"),
    ("admin", "airflow"),
    ("airflow", "password"),
    ("admin", "password"),
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


def _looks_like_v1_dag_collection(resp: AirflowResponse) -> bool:
    data = resp.json()
    if not isinstance(data, dict) or not isinstance(data.get("dags"), list):
        return False
    total_entries = data.get("total_entries")
    return isinstance(total_entries, int) and not isinstance(total_entries, bool) and total_entries >= 0


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
    """Unauthenticated role ladder: viewer -> op -> admin. The highest rung that
    returns 200 is the anonymous role; a 401/403 on the lowest rung means auth is
    enforced."""
    endpoints = _ENDPOINTS.get(generation, _ENDPOINTS["v1"])
    viewer = client.get(endpoints["viewer"], authed=False)
    if viewer.transport_error:
        return AnonymousResult(reachable=False)
    if viewer.http_status in {401, 403}:
        return AnonymousResult(reachable=True, auth_required=True, role="none")
    if viewer.http_status != 200:
        return AnonymousResult(reachable=True, auth_required=None, role="unknown")
    role = "viewer"
    for rung in ("op", "admin"):
        resp = client.get(endpoints[rung], authed=False)
        if not resp.transport_error and resp.http_status == 200:
            role = rung
    return AnonymousResult(reachable=True, auth_required=False, role=role)


# --- credentials -----------------------------------------------------------


def verify_credential(pool_client_factory: Any, generation: str, username: str, password: str) -> CredentialResult:
    """Verify one credential for the pinned generation.

    2.x: HTTP Basic against a Viewer endpoint (200 valid / 401 invalid / 403
    valid_but_restricted). 3.x: POST /auth/token (200 + access_token valid / 401
    invalid); the issued JWT is kept for the role probe.
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
    resp = client.get(_ENDPOINTS["v1"]["viewer"], authed=True)
    if resp.transport_error:
        return CredentialResult(state="transient_failure", username=username)
    if resp.http_status == 401 and _looks_like_airflow_problem(resp, 401):
        return CredentialResult(state="invalid", username=username, error_code="401")
    if resp.http_status == 403 and _looks_like_airflow_problem(resp, 403):
        return CredentialResult(state="valid_but_restricted", username=username, error_code="403")
    if resp.http_status == 200 and _looks_like_v1_dag_collection(resp):
        return CredentialResult(state="valid", username=username)
    return CredentialResult(state="verification_unavailable", username=username, error_code=str(resp.http_status))


# --- role capability -------------------------------------------------------


def classify_role(client: AirflowClient, generation: str) -> RoleCapability:
    """Authenticated role ladder (viewer -> op -> admin) with the winning credential."""
    endpoints = _ENDPOINTS.get(generation, _ENDPOINTS["v1"])
    states: dict[str, str] = {}
    role = "none"
    reachable_any = False
    for rung in _ROLE_RUNGS:
        resp = client.get(endpoints[rung], authed=True)
        if resp.transport_error:
            states[rung] = "error"
            continue
        states[rung] = str(resp.http_status)
        if resp.http_status == 200:
            reachable_any = True
            role = rung
    if not reachable_any and all(v == "error" for v in states.values()):
        role = "unknown"
    return RoleCapability(role=role, evidence=states)


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
        # An explicit scheme from the target URL is authoritative: never probed,
        # never flipped. Without one, `resolve_scheme` probes from the port guess.
        self.explicit_scheme: str | None = scheme
        self.resolved_scheme: str | None = scheme
        self.bearer_token: str | None = None
        self.pool = HttpSessionPool(
            timeout=float(getattr(args, "timeout", 5.0) or 5.0),
            insecure=True,
            retries=int(getattr(args, "retries", 0) or 0),
        )

    def _probe_scheme(self, scheme: str) -> AirflowResponse:
        client = AirflowClient(self.pool, scheme=scheme, host=self.host, port=self.port)
        return client.get(_ENDPOINTS["v2"]["version"], authed=False)

    def resolve_scheme(self) -> str:
        """Return the transport scheme, honoring an explicit target scheme and
        otherwise probing once from the port heuristic (flipped on a transport
        mismatch or a plaintext ``400`` whose body says the server expected TLS)."""
        if self.resolved_scheme is not None:
            return self.resolved_scheme
        guess = "https" if self.port in {443, 8443} else "http"
        resp = self._probe_scheme(guess)
        mismatch = bool(resp.transport_error and _transport_mismatch(guess, resp.transport_error))
        tls_required = guess == "http" and resp.http_status == 400 and b"https" in (resp.body or b"").lower()
        if mismatch or tls_required:
            guess = "http" if guess == "https" else "https"
        self.resolved_scheme = guess
        return guess

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
    else:
        scheme = "https" if int(ctx.port) in {443, 8443} else "http"
        pool = HttpSessionPool(timeout=float(getattr(ctx.args, "timeout", 5.0) or 5.0), insecure=True)
    return AirflowClient(
        pool,
        scheme=scheme,
        host=str(ctx.host),
        port=int(ctx.port),
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
        record["anonymous_role"] = anon.role
        record["auth_required"] = anon.auth_required
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
    anonymous_role = str(prior.get("anonymous_role") or "").strip().lower()
    anonymous_open = prior.get("auth_required") is False or anonymous_role not in {"", "none", "unknown"}
    credential_state = result.state
    error_code = result.error_code
    if anonymous_open and credential_state in {"valid", "valid_but_restricted"}:
        credential_state = "verification_unavailable"
        error_code = "anonymous_access_already_succeeded"
    merged["credential_state"] = credential_state
    merged["credential_results"] = [{"username": result.username, "state": credential_state, "error_code": error_code}]
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
        return merged
    generation = str(prior.get("api_generation") or "v1")
    credential = ctx.credential
    if generation == "v2":
        state = getattr(ctx, "lifecycle_state", None)
        token = state.bearer_token if isinstance(state, AirflowLifecycleState) else None
        client = _client_for(ctx, bearer_token=token)
    else:
        client = _client_for(
            ctx, basic_user=getattr(credential, "username", None), basic_password=getattr(credential, "password", None)
        )
    cap = classify_role(client, generation)
    merged["role"] = cap.role
    merged["role_evidence"] = cap.evidence
    return merged


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
    "classify_role",
    "detect_record",
    "auth_record",
    "capabilities_record",
    "AirflowLifecycleState",
    "airflow_lifecycle_state_factory",
    "host_stage",
]
