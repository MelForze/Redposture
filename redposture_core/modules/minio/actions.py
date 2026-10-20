"""MinIO detection / anonymous / auth-verification actions."""

from __future__ import annotations

import base64
import json
import re
import time
from collections.abc import Callable, Iterable
from dataclasses import replace
from typing import Any
from urllib.parse import quote, quote_plus, urlsplit
from xml.etree import ElementTree

from ...clients.http_api import http_response_requires_https
from ...clients.http_session import HttpSessionPool
from ...clients.minio_api import MinioClient, MinioResponse
from .types import AdminCapability, AnonymousResult, CredentialResult, MinioDetection

# `Server: MinIO/RELEASE.2021-06-17T00-10-46Z` on older deployments; modern ones
# return a bare `Server: MinIO` and the version is only in the Admin API.
_SERVER_VERSION_RE = re.compile(r"MinIO/(\S+)", re.IGNORECASE)


def _server_header_version(resp: MinioResponse) -> str | None:
    server = next((str(value) for key, value in resp.headers.items() if str(key).lower() == "server"), "")
    match = _SERVER_VERSION_RE.search(server)
    return match.group(1) if match else None


def _admin_info_version(resp: MinioResponse) -> str | None:
    """MinIO version from an authenticated `admin/v3/info` response.

    Newer MinIO nests the release under `servers[].version`; older builds expose a
    top-level `version`. Both are handled.
    """
    if resp.transport_error or resp.http_status != 200:
        return None
    try:
        data = json.loads(resp.body or b"")
    except (ValueError, TypeError):
        return None
    if not isinstance(data, dict):
        return None
    servers = data.get("servers")
    if isinstance(servers, list):
        for server in servers:
            if isinstance(server, dict) and server.get("version"):
                return str(server["version"])
    version = data.get("version")
    return str(version) if version else None


# Модуль использует detect/auth хуки, а не монолитный host_stage. Значение None
# корректно (runner в stage_runtime.py при host_stage=None + detect/auth идёт по
# staged-пути), и наличие имени `host_stage = ` удовлетворяет architecture-guard
# (tests/test_architecture_guards.py::test_module_actions_are_typed_hook_facades).
host_stage = None

_MINIO_REAL_DEFAULT_CREDENTIALS: tuple[tuple[str, str], ...] = (("minioadmin", "minioadmin"),)
_MINIO_HEURISTIC_DEFAULT_CREDENTIALS: tuple[tuple[str, str], ...] = (
    ("minio", "minio123"),
    ("minioadmin", "minio123"),
    ("minioadmin", "password"),
    ("minioadmin", "12345678"),
    ("admin", "admin"),
    ("admin", "minioadmin"),
    ("admin", "password"),
    ("root", "minioadmin"),
    ("root", "password"),
    ("minio", "minio"),
    ("access", "secret"),
)
_MINIO_DEFAULT_CREDENTIALS: tuple[tuple[str, str], ...] = (
    _MINIO_REAL_DEFAULT_CREDENTIALS + _MINIO_HEURISTIC_DEFAULT_CREDENTIALS
)


def _has_s3_xml_shape(body: bytes) -> bool:
    try:
        root = ElementTree.fromstring(body)
    except (ElementTree.ParseError, ValueError, LookupError):
        return False
    for namespace in ("", "{http://s3.amazonaws.com/doc/2006-03-01/}"):
        if root.tag in {f"{namespace}ListAllMyBucketsResult", f"{namespace}ListBucketResult"}:
            return True
        if root.tag == f"{namespace}Error":
            code = root.findtext(f"{namespace}Code", "").strip()
            return bool(re.fullmatch(r"[A-Za-z][A-Za-z0-9:._-]*", code))
    return False


def _has_s3_shape(resp: MinioResponse) -> bool:
    if resp.transport_error or resp.truncated:
        return False
    if resp.error is not None and resp.error.code:
        return True
    return _has_s3_xml_shape(resp.body or b"")


def _server_is_minio(resp: MinioResponse) -> bool:
    server = next((v for k, v in resp.headers.items() if k.lower() == "server"), "")
    return "minio" in str(server).lower()


_MINIO_CONSOLE_TITLE_RE = re.compile(rb"<title\b[^>]*>\s*MinIO\s+Console\b", re.I)
_CONSOLE_API_CANDIDATE_PORTS = (9000,)


def _http_origin(url: str | None) -> tuple[str, str, int] | None:
    if not url:
        return None
    try:
        parsed = urlsplit(url)
        scheme = parsed.scheme.lower()
        if scheme not in {"http", "https"} or not parsed.hostname:
            return None
        return scheme, parsed.hostname, parsed.port or (443 if scheme == "https" else 80)
    except ValueError:
        return None


def _origin_url(url: str | None) -> str | None:
    origin = _http_origin(url)
    if origin is None:
        return None
    scheme, host, port = origin
    authority = f"[{host}]" if ":" in host else host
    return f"{scheme}://{authority}:{port}"


def _is_minio_console(resp: MinioResponse) -> bool:
    """True when the endpoint serves the MinIO Console SPA (an HTML page titled
    ``MinIO Console``) rather than the S3/Admin API. The console proves a MinIO
    deployment is present but carries no S3 verifier, so credentials are never
    replayed against it."""
    if resp.transport_error or resp.http_status != 200:
        return False
    return bool(_MINIO_CONSOLE_TITLE_RE.search(resp.body or b""))


def _is_s3_request_on_console_port(resp: MinioResponse) -> bool:
    """MinIO Console's canonical response to a signed S3 request."""
    if resp.transport_error or resp.error is None:
        return False
    code = str(resp.error.code or "").strip().lower()
    message = re.sub(r"\s+", " ", str(resp.error.message or "")).strip().lower().rstrip(".")
    return code == "invalidargument" and message == "s3 api requests must be made to api port"


def _health_live(resp: MinioResponse) -> bool:
    # MinIO's live probe has an empty body. A login page or catch-all JSON/XML
    # returned with HTTP 200 is not an independent health signal.
    return not resp.transport_error and not resp.truncated and resp.http_status in {200, 204} and not resp.body.strip()


def _admin_plane(resp: MinioResponse) -> bool:
    if resp.transport_error or resp.truncated:
        return False
    if resp.http_status == 404:
        return False
    return _has_s3_shape(resp) or (resp.http_status == 200 and _is_admin_info_response(resp.body))


def detect_minio(client: MinioClient) -> MinioDetection:
    root = client.get_service_root(signed=False)
    if root.transport_error:
        return MinioDetection(
            status="transport_failure",
            api_endpoint=client.base_url,
            evidence={"transport_error": root.transport_error},
        )
    health = client.health("live")
    admin = client.admin_info(signed=False)

    root_console = _is_minio_console(root)
    # An unsigned GET / on the S3 listener may redirect to the Console. The
    # Admin API's S3-shaped denial plus the MinIO health endpoint still verify
    # that the *source* listener serves the API.
    admin_s3_shape = _has_s3_shape(admin)
    s3_shape = _has_s3_shape(root) or (root_console and admin_s3_shape and _health_live(health))
    server_minio = _server_is_minio(root)
    health_ok = _health_live(health)
    admin_ok = _admin_plane(admin)

    evidence = {
        "s3_shape": s3_shape,
        "admin_s3_shape": admin_s3_shape,
        "server_minio": server_minio,
        "health_live": health_ok,
        "admin_plane": admin_ok,
        "root_status": root.http_status,
        # Unauthenticated version fallback (older MinIO exposes it in Server:);
        # the authoritative value comes from the Admin API once authenticated.
        "server_version": _server_header_version(root),
    }

    # A generic S3 server/gateway can deny EVERY path, including /minio/admin/.
    # Treat Admin as an independent product signal only for typed server info,
    # or its JSON error envelope alongside the distinct S3 XML root surface.
    independent_admin = admin_ok and (
        _is_admin_info_response(admin.body)
        or (admin.error is not None and admin.body.lstrip().startswith(b"{") and _has_s3_xml_shape(root.body))
    )
    if s3_shape and (health_ok or server_minio or independent_admin):
        return MinioDetection(
            status="confirmed",
            api_endpoint=client.base_url,
            console_endpoint=_origin_url(root.final_url) if root_console else None,
            evidence=evidence,
        )
    if root_console:
        # Console-only exposure: MinIO is present, but the S3 API is not reachable
        # here. Report the console endpoint and leave the S3 API unverified.
        evidence["console"] = True
        return MinioDetection(
            status="console", console_endpoint=_origin_url(root.final_url) or client.base_url, evidence=evidence
        )
    status = "probable" if s3_shape else "not_minio"
    return MinioDetection(status=status, api_endpoint=client.base_url, evidence=evidence)


def _parse_bucket_names(body: bytes) -> tuple[str, ...]:
    try:
        root = ElementTree.fromstring(body)
    except ElementTree.ParseError:
        return ()
    names: list[str] = []
    for elem in root.iter():
        if elem.tag.split("}")[-1] == "Name":
            text = (elem.text or "").strip()
            if text:
                names.append(text)
    return tuple(names)


def classify_anonymous(client: MinioClient, *, known_bucket: str | None = None) -> AnonymousResult:
    root = client.get_service_root(signed=False)
    if root.transport_error:
        return AnonymousResult(api_reachable=False, classification="verification_unavailable")

    if root.http_status == 200 and b"ListAllMyBucketsResult" in (root.body or b""):
        buckets = _parse_bucket_names(root.body or b"")
        return AnonymousResult(api_reachable=True, classification="anonymous_list_ok", buckets=buckets)

    if root.error is not None and root.error.code in {"AccessDenied", "InvalidAccessKeyId"}:
        classification = "authentication_required"
    elif root.http_status in {401, 403}:
        classification = "authentication_required"
    elif root.http_status == 404 or (root.error is not None and root.error.code in {"NoSuchBucket", "NoSuchKey"}):
        classification = "not_found"
    else:
        classification = "access_denied" if root.http_status >= 400 else "verification_unavailable"

    read_probe: str | None = None
    if known_bucket:
        listing = client.list_objects_v2(known_bucket, max_keys=1, signed=False)
        if listing.transport_error:
            read_probe = None
        elif listing.http_status == 200:
            read_probe = "anonymous_read_ok"
        elif listing.error is not None and listing.error.code in {"NoSuchBucket", "NoSuchKey"}:
            read_probe = "not_found"
        elif listing.http_status in {401, 403}:
            read_probe = "access_denied"

    return AnonymousResult(api_reachable=True, classification=classification, read_probe=read_probe)


_INVALID_CRED_CODES = {"SignatureDoesNotMatch", "InvalidAccessKeyId", "AccessKeyDisabled"}


def _is_service_bucket_listing(body: bytes) -> bool:
    """Require the ListBuckets response structure, including an empty bucket list."""
    try:
        root = ElementTree.fromstring(body)
    except (ElementTree.ParseError, ValueError, LookupError):
        return False
    for namespace in ("", "{http://s3.amazonaws.com/doc/2006-03-01/}"):
        if root.tag == f"{namespace}ListAllMyBucketsResult":
            return root.find(f"{namespace}Buckets") is not None
    return False


def _is_admin_info_response(body: bytes) -> bool:
    try:
        data = json.loads(body)
    except (ValueError, TypeError):
        return False
    return isinstance(data, dict) and isinstance(data.get("servers"), list)


def _signed_credential_verdict(
    resp: MinioResponse,
    access_key: str | None,
    *,
    admin: bool = False,
    expected_shape: Callable[[bytes], bool] | None = None,
) -> CredentialResult:
    if resp.transport_error:
        return CredentialResult(state="transient_failure", access_key=access_key)
    if 200 <= resp.http_status < 300:
        shape = expected_shape or (_is_admin_info_response if admin else _is_service_bucket_listing)
        state = (
            "valid"
            if resp.http_status == 200 and not resp.truncated and shape(resp.body)
            else "verification_unavailable"
        )
        return CredentialResult(state=state, access_key=access_key)
    code = resp.error.code if resp.error is not None else ""
    if code in _INVALID_CRED_CODES:
        return CredentialResult(state="invalid", access_key=access_key, error_code=code)
    if code == "AccessDenied":
        # MinIO checked the signature before denying this read-only operation.
        return CredentialResult(state="valid_but_restricted", access_key=access_key, error_code=code)
    return CredentialResult(state="verification_unavailable", access_key=access_key, error_code=code or None)


def _credential_probe_debug(
    client: MinioClient,
    probe: str,
    resp: MinioResponse,
    result: CredentialResult,
    debug_emit: Callable[[str], None] | None,
) -> None:
    if debug_emit is None:
        return

    def safe(value: Any, limit: int = 256) -> str:
        text = str(value or "-")
        for secret in (getattr(client, "secret_key", None), getattr(client, "session_token", None)):
            if secret:
                for variant in {str(secret), quote(str(secret), safe=""), quote_plus(str(secret))}:
                    text = text.replace(variant, "<redacted>")
        # JSON quoting keeps embedded newlines, terminal escapes and proxy error
        # pages on a single diagnostic line. Never log request auth headers.
        return json.dumps(text[:limit], ensure_ascii=True)

    content_type = next((v for k, v in resp.headers.items() if k.lower() == "content-type"), "-")
    details = (
        f"minio auth probe={probe} HTTP={resp.http_status} content_type={safe(content_type, 80)} "
        f"s3_code={safe(resp.error.code if resp.error else None, 80)} verdict={result.state} "
        f"final_url={safe(resp.final_url or resp.request_url)} truncated={resp.truncated}"
    )
    if resp.transport_error:
        details += f" transport_error={safe(resp.transport_error)}"
    elif result.state == "verification_unavailable":
        details += f" body={safe(resp.body.decode('utf-8', errors='replace'))}"
    debug_emit(details)


def _credential_account_shape(body: bytes) -> bool:
    payload = _json_object(body)
    if payload is not None:
        # madmin.AccountInfo uses exported Go names in released MinIO builds;
        # accept the lower-camel variant too, with the same typed fields.
        payload = {str(key).lower(): value for key, value in payload.items()}
    return bool(
        payload
        and isinstance(payload.get("accountname"), str)
        and payload["accountname"]
        and isinstance(payload.get("policy"), dict)
        and isinstance(payload.get("server"), dict)
        and (payload.get("buckets") is None or isinstance(payload.get("buckets"), list))
    )


def _bucket_location_shape(body: bytes) -> bool:
    try:
        root = ElementTree.fromstring(body)
    except (ElementTree.ParseError, ValueError, LookupError):
        return False
    return root.tag in {
        "LocationConstraint",
        "{http://s3.amazonaws.com/doc/2006-03-01/}LocationConstraint",
    } and not len(root)


def verify_credential(
    client: MinioClient,
    *,
    known_bucket: str | None = None,
    debug_emit: Callable[[str], None] | None = None,
) -> CredentialResult:
    access_key = getattr(client, "access_key", None)

    def probe(
        name: str, operation: Callable[..., MinioResponse], shape: Callable[[bytes], bool], *, signed: bool = True
    ) -> CredentialResult:
        response = operation(signed=signed)
        verdict = _signed_credential_verdict(response, access_key, expected_shape=shape)
        debug_result = verdict
        if not signed and verdict.state in {"valid", "valid_but_restricted", "invalid"}:
            # An unsigned AccessDenied says nothing about the candidate secret.
            debug_result = replace(
                verdict, state="anonymous_access" if verdict.state == "valid" else "anonymous_denied"
            )
        _credential_probe_debug(client, name, response, debug_result, debug_emit)
        return verdict

    result = probe("s3_root", client.get_service_root, _is_service_bucket_listing)
    if result.state in {"valid", "valid_but_restricted", "invalid", "transient_failure"}:
        return result
    if callable(getattr(client, "admin_info", None)):
        result = probe("admin_info", client.admin_info, _is_admin_info_response)
        if result.state in {"valid", "valid_but_restricted", "invalid"}:
            return result

    fallbacks: list[tuple[str, Callable[..., MinioResponse], Callable[[bytes], bool]]] = []
    if callable(getattr(client, "account_info", None)):
        fallbacks.append(("account_info", client.account_info, _credential_account_shape))
    if known_bucket and callable(getattr(client, "bucket_location", None)):
        fallbacks.append(
            ("bucket_location", lambda **kw: client.bucket_location(known_bucket, **kw), _bucket_location_shape)
        )
    for name, operation, shape in fallbacks:
        result = probe(name, operation, shape)
        if result.state == "invalid":
            return result
        if result.state not in {"valid", "valid_but_restricted"}:
            continue
        # Public buckets and gateway caches can return the same well-formed
        # data for any secret. Require rejection of a deliberately bad signature
        # on the SAME endpoint before claiming the candidate is authenticated.
        probe(name + "_anonymous_control", operation, shape, signed=False)
        control_client = client.invalid_signature_client()
        control_operation = (
            control_client.account_info
            if name == "account_info"
            else lambda control_client=control_client, **kw: control_client.bucket_location(str(known_bucket), **kw)
        )
        control = probe(name + "_invalid_signature_control", control_operation, shape)
        if control.state == "invalid":
            # These operations don't prove permission to list all buckets.
            return CredentialResult(state="valid_but_restricted", access_key=access_key)
        result = CredentialResult(
            state="verification_unavailable", access_key=access_key, error_code="signature_control_inconclusive"
        )
        if debug_emit is not None:
            debug_emit(
                f"minio auth probe={name} verdict=verification_unavailable reason=signature_control_inconclusive"
            )
    return result


def _json_object(body: bytes) -> dict[str, Any] | None:
    try:
        payload = json.loads(body or b"")
    except (ValueError, TypeError):
        return None
    return payload if isinstance(payload, dict) else None


def _account_info_shape(body: bytes) -> bool:
    payload = _json_object(body)
    if payload is None:
        return False
    markers = {"accountname", "policy", "buckets", "server"}
    return any(str(key).lower() in markers for key in payload)


def _users_shape(body: bytes) -> bool:
    payload = _json_object(body)
    return payload is not None and all(isinstance(value, dict) for value in payload.values())


def _policies_shape(body: bytes) -> bool:
    payload = _json_object(body)
    return payload is not None and all(isinstance(value, dict) for value in payload.values())


def _probe_state(resp: MinioResponse, expected_shape: Callable[[bytes], bool]) -> str:
    if resp.transport_error:
        return "unknown"
    if 200 <= resp.http_status < 300:
        return "ok" if expected_shape(resp.body or b"") else "unknown"
    if resp.error is not None and resp.error.code in {"AccessDenied", "AccessKeyDisabled"}:
        return "denied"
    if resp.http_status in {401, 403}:
        return "denied"
    return "unknown"


def _looks_admin_policy(body: bytes) -> bool:
    lowered = (body or b"").lower()
    return b"admin:" in lowered or b"consoleadmin" in lowered or b'"action":["*"]' in lowered.replace(b" ", b"")


def classify_admin_capability(client: Any) -> AdminCapability:
    """Read-only admin capability probe: accountinfo + list-users + list-policies."""
    account = client.account_info(signed=True)
    users = client.list_users(signed=True)
    policies = client.list_canned_policies(signed=True)
    states = {
        "accountinfo": _probe_state(account, _account_info_shape),
        "list_users": _probe_state(users, _users_shape),
        "list_canned_policies": _probe_state(policies, _policies_shape),
    }
    admin_probes = [states["list_users"], states["list_canned_policies"]]
    ok_admin = sum(1 for state in admin_probes if state == "ok")
    denied_admin = sum(1 for state in admin_probes if state == "denied")

    if all(state == "unknown" for state in states.values()):
        capability = "unknown"
    elif ok_admin >= 2:
        capability = "confirmed"
    elif ok_admin >= 1:
        capability = "partial"
    elif denied_admin >= 1 and states["accountinfo"] in {"ok", "denied"}:
        capability = "not_confirmed"
    else:
        capability = "unknown"

    identity_kind = "unknown"
    if states["accountinfo"] == "ok":
        # An admin-equivalent policy on the caller is reported `delegated_admin`.
        # `accountinfo` always names the caller's own account, so it cannot by
        # itself distinguish the built-in root from a named user attached to
        # consoleAdmin — root vs delegated is a Phase-4 lab-calibration item, and
        # we never over-claim root from broad access.
        identity_kind = "delegated_admin" if _looks_admin_policy(account.body or b"") else "s3_user"

    return AdminCapability(capability=capability, identity_kind=identity_kind, evidence=states)


# Ports whose scheme is guessed as HTTPS before probing (the guess is a starting
# point; `resolve_scheme` flips it if the live transport disagrees).
_TLS_PORTS = frozenset({443, 10443, 20443})

# Transport-error signatures that mean "the scheme I tried is wrong". When we
# spoke TLS to a plaintext server the SSL layer reports a bad record/version;
# when we spoke plaintext to a TLS server http.client cannot parse the TLS alert
# and reports a truncated/aborted response. Matched case-insensitively.
_HTTPS_ON_PLAINTEXT = ("wrong_version_number", "record layer", "unknown protocol", "sslv3_alert", "http_request")
_HTTP_ON_TLS = ("badstatusline", "remotedisconnected", "connectionreset", "connection reset", "reset by peer")


def _transport_mismatch(scheme: str, transport_error: str) -> bool:
    """True when `transport_error` indicates the opposite scheme should be used."""
    err = transport_error.lower()
    markers = _HTTPS_ON_PLAINTEXT if scheme == "https" else _HTTP_ON_TLS
    return any(marker in err for marker in markers)


_WRITE_PROBE_BODY = b"redposture-write-probe"
_WRITE_DENIED_CODES = {"AccessDenied", "SignatureDoesNotMatch", "InvalidAccessKeyId"}


def probe_write_capability(client: MinioClient, buckets: Any) -> tuple[dict[str, Any], list[dict[str, str]]]:
    """Active write-probe (opt-in, mutating): PUT a random canary object into each
    bucket, read the exact canary back, then immediately DELETE it to roll back.

    Returns ``(per_bucket, leftovers)`` where per_bucket maps a bucket to
    ``{"write": True/False/"unknown", "cleanup": "ok"/"failed"/"unknown", "leftover": key?}``
    and leftovers lists canaries whose rollback DELETE failed (so the operator can
    remove them). A 403/AccessDenied on PUT means write is denied; the object was
    never created, so no DELETE is attempted.
    """
    import secrets

    per_bucket: dict[str, Any] = {}
    leftovers: list[dict[str, str]] = []
    for bucket in buckets:
        key = f".redposture-probe-{secrets.token_hex(8)}"
        put = client.put_object(bucket, key, _WRITE_PROBE_BODY, signed=True)
        if put.transport_error:
            per_bucket[bucket] = {"write": "unknown"}
            continue
        if put.http_status in {200, 201, 204}:
            verify = client.get_object(bucket, key, max_bytes=len(_WRITE_PROBE_BODY) + 1, signed=True)
            write_confirmed = (
                not verify.transport_error and verify.http_status in {200, 206} and verify.body == _WRITE_PROBE_BODY
            )
            entry: dict[str, Any] = {"write": True if write_confirmed else "unknown"}
            delete = client.delete_object(bucket, key, signed=True)
            rolled_back = not delete.transport_error and delete.http_status in {200, 202, 204}
            if rolled_back:
                entry["cleanup"] = "ok" if write_confirmed else "unknown"
            else:
                entry["cleanup"] = "failed"
                entry["leftover"] = key
                leftovers.append({"bucket": bucket, "key": key})
            per_bucket[bucket] = entry
        elif put.http_status in {401, 403} or (put.error is not None and put.error.code in _WRITE_DENIED_CODES):
            per_bucket[bucket] = {"write": False}
        else:
            per_bucket[bucket] = {"write": "unknown"}
    return per_bucket, leftovers


class MinioLifecycleState:
    """Holds one HttpSessionPool per target lifecycle (pool reuse) and the
    transport scheme resolved for that target (probed once, then cached).

    Certificates are always accepted (``insecure=True``): this is an audit tool
    that inspects exposure rather than establishing trust, so a self-signed or
    otherwise untrusted TLS endpoint must never abort the scan.
    """

    def __init__(self, args: Any, host: str, port: int, *, scheme: str | None = None, base_path: str = "") -> None:
        self.host = str(host)
        self.port = int(port)
        if scheme not in {None, "http", "https"}:
            raise ValueError("minio supports HTTP/HTTPS targets only")
        # HTTPS targets can be used immediately. HTTP is treated as the preferred
        # starting scheme: an unsigned probe may reveal that the endpoint redirects
        # to HTTPS, which must be cached before SigV4 credentials are sent.
        self.explicit_scheme: str | None = scheme
        self.resolved_scheme: str | None = "https" if scheme == "https" else None
        self.resolved_host = self.host
        self.resolved_port = self.port
        self.base_path = base_path
        self._https_probe_attempted = False
        self.pool = HttpSessionPool(
            timeout=float(getattr(args, "timeout", 5.0) or 5.0),
            insecure=True,
            retries=int(getattr(args, "retries", 0) or 0),
            max_idle_per_origin=8 if bool(getattr(args, "discover", False)) else 4,
        )

    def _probe(self, scheme: str) -> MinioResponse:
        client = MinioClient(
            self.pool,
            scheme=scheme,
            host=self.resolved_host,
            port=self.resolved_port,
            base_path=self.base_path,
        )
        return client.get_service_root(signed=False)

    def _remember_origin(self, url: str | None) -> str | None:
        origin = _http_origin(url)
        if origin is None:
            return None
        scheme, host, port = origin
        self.resolved_host = host
        self.resolved_port = port
        return scheme

    def _remember_final_origin(self, resp: MinioResponse) -> str | None:
        return self._remember_origin(resp.final_url)

    def resolve_scheme(self) -> str:
        """Return the transport scheme for this target, probing once and caching.

        An explicit ``http`` is a starting preference rather than a lock. If its
        unsigned probe is redirected to HTTPS, subsequent detection and signed
        credential requests start directly on HTTPS. The port heuristic remains
        the starting point for bare targets. Transport mismatches and plaintext
        ``400`` responses that require TLS also flip the scheme.
        """
        if self.resolved_scheme is not None:
            return self.resolved_scheme
        guess = self.explicit_scheme or ("https" if self.port in _TLS_PORTS else "http")
        resp = self._probe(guess)
        if _is_minio_console(resp) and resp.redirect_history:
            # The final URL is a web UI, not an S3 origin. Retain the listener
            # that issued the final redirect. A same-host, same-port HTTPS
            # upgrade is still a transport change worth probing before making
            # that distinction.
            source = _http_origin(resp.redirect_history[-1])
            final = _http_origin(resp.final_url)
            selected = (
                resp.final_url
                if source and final and source[1:] == final[1:] and source[0] != final[0]
                else resp.redirect_history[-1]
            )
            self.resolved_scheme = self._remember_origin(selected) or guess
            return self.resolved_scheme
        final_scheme = self._remember_final_origin(resp)
        if resp.redirect_history and resp.final_url and _has_s3_shape(resp):
            # Only an S3-shaped final response can establish the mounted API
            # path. A console/SSO redirect must not become the signed origin.
            self.base_path = (urlsplit(resp.final_url).path or "/").rstrip("/")
        mismatch = bool(resp.transport_error and _transport_mismatch(guess, resp.transport_error))
        tls_required = guess == "http" and http_response_requires_https(resp.http_status, resp.body)
        if final_scheme in {"http", "https"} and final_scheme != guess:
            guess = final_scheme
        elif mismatch or tls_required:
            guess = "http" if guess == "https" else "https"
        elif guess == "http" and _is_minio_console(resp) and self.try_https_upgrade():
            return "https"
        self.resolved_scheme = guess
        return guess

    def find_api_for_console(self, console_endpoint: str | None) -> MinioDetection | None:
        """Try the conventional S3 port on the same host using unsigned requests."""
        for port in _CONSOLE_API_CANDIDATE_PORTS:
            if port == self.resolved_port and self.host == self.resolved_host:
                continue
            first_scheme = self.resolved_scheme or self.explicit_scheme or "http"
            for scheme in (first_scheme, "https" if first_scheme == "http" else "http"):
                client = MinioClient(self.pool, scheme=scheme, host=self.host, port=port)
                detection = detect_minio(client)
                if detection.status != "confirmed":
                    continue
                self.resolved_scheme = scheme
                self.resolved_host = self.host
                self.resolved_port = port
                # The alternate API listener is addressed directly, without
                # the reverse-proxy mount used by the console URL.
                self.base_path = ""
                return replace(detection, console_endpoint=console_endpoint)
        return None

    def try_https_upgrade(self) -> bool:
        """Switch an HTTP lifecycle to HTTPS when HTTPS exposes an S3 endpoint.

        This is also used after an ambiguous signed response. The alternate probe
        is unsigned and runs at most once per target, so ``--defcreds`` does not
        repeat it for every candidate.
        """
        if self.resolved_scheme not in {None, "http"} or self._https_probe_attempted:
            return self.resolved_scheme == "https"
        self._https_probe_attempted = True
        alternate = self._probe("https")
        if _has_s3_shape(alternate):
            self._remember_final_origin(alternate)
            self.resolved_scheme = "https"
            return True
        return False

    def close(self) -> None:
        self.pool.close()


def minio_lifecycle_state_factory(ctx: Any) -> MinioLifecycleState:
    target = getattr(ctx, "target", None)
    scheme = getattr(target, "scheme", None)
    from ...clients.http_api import infer_http_base_path

    base_path = infer_http_base_path(
        str(getattr(target, "path", "") or ""),
        ("/minio/health", "/minio/admin"),
    )
    return MinioLifecycleState(ctx.args, ctx.host, ctx.port, scheme=scheme, base_path=base_path)


def _client_for(ctx: Any, credential: Any) -> MinioClient:
    state = getattr(ctx, "lifecycle_state", None)
    if isinstance(state, MinioLifecycleState):
        scheme = state.resolve_scheme()
        pool = state.pool
        host = state.resolved_host
        port = state.resolved_port
        base_path = state.base_path
    else:
        scheme = "https" if int(ctx.port) in _TLS_PORTS else "http"
        pool = HttpSessionPool(timeout=float(getattr(ctx.args, "timeout", 5.0) or 5.0), insecure=True)
        host = str(ctx.host)
        port = int(ctx.port)
        base_path = ""
    return MinioClient(
        pool,
        scheme=scheme,
        host=host,
        port=port,
        base_path=base_path,
        access_key=getattr(credential, "username", None),
        secret_key=getattr(credential, "password", None),
        session_token=getattr(ctx.args, "session_token", None),
    )


def detect_record(ctx: Any) -> dict[str, Any]:
    client = _client_for(ctx, ctx.credential)
    detection = detect_minio(client)
    state = getattr(ctx, "lifecycle_state", None)
    args = getattr(ctx, "args", None)
    credential = getattr(ctx, "credential", None)
    wants_credentials = bool(
        getattr(args, "defcreds", False)
        or getattr(args, "username", None)
        or (getattr(credential, "username", None) and getattr(credential, "password", None))
    )
    if detection.status == "console" and wants_credentials and isinstance(state, MinioLifecycleState):
        recovered = state.find_api_for_console(detection.console_endpoint)
        if recovered is not None:
            detection = recovered
            client = _client_for(ctx, ctx.credential)
    anon = classify_anonymous(client) if detection.status == "confirmed" else None
    verification_status = "available" if detection.status == "confirmed" else "unavailable"
    status_word = {
        "confirmed": "detected",
        "console": "detected",
        "probable": "probable",
        "not_minio": "not_service",
        "transport_failure": "fail",
    }[detection.status]
    record: dict[str, Any] = {
        "host": str(ctx.host),
        "port": int(ctx.port),
        "is_minio": detection.status in {"confirmed", "console"},
        "status": status_word,
        "detection_status": detection.status,
        "api_endpoint": detection.api_endpoint,
        "console_endpoint": detection.console_endpoint,
        "detection": detection.evidence,
        "credential_verification_status": verification_status,
    }
    if detection.status == "transport_failure":
        # Surface the transport error so the runtime classifies this as a
        # pre-detection operational failure (reported in the no-service summary)
        # rather than a conclusive "no service".
        record["operational_failure"] = True
        transport_error = detection.evidence.get("transport_error")
        if transport_error:
            record["error"] = str(transport_error)
    header_version = detection.evidence.get("server_version")
    if header_version:
        record["version"] = header_version
    if anon is not None:
        record["anonymous"] = anon.classification
        record["auth_required"] = (
            True
            if anon.classification == "authentication_required"
            else False
            if anon.classification == "anonymous_list_ok"
            else None
        )
        # Distinct key from the structured `buckets` list emitted by --show-buckets
        # (data_record) so the JSON `buckets` field is not polymorphic.
        record["anonymous_buckets"] = list(anon.buckets)
    return record


def auth_record(ctx: Any, prior: dict[str, Any]) -> dict[str, Any]:
    credential = ctx.credential
    if not (getattr(credential, "username", None) and getattr(credential, "password", None)):
        return dict(prior)
    client = _client_for(ctx, credential)
    verifier_options: dict[str, Any] = {}
    if getattr(ctx.args, "bucket", None):
        verifier_options["known_bucket"] = ctx.args.bucket
    if bool(getattr(ctx.args, "debug", False)) and callable(getattr(ctx, "debug_emit", None)):
        verifier_options["debug_emit"] = ctx.debug_emit
    result = verify_credential(client, **verifier_options)
    state = getattr(ctx, "lifecycle_state", None)
    if (
        result.state in {"verification_unavailable", "transient_failure"}
        and isinstance(state, MinioLifecycleState)
        and client.scheme == "http"
        and state.try_https_upgrade()
    ):
        client = _client_for(ctx, credential)
        result = verify_credential(client, **verifier_options)
    merged = dict(prior)
    anonymous_open = prior.get("auth_required") is False or str(prior.get("anonymous") or "") in {
        "anonymous_list_ok",
        "anonymous_bucket_read_ok",
    }
    credential_state = result.state
    error_code = result.error_code
    if anonymous_open and credential_state in {"valid", "valid_but_restricted"}:
        credential_state = "verification_unavailable"
        error_code = "anonymous_access_already_succeeded"
    merged["credential_state"] = credential_state
    merged["credential_type"] = "session-token" if getattr(ctx.args, "session_token", None) else "access-key"
    merged["credential_results"] = [
        {"access_key": result.access_key, "state": credential_state, "error_code": error_code}
    ]
    merged["provided_credentials_ok"] = (
        True
        if credential_state in {"valid", "valid_but_restricted"}
        else False
        if credential_state == "invalid"
        else None
    )
    merged["default_credentials"] = (
        getattr(credential, "source", "") == "default" and merged["provided_credentials_ok"] is True
    )
    if merged["provided_credentials_ok"]:
        # TXT-only echo of the accepted secret so the detail line can show the
        # working access-key:secret pair. Redacted from JSON (see stage spec),
        # matching how minio already keeps attempted_credentials out of JSON.
        merged["credential_secret"] = getattr(credential, "password", None)
        # The auth phase can be emitted immediately for --enum-cve/--discover.
        # Probe read-only Admin API access now so that its first result already
        # has a supported admin verdict, then reuse it in capabilities_record.
        try:
            cap = classify_admin_capability(client)
        except Exception as exc:  # a failed Admin API must not erase a verified S3 credential
            cap = AdminCapability(
                capability="unknown",
                identity_kind="unknown",
                evidence={"probe_error": type(exc).__name__},
            )
        merged["admin_capability"] = cap.capability
        merged["identity_kind"] = cap.identity_kind
        merged["admin_evidence"] = cap.evidence
    return merged


def capabilities_record(ctx: Any, prior: dict[str, Any]) -> dict[str, Any]:
    """After a valid credential, probe admin capability (read-only) and summarise perms."""
    merged = dict(prior)
    if str(prior.get("credential_state") or "") not in {"valid", "valid_but_restricted"}:
        return merged
    client = _client_for(ctx, ctx.credential)
    if "admin_capability" not in merged:
        cap = classify_admin_capability(client)
        merged["admin_capability"] = cap.capability
        merged["identity_kind"] = cap.identity_kind
        merged["admin_evidence"] = cap.evidence
    # The Admin API carries the authoritative server version; it overrides any
    # unauthenticated Server-header guess captured at detection time.
    admin_version = _admin_info_version(client.admin_info(signed=True))
    if admin_version:
        merged["version"] = admin_version
    admin_plane = (
        "ok"
        if merged["admin_capability"] in {"confirmed", "partial"}
        else "denied"
        if merged["admin_capability"] == "not_confirmed"
        else "unknown"
    )
    merged["permissions"] = {
        "list_buckets": "ok" if prior.get("credential_state") == "valid" else "unknown",
        "list_objects": "unknown",
        "read_objects": "unknown",
        "write_objects": "unknown",  # not verified without active probe
        "delete_objects": "unknown",
        "admin_plane": admin_plane,
    }
    return merged


def _split_object_ref(ref: Any) -> tuple[str | None, str | None]:
    text = str(ref or "").lstrip("/")
    if "/" not in text:
        return None, None
    bucket, key = text.split("/", 1)
    return (bucket or None), (key or None)


def _object_op_targets(
    client: MinioClient,
    merged: dict[str, Any],
    *,
    object_ref: Any,
    bucket: Any,
    all_buckets: bool = False,
    on_list_error: Callable[[str], None] | None = None,
) -> Iterable[tuple[str, str]] | None:
    """Resolve the (bucket, key) targets for --dump/--download.

    Exactly one source is expected (the CLI already rejects both): ``--object``
    yields the single pair, ``--bucket`` yields every object in that bucket.
    Returns None on an invalid reference (with ``object_op_error`` set)."""
    from . import enumerate as _enum

    if object_ref:
        o_bucket, o_key = _split_object_ref(object_ref)
        if not o_bucket or not o_key:
            merged["object_op_error"] = f"invalid --object '{object_ref}' (expected bucket/key)"
            return None
        return [(o_bucket, o_key)]
    if bucket:
        return (
            (str(obj.bucket), str(obj.key)) for obj in _enum.iter_objects(client, str(bucket), on_error=on_list_error)
        )
    if all_buckets:
        names = (item.name for item in _enum.iter_buckets(client, on_error=on_list_error))
        return (
            (str(obj.bucket), str(obj.key)) for obj in _enum.iter_objects_multi(client, names, on_error=on_list_error)
        )
    merged["object_op_error"] = "specify --object bucket/key or --bucket name for --dump/--download"
    return None


def _run_object_op(
    client: MinioClient,
    merged: dict[str, Any],
    *,
    object_ref: Any,
    bucket: Any,
    want_dump: bool,
    want_download: bool,
    max_bytes: int,
) -> None:
    """--dump / --download for one --object or every object in --bucket.

    Read-only GET, bounded per object by max_bytes. Downloads are written to
    ``./minio-downloads/<endpoint-id>/<bucket-id>/<key-id>``. Existing files
    are preserved with a numeric suffix; hashes retain exact endpoint/key identity."""
    import os

    errors: list[str] = []
    targets = _object_op_targets(
        client,
        merged,
        object_ref=object_ref,
        bucket=bucket,
        all_buckets=(want_dump or want_download) and not object_ref and not bucket,
        on_list_error=errors.append,
    )
    if targets is None:
        return
    # A bucket-wide dump prefixes each object with a `=== bucket/key ===` header so
    # the concatenated content stays legible; a single --object dump does not.
    labeled = not object_ref

    dumps: list[dict[str, Any]] = []
    downloads: list[dict[str, Any]] = []
    bytes_used = 0
    deadline = time.monotonic() + 300.0
    partial = False
    count = 0
    for o_bucket, o_key in targets:
        if count >= 10_000 or bytes_used >= 64 * 1024 * 1024 or time.monotonic() >= deadline:
            partial = True
            break
        count += 1
        resp = client.get_object(o_bucket, o_key, max_bytes=min(max_bytes, 64 * 1024 * 1024 - bytes_used))
        if resp.transport_error:
            errors.append(f"{o_bucket}/{o_key}: transport error")
            continue
        if resp.http_status not in {200, 206}:
            code = resp.error.code if resp.error is not None and resp.error.code else str(resp.http_status)
            errors.append(f"{o_bucket}/{o_key}: {code}")
            continue
        body = resp.body or b""
        bytes_used += len(body)
        if getattr(resp, "truncated", False):
            errors.append(f"{o_bucket}/{o_key}: object exceeds dump byte limit")
            partial = True
            continue
        if want_dump:
            try:
                content = body.decode("utf-8")
                if "\x00" in content:
                    raise UnicodeDecodeError("utf-8", body, 0, 1, "binary NUL")
                value: dict[str, Any] = {"content": content}
            except UnicodeDecodeError:
                value = {"base64": base64.b64encode(body).decode()}
            dumps.append(
                {
                    "bucket": o_bucket,
                    "key": o_key,
                    "size": len(body),
                    **value,
                }
            )
        if want_download:
            from ...download_paths import identity_component, write_unique_file

            root = os.path.join("minio-downloads", identity_component(str(getattr(client, "base_url", "unknown"))))
            dest = os.path.join(root, identity_component(o_bucket), identity_component(o_key))
            try:
                dest = write_unique_file(dest, body)
            except OSError as exc:
                errors.append(f"{o_bucket}/{o_key}: write failed ({exc})")
                continue
            downloads.append({"bucket": o_bucket, "key": o_key, "path": dest, "size": len(body)})

    if dumps:
        merged["object_dumps"] = dumps
        merged["object_dumps_labeled"] = labeled
    if downloads:
        merged["object_downloads"] = downloads
    if errors:
        # Preserve the single-error field for the common one-object case; keep the
        # full list for a bucket-wide op where several objects may fail.
        merged["object_op_error"] = errors[0]
        if len(errors) > 1:
            merged["object_op_errors"] = errors
    if partial or errors:
        merged["object_dump_partial"] = True


def data_record(ctx: Any, prior: dict[str, Any]) -> dict[str, Any]:
    """Optional enumeration + secret discovery + write-probe, only when requested.

    Object listing is unbounded but memory-safe: objects are streamed page by page
    into a temp file of pre-formatted lines (`_stream_lines_file`), which the
    runtime emits and deletes at output time (see the stream-forget design).
    """
    import os
    import tempfile
    from dataclasses import asdict

    from . import discover as _discover
    from . import enumerate as _enum
    from . import render as _render

    if prior.get("credential_state") == "verification_unavailable":
        return dict(prior)

    args = ctx.args
    want_buckets = bool(getattr(args, "show_buckets", False))
    want_objects = bool(getattr(args, "show_objects", False))
    want_discover = bool(getattr(args, "discover", False))
    want_probe = bool(getattr(args, "probe_write", False))
    want_dump = bool(getattr(args, "dump", False))
    want_download = bool(getattr(args, "download", False))
    want_object_op = want_dump or want_download
    if not (want_buckets or want_objects or want_discover or want_probe or want_object_op):
        return dict(prior)

    merged = dict(prior)
    client = _client_for(ctx, ctx.credential)
    bucket = getattr(args, "bucket", None)
    output_format = str(getattr(args, "output_format", "txt") or "txt")

    if want_object_op:
        _run_object_op(
            client,
            merged,
            object_ref=getattr(args, "object", None),
            bucket=bucket,
            want_dump=want_dump,
            want_download=want_download,
            max_bytes=100 * 1024 * 1024,
        )

    listing_errors: list[str] = []
    bucket_infos: list[Any] | None = None
    if want_buckets:
        bucket_infos = list(_enum.iter_buckets(client, on_error=listing_errors.append))
        merged["buckets"] = [asdict(b) for b in bucket_infos]

    target_buckets: list[str] = []
    if want_objects or want_discover or want_probe:
        # A single `--bucket` targets one bucket; otherwise enumerate every listable
        # bucket (reusing the listing already fetched for --show-buckets).
        if bucket:
            target_buckets = [str(bucket)]
        else:
            if bucket_infos is None:
                bucket_infos = list(_enum.iter_buckets(client, on_error=listing_errors.append))
            target_buckets = [b.name for b in bucket_infos]

    if want_probe:
        # Active, mutating write-probe (opt-in): canary PUT immediately rolled back.
        per_bucket, leftovers = probe_write_capability(client, target_buckets)
        merged["write_probe"] = per_bucket
        merged["write_probe_leftovers"] = leftovers

    if want_objects or want_discover:
        if want_objects:
            # Stream the full listing to a temp file, one final line per object,
            # counting as we go. Memory stays bounded to one page (~1000).
            fd, stream_path = tempfile.mkstemp(prefix="redposture-minio-objects-", suffix=".txt")
            count = 0
            grouped = output_format == "txt" and (want_buckets or want_dump)
            dump_rows = [item for item in merged.get("object_dumps", []) if isinstance(item, dict)]
            emitted_dumps: set[int] = set()
            dumps_by_object: dict[tuple[str, str], list[int]] = {}
            for index, dump in enumerate(dump_rows):
                key = (str(dump.get("bucket") or ""), str(dump.get("key") or ""))
                dumps_by_object.setdefault(key, []).append(index)
            bucket_details = {
                str(item.get("name")): item
                for item in merged.get("buckets", [])
                if isinstance(item, dict) and item.get("name")
            }
            stream_prefix = f"MINIO\t{ctx.host or '?'}\t{int(ctx.port or 0)}\t"
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                if grouped:
                    handle.write(f"{stream_prefix} [*] Buckets and Objects\n")
                    for name in bucket_details:
                        if name not in target_buckets:
                            handle.write(f"{stream_prefix} {name}\n")
                next_bucket = 0
                active_bucket: str | None = None

                def emit_bucket(name: str) -> None:
                    wp = (merged.get("write_probe") or {}).get(name)
                    suffix = f" (write:{wp.get('write')})" if isinstance(wp, dict) else ""
                    handle.write(f"{stream_prefix} {name}{suffix}\n")

                for obj in _enum.iter_objects_multi(client, target_buckets, on_error=listing_errors.append):
                    if grouped and obj.bucket != active_bucket:
                        while next_bucket < len(target_buckets) and target_buckets[next_bucket] != obj.bucket:
                            emit_bucket(target_buckets[next_bucket])
                            next_bucket += 1
                        if next_bucket < len(target_buckets):
                            emit_bucket(target_buckets[next_bucket])
                            next_bucket += 1
                        active_bucket = obj.bucket
                    handle.write(_render.object_stream_line(ctx.host, ctx.port, asdict(obj), output_format) + "\n")
                    count += 1
                    if grouped:
                        for index in dumps_by_object.get((obj.bucket, obj.key), []):
                            if index not in emitted_dumps:
                                dump = dump_rows[index]
                                for line in _render.format_object_dump_lines(
                                    merged, dump, labeled=bool(merged.get("object_dumps_labeled"))
                                ):
                                    handle.write(line + "\n")
                                emitted_dumps.add(index)
                if grouped:
                    for bucket_name in target_buckets[next_bucket:]:
                        emit_bucket(bucket_name)
                    for index, dump in enumerate(dump_rows):
                        if index not in emitted_dumps:
                            for line in _render.format_object_dump_lines(
                                merged, dump, labeled=bool(merged.get("object_dumps_labeled"))
                            ):
                                handle.write(line + "\n")
            merged["objects_streamed"] = True
            merged["objects_count"] = count
            merged["_stream_lines_file"] = stream_path
            if grouped:
                merged["_inventory_grouped_stream"] = True
        if want_discover:
            budget = _discover.Budget(
                time_budget=getattr(args, "discover_time", None),
                max_total_bytes=getattr(args, "discover_max_bytes", 50 * 1024 * 1024),
            )
            scan_iter = _enum.iter_objects_multi(client, target_buckets, on_error=listing_errors.append)

            # Findings are streamed immediately. Detection/auth and the final summary
            # are emitted by the common staged runtime so every discovery module has
            # the same lifecycle and no target lines are duplicated.
            live_emit: Any = getattr(ctx, "live_emit", None)
            self_emit = output_format == "txt" and callable(live_emit)
            on_finding: Any = None
            if self_emit:

                def on_finding(finding: dict[str, Any]) -> None:
                    live_emit([_render.format_finding_line(ctx.host, ctx.port, finding)])

            debug_emit = getattr(ctx, "debug_emit", None)
            nested_scheduler = getattr(ctx, "nested_scheduler", None)
            if debug_emit is not None:
                debug_emit(
                    f"{ctx.host}:{ctx.port} minio discover workers="
                    f"{min(_discover.DISCOVER_WORKERS, int(getattr(ctx.args, '_audit_nested_workers', 1) or 1))}"
                )
            discover_kwargs: dict[str, Any] = {"budget": budget, "on_finding": on_finding}
            if nested_scheduler is not None:
                discover_kwargs.update(
                    {
                        "nested_scheduler": nested_scheduler,
                        "scheduler_key": ("minio-discover", ctx.host, ctx.port),
                    }
                )
            result = _discover.discover_secrets(client, scan_iter, **discover_kwargs)
            candidates_count = len(result.candidates)
            # Coverage = share of interesting-by-name objects actually inspected.
            # 100% on a complete run; when a budget cap truncated the scan the
            # `status:partial` + partial reasons flag that the denominator itself
            # may be incomplete, so the two axes stay honest together.
            coverage_percent: float | None
            if result.coverage_complete or candidates_count == 0:
                coverage_percent = 100.0
            else:
                coverage_percent = 100.0 * result.objects_scanned / candidates_count
            if listing_errors:
                coverage_percent = None
                result.partial_reasons.extend(error for error in listing_errors if error not in result.partial_reasons)
            status = "complete" if result.coverage_complete and not listing_errors else "partial"
            merged["discover_requested"] = True
            merged["secret_candidates"] = result.candidates
            merged["secret_findings"] = result.findings
            merged["discover_partial_reasons"] = result.partial_reasons
            merged["discover_coverage"] = status
            merged["discover_coverage_percent"] = round(coverage_percent, 2) if coverage_percent is not None else None
            merged["discover_candidates_count"] = candidates_count
            merged["discover_findings_count"] = len(result.findings)
            merged["discover_objects_scanned"] = result.objects_scanned
            merged["discover_bytes_read"] = result.bytes_read

            if self_emit:
                merged["_discover_findings_streamed"] = True
    if listing_errors:
        merged["listing_errors"] = list(dict.fromkeys(listing_errors))
        merged["inventory_coverage"] = "partial"
    return merged


def _build_credential_candidates(
    username: str | None, password: str | None, defcreds: bool
) -> list[tuple[str, str, str]]:
    candidates: list[tuple[str, str, str]] = []
    seen: set[tuple[str, str]] = set()
    if password is not None:
        user = (username or "").strip()
        pair = (user, password)
        candidates.append((user, password, "provided"))
        seen.add(pair)
    if defcreds:
        for access_key, secret_key in _MINIO_DEFAULT_CREDENTIALS:
            pair = (access_key, secret_key)
            if pair in seen:
                continue
            seen.add(pair)
            candidates.append((access_key, secret_key, "default"))
    return candidates
