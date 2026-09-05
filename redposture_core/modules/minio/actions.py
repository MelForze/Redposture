"""MinIO detection / anonymous / auth-verification actions."""

from __future__ import annotations

import json
import re
from typing import Any
from xml.etree import ElementTree

from ...clients.http_session import HttpSessionPool
from ...clients.minio_api import MinioClient, MinioResponse
from .types import AdminCapability, AnonymousResult, CredentialResult, MinioDetection

# `Server: MinIO/RELEASE.2021-06-17T00-10-46Z` on older deployments; modern ones
# return a bare `Server: MinIO` and the version is only in the Admin API.
_SERVER_VERSION_RE = re.compile(r"MinIO/(\S+)", re.IGNORECASE)


def _server_header_version(resp: MinioResponse) -> str | None:
    server = str(resp.headers.get("Server") or resp.headers.get("server") or "")
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

_S3_MARKERS = (b"ListAllMyBucketsResult", b"ListBucketResult", b"<Error>", b"<Code>")


def _has_s3_shape(resp: MinioResponse) -> bool:
    if resp.transport_error:
        return False
    if resp.error is not None and resp.error.code:
        return True
    body = resp.body or b""
    return any(marker in body for marker in _S3_MARKERS)


def _server_is_minio(resp: MinioResponse) -> bool:
    server = str(resp.headers.get("Server") or resp.headers.get("server") or "")
    return "minio" in server.lower()


def _health_live(resp: MinioResponse) -> bool:
    return not resp.transport_error and resp.http_status in {200, 204}


def _admin_plane(resp: MinioResponse) -> bool:
    # Admin API present when the admin path answers with an S3/MinIO error
    # (403/AccessDenied) rather than a plain 404.
    if resp.transport_error:
        return False
    if resp.http_status == 404:
        return False
    return resp.http_status in {401, 403} or (resp.error is not None and bool(resp.error.code))


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

    s3_shape = _has_s3_shape(root)
    server_minio = _server_is_minio(root)
    health_ok = _health_live(health)
    admin_ok = _admin_plane(admin)

    evidence = {
        "s3_shape": s3_shape,
        "server_minio": server_minio,
        "health_live": health_ok,
        "admin_plane": admin_ok,
        "root_status": root.http_status,
        # Unauthenticated version fallback (older MinIO exposes it in Server:);
        # the authoritative value comes from the Admin API once authenticated.
        "server_version": _server_header_version(root),
    }

    strong_signals = sum(1 for flag in (health_ok, admin_ok, server_minio) if flag)
    if s3_shape and strong_signals >= 1 and (health_ok or admin_ok or (server_minio and strong_signals >= 2)):
        status = "confirmed"
    elif s3_shape:
        status = "probable"
    else:
        status = "not_minio"

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


def verify_credential(client: MinioClient) -> CredentialResult:
    resp = client.get_service_root(signed=True)
    access_key = getattr(client, "access_key", None)
    if resp.transport_error:
        return CredentialResult(state="transient_failure", access_key=access_key)
    if 200 <= resp.http_status < 300:
        return CredentialResult(state="valid", access_key=access_key)
    code = resp.error.code if resp.error is not None else ""
    if code in _INVALID_CRED_CODES:
        return CredentialResult(state="invalid", access_key=access_key, error_code=code)
    if code == "AccessDenied":
        # Подпись принята сервером (иначе был бы SignatureDoesNotMatch) -> креды
        # валидны, просто нет прав на пробную операцию.
        return CredentialResult(state="valid_but_restricted", access_key=access_key, error_code=code)
    return CredentialResult(state="verification_unavailable", access_key=access_key, error_code=code or None)


def _probe_state(resp: MinioResponse) -> str:
    if resp.transport_error:
        return "unknown"
    if 200 <= resp.http_status < 300:
        return "ok"
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
        "accountinfo": _probe_state(account),
        "list_users": _probe_state(users),
        "list_canned_policies": _probe_state(policies),
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
    bucket, then immediately DELETE it to roll back.

    Returns ``(per_bucket, leftovers)`` where per_bucket maps a bucket to
    ``{"write": True/False/"unknown", "cleanup": "ok"/"failed", "leftover": key?}``
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
            entry: dict[str, Any] = {"write": True}
            delete = client.delete_object(bucket, key, signed=True)
            rolled_back = not delete.transport_error and delete.http_status in {200, 202, 204}
            if rolled_back:
                entry["cleanup"] = "ok"
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

    def __init__(self, args: Any, host: str, port: int) -> None:
        self.host = str(host)
        self.port = int(port)
        self.resolved_scheme: str | None = None
        self.pool = HttpSessionPool(
            timeout=float(getattr(args, "timeout", 5.0) or 5.0),
            insecure=True,
            retries=int(getattr(args, "retries", 0) or 0),
        )

    def _probe(self, scheme: str) -> MinioResponse:
        client = MinioClient(self.pool, scheme=scheme, host=self.host, port=self.port)
        return client.get_service_root(signed=False)

    def resolve_scheme(self) -> str:
        """Return the transport scheme for this target, probing once and caching.

        Starts from the port heuristic, then flips to the other scheme if the
        first probe returns a transport-mismatch signature. A single probe is
        enough: an unrelated failure (refused/timeout) leaves the guess intact.
        """
        if self.resolved_scheme is not None:
            return self.resolved_scheme
        guess = "https" if self.port in _TLS_PORTS else "http"
        resp = self._probe(guess)
        if resp.transport_error and _transport_mismatch(guess, resp.transport_error):
            guess = "http" if guess == "https" else "https"
        self.resolved_scheme = guess
        return guess

    def close(self) -> None:
        self.pool.close()


def minio_lifecycle_state_factory(ctx: Any) -> MinioLifecycleState:
    return MinioLifecycleState(ctx.args, ctx.host, ctx.port)


def _client_for(ctx: Any, credential: Any) -> MinioClient:
    state = getattr(ctx, "lifecycle_state", None)
    if isinstance(state, MinioLifecycleState):
        scheme = state.resolve_scheme()
        pool = state.pool
    else:
        scheme = "https" if int(ctx.port) in _TLS_PORTS else "http"
        pool = HttpSessionPool(timeout=float(getattr(ctx.args, "timeout", 5.0) or 5.0), insecure=True)
    return MinioClient(
        pool,
        scheme=scheme,
        host=str(ctx.host),
        port=int(ctx.port),
        access_key=getattr(credential, "username", None),
        secret_key=getattr(credential, "password", None),
        session_token=getattr(ctx.args, "session_token", None),
    )


def detect_record(ctx: Any) -> dict[str, Any]:
    client = _client_for(ctx, ctx.credential)
    detection = detect_minio(client)
    anon = classify_anonymous(client) if detection.status == "confirmed" else None
    verification_status = "available" if detection.status == "confirmed" else "unavailable"
    status_word = {
        "confirmed": "detected",
        "probable": "probable",
        "not_minio": "not_service",
        "transport_failure": "fail",
    }[detection.status]
    record: dict[str, Any] = {
        "host": str(ctx.host),
        "port": int(ctx.port),
        "status": status_word,
        "detection_status": detection.status,
        "api_endpoint": detection.api_endpoint,
        "console_endpoint": detection.console_endpoint,
        "detection": detection.evidence,
        "credential_verification_status": verification_status,
    }
    header_version = detection.evidence.get("server_version")
    if header_version:
        record["version"] = header_version
    if anon is not None:
        record["anonymous"] = anon.classification
        record["auth_required"] = anon.classification == "authentication_required"
        # Distinct key from the structured `buckets` list emitted by --show-buckets
        # (data_record) so the JSON `buckets` field is not polymorphic.
        record["anonymous_buckets"] = list(anon.buckets)
    return record


def auth_record(ctx: Any, prior: dict[str, Any]) -> dict[str, Any]:
    credential = ctx.credential
    if not (getattr(credential, "username", None) and getattr(credential, "password", None)):
        return dict(prior)
    client = _client_for(ctx, credential)
    result = verify_credential(client)
    merged = dict(prior)
    merged["credential_state"] = result.state
    merged["credential_type"] = "session-token" if getattr(ctx.args, "session_token", None) else "access-key"
    merged["credential_results"] = [
        {"access_key": result.access_key, "state": result.state, "error_code": result.error_code}
    ]
    merged["provided_credentials_ok"] = result.state in {"valid", "valid_but_restricted"}
    merged["default_credentials"] = getattr(credential, "source", "") == "default" and merged["provided_credentials_ok"]
    return merged


def capabilities_record(ctx: Any, prior: dict[str, Any]) -> dict[str, Any]:
    """After a valid credential, probe admin capability (read-only) and summarise perms."""
    merged = dict(prior)
    if str(prior.get("credential_state") or "") not in {"valid", "valid_but_restricted"}:
        return merged
    client = _client_for(ctx, ctx.credential)
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
        if cap.capability in {"confirmed", "partial"}
        else "denied"
        if cap.capability == "not_confirmed"
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
    text = str(ref or "").strip().lstrip("/")
    if "/" not in text:
        return None, None
    bucket, key = text.split("/", 1)
    return (bucket or None), (key or None)


def _run_object_op(
    client: MinioClient,
    merged: dict[str, Any],
    *,
    object_ref: Any,
    want_dump: bool,
    download_dir: Any,
    max_bytes: int,
) -> None:
    """--dump / --download a single object (bounded by max_bytes). Read-only GET."""
    import os

    o_bucket, o_key = _split_object_ref(object_ref)
    if not object_ref:
        merged["object_op_error"] = "specify --object bucket/key for --dump/--download"
        return
    if not o_bucket or not o_key:
        merged["object_op_error"] = f"invalid --object '{object_ref}' (expected bucket/key)"
        return
    resp = client.get_object(o_bucket, o_key, max_bytes=max_bytes)
    if resp.transport_error:
        merged["object_op_error"] = f"{o_bucket}/{o_key}: transport error"
        return
    if resp.http_status not in {200, 206}:
        code = resp.error.code if resp.error is not None and resp.error.code else str(resp.http_status)
        merged["object_op_error"] = f"{o_bucket}/{o_key}: {code}"
        return
    body = resp.body or b""
    if want_dump:
        merged["object_dump"] = {
            "bucket": o_bucket,
            "key": o_key,
            "size": len(body),
            "content": body.decode("utf-8", errors="replace"),
        }
    if download_dir:
        dest = os.path.join(str(download_dir), o_bucket, o_key)
        try:
            os.makedirs(os.path.dirname(dest) or ".", exist_ok=True)
            with open(dest, "wb") as handle:
                handle.write(body)
        except OSError as exc:
            merged["object_op_error"] = f"{o_bucket}/{o_key}: write failed ({exc})"
            return
        merged["object_download"] = {"bucket": o_bucket, "key": o_key, "path": dest, "size": len(body)}


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

    args = ctx.args
    want_buckets = bool(getattr(args, "show_buckets", False))
    want_objects = bool(getattr(args, "show_objects", False))
    want_discover = bool(getattr(args, "discover", False))
    want_probe = bool(getattr(args, "probe_write", False))
    want_dump = bool(getattr(args, "dump", False))
    download_dir = getattr(args, "download", None)
    want_object_op = want_dump or bool(download_dir)
    if not (want_buckets or want_objects or want_discover or want_probe or want_object_op):
        return dict(prior)

    merged = dict(prior)
    client = _client_for(ctx, ctx.credential)
    bucket = getattr(args, "bucket", None)
    prefix = str(getattr(args, "prefix", "") or "")
    output_format = str(getattr(args, "output_format", "txt") or "txt")

    if want_object_op:
        _run_object_op(
            client,
            merged,
            object_ref=getattr(args, "object", None),
            want_dump=want_dump,
            download_dir=download_dir,
            max_bytes=int(getattr(args, "max_object_size", 10 * 1024 * 1024)),
        )

    bucket_infos: list[Any] | None = None
    if want_buckets:
        bucket_infos = list(_enum.iter_buckets(client))
        merged["buckets"] = [asdict(b) for b in bucket_infos]

    target_buckets: list[str] = []
    if want_objects or want_discover or want_probe:
        # A single `--bucket` targets one bucket; otherwise enumerate every listable
        # bucket (reusing the listing already fetched for --show-buckets).
        if bucket:
            target_buckets = [str(bucket)]
        else:
            if bucket_infos is None:
                bucket_infos = list(_enum.iter_buckets(client))
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
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                for obj in _enum.iter_objects_multi(client, target_buckets, prefix=prefix):
                    handle.write(_render.object_stream_line(ctx.host, ctx.port, asdict(obj), output_format) + "\n")
                    count += 1
            merged["objects_streamed"] = True
            merged["objects_count"] = count
            merged["_stream_lines_file"] = stream_path
        if want_discover:
            budget = _discover.Budget(
                max_object_size=int(getattr(args, "max_object_size", 100 * 1024 * 1024)),
                max_objects=int(getattr(args, "max_objects", 1000)),
                time_budget=float(getattr(args, "discover_time", 30.0)),
            )
            scan_iter = _enum.iter_objects_multi(client, target_buckets, prefix=prefix, limit=budget.max_objects + 1)

            # Real-time output: when TXT and a live sink is available (and we are not
            # also streaming an object listing), emit the target's static lines now,
            # stream each finding as it is discovered, then a summary footer — instead
            # of letting the runtime render the whole record at the end.
            live_emit: Any = getattr(ctx, "live_emit", None)
            self_emit = output_format == "txt" and not want_objects and live_emit is not None
            on_finding: Any = None
            emitted = 0
            if self_emit:
                pre = [
                    _render._format_detect_record(merged, "txt"),
                    _render._format_record(merged, "txt"),
                    *_render._format_minio_detail_records(merged, "txt"),
                ]
                pre = [line for line in pre if line]
                live_emit(pre)
                emitted += len(pre)

                def on_finding(finding: dict[str, Any]) -> None:
                    nonlocal emitted
                    live_emit([_render.format_finding_line(ctx.host, ctx.port, finding)])
                    emitted += 1

            result = _discover.discover_secrets(client, scan_iter, budget=budget, on_finding=on_finding)
            candidates_count = len(result.candidates)
            # Coverage = share of interesting-by-name objects actually inspected.
            # 100% on a complete run; when a budget cap truncated the scan the
            # `status:partial` + partial reasons flag that the denominator itself
            # may be incomplete, so the two axes stay honest together.
            if result.coverage_complete or candidates_count == 0:
                coverage_percent = 100.0
            else:
                coverage_percent = 100.0 * result.objects_scanned / candidates_count
            status = "complete" if result.coverage_complete else "partial"
            merged["discover_requested"] = True
            merged["secret_candidates"] = result.candidates
            merged["secret_findings"] = result.findings
            merged["discover_partial_reasons"] = result.partial_reasons
            merged["discover_coverage"] = status
            merged["discover_coverage_percent"] = round(coverage_percent, 2)
            merged["discover_candidates_count"] = candidates_count
            merged["discover_findings_count"] = len(result.findings)
            merged["discover_objects_scanned"] = result.objects_scanned
            merged["discover_bytes_read"] = result.bytes_read

            if self_emit:
                tail = [
                    _render.format_discover_summary(
                        ctx.host,
                        ctx.port,
                        status=status,
                        coverage_percent=coverage_percent,
                        findings=len(result.findings),
                        objects_scanned=result.objects_scanned,
                    )
                ]
                if result.partial_reasons:
                    tail.append(
                        f"MINIO\t{ctx.host}\t{int(ctx.port)}\t "
                        f"[!] Discover partial: {','.join(str(r) for r in result.partial_reasons)}"
                    )
                live_emit(tail)
                emitted += len(tail)
                merged["_self_emitted"] = True
                merged["_self_emitted_lines"] = emitted
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
