"""AWS Signature Version 4 signer for S3 / MinIO Admin API requests.

Pure, dependency-free (stdlib hmac/hashlib). MinIO signs both S3 and Admin API
requests with SigV4, service "s3". Only the header-based signing flow is
implemented (no presigned URLs, no chunked payloads).
"""

from __future__ import annotations

import datetime
import hashlib
import hmac
from urllib.parse import quote, unquote

EMPTY_PAYLOAD_HASH = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

_ALGORITHM = "AWS4-HMAC-SHA256"


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _hmac(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def _signing_key(secret_key: str, date_stamp: str, region: str, service: str) -> bytes:
    k_date = _hmac(("AWS4" + secret_key).encode("utf-8"), date_stamp)
    k_region = _hmac(k_date, region)
    k_service = _hmac(k_region, service)
    return _hmac(k_service, "aws4_request")


def _canonical_query(query: str) -> str:
    if not query:
        return ""
    # The wire query is already RFC3986-encoded by the caller. Canonicalise by
    # decoding then re-encoding ONCE (idempotent) so the signed canonical query
    # matches the server's — never double-encode (`%2F` must not become `%252F`).
    pairs: list[tuple[str, str]] = []
    for part in query.split("&"):
        if not part:
            continue
        name, _, value = part.partition("=")
        pairs.append((quote(unquote(name), safe="-_.~"), quote(unquote(value), safe="-_.~")))
    pairs.sort()
    return "&".join(f"{name}={value}" for name, value in pairs)


def sign_request(
    *,
    method: str,
    host: str,
    path: str,
    query: str = "",
    headers: dict[str, str] | None = None,
    payload_hash: str,
    access_key: str,
    secret_key: str,
    region: str = "us-east-1",
    service: str = "s3",
    session_token: str | None = None,
    timestamp: datetime.datetime | None = None,
) -> dict[str, str]:
    """Return the SigV4 auth headers to merge into the outgoing request."""
    now = timestamp or datetime.datetime.now(datetime.timezone.utc)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = now.strftime("%Y%m%d")

    signed_headers_map: dict[str, str] = {}
    for name, value in (headers or {}).items():
        signed_headers_map[name.lower()] = str(value).strip()
    signed_headers_map["host"] = host
    signed_headers_map["x-amz-content-sha256"] = payload_hash
    signed_headers_map["x-amz-date"] = amz_date
    if session_token:
        signed_headers_map["x-amz-security-token"] = session_token

    sorted_names = sorted(signed_headers_map)
    canonical_headers = "".join(f"{name}:{signed_headers_map[name]}\n" for name in sorted_names)
    signed_headers = ";".join(sorted_names)

    canonical_request = (
        f"{method.upper()}\n"
        f"{path or '/'}\n"
        f"{_canonical_query(query)}\n"
        f"{canonical_headers}\n"
        f"{signed_headers}\n"
        f"{payload_hash}"
    )
    credential_scope = f"{date_stamp}/{region}/{service}/aws4_request"
    string_to_sign = "\n".join([_ALGORITHM, amz_date, credential_scope, _sha256_hex(canonical_request.encode("utf-8"))])
    signature = hmac.new(
        _signing_key(secret_key, date_stamp, region, service),
        string_to_sign.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    authorization = (
        f"{_ALGORITHM} Credential={access_key}/{credential_scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )
    result = {
        "Authorization": authorization,
        "x-amz-date": amz_date,
        "x-amz-content-sha256": payload_hash,
    }
    if session_token:
        result["x-amz-security-token"] = session_token
    return result


__all__ = ["sign_request", "EMPTY_PAYLOAD_HASH"]
