"""Thin S3 / MinIO Admin API client over the shared HttpSessionPool.

Read-only by default (GET/HEAD). `put_object`/`delete_object` exist ONLY for the
opt-in `--probe-write` capability check (a canary PUT immediately rolled back with
DELETE); no other code path mutates a target. Parses S3 error XML into a typed
(code, message). No third-party SDK; requests are SigV4-signed with
clients.s3_sigv4 when credentials are present.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import TYPE_CHECKING
from urllib.parse import quote, urlencode
from xml.etree import ElementTree

from . import s3_sigv4

if TYPE_CHECKING:
    from .http_session import HttpSessionPool

_RESPONSE_CAP = 5 * 1024 * 1024


@dataclass(frozen=True)
class S3Error:
    http_status: int
    code: str
    message: str


@dataclass(frozen=True)
class MinioResponse:
    http_status: int
    headers: dict[str, str]
    body: bytes
    error: S3Error | None = None
    transport_error: str | None = None


def _parse_s3_error(status: int, body: bytes) -> S3Error | None:
    if status < 400 or not body:
        return None
    try:
        root = ElementTree.fromstring(body)
    except ElementTree.ParseError:
        return S3Error(http_status=status, code="", message="")
    if root.tag.split("}")[-1] != "Error":
        return None
    code = ""
    message = ""
    for child in root:
        tag = child.tag.split("}")[-1]
        if tag == "Code":
            code = (child.text or "").strip()
        elif tag == "Message":
            message = (child.text or "").strip()
    return S3Error(http_status=status, code=code, message=message)


class MinioClient:
    def __init__(
        self,
        pool: HttpSessionPool,
        *,
        scheme: str,
        host: str,
        port: int,
        access_key: str | None = None,
        secret_key: str | None = None,
        session_token: str | None = None,
    ) -> None:
        self._pool = pool
        self.scheme = scheme
        self.host = host
        self.port = int(port)
        self.access_key = access_key
        self.secret_key = secret_key
        self.session_token = session_token

    @property
    def base_url(self) -> str:
        return f"{self.scheme}://{self.host}:{self.port}"

    @property
    def _host_header(self) -> str:
        if (self.scheme == "http" and self.port == 80) or (self.scheme == "https" and self.port == 443):
            return self.host
        return f"{self.host}:{self.port}"

    def _request(
        self,
        method: str,
        path: str,
        query: str,
        *,
        signed: bool,
        extra_headers: dict[str, str] | None = None,
        response_cap: int | None = None,
        body: bytes | None = None,
    ) -> MinioResponse:
        url = f"{self.base_url}{path}"
        if query:
            url = f"{url}?{query}"
        headers: dict[str, str] = dict(extra_headers or {})
        if signed and self.access_key and self.secret_key:
            # SigV4 must bind the actual request body: an empty-payload hash for
            # GET/HEAD/DELETE, the real sha256 for a PUT that carries a body.
            payload_hash = hashlib.sha256(body).hexdigest() if body else s3_sigv4.EMPTY_PAYLOAD_HASH
            headers.update(
                s3_sigv4.sign_request(
                    method=method,
                    host=self._host_header,
                    path=path,
                    query=query,
                    headers=extra_headers,
                    payload_hash=payload_hash,
                    access_key=self.access_key,
                    secret_key=self.secret_key,
                    session_token=self.session_token,
                )
            )
        cap = _RESPONSE_CAP if response_cap is None else max(1, int(response_cap))
        try:
            resp = self._pool.request(method, url, headers=headers, body=body, response_size_cap=cap)
        except Exception as exc:  # noqa: BLE001 - transport errors normalized for callers
            return MinioResponse(http_status=0, headers={}, body=b"", transport_error=str(exc))
        if getattr(resp, "error", None):
            return MinioResponse(http_status=0, headers={}, body=b"", transport_error=str(resp.error))
        status = int(resp.status)
        body = resp.body or b""
        return MinioResponse(
            http_status=status,
            headers=dict(resp.headers or {}),
            body=body,
            error=_parse_s3_error(status, body),
        )

    def get_service_root(self, *, signed: bool) -> MinioResponse:
        return self._request("GET", "/", "", signed=signed)

    def head_bucket(self, bucket: str, *, signed: bool) -> MinioResponse:
        return self._request("HEAD", f"/{quote(bucket)}", "", signed=signed)

    def list_objects_v2(
        self,
        bucket: str,
        *,
        max_keys: int = 1,
        prefix: str = "",
        continuation_token: str | None = None,
        signed: bool,
    ) -> MinioResponse:
        params = {"list-type": "2", "max-keys": str(max(1, int(max_keys)))}
        if prefix:
            params["prefix"] = prefix
        if continuation_token:
            params["continuation-token"] = continuation_token
        return self._request("GET", f"/{quote(bucket)}", urlencode(params, quote_via=quote), signed=signed)

    def head_object(self, bucket: str, key: str, *, signed: bool) -> MinioResponse:
        path = f"/{quote(bucket)}/{quote(key, safe='/')}"
        return self._request("HEAD", path, "", signed=signed)

    def get_object_range(self, bucket: str, key: str, *, start: int = 0, length: int, signed: bool) -> MinioResponse:
        # Percent-encode the object key in the path BEFORE signing so the signed
        # canonical path matches the wire path (SigV4 correctness for arbitrary keys).
        path = f"/{quote(bucket)}/{quote(key, safe='/')}"
        end = max(int(start), int(start) + int(length) - 1)
        headers = {"Range": f"bytes={int(start)}-{end}"}
        return self._request("GET", path, "", signed=signed, extra_headers=headers, response_cap=length)

    def put_object(self, bucket: str, key: str, body: bytes, *, signed: bool = True) -> MinioResponse:
        # Write path — used only by the opt-in write-probe (canary object).
        path = f"/{quote(bucket)}/{quote(key, safe='/')}"
        return self._request("PUT", path, "", signed=signed, body=body)

    def delete_object(self, bucket: str, key: str, *, signed: bool = True) -> MinioResponse:
        # Rollback path for the write-probe canary.
        path = f"/{quote(bucket)}/{quote(key, safe='/')}"
        return self._request("DELETE", path, "", signed=signed)

    def get_object(self, bucket: str, key: str, *, max_bytes: int, signed: bool = True) -> MinioResponse:
        # Full object GET for --dump/--download, bounded by `max_bytes` (the pool
        # caps the response body) so a huge object can never exhaust memory.
        path = f"/{quote(bucket)}/{quote(key, safe='/')}"
        return self._request("GET", path, "", signed=signed, response_cap=max(1, int(max_bytes)))

    def health(self, kind: str) -> MinioResponse:
        return self._request("GET", f"/minio/health/{kind}", "", signed=False)

    def admin_info(self, *, signed: bool = True) -> MinioResponse:
        return self._request("GET", "/minio/admin/v3/info", "", signed=signed)

    def account_info(self, *, signed: bool = True) -> MinioResponse:
        return self._request("GET", "/minio/admin/v3/accountinfo", "", signed=signed)

    def list_users(self, *, signed: bool = True) -> MinioResponse:
        return self._request("GET", "/minio/admin/v3/list-users", "", signed=signed)

    def list_canned_policies(self, *, signed: bool = True) -> MinioResponse:
        return self._request("GET", "/minio/admin/v3/list-canned-policies", "", signed=signed)


__all__ = ["MinioClient", "MinioResponse", "S3Error"]
