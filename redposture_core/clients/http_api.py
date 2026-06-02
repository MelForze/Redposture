"""Shared HTTP/API client used by stage modules."""

from __future__ import annotations

import json
import ssl
import time
import urllib.error
import urllib.request
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from ..network_proxy import ProxyConfig


@dataclass(frozen=True)
class HttpClientConfig:
    timeout: float = 3.0
    retries: int = 0
    backoff: float = 0.15
    insecure: bool = False
    ca_file: str | None = None
    proxy: ProxyConfig | None = None
    response_size_cap: int = 10 * 1024 * 1024
    default_headers: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class HttpRequest:
    method: str
    url: str
    headers: Mapping[str, str] = field(default_factory=dict)
    body: bytes | str | None = None
    json_body: Any = None


@dataclass(frozen=True)
class HttpResponse:
    status: int
    body: bytes
    headers: dict[str, str]
    error: str | None = None

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")

    def json(self) -> Any:
        return json.loads(self.text)


def normalize_http_error(exc: BaseException) -> str:
    text = str(exc).strip()
    if text.startswith("<urlopen error ") and text.endswith(">"):
        text = text[len("<urlopen error ") : -1].strip()
    return text or exc.__class__.__name__


def _ssl_context(insecure: bool, ca_file: str | None = None) -> ssl.SSLContext:
    context = ssl.create_default_context(cafile=ca_file or None)
    if insecure:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    return context


class HttpApiClient:
    """Small stdlib HTTP client with normalized errors and shared config.

    Proxy support is intentionally compatible with the global
    `proxy_socket_context`: modules pass the parsed proxy in config for telemetry,
    while the actual socket routing is handled by the shared socket patch.
    """

    def __init__(self, config: HttpClientConfig | None = None) -> None:
        self.config = config or HttpClientConfig()
        self._context = (
            _ssl_context(self.config.insecure, self.config.ca_file)
            if self.config.insecure or self.config.ca_file
            else None
        )

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        body: bytes | str | None = None,
        json_body: Any = None,
        timeout: float | None = None,
    ) -> HttpResponse:
        request = HttpRequest(
            method=method,
            url=url,
            headers=headers or {},
            body=body,
            json_body=json_body,
        )
        return self.send(request, timeout=timeout)

    def get(self, url: str, *, headers: Mapping[str, str] | None = None, timeout: float | None = None) -> HttpResponse:
        return self.request("GET", url, headers=headers, timeout=timeout)

    def post(
        self,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        body: bytes | str | None = None,
        json_body: Any = None,
        timeout: float | None = None,
    ) -> HttpResponse:
        return self.request("POST", url, headers=headers, body=body, json_body=json_body, timeout=timeout)

    def download_to_file(
        self,
        url: str,
        out_path: str,
        *,
        headers: Mapping[str, str] | None = None,
        timeout: float | None = None,
        chunk_size: int = 1024 * 64,
    ) -> tuple[int, int, str | None]:
        req = urllib.request.Request(
            url,
            method="GET",
            headers={**{str(k): str(v) for k, v in self.config.default_headers.items()}, **dict(headers or {})},
        )
        try:
            timeout_value = float(timeout if timeout is not None else self.config.timeout)
            request_kwargs: dict[str, Any] = {"timeout": timeout_value}
            if self._context is not None:
                request_kwargs["context"] = self._context
            with urllib.request.urlopen(req, **request_kwargs) as resp:
                size = 0
                with open(out_path, "wb") as fh:
                    while True:
                        chunk = resp.read(max(1, int(chunk_size)))
                        if not chunk:
                            break
                        fh.write(chunk)
                        size += len(chunk)
                return int(getattr(resp, "status", 0) or resp.getcode()), size, None
        except urllib.error.HTTPError as exc:
            return int(exc.code), 0, None
        except Exception as exc:
            return 0, 0, normalize_http_error(exc)

    def send(self, request: HttpRequest, *, timeout: float | None = None) -> HttpResponse:
        attempts = max(1, int(self.config.retries) + 1)
        last_error = ""
        for attempt in range(1, attempts + 1):
            response = self._send_once(request, timeout=timeout)
            if response.error is None:
                return response
            last_error = response.error
            if attempt < attempts:
                time.sleep(max(0.0, float(self.config.backoff)) * attempt)
        return HttpResponse(status=0, body=b"", headers={}, error=last_error or "request failed")

    def _send_once(self, request: HttpRequest, *, timeout: float | None = None) -> HttpResponse:
        headers = {str(key): str(value) for key, value in self.config.default_headers.items()}
        headers.update({str(key): str(value) for key, value in request.headers.items()})
        body = request.body
        if request.json_body is not None:
            body = json.dumps(request.json_body, separators=(",", ":")).encode("utf-8")
            headers.setdefault("Content-Type", "application/json")
        elif isinstance(body, str):
            body = body.encode("utf-8")

        req = urllib.request.Request(
            request.url,
            data=body,
            method=str(request.method or "GET").upper(),
            headers=headers,
        )
        try:
            timeout_value = float(timeout if timeout is not None else self.config.timeout)
            request_kwargs: dict[str, Any] = {"timeout": timeout_value}
            if self._context is not None:
                request_kwargs["context"] = self._context
            open_response = urllib.request.urlopen(req, **request_kwargs)
            with open_response as resp:
                read_size = max(0, int(self.config.response_size_cap)) + 1
                try:
                    payload = resp.read(read_size)
                except TypeError:
                    payload = resp.read()
                if len(payload) > int(self.config.response_size_cap):
                    payload = payload[: int(self.config.response_size_cap)]
                return HttpResponse(
                    status=int(getattr(resp, "status", 0) or resp.getcode()),
                    body=payload,
                    headers={str(key): str(value) for key, value in getattr(resp, "headers", {}).items()},
                    error=None,
                )
        except urllib.error.HTTPError as exc:
            try:
                read_size = max(0, int(self.config.response_size_cap)) + 1
                try:
                    payload = exc.read(read_size)
                except TypeError:
                    payload = exc.read()
            except Exception:
                payload = b""
            if len(payload) > int(self.config.response_size_cap):
                payload = payload[: int(self.config.response_size_cap)]
            return HttpResponse(
                status=int(exc.code),
                body=payload,
                headers={str(key): str(value) for key, value in exc.headers.items()},
                error=None,
            )
        except Exception as exc:
            return HttpResponse(status=0, body=b"", headers={}, error=normalize_http_error(exc))


__all__ = [
    "HttpApiClient",
    "HttpClientConfig",
    "HttpRequest",
    "HttpResponse",
    "normalize_http_error",
]
