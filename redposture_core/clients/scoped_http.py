"""Small API-compatible view of an HTTP pool scoped to one audit target."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from .http_api import HttpResponse
from .http_session import HttpSessionPool


@dataclass
class HttpLifecycleState:
    http: HttpSessionPool | None

    def close(self) -> None:
        if self.http is not None:
            self.http.close()
            self.http = None


@dataclass(frozen=True)
class ScopedHttpClient:
    pool: HttpSessionPool
    response_size_cap: int
    allow_cross_origin_redirects: bool = False

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        timeout: float | None = None,
    ) -> HttpResponse:
        return self.pool.request(
            method,
            url,
            headers=headers,
            timeout=timeout,
            response_size_cap=self.response_size_cap,
            allow_cross_origin_redirects=self.allow_cross_origin_redirects,
            preserve_authorization_on_cross_origin=False,
        )

    def get(
        self,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        timeout: float | None = None,
    ) -> HttpResponse:
        return self.request("GET", url, headers=headers, timeout=timeout)


__all__ = ["HttpLifecycleState", "ScopedHttpClient"]
