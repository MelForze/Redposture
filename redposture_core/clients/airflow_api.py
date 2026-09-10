"""Thin Apache Airflow REST API client over the shared HttpSessionPool.

Read-only apart from the `POST /auth/token` login used by Airflow 3.x (it creates
no server-side state). Supports both auth carriers: HTTP Basic (Airflow 2.x) and a
Bearer JWT (Airflow 3.x). Transport errors are normalized so callers never see raw
exceptions; JSON parsing is best-effort.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .http_session import HttpSessionPool

_RESPONSE_CAP = 2 * 1024 * 1024


@dataclass(frozen=True)
class AirflowResponse:
    http_status: int
    headers: dict[str, str]
    body: bytes
    transport_error: str | None = None

    def json(self) -> Any | None:
        if self.transport_error or not self.body:
            return None
        try:
            return json.loads(self.body)
        except (ValueError, TypeError):
            return None


class AirflowClient:
    def __init__(
        self,
        pool: HttpSessionPool,
        *,
        scheme: str,
        host: str,
        port: int,
        basic_user: str | None = None,
        basic_password: str | None = None,
        bearer_token: str | None = None,
    ) -> None:
        self._pool = pool
        self.scheme = scheme
        self.host = host
        self.port = int(port)
        self.basic_user = basic_user
        self.basic_password = basic_password
        self.bearer_token = bearer_token

    @property
    def base_url(self) -> str:
        return f"{self.scheme}://{self.host}:{self.port}"

    def _auth_header(self) -> dict[str, str]:
        if self.bearer_token:
            return {"Authorization": f"Bearer {self.bearer_token}"}
        if self.basic_user is not None and self.basic_password is not None:
            token = base64.b64encode(f"{self.basic_user}:{self.basic_password}".encode()).decode()
            return {"Authorization": f"Basic {token}"}
        return {}

    def _request(
        self,
        method: str,
        path: str,
        *,
        authed: bool,
        body: bytes | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> AirflowResponse:
        headers: dict[str, str] = dict(extra_headers or {})
        if authed:
            headers.update(self._auth_header())
        try:
            resp = self._pool.request(
                method, f"{self.base_url}{path}", headers=headers, body=body, response_size_cap=_RESPONSE_CAP
            )
        except Exception as exc:  # noqa: BLE001 - transport errors normalized for callers
            return AirflowResponse(http_status=0, headers={}, body=b"", transport_error=str(exc))
        if getattr(resp, "error", None):
            return AirflowResponse(http_status=0, headers={}, body=b"", transport_error=str(resp.error))
        return AirflowResponse(
            http_status=int(resp.status),
            headers=dict(resp.headers or {}),
            body=resp.body or b"",
        )

    def get(self, path: str, *, authed: bool = True) -> AirflowResponse:
        return self._request("GET", path, authed=authed)

    def post_json(self, path: str, payload: dict[str, Any], *, authed: bool = False) -> AirflowResponse:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        return self._request("POST", path, authed=authed, body=body, extra_headers={"Content-Type": "application/json"})


__all__ = ["AirflowClient", "AirflowResponse"]
