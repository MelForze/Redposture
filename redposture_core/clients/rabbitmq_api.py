"""Bounded, read-only RabbitMQ Management HTTP API client."""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlencode

from .http_session import HttpSessionPool

RESPONSE_CAP = 2 * 1024 * 1024


@dataclass(frozen=True)
class RabbitMQResponse:
    status: int
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    data: Any = None
    error: str | None = None
    truncated: bool = False
    request_url: str | None = None
    final_url: str | None = None
    redirect_history: tuple[str, ...] = ()

    @property
    def outcome(self) -> str:
        if self.error:
            return "transport_error"
        if self.truncated:
            return "response_limit"
        if self.status in {401, 403}:
            return "denied"
        if self.status == 404:
            return "unavailable"
        if self.status == 200 and self.data is not None:
            return "ok"
        return "unexpected_response"


@dataclass(frozen=True)
class RabbitMQCollection:
    items: list[dict[str, Any]]
    status: str
    truncated: bool = False
    http_status: int = 200


class RabbitMQClient:
    def __init__(
        self,
        pool: HttpSessionPool,
        *,
        host: str,
        port: int,
        scheme: str,
        base_path: str = "",
        username: str | None = None,
        password: str | None = None,
    ) -> None:
        self.pool = pool
        authority = f"[{host}]" if ":" in host and not host.startswith("[") else host
        self.base_url = f"{scheme}://{authority}:{port}{base_path.rstrip('/')}"
        self.username = username
        self.password = password

    def get(self, path: str, params: dict[str, str | int] | None = None) -> RabbitMQResponse:
        url = self.base_url + path
        if params:
            url += "?" + urlencode(params)
        headers = {"Accept": "application/json"}
        if self.username is not None and self.password is not None:
            encoded = base64.b64encode(f"{self.username}:{self.password}".encode()).decode("ascii")
            headers["Authorization"] = f"Basic {encoded}"
        try:
            response = self.pool.request(
                "GET",
                url,
                headers=headers,
                response_size_cap=RESPONSE_CAP,
                allow_cross_origin_redirects=True,
            )
        except Exception as exc:  # noqa: BLE001 - normalize per-target transport failures
            return RabbitMQResponse(0, error=str(exc))
        body = response.body or b""
        data = None
        if not response.error and not response.truncated:
            try:
                data = json.loads(body)
            except (ValueError, UnicodeError):
                pass
        return RabbitMQResponse(
            status=response.status,
            headers=dict(response.headers or {}),
            body=body,
            data=data,
            error=response.error,
            truncated=response.truncated,
            request_url=getattr(response, "request_url", None),
            final_url=getattr(response, "final_url", None),
            redirect_history=tuple(getattr(response, "redirect_history", ()) or ()),
        )

    def collection(
        self,
        path: str,
        *,
        limit: int,
        page_size: int = 100,
        columns: str = "",
        paginated: bool = True,
    ) -> RabbitMQCollection:
        """Accept paginated responses and older endpoints returning plain lists.

        The item limit also bounds the number of requests, even if a broken
        server keeps advertising more pages. Truncated bodies are never parsed.
        """
        items: list[dict[str, Any]] = []
        page = 1
        size = min(page_size, limit, 500)
        while len(items) < limit:
            params: dict[str, str | int] = {"pagination": "true", "page": page, "page_size": size} if paginated else {}
            if columns:
                params["columns"] = columns
            response = self.get(path, params)
            if response.outcome != "ok":
                return RabbitMQCollection(items, response.outcome, bool(items) or response.truncated, response.status)
            data = response.data
            rows = data if isinstance(data, list) else data.get("items") if isinstance(data, dict) else None
            if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
                return RabbitMQCollection(items, "unexpected_response", bool(items), response.status)
            remaining = limit - len(items)
            items.extend(rows[:remaining])
            if isinstance(data, list):
                return RabbitMQCollection(items, "ok", len(rows) > remaining)
            pages = data.get("page_count")
            if not isinstance(pages, int) or isinstance(pages, bool) or pages < page:
                # RabbitMQ may return zero pages for an empty collection.
                if not rows and page == 1 and pages == 0:
                    return RabbitMQCollection(items, "ok")
                return RabbitMQCollection(items, "unexpected_response", True)
            more = page < pages or len(rows) > remaining
            if not more:
                return RabbitMQCollection(items, "ok")
            if not rows or len(items) >= limit:
                return RabbitMQCollection(items, "ok" if rows else "unexpected_response", True)
            page += 1
        return RabbitMQCollection(items, "ok", True)
