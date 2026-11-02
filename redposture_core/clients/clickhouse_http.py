"""Custom header compatibility for Connect releases without constructor support."""

from __future__ import annotations

from collections.abc import Mapping
from inspect import signature
from typing import Any


def constructor_headers(headers: Mapping[str, str]) -> dict[str, str]:
    """Replace SDK constructor defaults despite case-sensitive dict merging."""
    defaults = {
        name.lower(): name
        for name in ("Authorization", "User-Agent", "X-ClickHouse-User", "X-ClickHouse-SSL-Certificate-Auth")
    }
    return {defaults.get(name.lower(), name): value for name, value in headers.items()}


def _overlay(headers: Mapping[str, str] | None, overrides: Mapping[str, str]) -> dict[str, str]:
    replaced = {name.lower() for name in overrides}
    result = {name: value for name, value in (headers or {}).items() if name.lower() not in replaced}
    result.update(overrides)
    return result


def create_http_client_with_headers(options: Mapping[str, Any], headers: Mapping[str, str]) -> Any:
    from clickhouse_connect.driver.httpclient import HttpClient

    operator_headers = dict(headers)

    class HeaderClient(HttpClient):
        def _raw_request(
            self,
            data: Any,
            params: dict[str, str],
            headers: Mapping[str, str] | None = None,
            *args: Any,
            **kwargs: Any,
        ) -> Any:
            # This hook is also used by the SDK's metadata requests inside
            # __init__. Retain its TLS/proxy/pool setup and change only headers.
            # Normalize the base too: the parent merges it with request headers
            # case-sensitively and could otherwise reintroduce Authorization.
            merged = _overlay(self.headers, operator_headers)
            # Connect 1.x shares this dict with its HTTP backend. Preserve the
            # object so constructor defaults cannot survive in a stale copy.
            self.headers.clear()
            self.headers.update(merged)
            return super()._raw_request(data, params, _overlay(headers, operator_headers), *args, **kwargs)

    # Our caller already resolved interface/database/auth explicitly. secure is
    # a get_client factory option; HttpClient takes the resolved interface.
    kwargs = {key: value for key, value in options.items() if key not in {"headers", "secure"}}
    if "headers" in signature(HttpClient.__init__).parameters:
        # New Connect backends perform initialization without calling the
        # facade's _raw_request override. Apply operator headers at creation.
        kwargs["headers"] = constructor_headers(operator_headers)
    return HeaderClient(**kwargs)
