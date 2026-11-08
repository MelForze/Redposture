"""Shared HTTP redirect policy. See ARCHITECTURE.md#http-redirects."""

from __future__ import annotations

import urllib.parse
import urllib.request
from collections.abc import Awaitable, Callable, Generator, Mapping
from dataclasses import replace
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .http_api import HttpResponse

REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
MAX_REDIRECTS = 5
RequestPreparer = Callable[[str, str, dict[str, str], bytes | None], dict[str, str]]
RequestSender = Callable[[str, str, dict[str, str], bytes | None], "HttpResponse"]


def http_origin(url: str) -> tuple[str, str, int]:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise ValueError(f"unsupported HTTP redirect URL: {url}")
    return (
        parsed.scheme.lower(),
        parsed.hostname.lower(),
        parsed.port or (443 if parsed.scheme.lower() == "https" else 80),
    )


def is_redirect_policy_error(response: HttpResponse) -> bool:
    """A completed redirect policy decision needs no larger sync re-read."""
    return (
        response.status in REDIRECT_STATUSES
        and bool(response.error)
        and str(response.error).startswith(
            (
                "cross-origin redirect blocked:",
                "redirect loop detected",
                "redirect limit exceeded (",
                "unsupported HTTP redirect URL:",
            )
        )
    )


def _redirect_requests(
    method: str,
    url: str,
    *,
    headers: Mapping[str, str] | None = None,
    body: bytes | str | None = None,
    allow_cross_origin: bool = True,
    preserve_authorization: bool = True,
    prepare_request: RequestPreparer | None = None,
) -> Generator[tuple[str, str, dict[str, str], bytes | None], HttpResponse, HttpResponse]:
    """Follow HTTP redirects independently of retry/replay policy.

    All operator-supplied credentials are retained by default. Host follows
    the destination; request-specific signatures can be rebuilt before each
    send. Explicit restrictive flags remain available for library callers.
    """
    from .http_api import HttpResponse

    method = str(method or "GET").upper()
    body = body.encode("utf-8") if isinstance(body, str) else body
    headers = {str(k): str(v) for k, v in (headers or {}).items()}
    original_url = str(url)
    current_url = urllib.parse.urldefrag(original_url)[0]
    history: list[str] = []
    visited = {current_url}
    for hop in range(MAX_REDIRECTS + 1):
        try:
            origin = http_origin(current_url)
            outgoing = prepare_request(method, current_url, dict(headers), body) if prepare_request else dict(headers)
            response = yield method, current_url, outgoing, body
        except Exception as exc:
            return HttpResponse(
                0,
                b"",
                {},
                error=str(exc),
                request_url=original_url,
                final_url=current_url,
                redirect_history=tuple(history),
            )
        response = replace(
            response,
            request_url=original_url,
            final_url=response.final_url or current_url,
            redirect_history=tuple(history) or response.redirect_history,
        )
        if response.error or response.status not in REDIRECT_STATUSES:
            return response
        location = next((v for k, v in response.headers.items() if k.lower() == "location"), "")
        if not location:
            return response
        try:
            destination = urllib.parse.urldefrag(urllib.parse.urljoin(current_url, location))[0]
            cross_origin = origin != http_origin(destination)
        except ValueError as exc:
            return replace(response, error=str(exc))
        if cross_origin and not allow_cross_origin:
            return replace(response, error=f"cross-origin redirect blocked: {current_url} -> {destination}")
        if destination in visited:
            return replace(response, error="redirect loop detected")
        if hop == MAX_REDIRECTS:
            return replace(response, error=f"redirect limit exceeded ({MAX_REDIRECTS})")
        if cross_origin:
            headers = {
                k: v
                for k, v in headers.items()
                if k.lower() != "host" and (preserve_authorization or k.lower() != "authorization")
            }
        if (response.status == 303 and method != "HEAD") or (response.status in {301, 302} and method == "POST"):
            method, body = "GET", None
            headers = {
                k: v
                for k, v in headers.items()
                if k.lower() not in {"content-length", "content-type", "transfer-encoding"}
            }
        history.append(current_url)
        visited.add(destination)
        current_url = destination
    raise AssertionError("unreachable")


def follow_redirects(
    send: RequestSender,
    method: str,
    url: str,
    *,
    headers: Mapping[str, str] | None = None,
    body: bytes | str | None = None,
    allow_cross_origin: bool = True,
    preserve_authorization: bool = True,
    prepare_request: RequestPreparer | None = None,
) -> HttpResponse:
    """Drive the shared redirect policy with a synchronous sender."""
    steps = _redirect_requests(
        method,
        url,
        headers=headers,
        body=body,
        allow_cross_origin=allow_cross_origin,
        preserve_authorization=preserve_authorization,
        prepare_request=prepare_request,
    )
    try:
        request = next(steps)
        while True:
            try:
                response = send(*request)
            except Exception as exc:
                request = steps.throw(exc)
            else:
                request = steps.send(response)
    except StopIteration as result:
        return result.value
    finally:
        steps.close()


async def follow_redirects_async(
    send: Callable[[str, str, dict[str, str], bytes | None], Awaitable[HttpResponse]],
    method: str,
    url: str,
    *,
    headers: Mapping[str, str] | None = None,
    body: bytes | str | None = None,
    allow_cross_origin: bool = True,
    preserve_authorization: bool = True,
    passthrough: tuple[type[Exception], ...] = (),
) -> HttpResponse:
    """Use the same decisions; cancellation and explicit fallback escape."""
    steps = _redirect_requests(
        method,
        url,
        headers=headers,
        body=body,
        allow_cross_origin=allow_cross_origin,
        preserve_authorization=preserve_authorization,
    )
    try:
        request = next(steps)
        while True:
            try:
                response = await send(*request)
            except Exception as exc:
                if isinstance(exc, passthrough):
                    raise
                request = steps.throw(exc)
            else:
                request = steps.send(response)
    except StopIteration as result:
        return result.value
    finally:
        steps.close()


class NoAutomaticRedirects(urllib.request.HTTPRedirectHandler):
    """Let the shared coordinator handle redirects, including POST 307/308."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None
