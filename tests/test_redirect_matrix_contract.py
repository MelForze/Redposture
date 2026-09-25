"""Pure redirect-policy matrix: status, URL form, origin and credentials."""

from __future__ import annotations

import pytest

from redposture_core.clients.http_api import HttpResponse
from redposture_core.clients.http_redirects import follow_redirects


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
@pytest.mark.parametrize(
    ("location", "expected"),
    [
        ("/next?q=a%2Fb", "http://source.test/next?q=a%2Fb"),
        ("next", "http://source.test/base/next"),
        ("//other.test:8443/next", "http://other.test:8443/next"),
        ("https://other.test/next#ignored", "https://other.test/next"),
    ],
)
def test_redirect_destination_resolution_matrix(status: int, location: str, expected: str) -> None:
    calls: list[str] = []

    def send(_method: str, url: str, _headers: dict[str, str], _body: bytes | None) -> HttpResponse:
        calls.append(url)
        return HttpResponse(status, b"", {"Location": location}) if len(calls) == 1 else HttpResponse(204, b"", {})

    response = follow_redirects(send, "GET", "http://source.test/base/start#fragment")

    assert response.status == 204
    assert calls == ["http://source.test/base/start", expected]
    assert response.redirect_history == ("http://source.test/base/start",)
    assert response.final_url == expected


@pytest.mark.parametrize("preserve_authorization", [False, True])
def test_cross_origin_redirect_credential_policy_is_explicit(preserve_authorization: bool) -> None:
    seen: list[dict[str, str]] = []

    def send(_method: str, _url: str, headers: dict[str, str], _body: bytes | None) -> HttpResponse:
        seen.append(headers)
        if len(seen) == 1:
            return HttpResponse(302, b"", {"Location": "https://destination.test/final"})
        return HttpResponse(200, b"ok", {})

    response = follow_redirects(
        send,
        "GET",
        "http://source.test/start",
        headers={"Authorization": "Bearer secret", "Host": "forced.test", "X-Trace": "yes"},
        preserve_authorization=preserve_authorization,
    )

    assert response.status == 200
    assert "Host" not in seen[1]
    assert seen[1]["X-Trace"] == "yes"
    assert ("Authorization" in seen[1]) is preserve_authorization


def test_cross_origin_redirect_can_be_blocked_before_destination_request() -> None:
    calls: list[str] = []

    def send(_method: str, url: str, _headers: dict[str, str], _body: bytes | None) -> HttpResponse:
        calls.append(url)
        return HttpResponse(307, b"", {"Location": "https://other.test/action"})

    response = follow_redirects(send, "POST", "http://source.test/action", allow_cross_origin=False)

    assert response.error == "cross-origin redirect blocked: http://source.test/action -> https://other.test/action"
    assert calls == ["http://source.test/action"]


def test_redirect_limit_and_signature_preparer_cover_every_hop() -> None:
    prepared: list[tuple[str, str]] = []
    calls = 0

    def prepare(method: str, url: str, headers: dict[str, str], _body: bytes | None) -> dict[str, str]:
        prepared.append((method, url))
        return {**headers, "X-Signed-For": url}

    def send(_method: str, url: str, headers: dict[str, str], _body: bytes | None) -> HttpResponse:
        nonlocal calls
        calls += 1
        assert headers["X-Signed-For"] == url
        return HttpResponse(308, b"", {"Location": f"/hop-{calls}"})

    response = follow_redirects(send, "PUT", "https://source.test/start", body=b"payload", prepare_request=prepare)

    assert response.error == "redirect limit exceeded (5)"
    assert calls == 6
    assert len(prepared) == calls
