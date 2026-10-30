"""Sessions are scoped to the verified identity, origin and mount."""

from __future__ import annotations

import pytest

from redposture_core.modules.grafana import actions


@pytest.mark.parametrize(
    "cookie",
    [
        "grafana_session=x; Domain=other.test; Path=/",
        "grafana_session=x; Path=/other",
        "grafana_session=x; Secure; Path=/",
        "grafana_session=; Path=/",
        "grafana_session=x; Max-Age=0; Path=/",
        "grafana_session=x; Expires=Wed, 01 Jan 2020 00:00:00 GMT; Path=/",
    ],
)
def test_grafana_login_ignores_unusable_session_cookies(cookie: str) -> None:
    assert actions._grafana_login_cookie({"Set-Cookie": cookie}, "http://qa.test:3000/grafana/login") is None


def test_selected_session_replay_requires_identity_origin_and_path(monkeypatch: pytest.MonkeyPatch) -> None:
    authorization = actions._auth_header("alice", "correct")
    state = actions.GrafanaLifecycleState(
        selected_session={
            "authorization": authorization,
            "origin": "http://qa.test:3000",
            "path": "/grafana",
            "cookie": "grafana_session=opaque",
        }
    )
    monkeypatch.setattr(actions._THREAD_LOCAL_HTTP, "state", state, raising=False)
    monkeypatch.setattr(actions._THREAD_LOCAL_HTTP, "verifying_credentials", False, raising=False)
    headers = {"Authorization": authorization}
    assert actions._grafana_request_headers(headers, "http://qa.test:3000/grafana/api/user") == {
        "Cookie": "grafana_session=opaque"
    }
    for url in (
        "http://other.test:3000/grafana/api/user",
        "https://qa.test:3000/grafana/api/user",
        "http://qa.test:3000/grafana-other/api/user",
    ):
        assert actions._grafana_request_headers(headers, url) == headers
    wrong = {"Authorization": actions._auth_header("alice", "wrong")}
    assert actions._grafana_request_headers(wrong, "http://qa.test:3000/grafana/api/user") == wrong
    monkeypatch.setattr(actions._THREAD_LOCAL_HTTP, "verifying_credentials", True)
    assert actions._grafana_request_headers(headers, "http://qa.test:3000/grafana/api/user") == headers
