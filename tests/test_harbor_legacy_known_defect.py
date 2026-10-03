"""Harbor 1.8.x Basic identity verification regressions."""

from __future__ import annotations

import pytest

from redposture_core.modules.registry import actions


def test_harbor_18_uses_legacy_identity_endpoint_after_v2_404(monkeypatch: pytest.MonkeyPatch) -> None:
    requests: list[str] = []

    def request(_host: str, _port: int, _method: str, path: str, _timeout: float, **_kwargs: object):
        requests.append(path)
        if path == "/api/v2.0/users/current":
            return 404, b"not found", {}, None
        if path == "/api/users/current":
            return 200, b'{"user_id":1,"username":"admin"}', {}, None
        pytest.fail(f"unexpected endpoint: {path}")

    monkeypatch.setattr(actions, "_http_request", request)
    verified, reason = actions._verify_registry_credential(
        "harbor", "127.0.0.1", 18280, 5.0, "admin", "Harbor12345", None, anonymous_probe=None
    )
    assert verified is True and reason is None
    assert requests == ["/api/v2.0/users/current", "/api/users/current"]


@pytest.mark.parametrize(
    ("legacy_status", "legacy_body", "expected"),
    [
        (401, b"unauthorized", False),
        (200, b'{"version":"1.8.3"}', None),
        (200, b'{"user_id":true,"username":"admin"}', None),
        (200, b'{"user_id":1,"username":"someone-else"}', None),
    ],
)
def test_harbor_legacy_identity_requires_matching_user(
    monkeypatch: pytest.MonkeyPatch, legacy_status: int, legacy_body: bytes, expected: bool | None
) -> None:
    def request(_host: str, _port: int, _method: str, path: str, _timeout: float, **_kwargs: object):
        if path == "/api/v2.0/users/current":
            return 404, b"not found", {}, None
        if path == "/api/users/current":
            return legacy_status, legacy_body, {}, None
        pytest.fail(f"unexpected endpoint: {path}")

    monkeypatch.setattr(actions, "_http_request", request)
    verified, _reason = actions._verify_registry_credential(
        "harbor", "127.0.0.1", 18280, 5.0, "admin", "guess", None, anonymous_probe=None
    )
    assert verified is expected
