"""Cross-product registry detection must preserve the selected product identity."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from redposture_core.modules.registry import actions

_PRODUCTS = ("docker-registry", "harbor", "nexus", "gitlab")


@pytest.mark.parametrize("selected", _PRODUCTS)
@pytest.mark.parametrize("actual", _PRODUCTS)
def test_registry_detection_confirms_only_its_own_product(
    monkeypatch: pytest.MonkeyPatch, selected: str, actual: str
) -> None:
    paths: list[str] = []

    def request(_host: str, _port: int, _method: str, path: str, _timeout: float, **_kwargs: object):
        paths.append(path)
        assert path == "/v2/"
        if actual == "nexus":
            return 404, b"", {}, None
        if actual == "harbor":
            return (
                401,
                b'{"errors":[{"code":"UNAUTHORIZED"}]}',
                {"www-authenticate": 'Bearer realm="https://host/service/token",service="harbor-registry"'},
                None,
            )
        if actual == "gitlab":
            return (
                401,
                b'{"errors":[{"code":"UNAUTHORIZED"}]}',
                {"www-authenticate": 'Bearer realm="https://host/jwt/auth",service="container_registry"'},
                None,
            )
        return 200, b"{}", {"docker-distribution-api-version": "registry/2.0"}, None

    monkeypatch.setattr(actions, "_http_request", request)
    monkeypatch.setattr(
        actions,
        "_fetch_nexus_info",
        lambda *_args, **_kwargs: ({"version": "3.72.0"}, None) if actual == "nexus" else (None, "not nexus"),
    )
    monkeypatch.setattr(
        actions,
        "_fetch_harbor_info",
        lambda *_args, **_kwargs: ({"harbor_version": "v2.11.1"}, None) if actual == "harbor" else (None, "not harbor"),
    )
    monkeypatch.setattr(actions, "_fetch_nexus_repository_records", lambda *_args, **_kwargs: ([], None))
    ctx = SimpleNamespace(
        host="host",
        port=5000,
        args=SimpleNamespace(timeout=1.0, retries=0),
        credential=SimpleNamespace(username=None, password=None, token=None),
        lifecycle_state=actions.RegistryLifecycleState(),
    )
    options = {
        "product": selected,
        "nexus": selected == "nexus",
        "harbor": selected == "harbor",
        "gitlab": selected == "gitlab",
        "docker": selected == "docker-registry",
        "show_images": False,
        "show_tags": False,
        "repository": None,
        "tag": None,
        "metadata": False,
        "assets": False,
        "inspect": False,
        "image": None,
        "download": False,
    }
    record = actions.detect_registry(ctx, options)

    assert paths == ["/v2/"]
    assert record["is_registry"] is (selected == actual)
    assert record["status"] in ({"open_no_auth", "auth_required"} if selected == actual else {"not_registry"})
    if selected == actual:
        assert record["credential_verification_status"] in {"available", "unavailable"}
    else:
        assert record["auth_required"] is None
