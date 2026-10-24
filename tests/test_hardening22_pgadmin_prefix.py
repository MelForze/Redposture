"""pgAdmin identity proof must keep the exact mounted browser path."""

from types import SimpleNamespace

import pytest

from redposture_core import web_panels
from redposture_core.clients.http_api import HttpResponse


@pytest.mark.parametrize("prefix", ["", "/qa", "/nested/admin"])
@pytest.mark.parametrize("landing", ["browser", "login", "foreign-prefix"])
def test_pgadmin_authentication_checks_browser_under_the_confirmed_prefix(
    monkeypatch: pytest.MonkeyPatch, prefix: str, landing: str
) -> None:
    base = "https://127.0.0.1" + prefix

    def get(_pool: object, _base: str, path: str, **kwargs: object) -> HttpResponse:
        if path == "/login":
            return HttpResponse(
                200, b'<input name="csrf_token" type="hidden" value="fresh-token">', {"Set-Cookie": "sid=pre"}
            )
        final = (
            base + "/browser/"
            if landing == "browser"
            else base + "/login"
            if landing == "login"
            else "https://127.0.0.1/other/browser/"
        )
        return HttpResponse(200, b"pgadmin.browser", {}, final_url=final)

    monkeypatch.setattr(web_panels, "_get", get)
    monkeypatch.setattr(
        web_panels,
        "_post",
        lambda *a, **kw: HttpResponse(302, b"", {"Set-Cookie": "sid=authenticated", "Location": prefix + "/browser/"}),
    )
    ctx = SimpleNamespace(args=SimpleNamespace(), credential=SimpleNamespace(username="reader", password="valid-pass"))
    result = web_panels.authenticate_panel(ctx, {"ui_product": "pgadmin", "ui": {"endpoint": base}})
    assert (result.get("provided_credentials_ok") is True) is (landing == "browser"), result
