from __future__ import annotations

from types import SimpleNamespace

import pytest

from redposture_core.modules.grafana.actions import _looks_like_grafana_login
from redposture_core.modules.minio.actions import _is_minio_console
from tests.application_markup import application_page


def confirmed(product, body, headers=None):
    if product == "grafana":
        return _looks_like_grafana_login(200, body, headers or {})
    return _is_minio_console(
        SimpleNamespace(http_status=200, body=body.encode(), transport_error=None, truncated=False)
    )


@pytest.mark.parametrize("product,version", [("grafana", "11.1.6"), ("grafana", "13.0.2"), ("minio", None)])
def test_real_product_page_dom_is_a_positive_control(product, version):
    assert confirmed(product, application_page(product, version))


@pytest.mark.parametrize("product", ["grafana", "minio"])
@pytest.mark.parametrize("mode", ["title_only", "no_styles", "no_scripts", "no_root", "inert_assets", "query_assets"])
def test_title_without_a_real_application_is_insufficient(product, mode):
    page = application_page(product)
    if mode == "title_only":
        page = "<title>" + ("Grafana" if product == "grafana" else "MinIO Console") + "</title>"
    elif mode == "no_styles":
        page = page.replace('rel="stylesheet"', 'rel="alternate"')
    elif mode == "no_scripts":
        page = page.replace(" src=", " data-src=")
    elif mode == "no_root":
        page = page.replace('id="reactRoot"', 'id="other"').replace('id="root"', 'id="other"')
    elif mode == "inert_assets":
        page = (
            "<title>"
            + ("Grafana" if product == "grafana" else "MinIO Console")
            + "</title><template>"
            + page
            + "</template>"
        )
    elif mode == "query_assets":
        page = page.replace('href="', 'href="/documentation?example=').replace('src="', 'src="/documentation?example=')
    assert confirmed(product, page) is False


def test_cookie_without_product_application_is_not_grafana_proof():
    assert (
        confirmed("grafana", "<title>Other application</title>", {"Set-Cookie": "grafana_session=fixture; Path=/"})
        is False
    )
