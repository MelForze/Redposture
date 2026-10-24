import pytest

from redposture_core import web_panels
from redposture_core.clients.http_api import HttpResponse


@pytest.mark.parametrize(
    "product,header,login_path", [("kibana", "kbn", "/login"), ("opensearch_dashboards", "osd", "/app/login")]
)
def test_protected_ui_keeps_its_own_version_header(monkeypatch, product, header, login_path):
    routes = {
        "/api/status": HttpResponse(401, b"{}", {header + "-name": "qa", header + "-version": "2.19.1"}),
        login_path: HttpResponse(
            200,
            ("<title>" + ("Kibana" if product == "kibana" else "OpenSearch Dashboards") + "</title>").encode(),
            {header + "-name": "qa"},
        ),
    }
    monkeypatch.setattr(web_panels, "_get", lambda pool, base, path: routes[path])
    found = web_panels._fingerprints("elastic", object(), "http://qa")
    assert found and found[:2] == (product, "2.19.1")


def test_generic_server_header_cannot_supply_ui_backend_version(monkeypatch):
    routes = {
        "/api/status": HttpResponse(401, b"{}", {"osd-name": "qa", "Server": "OpenSearch/2.19.1"}),
        "/app/login": HttpResponse(200, b"<title>OpenSearch Dashboards</title>", {"osd-name": "qa"}),
    }
    monkeypatch.setattr(web_panels, "_get", lambda pool, base, path: routes[path])
    assert web_panels._fingerprints("elastic", object(), "http://qa")[1] is None
