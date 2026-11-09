"""Image Config sources respect endpoint selection and full catalog fallback."""

from types import SimpleNamespace

import pytest

from redposture_core.modules.portainer.discover import discover_image_configs
from redposture_core.storage_discovery import DiscoveryCollector
from tests.test_docker_discover import Pool


@pytest.mark.parametrize("partial", [False, True])
def test_image_catalog_and_configs_use_selected_environment_only(partial):
    Pool.calls = []
    Pool.routes = {
        "/api/endpoints/2/docker/images/json": (200, [{"Id": "i"}, {"Id": "i"}]),
        "/api/endpoints/2/docker/images/i/json": (200, {"Config": {"Env": ["PASSWORD=inactive-image-only!42"]}}),
    }
    ctx = SimpleNamespace(host="qa", port=9000, args=SimpleNamespace(discover_time=30))
    collector = DiscoveryCollector("portainer", ctx, {"status": "valid_credentials"})
    inventory = {"images": {"records": [{"environment": 2, "Id": "i"}], "partial": partial}}
    discover_image_configs(collector, Pool(), "http://qa", {}, 1, {2}, inventory)
    report = collector.result()
    assert report["status"] == "complete"
    assert [str(f["value"]) for f in report["findings"]] == ["inactive-image-only!42"]
    assert Pool.calls.count("/api/endpoints/2/docker/images/i/json") == 1
    assert ("/api/endpoints/2/docker/images/json" in Pool.calls) == partial


def test_denied_image_inspection_is_unavailable_not_false_complete():
    Pool.calls = []
    Pool.routes = {"/api/endpoints/2/docker/images/i/json": (403, {"password": "not-readable-error"})}
    ctx = SimpleNamespace(host="qa", port=9000, args=SimpleNamespace(discover_time=30))
    c = DiscoveryCollector("portainer", ctx, {"status": "valid_credentials"})
    discover_image_configs(c, Pool(), "http://qa", {}, 1, {2}, {"images": {"records": [{"environment": 2, "Id": "i"}]}})
    result = c.result()
    assert result["status"] == "unavailable" and not result["findings"]
    assert next(s for s in result["sources"] if s["id"] == "portainer.image_inspect")["denied"] == 1
