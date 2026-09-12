from __future__ import annotations

from types import SimpleNamespace
from urllib.parse import urlsplit

from redposture_core.clients.http_api import HttpResponse
from redposture_core.modules.etcd import actions as etcd
from redposture_core.modules.gitlab import actions as gitlab
from redposture_core.modules.grafana import actions as grafana
from redposture_core.modules.proxmox import actions as proxmox
from redposture_core.modules.qdrant import actions as qdrant
from redposture_core.modules.registry import actions as registry


class HttpsRequiredPool:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    def request(self, method: str, url: str, **_kwargs: object) -> HttpResponse:
        scheme = urlsplit(url).scheme
        self.calls.append((method, scheme))
        if scheme == "http":
            return HttpResponse(400, b"Client sent an HTTP request to an HTTPS server.", {}, final_url=url)
        return HttpResponse(200, b"{}", {}, final_url=url)

    def close(self) -> None:
        return None


def test_grafana_discovery_upgrades_exact_https_required_response() -> None:
    pool = HttpsRequiredPool()
    state = grafana.GrafanaLifecycleState(http=pool, scheme="http", host="service.local", port=3000)
    grafana._activate_grafana_transport(state)
    try:
        assert grafana._http_request("service.local", 3000, "/api/health", 1.0)[:2] == (200, "{}")
        assert state.scheme == "https"
        assert pool.calls == [("GET", "http"), ("GET", "https")]
    finally:
        delattr(grafana._THREAD_LOCAL_HTTP, "state")


def test_etcd_discovery_upgrades_exact_https_required_response() -> None:
    pool = HttpsRequiredPool()
    state = etcd._EtcdHttpLifecycle(pool=pool, scheme="http", host="service.local", port=2379)
    etcd._ETCD_HTTP_LOCAL.state = state
    try:
        assert etcd._http_json_request("service.local", 2379, "GET", "/version", 1.0) == (200, "{}")
        assert state.scheme == "https"
        assert pool.calls == [("GET", "http"), ("GET", "https")]
    finally:
        delattr(etcd._ETCD_HTTP_LOCAL, "state")


def test_qdrant_discovery_upgrades_exact_https_required_response() -> None:
    pool = HttpsRequiredPool()
    state = qdrant.QdrantLifecycleState(http=pool, scheme="http", host="service.local", port=6333)
    qdrant._activate_qdrant_transport(state)
    try:
        assert qdrant._http_json_request("service.local", 6333, "GET", "/collections", 1.0) == (200, {}, None)
        assert state.scheme == "https"
        assert pool.calls == [("GET", "http"), ("GET", "https")]
    finally:
        delattr(qdrant._THREAD_LOCAL_TRANSPORT, "state")


def test_registry_discovery_upgrades_exact_https_required_response() -> None:
    pool = HttpsRequiredPool()
    state = registry.RegistryLifecycleState(http=pool, scheme="http", host="service.local", port=5000)
    registry._activate_registry_transport(state)
    try:
        assert registry._http_request("service.local", 5000, "GET", "/v2/", 1.0) == (200, b"{}", {}, None)
        assert state.scheme == "https"
        assert pool.calls == [("GET", "http"), ("GET", "https")]
    finally:
        delattr(registry._THREAD_LOCAL_HTTP, "state")


def test_gitlab_discovery_upgrades_exact_https_required_response() -> None:
    pool = HttpsRequiredPool()
    state = gitlab.GitLabLifecycleState(http=pool, scheme="http", host="service.local", port=8080)
    gitlab._activate_gitlab_transport(state)
    try:
        assert gitlab._http_request("service.local", 8080, "GET", "/api/v4/version", 1.0, use_https=False) == (
            200,
            b"{}",
            {},
            None,
        )
        assert state.scheme == "https"
        assert pool.calls == [("GET", "http"), ("GET", "https")]
    finally:
        delattr(gitlab._THREAD_LOCAL_HTTP, "state")


def test_proxmox_discovery_upgrades_exact_https_required_response() -> None:
    class ProxmoxPool(HttpsRequiredPool, proxmox.HttpSessionPool):
        def __init__(self) -> None:
            HttpsRequiredPool.__init__(self)

    pool = ProxmoxPool()
    origin = SimpleNamespace(scheme="http", host="service.local", port=8006, origin_resolved=False)
    proxmox.activate_proxmox_transport(pool, origin)
    try:
        assert proxmox._proxmox_request_once(
            "service.local",
            8006,
            "/version",
            1.0,
            pve_api_token="",
            use_https=False,
            insecure=True,
            proxy=None,
        ) == (200, b"{}", {}, None)
        assert origin.scheme == "https"
        assert pool.calls == [("GET", "http"), ("GET", "https")]
    finally:
        proxmox.activate_proxmox_transport(None, None)
