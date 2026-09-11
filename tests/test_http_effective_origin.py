from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from redposture_core.clients.http_api import HttpResponse, http_target_context
from redposture_core.modules.airflow import actions as airflow
from redposture_core.modules.consul import actions as consul
from redposture_core.modules.elastic import actions as elastic
from redposture_core.modules.etcd import actions as etcd
from redposture_core.modules.gitlab import actions as gitlab
from redposture_core.modules.grafana import actions as grafana
from redposture_core.modules.kubeapi import actions as kubeapi
from redposture_core.modules.proxmox import actions as proxmox
from redposture_core.modules.proxmox import stage as proxmox_stage
from redposture_core.modules.qdrant import actions as qdrant
from redposture_core.modules.rabbitmq import actions as rabbitmq
from redposture_core.modules.registry import actions as registry


class SequencePool:
    def __init__(self, responses: list[HttpResponse]) -> None:
        self.responses = list(responses)
        self.calls: list[str] = []

    def request(self, _method: str, url: str, **_kwargs: Any) -> HttpResponse:
        self.calls.append(url)
        return self.responses.pop(0)

    def close(self) -> None:
        pass


def _redirect(source: str, destination: str, body: bytes = b"{}", status: int = 200) -> HttpResponse:
    return HttpResponse(
        status,
        body,
        {},
        request_url=source,
        final_url=destination,
        redirect_history=(source,),
    )


def test_airflow_and_rabbitmq_reuse_redirected_origin(monkeypatch) -> None:
    airflow_source = "http://source.local:8080/api/v2/version"
    airflow_pool = SequencePool([_redirect(airflow_source, "https://airflow.local:9443/api/v2/version")])
    monkeypatch.setattr(airflow, "HttpSessionPool", lambda **_kwargs: airflow_pool)
    airflow_state = airflow.AirflowLifecycleState(
        SimpleNamespace(timeout=1, retries=0), "source.local", 8080, scheme="http"
    )
    assert airflow_state.resolve_scheme() == "https"
    assert (airflow_state.host, airflow_state.port) == ("airflow.local", 9443)

    rabbit_source = "http://source.local:15672/api/overview"
    rabbit_pool = SequencePool([_redirect(rabbit_source, "https://rabbit.local:15671/api/overview", status=401)])
    monkeypatch.setattr(rabbitmq, "HttpSessionPool", lambda **_kwargs: rabbit_pool)
    rabbit_ctx = SimpleNamespace(
        args=SimpleNamespace(timeout=1, retries=0),
        host="source.local",
        port=15672,
        target=SimpleNamespace(scheme="http", path=""),
    )
    rabbit_state = rabbitmq.RabbitMQLifecycleState(rabbit_ctx)
    rabbit_state.resolve()
    assert (rabbit_state.scheme, rabbit_state.host, rabbit_state.port) == ("https", "rabbit.local", 15671)


def test_grafana_qdrant_registry_and_gitlab_reuse_redirected_origin() -> None:
    target = SimpleNamespace(scheme="http", path="")

    grafana_pool = SequencePool(
        [
            _redirect("http://source.local:3000/api/health", "https://grafana.local:3443/api/health"),
            HttpResponse(200, b"{}", {}),
        ]
    )
    grafana_state = grafana.GrafanaLifecycleState(http=grafana_pool, scheme="http", host="source.local", port=3000)
    grafana._activate_grafana_transport(grafana_state)
    with http_target_context(target):
        grafana._http_request("source.local", 3000, "/api/health", 1)
        grafana._http_request("source.local", 3000, "/api/user", 1)
    assert grafana_pool.calls[-1] == "https://grafana.local:3443/api/user"
    grafana._THREAD_LOCAL_HTTP.state = None

    qdrant_pool = SequencePool(
        [
            _redirect("http://source.local:6333/", "https://qdrant.local:6443/"),
            HttpResponse(200, b"{}", {}),
        ]
    )
    qdrant_state = qdrant.QdrantLifecycleState(http=qdrant_pool, scheme="http", host="source.local", port=6333)
    qdrant._activate_qdrant_transport(qdrant_state)
    with http_target_context(target):
        qdrant._http_json_request("source.local", 6333, "GET", "/", 1)
        qdrant._http_json_request("source.local", 6333, "GET", "/collections", 1)
    assert qdrant_pool.calls[-1] == "https://qdrant.local:6443/collections"
    qdrant._THREAD_LOCAL_TRANSPORT.state = None

    registry_pool = SequencePool(
        [
            _redirect("http://source.local:5000/v2/", "https://registry.local:5443/v2/"),
            HttpResponse(200, b"{}", {}),
        ]
    )
    registry_state = registry.RegistryLifecycleState(http=registry_pool, scheme="http", host="source.local", port=5000)
    registry._activate_registry_transport(registry_state)
    with http_target_context(target):
        registry._http_request("source.local", 5000, "GET", "/v2/", 1)
        registry._http_request("source.local", 5000, "GET", "/v2/catalog", 1)
    assert registry_pool.calls[-1] == "https://registry.local:5443/v2/catalog"
    registry._THREAD_LOCAL_HTTP.state = None

    gitlab_pool = SequencePool(
        [
            _redirect("http://source.local:80/users/sign_in", "https://gitlab.local:443/users/sign_in"),
            HttpResponse(200, b"{}", {}),
        ]
    )
    gitlab_state = gitlab.GitLabLifecycleState(http=gitlab_pool, scheme="http", host="source.local", port=80)
    gitlab._activate_gitlab_transport(gitlab_state)
    with http_target_context(target):
        gitlab._http_request("source.local", 80, "GET", "/users/sign_in", 1, use_https=False)
        gitlab._http_request("source.local", 80, "GET", "/api/v4/user", 1, use_https=False)
    assert gitlab_pool.calls[-1] == "https://gitlab.local:443/api/v4/user"
    gitlab._THREAD_LOCAL_HTTP.state = None


def test_etcd_consul_and_proxmox_reuse_redirected_origin(monkeypatch) -> None:
    target = SimpleNamespace(scheme="http", path="")

    etcd_pool = SequencePool(
        [
            _redirect("http://source.local:2379/version", "https://etcd.local:2443/version"),
            HttpResponse(200, b"{}", {}),
        ]
    )
    etcd_state = etcd._EtcdHttpLifecycle(etcd_pool, scheme="http", host="source.local", port=2379)
    etcd._ETCD_HTTP_LOCAL.state = etcd_state
    try:
        with http_target_context(target):
            etcd._http_json_request("source.local", 2379, "GET", "/version", 1)
            etcd._http_json_request("source.local", 2379, "POST", "/v3/auth/authenticate", 1, payload={})
    finally:
        delattr(etcd._ETCD_HTTP_LOCAL, "state")
    assert etcd_pool.calls[-1] == "https://etcd.local:2443/v3/auth/authenticate"

    consul_pool = SequencePool(
        [
            _redirect("http://source.local:8500/v1/status/leader", "https://consul.local:8501/v1/status/leader"),
            HttpResponse(200, b'"127.0.0.1:8300"', {}),
        ]
    )
    monkeypatch.setattr(consul, "HttpSessionPool", SequencePool)
    consul_state = consul.ConsulLifecycleState(http=consul_pool, host="source.local", port=8500)
    with consul._ConsulLifecycleReplay(consul_state):
        consul._http_request("source.local", 8500, "GET", "/v1/status/leader", 1, use_https=False, insecure=True)
        consul._http_request("source.local", 8500, "GET", "/v1/agent/self", 1, use_https=False, insecure=True)
    assert consul_pool.calls[-1] == "https://consul.local:8501/v1/agent/self"

    proxmox_pool = SequencePool(
        [
            _redirect("http://source.local:8006/api2/json/access", "https://pve.local:8443/api2/json/access"),
            HttpResponse(200, b"{}", {}),
        ]
    )
    monkeypatch.setattr(proxmox, "HttpSessionPool", SequencePool)
    proxmox_state = proxmox_stage._ProxmoxLifecycleState(
        http=proxmox_pool, scheme="http", host="source.local", port=8006
    )
    proxmox.activate_proxmox_transport(proxmox_pool, proxmox_state)
    try:
        with http_target_context(target):
            kwargs = dict(pve_api_token="", insecure=True, proxy=None, auth_headers={})
            proxmox._proxmox_request_once("source.local", 8006, "/access", 1, use_https=False, **kwargs)
            proxmox._proxmox_request_once(
                "source.local", 8006, "/access/ticket", 1, use_https=False, method="POST", form={}, **kwargs
            )
    finally:
        proxmox.activate_proxmox_transport(None)
    assert proxmox_pool.calls[-1] == "https://pve.local:8443/api2/json/access/ticket"


def test_kubeapi_and_elastic_reuse_redirected_origin(monkeypatch) -> None:
    kube_calls: list[tuple[str, int, bool]] = []

    def fake_kube_get(host: str, port: int, *_args: Any, use_https: bool, **_kwargs: Any):
        kube_calls.append((host, port, use_https))
        headers = (
            {kubeapi._KUBE_EFFECTIVE_URL_HEADER: "https://kube.local:7443/version"} if len(kube_calls) == 1 else {}
        )
        return 200, {"major": "1", "minor": "30"}, headers, None

    monkeypatch.setattr(kubeapi, "_api_get_json", fake_kube_get)
    kube_state = kubeapi.KubeApiLifecycleState(use_https=False)
    kube_state.configure_transport("source.local", 8080, 1)
    kube_ctx = SimpleNamespace(args=SimpleNamespace(retries=0, timeout=1), host="source.local", port=8080)
    kubeapi._lifecycle_get_json_with_retries(kube_ctx, kube_state, "/version", response_size_cap=1024)
    kubeapi._lifecycle_get_json_with_retries(kube_ctx, kube_state, "/api", response_size_cap=1024)
    assert kube_calls[-1] == ("kube.local", 7443, True)

    elastic_calls: list[str] = []

    class FakeElasticClient:
        def __init__(self, *_args: Any, **_kwargs: Any) -> None:
            pass

        def request(self, _method: str, url: str, **_kwargs: Any) -> HttpResponse:
            elastic_calls.append(url)
            if len(elastic_calls) == 1:
                return _redirect(url, "https://elastic.local:9443/")
            return HttpResponse(200, b"{}", {})

    monkeypatch.setattr(elastic, "HttpApiClient", FakeElasticClient)
    elastic_state = elastic.ElasticLifecycleState()
    with http_target_context(SimpleNamespace(scheme="http", path="")):
        with elastic._elastic_session_scope(None, elastic_state):
            elastic._elastic_request("source.local", 9200, "/", 1, use_https=False, insecure=True, ca_file=None)
            elastic._elastic_request(
                "source.local", 9200, "/_security/_authenticate", 1, use_https=False, insecure=True, ca_file=None
            )
    assert elastic_calls[-1] == "https://elastic.local:9443/_security/_authenticate"
