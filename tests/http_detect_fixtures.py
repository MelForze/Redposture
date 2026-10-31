"""Small independently specified product responses for read-only detection tests."""

import json
from urllib.parse import urlsplit

from redposture_core.clients.http_api import HttpResponse


def detection_response(module, url):
    path = urlsplit(url).path
    status = 404
    data: object = {}
    headers = {"Content-Type": "application/json"}
    if module == "grafana" and path == "/api/health":
        status, data = 200, {"database": "ok", "version": "11.2.0", "commit": "abcdef"}
    elif module == "qdrant":
        if path == "/":
            status, data = 200, {"title": "qdrant", "version": "1.11.0"}
        elif path == "/collections":
            status, data = 200, {"result": {"collections": []}, "status": "ok", "time": 0.1}
    elif module == "rabbitmq":
        if path == "/api/overview":
            status, data = 200, {"rabbitmq_version": "4.0.1", "erlang_version": "27"}
        elif path == "/api/whoami":
            status, data = 200, {"name": "guest", "tags": ["administrator"]}
    elif module == "etcd":
        if path == "/version":
            status, data = 200, {"etcdserver": "3.5.16", "etcdcluster": "3.5.0"}
        elif path == "/health":
            status, data = 200, {"health": "true"}
        elif path.startswith("/v3/"):
            status, data = 200, {"header": {"cluster_id": "123"}, "kvs": []}
        headers["X-Etcd-Cluster-ID"] = "123"
    elif module == "proxmox" and path.startswith("/api2/json"):
        status, data = 200, {"data": [{"subdir": "ticket"}]}
        headers["Server"] = "pve-api-daemon/3.0"
    elif module in {"docker-registry", "gitlab"}:
        if path == "/v2/":
            status = 200 if module == "docker-registry" else 401
            headers["Docker-Distribution-Api-Version"] = "registry/2.0"
            if module == "gitlab":
                headers["WWW-Authenticate"] = (
                    f'Bearer realm="http://{urlsplit(url).netloc}/jwt/auth",service="container_registry"'
                )
        elif module == "gitlab" and path == "/api/v4/version":
            status, data = 200, {"version": "17.4.0", "revision": "abcdef"}
    elif module == "consul":
        routes = {
            "/v1/status/leader": "127.0.0.1:8300",
            "/v1/status/peers": ["127.0.0.1:8300"],
            "/v1/kv/": ["qa"],
            "/v1/catalog/services": {"consul": []},
            "/v1/agent/members": [{"Name": "qa"}],
            "/v1/agent/self": {"Config": {"Version": "1.20.0"}},
        }
        if path in routes:
            status, data = 200, routes[path]
        headers["X-Consul-Index"] = "1"
    elif module == "kubeapi":
        if path == "/version":
            status, data = 200, {"major": "1", "minor": "31", "gitVersion": "v1.31.2"}
        elif path == "/api":
            status, data = 200, {"kind": "APIVersions", "apiVersion": "v1", "versions": ["v1"]}
        elif path.endswith("/namespaces"):
            status, data = 200, {"kind": "NamespaceList", "apiVersion": "v1", "items": []}
        elif path.endswith("/pods"):
            status, data = 200, {"kind": "PodList", "apiVersion": "v1", "items": []}
    elif module == "minio":
        headers["Server"] = "MinIO"
        if path == "/minio/health/live":
            return HttpResponse(200, b"", headers, request_url=url, final_url=url)
        return HttpResponse(403, b"<Error><Code>AccessDenied</Code></Error>", headers, request_url=url, final_url=url)
    elif module == "elastic" and path == "/":
        status, data = (
            200,
            {
                "cluster_name": "qa",
                "version": {"number": "8.17.3", "build_flavor": "default"},
                "tagline": "You Know, for Search",
            },
        )
        headers["X-Elastic-Product"] = "Elasticsearch"
    return HttpResponse(status, json.dumps(data).encode(), headers, request_url=url, final_url=url)
