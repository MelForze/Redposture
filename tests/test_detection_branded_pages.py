"""A documentation or maintenance page is not an operational product API/UI."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.test_http_redirect_policy import _serve
from tests.test_network_fingerprint_matrix import HTTP_PRODUCTS, _detect

BRANDS = {
    "airflow": "Apache Airflow",
    "consul": "Consul",
    "docker": "Docker",
    "elastic": "Elasticsearch",
    "etcd": "etcd",
    "gitlab": "GitLab",
    "grafana": "Grafana",
    "jenkins": "Jenkins",
    "keycloak": "Keycloak",
    "vault": "Vault",
    "nomad": "Nomad",
    "jupyter": "Jupyter Server",
    "kubeapi": "Kubernetes Dashboard",
    "minio": "MinIO Console",
    "proxmox": "Proxmox Virtual Environment",
    "qdrant": "Qdrant",
    "rabbitmq": "RabbitMQ Management",
    "docker-registry": "Docker Registry",
    "harbor": "Harbor",
    "nexus": "Sonatype Nexus Repository",
    "spark": "Spark Master",
    "yarn": "Hadoop YARN",
    "portainer": "Portainer",
}


@pytest.mark.parametrize("module", HTTP_PRODUCTS)
@pytest.mark.parametrize("kind", ["documentation", "maintenance", "generic_login"])
def test_branded_wildcard_page_does_not_confirm_service(module, kind):
    brand = BRANDS[module]
    title = brand + " integration guide" if kind == "documentation" else brand
    text = (
        "Integration reference only"
        if kind == "documentation"
        else "Maintenance: application is not installed on this endpoint"
    )
    form = (
        '<form action="/login"><input name="username"><input name="password"></form>' if kind == "generic_login" else ""
    )
    body = f"<html><head><title>{title}</title></head><body><h1>{text}</h1>{form}</body></html>".encode()
    with _serve(lambda *a: (200, {"Content-Type": "text/html"}, body)) as (base, calls):
        detected, record = _detect(module, int(base.rsplit(":", 1)[1]))
    assert not detected, (module, kind, record)
    assert calls


def test_branded_negative_corpus_matches_all_http_modules():
    assert set(BRANDS) == set(HTTP_PRODUCTS)


REAL_DOCUMENTATION = json.loads(
    (Path(__file__).parent / "fixtures/detection_pages/foreign-documentation.json").read_text()
)


@pytest.mark.parametrize("module", HTTP_PRODUCTS)
@pytest.mark.parametrize("page", REAL_DOCUMENTATION, ids=lambda page: page["product"])
def test_actual_documentation_dom_is_not_product_api_or_ui(module, page):
    assert len(page["source_sha256"]) == 64 and page["source_bytes"] > len(page["markup"])
    body = page["markup"].encode()
    with _serve(lambda *args: (200, {"Content-Type": "text/html"}, body)) as (base, calls):
        detected, record = _detect(module, int(base.rsplit(":", 1)[1]))
    assert not detected, (module, page["source_url"], record)
    assert calls
