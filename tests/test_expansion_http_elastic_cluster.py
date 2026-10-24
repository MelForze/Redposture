"""Cluster health survives failed node inspection; settings need both surfaces."""

from __future__ import annotations

import json
from typing import Any

import pytest

from redposture_core.modules.elastic import actions as elastic


@pytest.mark.parametrize("surface", ["health", "nodes"])
@pytest.mark.parametrize("fault", ["transport", "denied", "server", "invalid_json"])
def test_elastic_cluster_failure_retains_only_verified_surfaces(
    monkeypatch: pytest.MonkeyPatch, surface: str, fault: str
) -> None:
    paths = []
    health = {"cluster_name": "qa", "status": "green"}
    faults = {
        "transport": (0, b"", {}, "reset"),
        "denied": (403, b"{}", {}, None),
        "server": (503, b"{}", {}, None),
        "invalid_json": (200, b"invalid", {}, None),
    }

    def request(host: str, port: int, path: str, timeout: float, **kwargs: Any) -> Any:
        paths.append(path)
        assert kwargs["headers"] == {"Authorization": "Bearer verified"}
        if (surface == "health" and path == "/_cluster/health") or (surface == "nodes" and path.startswith("/_nodes")):
            return faults[fault]
        return 200, json.dumps(health).encode(), {}, None

    monkeypatch.setattr(elastic, "_elastic_request", request)
    cluster, nodes, error = elastic._fetch_cluster_data(
        "qa", 9200, 1, scheme="https", insecure=False, ca_file=None, auth_headers={"Authorization": "Bearer verified"}
    )
    assert cluster == (health if surface == "nodes" else None) and nodes is None and error
    assert len(paths) == (2 if surface == "nodes" else 1)
    assert (
        error
        == {
            "transport": "reset",
            "denied": "Access Denied",
            "server": "nodes status=503" if surface == "nodes" else "cluster health status=503",
            "invalid_json": "invalid nodes payload" if surface == "nodes" else "invalid cluster health payload",
        }[fault]
    )


@pytest.mark.parametrize("surface", ["cluster", "nodes"])
@pytest.mark.parametrize("fault", ["transport", "denied", "server", "invalid_json"])
def test_elastic_misconfiguration_does_not_fabricate_findings_from_incomplete_settings(
    monkeypatch: pytest.MonkeyPatch, surface: str, fault: str
) -> None:
    paths = []
    faults = {
        "transport": (0, b"", {}, "reset"),
        "denied": (403, b"{}", {}, None),
        "server": (503, b"{}", {}, None),
        "invalid_json": (200, b"invalid", {}, None),
    }

    def request(host: str, port: int, path: str, timeout: float, **kwargs: Any) -> Any:
        paths.append(path)
        if (surface == "cluster" and path.startswith("/_cluster")) or (
            surface == "nodes" and path.startswith("/_nodes")
        ):
            return faults[fault]
        return 200, b'{"persistent":{"http.cors.enabled":"true","http.cors.allow-origin":"*"}}', {}, None

    monkeypatch.setattr(elastic, "_elastic_request", request)
    findings, error = elastic._fetch_cluster_misconfig_findings(
        "qa", 9200, 1, scheme="http", insecure=False, ca_file=None, auth_headers={}
    )
    assert findings is None and error
    assert len(paths) == (2 if surface == "nodes" else 1)
    assert (
        error
        == {
            "transport": "reset",
            "denied": "Access Denied",
            "server": f"{surface} settings status=503",
            "invalid_json": f"invalid {surface} settings payload",
        }[fault]
    )
