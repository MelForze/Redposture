"""Basic is an explicit terminating-proxy scenario, not modern native K8s auth."""

from __future__ import annotations

import base64
import json

import pytest

from scripts import performance_http_fixtures as fixtures


def request(path, *, password=None, limited=False, method="GET", body=b"", authorization=None):
    reply = getattr(fixtures, "kube_basic_proxy_reply", None)
    assert callable(reply), "missing explicit Kubernetes Basic proxy peer"
    headers = {}
    if password is not None:
        headers[b"authorization"] = b"Basic " + base64.b64encode(("admin:" + password).encode())
    if authorization is not None:
        headers[b"authorization"] = authorization
    wire = reply(method, path, headers, body, valid_pair=("admin", "admin"), limited=limited)
    head, _, raw = wire.partition(b"\r\n\r\n")
    return int(head.split()[1]), head, json.loads(raw)


@pytest.mark.parametrize("password", [None, "incorrect"])
def test_no_or_wrong_basic_gets_explicit_challenge_and_kubernetes_unauthorized(password):
    status, headers, data = request("/api/v1/namespaces", password=password)
    assert status == 401 and b'WWW-Authenticate: Basic realm="Kubernetes QA proxy"' in headers
    assert data["apiVersion"] == "v1" and data["kind"] == "Status" and data["reason"] == "Unauthorized"


@pytest.mark.parametrize("limited", [False, True])
def test_identity_is_verified_independently_from_namespace_acl(limited):
    status, _, data = request("/api/v1/namespaces", password="admin", limited=limited)
    assert status == (403 if limited else 200)
    if not limited:
        assert [row["metadata"]["name"] for row in data["items"]] == ["platform", "billing", "observability"]
    status, _, data = request(
        "/apis/authentication.k8s.io/v1/selfsubjectreviews",
        password="admin",
        limited=limited,
        method="POST",
        body=b'{"apiVersion":"authentication.k8s.io/v1","kind":"SelfSubjectReview"}',
    )
    assert status == 201 and data["status"]["userInfo"]["username"] == "admin"


@pytest.mark.parametrize("authorization", [b"Basic !!!!", b"Basic " + base64.b64encode(b"nocolon"), b"Bearer random"])
def test_arbitrary_headers_do_not_prove_basic_identity(authorization):
    assert request("/api/v1/namespaces", authorization=authorization)[0] == 401


def test_discovery_and_mutating_paths_remain_separate():
    assert request("/version")[0] == 200
    assert request("/api")[0] == 200
    assert request("/api/v1/pods", password="admin", method="POST", body=b"{}")[0] == 403
    assert request("/not-a-route", password="admin")[0] == 404
