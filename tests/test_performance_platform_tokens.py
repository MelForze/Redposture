"""Independent identity/ACL contracts for the platform HTTP performance peers."""

from __future__ import annotations

import json

import pytest

from scripts.performance_http_fixtures import platform_token_reply


def request(module, path, token=None, *, method="GET", body=b"", limited=False):
    header = {
        "consul": b"x-consul-token",
        "kubeapi": b"authorization",
        "qdrant": b"api-key",
        "gitlab": b"private-token",
    }[module]
    value = ("Bearer " if module == "kubeapi" else "") + str(token)
    wire = platform_token_reply(
        method,
        path,
        {header: value.encode()} if token else {},
        body,
        module=module,
        valid_token="correct",
        limited=limited,
        origin="http://qa.invalid",
    )
    head, _, raw = wire.partition(b"\r\n\r\n")
    try:
        payload = json.loads(raw)
    except ValueError:
        payload = raw.decode()
    return int(head.split(b" ")[1]), payload, head


@pytest.mark.parametrize("token", [None, "wrong"])
def test_consul_invalid_token_is_not_a_generic_proxy_403(token):
    status, payload, _ = request("consul", "/v1/acl/token/self", token)
    assert status == 403 and payload == "token does not exist: ACL not found"


@pytest.mark.parametrize("limited", [False, True])
def test_consul_token_identity_does_not_require_reading_services(limited):
    status, payload, _ = request("consul", "/v1/acl/token/self", "correct", limited=limited)
    assert status == 200 and payload["AccessorID"] and payload["SecretID"] == "correct"
    assert request("consul", "/v1/catalog/services", "correct", limited=limited)[0] == (403 if limited else 200)
    assert request("consul", "/v1/status/leader")[1] == "127.0.0.1:8300"
    assert request("consul", "/v1/status/peers")[1] == ["127.0.0.1:8300"]


@pytest.mark.parametrize("token", [None, "wrong"])
def test_kube_invalid_bearer_is_a_kubernetes_status_not_an_arbitrary_json_error(token):
    status, payload, _ = request("kubeapi", "/api/v1/namespaces", token)
    assert status == 401
    assert payload["kind"] == "Status" and payload["apiVersion"] == "v1"
    assert payload["reason"] == "Unauthorized" and payload["code"] == 401


@pytest.mark.parametrize("limited", [False, True])
def test_kube_self_review_preserves_identity_even_when_namespaces_are_forbidden(limited):
    status, payload, _ = request(
        "kubeapi",
        "/apis/authentication.k8s.io/v1/selfsubjectreviews",
        "correct",
        method="POST",
        body=b'{"apiVersion":"authentication.k8s.io/v1","kind":"SelfSubjectReview"}',
        limited=limited,
    )
    assert status in {200, 201}
    assert payload["status"]["userInfo"]["username"] == "profile-reader"
    assert payload["apiVersion"] == "authentication.k8s.io/v1" and payload["kind"] == "SelfSubjectReview"
    status, ns, _ = request("kubeapi", "/api/v1/namespaces", "correct", limited=limited)
    assert status == (403 if limited else 200)
    if limited:
        assert ns["reason"] == "Forbidden"
    else:
        assert len(ns["items"]) == 3 and ns["kind"] == "NamespaceList"


@pytest.mark.parametrize("body", [b"broken", b"[]", b'{"kind":"Pod","apiVersion":"v1"}'])
def test_kube_review_does_not_accept_malformed_or_mutating_resources(body):
    assert (
        request("kubeapi", "/apis/authentication.k8s.io/v1/selfsubjectreviews", "correct", method="POST", body=body)[0]
        == 400
    )


def test_qdrant_invalid_key_and_collection_acl_are_separate():
    status, payload, _ = request("qdrant", "/collections", "wrong")
    assert status in {401, 403} and payload["status"]["error"] == "Invalid API key or JWT"
    assert request("qdrant", "/collections", "correct", limited=True)[0] == 200
    assert request("qdrant", "/collections/restricted-ml", "correct", limited=True)[0] == 403
    assert request("qdrant", "/collections/restricted-ml", "correct")[0] == 200


def test_gitlab_user_and_project_access_are_separate_and_pagination_is_real():
    assert request("gitlab", "/api/v4/user", "wrong")[0] == 401
    assert request("gitlab", "/api/v4/user", "correct", limited=True)[1]["username"] == "profile-reader"
    assert request("gitlab", "/api/v4/projects?page=1", "correct", limited=True)[0] == 403
    _, first, headers = request("gitlab", "/api/v4/projects?page=1", "correct")
    _, second, _ = request("gitlab", "/api/v4/projects?page=2", "correct")
    assert b"X-Next-Page: 2" in headers
    assert [p["id"] for p in first + second] == [101, 102, 103]
    assert request("gitlab", "/api/v4/projects?page=3", "correct")[1] == []
    assert request("gitlab", "/api/v4/projects?visibility=public")[1] == []


@pytest.mark.parametrize("module", ["consul", "kubeapi", "qdrant", "gitlab"])
def test_unknown_route_or_write_is_not_a_product_shaped_success(module):
    assert request(module, "/not-a-route", "correct")[0] == 404
    assert request(module, "/api/v1/pods", "correct", method="POST", body=b"{}")[0] in {403, 405}
