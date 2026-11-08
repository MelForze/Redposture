"""Negative targets must retain actual credential requests, not hide them."""

from __future__ import annotations

import base64
import json
import threading
from urllib.parse import urlencode

import pytest

from scripts.performance_contracts import HttpPairWireLedger, HttpRouteStats
from scripts.performance_elastic import ElasticWireLedger
from scripts.performance_etcd import EtcdWireLedger
from scripts.performance_portainer import PortainerWireLedger
from scripts.profile_module_performance import Fixture


@pytest.mark.parametrize(
    "module,path,method",
    [
        ("elastic", "/_security/_authenticate", "GET"),
        ("etcd", "/v3/auth/authenticate", "POST"),
        ("nexus", "/service/rest/v1/security/users", "GET"),
        ("harbor", "/api/v2.0/users/current", "GET"),
        ("rabbitmq", "/api/whoami", "GET"),
        ("kubeapi", "/api/v1/namespaces", "GET"),
        ("portainer", "/api/auth", "POST"),
        ("gitlab", "/users/sign_in", "POST"),
    ],
)
def test_foreign_response_preserves_sent_full_credentials(module, path, method):
    peer = Fixture.__new__(Fixture)
    peer.module, peer.mode, peer.auth_case, peer.auth_surface = module, "credentials", "valid", "default"
    peer.roles, peer.port, peer.lock, peer.routes = {0: "foreign"}, 9000, threading.Lock(), HttpRouteStats()
    peer._s3_wire = None
    peer._kafka_ui = False
    peer._pair_wire = (
        ElasticWireLedger()
        if module == "elastic"
        else EtcdWireLedger()
        if module == "etcd"
        else PortainerWireLedger()
        if module == "portainer"
        else HttpPairWireLedger()
    )
    headers = {b"authorization": b"Basic " + base64.b64encode(b"qa: full:password ")}
    body = b""
    if module == "portainer":
        body = json.dumps({"Username": "qa", "Password": " full:password "}).encode()
        headers = {}
    if module == "etcd":
        body = json.dumps({"name": "qa", "password": " full:password "}).encode()
        headers = {}
    if module == "gitlab":
        body = urlencode(
            {"authenticity_token": "qa-csrf", "user[login]": "qa", "user[password]": " full:password "}
        ).encode()
        headers = {b"cookie": b"_gitlab_session=qa-session"}
    raw = peer._http_reply(method, path, headers, body, "127.32.0.1")
    assert raw.startswith(b"HTTP/1.1 404")
    wire = peer._pair_wire.pop(0)
    assert wire["complete"] and len(wire["calls"]) == 1, "fixture discarded the actual request on a foreign target"
    (call,) = wire["calls"]
    assert call["username"] == "qa" and call["password"] == " full:password "
    assert call["status"] == 404 and call["method"] == method and call["path"] == path
