from __future__ import annotations

from typing import Any

import pytest

from redposture_core.modules.consul import actions as consul
from redposture_core.modules.elastic import actions as elastic
from redposture_core.modules.etcd import actions as etcd
from redposture_core.modules.gitlab import actions as gitlab
from redposture_core.modules.grafana import actions as grafana
from redposture_core.modules.proxmox import actions as proxmox
from redposture_core.modules.qdrant import actions as qdrant
from redposture_core.modules.redis import actions as redis


def test_grafana_detection_rejects_generic_health_and_redirect() -> None:
    assert grafana._looks_like_grafana_login(302, "", {"Location": "/login"}) is False
    assert grafana._looks_like_grafana_health(200, '{"database":"ok","version":"11.0.0"}') == (
        False,
        None,
    )
    assert grafana._looks_like_grafana_health(
        200,
        '{"database":"ok","commit":"abc123","version":"11.0.0"}',
    ) == (True, "11.0.0")


def test_proxmox_detection_requires_product_specific_marker() -> None:
    assert proxmox._looks_like_proxmox_response(200, b'{"data":{}}', {}) is False
    assert (
        proxmox._looks_like_proxmox_response(
            401,
            b'{"data":null,"message":"authentication required"}',
            {},
        )
        is False
    )
    assert proxmox._looks_like_proxmox_response(401, b'{"data":null}', {"Server": "pve-api-daemon"}) is True
    assert proxmox._looks_like_proxmox_response(200, b'{"data":{"clustername":"lab"}}', {}) is True


def test_qdrant_detection_rejects_generic_result_envelope() -> None:
    assert qdrant._qdrant_looks_like_response({"result": {}, "status": "ok"}) is False
    assert qdrant._qdrant_looks_like_response({"result": {"collections": []}, "status": "ok", "time": 0.001}) is True


def test_gitlab_version_detection_requires_revision_correlation() -> None:
    assert gitlab._detect_version_payload({"version": "17.8.1"}) is None
    assert gitlab._detect_version_payload({"version": "17.8.1", "revision": "abc123"}) == "17.8.1"
    assert gitlab._detect_login_page("GitLab users/sign_in") is True


def test_redis_generic_resp_error_requires_second_fingerprint(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(redis, "_send_cmd", lambda *_args: ("error", "ERR generic failure"))
    assert redis._confirm_redis_error_response(object(), "ERR arbitrary") == (False, None)

    monkeypatch.setattr(
        redis,
        "_send_cmd",
        lambda *_args: ("bulk", b"# Server\r\nredis_version:7.4.0\r\n"),
    )
    assert redis._confirm_redis_error_response(object(), "ERR arbitrary") == (True, False)


def test_etcd_version_detection_rejects_cluster_field_alone() -> None:
    assert etcd._looks_like_etcd_version({"etcdcluster": "3.5.0"}) == (False, None)
    assert etcd._looks_like_etcd_version({"etcdserver": "not-a-version"}) == (False, None)
    assert etcd._looks_like_etcd_version({"etcdserver": "3.5.14", "etcdcluster": "3.5.0"}) == (True, "3.5.14")


def test_consul_leader_requires_correlated_endpoint(monkeypatch: pytest.MonkeyPatch) -> None:
    def generic_response(*args: Any, **_kwargs: Any) -> tuple[int, bytes, dict[str, str], None, bool, bool]:
        path = str(args[3])
        payload = b'"example:1234"' if path.endswith("leader") else b'{"status":"ok"}'
        return 200, payload, {}, None, False, False

    monkeypatch.setattr(consul, "_request_with_tls_fallback", generic_response)
    assert consul._probe_consul_scheme("example", 8500, 1.0)[0] is False

    def consul_response(*args: Any, **_kwargs: Any) -> tuple[int, bytes, dict[str, str], None, bool, bool]:
        path = str(args[3])
        payload = b'"10.0.0.1:8300"' if path.endswith("leader") else b'["10.0.0.1:8300"]'
        return 200, payload, {}, None, False, False

    monkeypatch.setattr(consul, "_request_with_tls_fallback", consul_response)
    assert consul._probe_consul_scheme("example", 8500, 1.0)[0] is True


def test_elastic_generic_root_is_not_a_hard_fingerprint() -> None:
    generic = elastic._classify_detect_probe(
        "/",
        200,
        b'{"name":"app","version":{"number":"1.2.3"}}',
        {"Content-Type": "application/json"},
        None,
    )
    assert generic["signal_kind"] == "soft_positive"

    canonical = elastic._classify_detect_probe(
        "/",
        200,
        b'{"name":"node","cluster_name":"lab","version":{"number":"8.13.4","build_flavor":"default"}}',
        {"Content-Type": "application/json"},
        None,
    )
    assert canonical["signal_kind"] == "hard_positive"
