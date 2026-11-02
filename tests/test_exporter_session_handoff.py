"""Exporter prefetch lends a framed anonymous connection without replaying actions."""

from __future__ import annotations

import asyncio
import json

import pytest

from redposture_core.clients.async_http_detect import AsyncDetectionHttp
from redposture_core.exporters import async_detect
from redposture_core.exporters.http_pool import HTTPConnectionPool, activate_http_pool
from tests.test_http_detect_handoff import peer


@pytest.mark.parametrize("secure", [False, True])
@pytest.mark.parametrize("optimized", [False, True])
def test_trigger_prefetch_to_callback_uses_same_tcp_tls_session(secure, optimized, mtls_material, monkeypatch):
    import ssl

    context = ssl._create_unverified_context() if secure else None
    if not optimized:
        monkeypatch.setattr(async_detect, "_detection_client", lambda **kw: AsyncDetectionHttp(**kw))
    with peer(
        secure=secure, material=mtls_material, responses={"/metrics": (200, b"mysql_exporter_build_info 1\n")}
    ) as (url, connections, requests):
        port = int(url.rsplit(":", 1)[1])
        with activate_http_pool(HTTPConnectionPool(max_idle_total=4, tls_context=context)):
            # activate_http_pool yields None by its established contract.
            from redposture_core.exporters.http_pool import get_active_http_pool

            owner = get_active_http_pool()
            assert owner is not None
            details = asyncio.run(
                async_detect.prefetch_metrics("127.0.0.1", port, "https" if secure else "http", 1, 0, context)
            )
            assert details["body"] == "mysql_exporter_build_info 1\n"
            assert "release_handoff" not in json.dumps(details)
            assert owner.get(url + "/callback?target=qa", 1)[0] == 200
            assert len(connections) == (1 if optimized else 2)
            assert [row[0] for row in requests] == ["/metrics", "/callback?target=qa"]


@pytest.mark.parametrize("hit", [False, True])
def test_collect_only_retains_confirmed_exporters_and_preserves_prefetched_result(hit):
    body = b"node_exporter_build_info 1\n" if hit else b"<html>Ordinary application</html>"
    with peer(responses={"/metrics": (200, body)}) as (url, connections, requests):
        port = int(url.rsplit(":", 1)[1])
        with activate_http_pool(HTTPConnectionPool(max_idle_total=4)):
            from redposture_core.exporters.http_pool import get_active_http_pool

            pool = get_active_http_pool()
            assert pool is not None
            record, matched = asyncio.run(
                async_detect.prefetch_discovery(
                    "127.0.0.1",
                    port,
                    "http",
                    1,
                    0,
                    [{"name": "node_exporter", "port": port, "markers": ["node_exporter_build_info"]}],
                )
            )
            assert bool(matched) is hit
            assert bool(pool._handoff_budget.active) is hit
            before = len(connections)
            pool.get(url + "/debug/vars", 1)
            assert len(connections) == before + (0 if hit else 1)
            assert record.responses
        assert pool._handoff_budget.active == 0


def test_callback_disconnect_is_not_given_an_extra_automatic_replay():
    with peer(drop_after=1) as (url, connections, requests):
        port = int(url.rsplit(":", 1)[1])
        with activate_http_pool(HTTPConnectionPool(max_idle_total=4)):
            from redposture_core.exporters.http_pool import get_active_http_pool

            pool = get_active_http_pool()
            assert pool is not None
            asyncio.run(async_detect.prefetch_metrics("127.0.0.1", port, "http", 1, 0))
            assert pool.get(url + "/after", 1)[3] is not None
            assert [row[0] for row in requests] == ["/metrics", "/after"]
            assert len(connections) == 1


def test_claimed_exporter_connections_do_not_accumulate_in_the_handoff_owner():
    with peer() as (url, _, _):
        port = int(url.rsplit(":", 1)[1])
        with activate_http_pool(HTTPConnectionPool(max_idle_total=4)):
            from redposture_core.exporters.http_pool import get_active_http_pool

            pool = get_active_http_pool()
            assert pool is not None
            for _ in range(20):
                asyncio.run(async_detect.prefetch_metrics("127.0.0.1", port, "http", 1, 0))
                assert pool.get(url + "/after", 1)[0] == 200
                assert len(pool._handoff_policy._connections) == 0
                assert len(pool._handoff_policy._idle) == 0
                assert len(pool._connections) <= 4


def test_handoff_and_ordinary_idle_sockets_share_the_existing_per_host_limit():
    with peer() as (url, _, _):
        port = int(url.rsplit(":", 1)[1])
        with activate_http_pool(HTTPConnectionPool(max_idle_total=16, max_idle_per_host=1)):
            from redposture_core.exporters.http_pool import get_active_http_pool

            pool = get_active_http_pool()
            assert pool is not None
            assert pool.get(url + "/ordinary", 1)[0] == 200
            asyncio.run(async_detect.prefetch_metrics("127.0.0.1", port, "http", 1, 0))
            key = ("http", "127.0.0.1", port)
            assert len(pool._idle.get(key, [])) + len(pool._handoff_policy._idle.get(key, [])) <= 1


def test_discarding_prefetch_releases_only_its_socket_and_is_idempotent():
    with peer() as (url, connections, _requests):
        port = int(url.rsplit(":", 1)[1])
        pool = HTTPConnectionPool(max_idle_total=4, max_idle_per_host=4)
        with activate_http_pool(pool):
            first = asyncio.run(async_detect.prefetch_metrics("127.0.0.1", port, "http", 1, 0))
            second = asyncio.run(async_detect.prefetch_metrics("127.0.0.1", port, "http", 1, 0))
            policy = pool._handoff_policy
            key = ("http", "127.0.0.1", port)
            retained = list(policy._retained_claims)
            first_socket, second_socket = (connection.sock for connection in retained)
            assert first_socket is not None and second_socket is not None
            release_first = getattr(first, "release_handoff", None)
            release_second = getattr(second, "release_handoff", None)
            assert callable(release_first) and callable(release_second)
            assert pool._handoff_budget.active == 2

            release_first()
            assert first_socket.fileno() == -1
            assert second_socket.fileno() >= 0
            assert policy._idle[key] == [retained[1]]
            assert retained[0] not in policy._connections
            assert pool._handoff_budget.active == 1

            release_first()
            assert pool._handoff_budget.active == 1
            release_second()
            assert second_socket.fileno() == -1
            assert pool._handoff_budget.active == 0
            assert not policy._idle
            assert not policy._connections
            assert not policy._retained_claims
            release_second()

            assert pool.get(url + "/after-discard", 1)[0] == 200
            assert len(connections) == 3


def test_full_handoff_budget_does_not_cache_an_ordinary_connection():
    with peer() as (url, connections, _requests):
        port = int(url.rsplit(":", 1)[1])
        pool = HTTPConnectionPool(max_idle_total=1)
        with activate_http_pool(pool):
            details = asyncio.run(async_detect.prefetch_metrics("127.0.0.1", port, "http", 1, 0))
            assert pool._handoff_budget.active == 1
            # A different origin must not claim the pending target's socket.
            other_origin = url.replace("127.0.0.1", "localhost")
            assert pool.get(other_origin + "/ordinary", 1)[0] == 200
            assert len(connections) == 2
            assert pool._handoff_budget.active == 1
            assert pool._idle_total == 0
            assert not pool._connections

            release = getattr(details, "release_handoff", None)
            assert callable(release)
            release()
            assert pool._handoff_budget.active == 0
            assert pool.get(other_origin + "/after-release", 1)[0] == 200
            assert pool._idle_total == 1
            assert len(connections) == 3


def test_full_per_host_handoff_bucket_preserves_response_and_original_socket():
    with peer() as (url, connections, _requests):
        port = int(url.rsplit(":", 1)[1])
        pool = HTTPConnectionPool(max_idle_total=4, max_idle_per_host=1)
        with activate_http_pool(pool):
            first = asyncio.run(async_detect.prefetch_metrics("127.0.0.1", port, "http", 1, 0))
            second = asyncio.run(async_detect.prefetch_metrics("127.0.0.1", port, "http", 1, 0))
            assert first["body"] == second["body"]
            assert second["status"] == 200
            assert second["error"] is None
            assert not hasattr(second, "release_handoff")
            assert pool._handoff_budget.active == 1
            assert len(pool._handoff_policy._retained_claims) == 1
            assert pool.get(url + "/after-rejected-handoff", 1)[0] == 200
            assert pool._handoff_budget.active == 0
            assert len(connections) == 2
