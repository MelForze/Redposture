from __future__ import annotations

import base64
import socket
import time
import urllib.request
from urllib.parse import parse_qs, urlparse

import pytest

from redposture_core.exporters.trigger import trigger_detected_exporter_task, trigger_query_variants
from redposture_core.logger import AttemptLogger
from redposture_core.servers import (
    _snmp_community_from_packet,
    make_callback_server,
    make_exporter_http_callback_handler,
    make_http_server,
    start_server,
)


@pytest.mark.parametrize(
    ("exporter", "parameter", "expected"),
    [
        ("mysqld_exporter", "auth_module", "client"),
        ("elasticsearch_exporter", "auth_module", "basic"),
        ("postgres_exporter", "auth_module", "userpass"),
        ("snmp_exporter", "auth", "public_v2"),
        ("json_exporter", "module", "basic"),
        ("ipmi_exporter", "module", "default"),
        ("blackbox_exporter", "module", "http_2xx"),
        ("proxmox_exporter", "module", "default"),
    ],
)
def test_trigger_profiles_include_known_names_without_duplicate_queries(
    exporter: str, parameter: str, expected: str
) -> None:
    queries = trigger_query_variants({"name": exporter})
    assert queries[0] == ""
    assert len(queries) == len(set(queries))
    assert 20 <= len(queries) <= 40
    assert any(parse_qs(query).get(parameter) == [expected] for query in queries)


def test_explicit_custom_profile_is_not_overridden_by_guesses() -> None:
    assert trigger_query_variants({"name": "elasticsearch_exporter", "trigger_query": "x=1&auth_module=custom"}) == [
        "x=1&auth_module=custom"
    ]
    assert trigger_query_variants({"name": "redis_exporter"}) == [""]


def test_trigger_continues_after_earlier_ssrf_or_unknown_profile() -> None:
    exporter = {
        "name": "elasticsearch_exporter",
        "port": 9114,
        "trigger_path": "/probe",
        "target_fmt": "http://{our_host}:9200/",
    }
    seen: list[str] = []
    events: list[dict[str, object]] = []

    def request(url: str, _timeout: float, _retries: int) -> tuple[int, str]:
        seen.append(url)
        profile = parse_qs(urlparse(url).query).get("auth_module")
        if profile == ["basic"]:
            return 200, "probe_success 1\n"
        if not profile:
            return 200, "probe_success 0\n"
        return 400, "unknown module"

    result = trigger_detected_exporter_task(
        None, "exporter.example", exporter, ["127.0.0.1"], 1, 0, request, events.append
    )
    assert len(seen) == len(trigger_query_variants(exporter))
    assert result["attempted"] == len(seen)
    assert result["success"] == 1
    assert any(event.get("profile_name") == "basic" for event in events)


def test_profile_guesses_are_serial_paced_and_not_retried() -> None:
    exporter = {
        "name": "elasticsearch_exporter",
        "port": 9114,
        "trigger_path": "/probe",
        "target_fmt": "http://{our_host}:9200/",
    }
    retries_seen: list[int] = []
    pauses: list[float] = []

    def request(_url: str, _timeout: float, retries: int) -> tuple[int, str]:
        retries_seen.append(retries)
        return 400, "unknown module"

    result = trigger_detected_exporter_task(
        None,
        "exporter.example",
        exporter,
        ["127.0.0.1"],
        1,
        3,
        request,
        profile_delay=0.05,
        sleep_fn=pauses.append,
    )
    assert result["attempted"] == len(trigger_query_variants(exporter))
    assert retries_seen == [3] + [0] * (result["attempted"] - 1)
    assert pauses == [0.05] * (result["attempted"] - 1)


def test_repeated_server_failures_stop_profile_sweep() -> None:
    exporter = {
        "name": "elasticsearch_exporter",
        "port": 9114,
        "trigger_path": "/probe",
        "target_fmt": "http://{our_host}:9200/",
    }
    seen: list[str] = []

    def request(url: str, _timeout: float, _retries: int) -> tuple[int, str]:
        seen.append(url)
        return 503, "busy"

    result = trigger_detected_exporter_task(None, "exporter.example", exporter, ["127.0.0.1"], 1, 0, request)
    assert result["attempted"] == 3
    assert result["profile_sweep_stopped"] == "exporter_unavailable"


@pytest.mark.parametrize(
    ("authorization", "expected_key", "expected_value"),
    [
        ("Basic " + base64.b64encode(b"observer:password").decode(), "password", "password"),
        ("ApiKey " + base64.b64encode(b"id:secret").decode(), "api_key", base64.b64encode(b"id:secret").decode()),
        ("Bearer sample-token", "token", "sample-token"),
    ],
)
def test_http_callback_marks_only_observed_auth_as_credential(
    authorization: str, expected_key: str, expected_value: str
) -> None:
    logger = AttemptLogger()
    logger.set_trigger_callback_mode(True, ["127.0.0.1"])
    server = make_http_server("127.0.0.1", 0, make_exporter_http_callback_handler(logger, "elasticsearch"))
    running = start_server("elasticsearch", "127.0.0.1", server.server_address[1], server)
    try:
        request = urllib.request.Request(f"http://127.0.0.1:{running.port}/", headers={"Authorization": authorization})
        with urllib.request.urlopen(request, timeout=2) as response:
            assert response.status == 200
        event = logger.get_trigger_callback_events()[0]
        assert event[expected_key] == expected_value
        assert logger._is_trigger_cred_event(event)
    finally:
        server.shutdown()
        server.server_close()
        running.thread.join(timeout=2)


def test_http_callback_without_or_with_invalid_authorization_is_ssrf_only() -> None:
    logger = AttemptLogger()
    logger.set_trigger_callback_mode(True, ["127.0.0.1"])
    server = make_http_server("127.0.0.1", 0, make_exporter_http_callback_handler(logger, "elasticsearch"))
    running = start_server("elasticsearch", "127.0.0.1", server.server_address[1], server)
    try:
        for auth in (None, "Basic !!!", "AWS4-HMAC-SHA256 Credential=example"):
            headers = {"Authorization": auth} if auth else {}
            with urllib.request.urlopen(
                urllib.request.Request(f"http://127.0.0.1:{running.port}/", headers=headers), timeout=2
            ) as response:
                assert response.status == 200
        assert all(not logger._is_trigger_cred_event(event) for event in logger.get_trigger_callback_events())
    finally:
        server.shutdown()
        server.server_close()
        running.thread.join(timeout=2)


def test_http_callback_accepts_x_api_key_header() -> None:
    logger = AttemptLogger()
    logger.set_trigger_callback_mode(True, ["127.0.0.1"])
    server = make_http_server("127.0.0.1", 0, make_exporter_http_callback_handler(logger, "json"))
    running = start_server("json", "127.0.0.1", server.server_address[1], server)
    try:
        request = urllib.request.Request(f"http://127.0.0.1:{running.port}/", headers={"X-API-Key": "lab-key"})
        with urllib.request.urlopen(request, timeout=2) as response:
            assert response.status == 200
        assert logger.get_trigger_callback_events()[0]["api_key"] == "lab-key"
        assert logger._is_trigger_cred_event(logger.get_trigger_callback_events()[0])
    finally:
        server.shutdown()
        server.server_close()
        running.thread.join(timeout=2)


def test_snmp_community_is_captured_only_from_valid_v1_v2c_packet() -> None:
    packet = b"\x30\x0e\x02\x01\x01\x04\x07private\xa0\x00"
    assert _snmp_community_from_packet(packet) == "private"
    assert _snmp_community_from_packet(packet[:-1]) is None
    assert _snmp_community_from_packet(b"\x30\x0e\x02\x01\x03\x04\x07private\xa0\x00") is None

    logger = AttemptLogger()
    logger.set_trigger_callback_mode(True, ["127.0.0.1"])
    server = make_callback_server("127.0.0.1", 0, "snmp", logger)
    running = start_server("snmp", "127.0.0.1", server.server_address[1], server)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.sendto(packet, ("127.0.0.1", running.port))
        for _ in range(40):
            if logger.get_trigger_callback_events():
                break
            time.sleep(0.01)
        event = logger.get_trigger_callback_events()[0]
        assert event["community"] == "private"
        assert logger._is_trigger_cred_event(event)
    finally:
        server.shutdown()
        server.server_close()
        running.thread.join(timeout=2)
