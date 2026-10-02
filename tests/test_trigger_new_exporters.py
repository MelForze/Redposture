from __future__ import annotations

import argparse
import socket
import time
import urllib.request
from urllib.parse import parse_qs, urlparse

import pytest

from redposture_core.constants import SCAN_EXPORTERS
from redposture_core.exporters.trigger import trigger_detected_exporter_task, trigger_query_variants
from redposture_core.logger import AttemptLogger
from redposture_core.servers import (
    make_callback_server,
    make_exporter_http_callback_handler,
    make_http_server,
    start_server,
)
from redposture_core.stage_trigger import _parse_trigger_exporter_filter, _patch_trigger_exporters_for_with_listen


@pytest.mark.parametrize(
    ("name", "path", "target", "query"),
    [
        ("mysqld_exporter", "/probe", "127.0.0.1:13306", {}),
        ("json_exporter", "/probe", "http://127.0.0.1:17979/", {"module": ["default"]}),
        ("elasticsearch_exporter", "/probe", "http://127.0.0.1:19200/", {}),
        ("snmp_exporter", "/snmp", "udp://127.0.0.1:1161", {}),
        ("ipmi_exporter", "/ipmi", "127.0.0.1:16230", {}),
    ],
)
def test_new_trigger_profiles_use_documented_endpoint_and_callback_listener(
    name: str, path: str, target: str, query: dict[str, list[str]]
) -> None:
    profile = next(item for item in SCAN_EXPORTERS if item["name"] == name)
    assert _parse_trigger_exporter_filter(name.removesuffix("_exporter")) == {name}
    args = argparse.Namespace(
        mysql_port=13306,
        json_port=17979,
        elasticsearch_port=19200,
        snmp_port=1161,
        ipmi_port=16230,
    )
    patched = _patch_trigger_exporters_for_with_listen([profile], args)[0]
    seen: list[str] = []

    def get_text(url: str, _timeout: float, _retries: int) -> tuple[int, str]:
        seen.append(url)
        return 200, "# no proof of callback\n"

    result = trigger_detected_exporter_task(None, "exporter.example", patched, ["127.0.0.1"], 1, 0, get_text)
    assert result["attempted"] == len(trigger_query_variants(patched))
    assert result["success"] == 0
    assert result["unconfirmed"] == len(trigger_query_variants(patched))
    parsed = urlparse(seen[0])
    assert parsed.path == path
    assert parse_qs(parsed.query)["target"] == [target]
    for key, value in query.items():
        assert parse_qs(parsed.query)[key] == value


def test_new_exporter_markers_are_not_generic_process_metrics() -> None:
    assert "mongodb_exporter" not in {profile["name"] for profile in SCAN_EXPORTERS}
    with pytest.raises(ValueError, match="unsupported trigger exporters"):
        _parse_trigger_exporter_filter("mongodb")
    for profile in SCAN_EXPORTERS:
        if profile["name"] in {
            "mysqld_exporter",
            "json_exporter",
            "elasticsearch_exporter",
            "snmp_exporter",
            "ipmi_exporter",
        }:
            assert all(marker not in {"up", "process_", "go_"} for marker in profile["markers"])


@pytest.mark.parametrize("service", ["json", "elasticsearch"])
def test_http_callback_listener_requires_real_request(service: str) -> None:
    logger = AttemptLogger()
    logger.set_trigger_callback_mode(True, ["127.0.0.1"])
    server = make_http_server("127.0.0.1", 0, make_exporter_http_callback_handler(logger, service))
    running = start_server(service, "127.0.0.1", server.server_address[1], server)
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{running.port}/", timeout=2) as response:
            assert response.status == 200
        assert logger.get_trigger_callback_stats()["by_service"][service] == 1
        assert logger.get_trigger_callback_events()[0]["method"] == "GET"
    finally:
        server.shutdown()
        server.server_close()
        running.thread.join(timeout=2)


@pytest.mark.parametrize("service", ["mysql", "snmp", "ipmi"])
def test_protocol_callback_listener_rejects_noise_and_accepts_protocol(service: str) -> None:
    logger = AttemptLogger()
    logger.set_trigger_callback_mode(True, ["127.0.0.1"])
    server = make_callback_server("127.0.0.1", 0, service, logger)
    running = start_server(service, "127.0.0.1", server.server_address[1], server)
    try:
        if service in {"snmp", "ipmi"}:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                client.sendto(b"noise", ("127.0.0.1", running.port))
                valid = (
                    b"\x30\x08\x02\x01\x01\x04\x00\xa0\x01\x00" if service == "snmp" else b"\x06\x00\xff\x07\x00\x00"
                )
                client.sendto(valid, ("127.0.0.1", running.port))
        else:
            with socket.create_connection(("127.0.0.1", running.port), timeout=2) as client:
                client.sendall(b"noise-noise-noise")
            with socket.create_connection(("127.0.0.1", running.port), timeout=2) as client:
                assert client.recv(4)
                client.sendall((32).to_bytes(3, "little") + b"\x01" + b"\x00" * 32)
        for _ in range(40):
            if logger.get_trigger_callback_stats()["by_service"].get(service) == 1:
                break
            time.sleep(0.01)
        assert logger.get_trigger_callback_stats()["by_service"].get(service) == 1
    finally:
        server.shutdown()
        server.server_close()
        running.thread.join(timeout=2)
