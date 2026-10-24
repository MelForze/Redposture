from __future__ import annotations

import json
import socket
import threading
import tracemalloc
from types import SimpleNamespace

import pytest

from redposture_core import network_proxy
from redposture_core.auth_detection import detect_browser_sso
from redposture_core.clients.http_api import _parse_http_response_bytes_detailed
from redposture_core.data_discovery import _items, inspect_record
from redposture_core.shell_capture import ShellView
from redposture_core.validate.parsers import _extract_vulnerable_login_pairs_from_text


@pytest.mark.parametrize("module", ["zookeeper", "keeper"])
def test_znode_structured_dump_preserves_colons_in_path(module: str) -> None:
    record = {
        "znode_values": ["/prod:team/password:AuditPassword-2026!"],
        "znode_dump_items": [{"path": "/prod:team/password", "value": "AuditPassword-2026!"}],
    }
    assert list(_items(module, record)) == [("znode./prod:team/password", {"password": "AuditPassword-2026!"})]
    assert "prod:team/password" in inspect_record(module, record)["findings"][0]["object_path"]


def test_discovery_rejects_oversized_nested_value_before_json_copy() -> None:
    record = {"notebook_contents": [{"name": "large", "data": "x" * (8 * 1024**2)}]}
    tracemalloc.start()
    try:
        baseline = tracemalloc.get_traced_memory()[0]
        result = inspect_record("jupyter", record, max_bytes=1)
        peak = tracemalloc.get_traced_memory()[1] - baseline
    finally:
        tracemalloc.stop()
    assert result["status"] == "partial" and result["bytes_inspected"] == 0
    assert peak < 2 * 1024**2, f"serialization of rejected value allocated {peak} bytes"


def test_discovery_byte_budget_keeps_exact_utf8_accounting() -> None:
    record = {"notebook_contents": [{"x": "é"}]}
    assert inspect_record("jupyter", record, max_bytes=12)["bytes_inspected"] == 0
    assert inspect_record("jupyter", record, max_bytes=13)["bytes_inspected"] == 13


@pytest.mark.parametrize("cyclic_dict", [False, True])
def test_cyclic_discovery_payload_is_partial_without_recursing_forever(cyclic_dict: bool) -> None:
    value: dict | list = {} if cyclic_dict else []
    if isinstance(value, dict):
        value["self"] = value
    else:
        value.append(value)
    result = inspect_record("jupyter", {"notebook_contents": value})
    assert result["status"] == "partial" and result["bytes_inspected"] == 0


def test_discovery_budget_counts_scalars_and_shared_containers_without_false_rejection() -> None:
    shared = {123: None}
    value = [shared, shared, True, 1, 2.5]
    expected_bytes = len(b'[{"123": null}, {"123": null}, true, 1, 2.5]')
    result = inspect_record("jupyter", {"notebook_contents": value}, max_bytes=expected_bytes)
    assert result["bytes_inspected"] == expected_bytes and result["status"] == "complete"


def test_kafka_ui_partial_is_not_reported_as_complete_or_unavailable() -> None:
    result = inspect_record("kafka", {"ui_dump_partial": True, "ui_dump_records": []})
    assert result["status"] == "partial"


@pytest.mark.parametrize("pretty", [False, True])
def test_json_array_does_not_pair_credentials_from_unrelated_objects(pretty: bool) -> None:
    source = [{"username": "alice"}, {"password": "SeparateObjectPass2026!"}]
    assert _extract_vulnerable_login_pairs_from_text(json.dumps(source, indent=2 if pretty else None)) == []
    assert _extract_vulnerable_login_pairs_from_text('{"username":"alice","password":"SeparateObjectPass2026!"}') == [
        ("alice", "SeparateObjectPass2026!")
    ]


@pytest.mark.parametrize("source", ["url", "location"])
def test_saml_canonical_query_case_is_detected(source: str) -> None:
    url = "https://idp.example.invalid/sso?SAMLRequest=fixture&RelayState=fixture"
    result = detect_browser_sso(**({"final_url": url} if source == "url" else {"headers": {"Location": url}}))
    assert result is not None and result.protocol == "saml"


def test_empty_capture_limit_is_an_error_without_crashing_or_changing_limit() -> None:
    output: list[str] = []
    view = ShellView()
    before = view.capture_bytes
    assert view.handle(":limit ''", SimpleNamespace(plain=lambda line, **_kw: output.append(line))) == (True, False)
    assert view.capture_bytes == before
    assert output and output[0].startswith("[-]")


@pytest.mark.parametrize("interims", [[100], [103], [100, 103]])
def test_manual_http_parser_returns_final_response_after_informational(interims: list[int]) -> None:
    raw = b"".join(f"HTTP/1.1 {code} Interim\r\nLink: </x>\r\n\r\n".encode() for code in interims)
    raw += b'HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\n{"ok":true}'
    status, headers, body, truncated = _parse_http_response_bytes_detailed(raw, response_cap=100)
    assert (status, body, truncated) == (200, b'{"ok":true}', False)
    assert headers == {"Content-Length": "11"}


def test_interim_response_without_final_response_is_incomplete() -> None:
    with pytest.raises(OSError, match="response"):
        _parse_http_response_bytes_detailed(b"HTTP/1.1 103 Early Hints\r\n\r\n", response_cap=100)


def test_connect_does_not_consume_server_greeting(monkeypatch: pytest.MonkeyPatch) -> None:
    client, peer = socket.socketpair()
    client.settimeout(1)
    peer.settimeout(1)
    banner = b"\x0aMySQL-8.0-greeting\x00"
    errors: list[Exception] = []

    def serve() -> None:
        try:
            assert b"CONNECT database.invalid:3306" in peer.recv(4096)
            peer.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n" + banner)
        except Exception as exc:
            errors.append(exc)

    worker = threading.Thread(target=serve)
    worker.start()
    monkeypatch.setattr(network_proxy, "_open_proxy_connection", lambda *_a: client)
    proxy = network_proxy.ProxyConfig("http", "proxy.invalid", 8080, None, None, "http://proxy.invalid:8080")
    try:
        tunnel = network_proxy._http_open_tunnel(proxy, "database.invalid", 3306, 1, None)
        assert tunnel.recv(4096) == banner
        tunnel.sendall(b"ping")
        assert peer.recv(4) == b"ping"
    finally:
        client.close()
        peer.close()
        worker.join(2)
    assert not worker.is_alive() and not errors
