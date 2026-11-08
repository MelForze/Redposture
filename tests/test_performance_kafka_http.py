"""Known catalogues and no invented credential support for Kafka gateways."""

from __future__ import annotations

import json
import subprocess
import sys
from copy import deepcopy
from types import SimpleNamespace
from urllib.parse import urlsplit

import pytest

from redposture_core.clients.http_api import HttpResponse
from redposture_core.modules.kafka import http_surfaces
from scripts import performance_kafka_http as peer
from scripts.performance_kafka_ui import KafkaUIWireLedger
from scripts.profile_module_performance import is_http_profile


def run(surface):
    ledger = KafkaUIWireLedger()

    class Pool:
        def request(self, method, url, **kwargs):
            path = urlsplit(url).path
            raw = peer.http_reply(method, path, b"", surface=surface, access="open")
            ledger.record_response(0, method, path, {}, b"", raw)
            head, body = raw.split(b"\r\n\r\n", 1)
            headers = dict(line.decode().split(": ", 1) for line in head.split(b"\r\n")[1:])
            return HttpResponse(int(head.split()[1]), body, headers)

    try:
        record = http_surfaces.detect(Pool(), "http://qa.invalid:19000", SimpleNamespace(host="qa.invalid", port=19000))
        assert record is not None
        return record, ledger.pop(0)
    finally:
        ledger.close()


@pytest.mark.parametrize("surface", sorted(peer.SURFACES))
def test_full_known_http_surface_and_inventory(surface):
    assert is_http_profile("kafka", surface) and not is_http_profile("postgres", surface)
    record, wire = run(surface)
    assert peer.record_errors(record, wire, surface=surface, topics=False) == []
    result = http_surfaces.collect(record, {"show_topics": True})
    assert peer.record_errors(result, wire, surface=surface, topics=True) == []


@pytest.mark.parametrize("fault", ["missing", "extra", "duplicate", "wrong-vendor", "credential", "wrong-hash"])
def test_catalogue_and_wire_mutations_cannot_pass(fault):
    record, wire = run("rest-proxy")
    record, wire = deepcopy(record), deepcopy(wire)
    if fault == "missing":
        record["http_inventory"].pop()
    elif fault == "extra":
        record["http_inventory"].append("not-known")
    elif fault == "duplicate":
        record["http_inventory"][0] = record["http_inventory"][1]
    elif fault == "wrong-vendor":
        record["ui_vendor"] = "akhq"
    elif fault == "credential":
        record["attempted_credentials"] = [{"username": "invented", "ok": True}]
    elif fault == "wrong-hash":
        wire["calls"][-1]["response_sha256"] = "wrong"
    assert peer.record_errors(record, wire, surface="rest-proxy", topics=False)


@pytest.mark.parametrize("surface", sorted(peer.SURFACES))
def test_read_only_model_never_implements_login_or_execute(surface):
    for method, path in [("POST", "/login"), ("PUT", "/api/smartfilters/testexecutions"), ("DELETE", "/topics/x")]:
        raw = peer.http_reply(method, path, b"command=id", surface=surface, access="open")
        assert raw.startswith(b"HTTP/1.1 403 ")


@pytest.mark.parametrize("surface", sorted(peer.SURFACES))
def test_credential_mode_is_explicitly_rejected_before_starting_fixture(surface, tmp_path):
    result = subprocess.run(
        [
            sys.executable,
            "scripts/profile_module_performance.py",
            "--source",
            ".",
            "--module",
            "kafka",
            "--mode",
            "credentials",
            "--auth-surface",
            surface,
            "--output",
            str(tmp_path / "never.json"),
        ],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 2 and "credential verification is not implemented" in result.stderr
    assert not list(tmp_path.iterdir())


def test_official_denied_catalogue_is_not_silently_empty():
    raw = peer.http_reply("GET", "/api/topics", b"", surface="redpanda-console", access="denied")
    assert raw.startswith(b"HTTP/1.1 403 ")
    assert json.loads(raw.split(b"\r\n\r\n", 1)[1]) == {"message": "catalogue forbidden"}


@pytest.mark.parametrize("flags", [["--show-brokers"], ["--execute", "id"], ["--show-topics", "--dump"]])
def test_unmodelled_actions_are_rejected_before_any_network_or_output(flags, tmp_path):
    result = subprocess.run(
        [
            sys.executable,
            "scripts/profile_module_performance.py",
            "--source",
            ".",
            "--module",
            "kafka",
            "--mode",
            "actions",
            "--auth-surface",
            "rest-proxy",
            "--output",
            str(tmp_path / "never.json"),
            *("--action=" + flag for flag in flags),
        ],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 2 and "other actions need independent seeded matchers" in result.stderr
    assert not list(tmp_path.iterdir())
