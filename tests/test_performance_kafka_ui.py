"""QA evidence must bind full login pairs to issued sessions and identity."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from copy import deepcopy
from pathlib import Path
from urllib.parse import urlencode

import pytest

from scripts import performance_kafka_ui as ui
from scripts.performance_contracts import HttpRouteStats
from scripts.profile_module_performance import is_http_profile

ORIGIN = "http://127.32.0.1:18080"
PAIR = ("profile-user", "profile-password")


def exchange(ledger, method, path, *, surface="provectus-ui", pair=PAIR, headers=None, body=b"", index=0):
    fields = headers or {}
    raw = ui.kafka_ui_reply(method, path, fields, body, surface=surface, origin=ORIGIN, valid_pair=pair, limited=False)
    ledger.record_response(index, method, path, fields, body, raw)
    return raw


def evidence(surface="provectus-ui", *, pair=PAIR, accepted=True):
    ledger = ui.KafkaUIWireLedger()
    login = "/auth" if surface == "provectus-ui" else "/login"
    exchange(
        ledger,
        "POST",
        login,
        surface=surface,
        pair=pair if accepted else None,
        headers={b"content-type": b"application/x-www-form-urlencoded"},
        body=urlencode(dict(zip(["username", "password"], pair, strict=True))).encode(),
    )
    if accepted:
        exchange(
            ledger,
            "GET",
            "/api/authorization",
            surface=surface,
            pair=pair,
            headers={b"cookie": ui.session_cookie(ORIGIN, pair).encode()},
        )
    record = {
        "provided_username": pair[0],
        "provided_password": pair[1],
        "provided_credentials": True,
        "provided_credentials_ok": accepted,
        "status": "valid_credentials" if accepted else "invalid_credentials",
    }
    wire = ledger.pop(0)
    ledger.close()
    return record, wire


@pytest.mark.parametrize("surface", sorted(ui.AUTH_SURFACES))
@pytest.mark.parametrize("accepted", [True, False])
def test_complete_received_pair_session_and_identity(surface, accepted):
    record, wire = evidence(surface, accepted=accepted)
    observed, errors = ui.wire_kafka_ui_record(
        record, wire, surface=surface, origin=ORIGIN, valid_pair=PAIR if accepted else None
    )
    assert all(observed[key] == value for key, value in record.items()) and errors == []
    assert observed["attempted_credentials"][0]["credential_state"] == ("valid" if accepted else "invalid")
    assert wire["complete"] is True and wire["calls"][0]["body"] == urlencode(
        {"username": PAIR[0], "password": PAIR[1]}
    )


def test_full_unicode_and_long_password_is_not_inferred_from_username():
    pair = ("qa-reader", "密码" + "x" * 4096 + "-end")
    record, wire = evidence(pair=pair)
    assert ui.wire_kafka_ui_record(record, wire, surface="provectus-ui", origin=ORIGIN, valid_pair=pair)[1] == []
    assert pair[1] in str(record) and wire["calls"][0]["body"].endswith("-end")
    assert ui.wire_kafka_ui_record(
        record, wire, surface="provectus-ui", origin=ORIGIN, valid_pair=(pair[0], pair[1][:-1])
    )[1]


@pytest.mark.parametrize(
    "fault",
    [
        "body-hash",
        "response-hash",
        "cookie",
        "identity",
        "public-identity",
        "missing-post",
        "other-password",
        "wrong-verdict",
        "contradictory-verdict",
        "partial",
        "malformed-headers",
        "duplicate-post",
    ],
)
def test_corrupted_or_incomplete_evidence_never_passes(fault):
    record, wire = evidence()
    calls = wire["calls"]
    if fault == "body-hash":
        calls[0]["body_sha256"] = "bad"
    elif fault == "response-hash":
        calls[1]["response_sha256"] = "bad"
    elif fault == "cookie":
        calls[1]["headers"]["cookie"] = "SESSION=unissued"
    elif fault in {"identity", "public-identity"}:
        calls[1]["response_body"] = json.dumps(
            {"rbacEnabled": False, "userInfo": None if fault == "public-identity" else {"username": "other"}}
        )
        calls[1]["response_sha256"] = hashlib.sha256(calls[1]["response_body"].encode()).hexdigest()
    elif fault == "missing-post":
        del calls[0]
    elif fault == "other-password":
        record["provided_password"] = "other"
    elif fault == "wrong-verdict":
        record.update(status="invalid_credentials", provided_credentials_ok=False)
    elif fault == "contradictory-verdict":
        record["provided_credentials_ok"] = False
    elif fault == "partial":
        wire["complete"] = False
    elif fault == "malformed-headers":
        calls[0]["response_headers"] = {"x": []}
    elif fault == "duplicate-post":
        calls.append(deepcopy(calls[0]))
    assert ui.wire_kafka_ui_record(record, wire, surface="provectus-ui", origin=ORIGIN, valid_pair=PAIR)[1]


def test_cross_origin_session_cannot_confirm_credentials():
    record, wire = evidence()
    assert ui.wire_kafka_ui_record(
        record, wire, surface="provectus-ui", origin="http://127.32.0.2:18080", valid_pair=PAIR
    )[1]


def test_raw_runtime_false_attempt_requires_matching_explicit_rejected_root():
    record, wire = evidence(accepted=False)
    record["credential_attempts"] = [{"username": PAIR[0], "password": PAIR[1], "ok": False}]
    observation, errors = ui.wire_kafka_ui_record(record, wire, surface="provectus-ui", origin=ORIGIN, valid_pair=None)
    assert errors == [] and observation["attempted_credentials"][0]["credential_state"] == "invalid"
    assert "credential_state" not in record["credential_attempts"][0]
    for status in ["unknown_auth", "rate_limited", "fail"]:
        record["status"] = status
        assert ui.wire_kafka_ui_record(record, wire, surface="provectus-ui", origin=ORIGIN, valid_pair=None)[1]


def test_unique_session_and_exec_nonces_do_not_overflow_route_statistics():
    stats = HttpRouteStats()
    for index in range(10000):
        cookie = ui.session_cookie(f"http://127.32.0.{index}:18080", PAIR).encode()
        stats.record("GET", "/api/clusters", {b"cookie": cookie}, b"", body_group="kafka-ui-auth")
        stats.record(
            "PUT",
            "/api/smartfilters/testexecutions",
            {b"cookie": cookie},
            json.dumps({"filterCode": "nonce-" + str(index)}).encode(),
            body_group="kafka-ui-auth",
        )
    report = stats.snapshot()
    assert report["complete"] is True and len(report["routes"]) == 2
    assert sum(r["requests"] for r in report["routes"]) == 20000


def test_different_full_form_passwords_remain_distinct_in_statistics():
    stats = HttpRouteStats()
    for password in ["one", "two"]:
        stats.record(
            "POST",
            "/auth",
            {},
            urlencode({"username": PAIR[0], "password": password}).encode(),
            body_group="kafka-ui-auth",
        )
    assert len(stats.snapshot()["routes"]) == 2


def test_malformed_unicode_receipt_is_a_failure_without_crashing():
    record, wire = evidence()
    wire["calls"][0]["body"] = "\ud800"
    assert ui.wire_kafka_ui_record(record, wire, surface="provectus-ui", origin=ORIGIN, valid_pair=PAIR)[1]


def test_response_headers_count_toward_bounded_storage_and_pop_releases_it():
    ledger = ui.KafkaUIWireLedger(body_limit=1000)
    exchange(ledger, "GET", "/api/authorization", surface="kafbat-ui")
    assert 0 < ledger.pending_body_bytes <= 1000
    wire = ledger.pop(0)
    assert wire["complete"] is True and wire["calls"][0]["response_headers"]["content-type"] == "application/json"
    assert ledger.pending_body_bytes == 0
    ledger.close()
    with pytest.raises(RuntimeError):
        exchange(ledger, "GET", "/auth")
    assert ledger.pending_body_bytes == 0


def test_body_or_header_budget_failure_remains_visible_after_cleanup():
    ledger = ui.KafkaUIWireLedger(body_limit=16)
    exchange(ledger, "GET", "/api/authorization", surface="kafbat-ui")
    assert ledger.pop(0)["complete"] is False and ledger.pending_body_bytes == 0
    ledger.close()
    assert ledger.snapshot()["overflow"] > 0


def test_pending_evidence_over_eight_mib_is_disk_backed_and_consumed_exactly():
    ledger = ui.KafkaUIWireLedger()
    try:
        raw = b"HTTP/1.1 200 OK\r\nContent-Length: 32768\r\n\r\n" + b"x" * 32768
        for index in range(300):
            ledger.record_response(index, "GET", "/large", {}, b"", raw)
        assert ledger.snapshot()["overflow"] == 0
        assert ledger.pending_body_bytes > 8 * 1024 * 1024
        assert ledger.storage_path.is_file() and ledger.storage_path.stat().st_size > 8 * 1024 * 1024
        for index in range(300):
            value = ledger.pop(index)
            assert value["complete"] is True and value["calls"][0]["response_body"] == "x" * 32768
        assert ledger.pending_body_bytes == 0 and ledger.snapshot()["pending_calls"] == 0
    finally:
        ledger.close()
    assert not ledger.storage_path.exists()


def test_sqlite_failure_never_becomes_complete_and_cleanup_is_idempotent():
    ledger = ui.KafkaUIWireLedger()
    ledger._db.close()
    exchange(ledger, "GET", "/auth")
    assert ledger.pop(0)["complete"] is False and ledger.snapshot()["storage_errors"] > 0
    ledger.close()
    ledger.close()
    assert ledger.snapshot()["temporary_storage_removed"] == 1


@pytest.mark.parametrize("surface", sorted(ui.AUTH_SURFACES))
def test_real_product_content_negotiation_and_login_paths(surface):
    login = "/auth" if surface == "provectus-ui" else "/login"
    raw = ui.kafka_ui_reply(
        "GET",
        login,
        {b"accept": b"application/json"},
        b"",
        surface=surface,
        origin=ORIGIN,
        valid_pair=PAIR,
        limited=False,
    )
    assert raw.startswith(b"HTTP/1.1 406" if surface == "provectus-ui" else b"HTTP/1.1 200")
    assert is_http_profile("kafka", surface) and not is_http_profile("kafka", "default")
    assert not is_http_profile("redis", surface)


@pytest.mark.parametrize("surface", sorted(ui.AUTH_SURFACES))
def test_unknown_routes_and_execution_never_succeed(surface):
    for method, path in [("GET", "/missing"), ("PUT", "/api/smartfilters/testexecutions"), ("DELETE", "/api/clusters")]:
        raw = ui.kafka_ui_reply(method, path, {}, b"", surface=surface, origin=ORIGIN, valid_pair=PAIR, limited=False)
        assert not raw.startswith(b"HTTP/1.1 200")


@pytest.mark.parametrize("surface", sorted(ui.AUTH_SURFACES))
@pytest.mark.skipif(
    sys.platform != "linux",
    reason="Distinct loopback IP targets require Linux; run the profile in its owned container on macOS",
)
def test_public_cli_http_profile_runs_actual_ui_and_retains_full_wire(tmp_path, surface):
    root = Path(__file__).resolve().parents[1]
    output = tmp_path / "profile.json"
    command = [
        sys.executable,
        "scripts/profile_module_performance.py",
        "--source",
        str(root),
        "--module",
        "kafka",
        "--mode",
        "credentials",
        "--auth-case",
        "valid",
        "--auth-surface",
        surface,
        "--targets",
        "40",
        "--model",
        "positive",
        "--workers",
        "4",
        "--concurrency",
        "16",
        "--timeout",
        "1",
        "--delay-ms",
        "0",
        "--save",
        "--format",
        "json",
        "--output",
        str(output),
    ]
    run = subprocess.run(command, cwd=root, capture_output=True, timeout=90)
    assert run.returncode == 0, (run.stdout + run.stderr).decode()[-4000:]
    result = json.loads(output.read_text())
    assert result["quality"] == "PASS" and result["http_peer"] == "async" and result["native_peer"] is None
    assert result["read_wire_errors"] == {}
    assert result["missing"] == result["extra"] == [] and result["records"] == 40
    assert result["credential_observations"]["attempts_observed"] == 40
    receipts = [json.loads(line) for line in output.with_suffix(".read-wire.jsonl").read_text().splitlines()]
    assert len(receipts) == 40 and all(any(c["method"] == "POST" for c in r["wire"]["calls"]) for r in receipts)
