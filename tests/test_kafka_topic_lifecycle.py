from __future__ import annotations

import struct

import pytest

from redposture_core.clients import kafka
from redposture_core.modules.kafka import actions


def test_credential_capabilities_are_last_and_capitalized():
    record = {
        "host": "broker",
        "port": 9092,
        "status": "valid_credentials",
        "provided_username": "admin",
        "provided_password": "admin",
        "topic_count": 4,
        "topic_lifecycle": {"create": True, "delete": False},
    }
    assert actions._format_record(record, "txt").endswith(
        "[+] admin:admin (Topics:4) (Topic create:True) (Topic delete:False)"
    )


def test_missing_probe_is_not_reported_as_a_denial():
    line = actions._with_optional_topics({"topic_count": 0}, "[+] u:p")
    assert line.endswith("(Topics:0)")
    assert "Topic create:" not in line and "Topic delete:" not in line


def string(value):
    return kafka._encode_kafka_string(value)


class Socket:
    def gettimeout(self):
        return 1.0

    def settimeout(self, value):
        pass

    def close(self):
        pass


@pytest.mark.parametrize(
    "create_code,delete_code,fault,expected",
    [
        (0, 0, "none", (True, True)),
        (29, 0, "none", (False, None)),
        (36, 0, "none", (None, None)),
        (0, 29, "none", (True, False)),
        (0, 73, "none", (True, False)),
        (0, 0, "lost_create_reply", (True, True)),
        (0, 0, "lost_delete_reply", (True, True)),
        (0, 0, "cancel_create_reply", (True, True)),
        (0, 0, "preexisting", (None, None)),
        (0, 0, "pending_delete", (True, True)),
        (0, 0, "controller_redirect", (True, True)),
    ],
)
def test_real_cycle_only_deletes_its_created_topic(monkeypatch, create_code, delete_code, fault, expected):
    from redposture_core.modules.kafka.topic_lifecycle import probe_topic_lifecycle

    exists = fault == "preexisting"
    calls = []
    delete_pending = False

    def send(sock, *, api_key, api_version, correlation_id, client_id, body):
        nonlocal exists, delete_pending
        reader = kafka._KafkaReader(body)
        calls.append(api_key)
        if api_key == 3:
            if delete_pending:
                exists = False
                delete_pending = False
            assert api_version == 4
            assert reader.read_i32() == 1
            name = reader.read_string(nullable=False)
            assert reader.read_i8() == 0  # Never auto-create during verification.
            return (
                struct.pack(">iii", correlation_id, 0, 1)
                + struct.pack(">i", 1)
                + string("broker")
                + struct.pack(">i", 9092)
                + struct.pack(">h", -1)
                + string("cluster")
                + struct.pack(">ii", 1, 1)
                + struct.pack(">h", 0 if exists else 3)
                + string(name)
                + b"\x00"
                + struct.pack(">i", 0)
            )
        assert reader.read_i32() == 1
        name = reader.read_string(nullable=False)
        assert name.startswith("__redposture_probe_")
        if api_key == 19:
            if fault == "controller_redirect" and calls.count(19) == 1:
                return struct.pack(">iii", correlation_id, 0, 1) + string(name) + struct.pack(">hh", 41, -1)
            assert reader.read_i32() == 1
            reader.read_i16()
            configs = reader.read_i32()
            assert configs == 0  # No explicit replica assignment.
            configs = reader.read_i32()
            for _ in range(configs):
                reader.read_string(nullable=False)
                reader.read_string(nullable=True)
            reader.read_i32()
            assert reader.read_i8() == 0  # Real CreateTopics, not validateOnly.
            exists = create_code == 0
            if fault == "lost_create_reply":
                raise TimeoutError("lost CreateTopics reply")
            if fault == "cancel_create_reply":
                raise KeyboardInterrupt
            return struct.pack(">iii", correlation_id, 0, 1) + string(name) + struct.pack(">hh", create_code, -1)
        assert api_key == 20 and exists
        if delete_code == 0:
            if fault == "pending_delete":
                delete_pending = True
            else:
                exists = False
        if fault == "lost_delete_reply":
            raise TimeoutError("lost DeleteTopics reply")
        return struct.pack(">iii", correlation_id, 0, 1) + string(name) + struct.pack(">h", delete_code)

    monkeypatch.setattr(kafka, "_send_kafka_request", send)
    session = kafka.KafkaSession(
        Socket(), "plaintext", ("admin", "admin"), api_versions={3: (0, 12), 19: (0, 7), 20: (0, 6)}
    )
    monkeypatch.setattr(
        kafka.KafkaSession,
        "open",
        lambda *a, **kw: kafka.KafkaSession(
            Socket(), "plaintext", ("admin", "admin"), api_versions=session.api_versions
        ),
    )
    monkeypatch.setattr(kafka.KafkaSession, "bootstrap", lambda *a, **kw: (True, None))
    if fault == "cancel_create_reply":
        with pytest.raises(KeyboardInterrupt):
            probe_topic_lifecycle("broker", 9092, 0.2, username="admin", password="admin", existing_session=session)
        assert not exists and calls.count(19) == calls.count(20) == 1
        return
    result = probe_topic_lifecycle("broker", 9092, 0.2, username="admin", password="admin", existing_session=session)
    assert (result["create"], result["delete"]) == expected
    assert (20 in calls) is (create_code == 0 and fault != "preexisting")
    assert calls.count(19) <= (2 if fault == "controller_redirect" else 1)
    if fault == "preexisting":
        assert exists and calls == [3]
        return
    if create_code == 0 and delete_code == 0:
        assert not exists and result["cleanup_complete"] is True
    if delete_code in {29, 73}:
        assert exists and result["cleanup_complete"] is False


@pytest.mark.parametrize("fault", ["correlation", "name", "empty", "duplicate", "trailing", "truncated"])
@pytest.mark.parametrize("create", [True, False])
def test_mutation_response_requires_complete_exact_named_result(fault, create):
    from redposture_core.modules.kafka.topic_lifecycle import _mutation_result

    name = "owned"
    result = (
        string("foreign" if fault == "name" else name)
        + struct.pack(">h", 0)
        + (struct.pack(">h", -1) if create else b"")
    )
    count = 0 if fault == "empty" else 2 if fault == "duplicate" else 1
    payload = struct.pack(">iii", 99 if fault == "correlation" else 1, 0, count) + result * count
    if fault == "trailing":
        payload += b"garbage"
    if fault == "truncated":
        payload = payload[:-1]
    with pytest.raises(ValueError):
        _mutation_result(payload, 1, name, create=create)


def test_unsupported_admin_apis_do_not_send_mutations(monkeypatch):
    from redposture_core.modules.kafka.topic_lifecycle import probe_topic_lifecycle

    session = kafka.KafkaSession(Socket(), "plaintext", ("a", "b"), api_versions={3: (0, 12)})
    monkeypatch.setattr(kafka, "_send_kafka_request", lambda *a, **k: pytest.fail("unsupported API was called"))
    result = probe_topic_lifecycle("broker", 9092, 0.1, username="a", password="b", existing_session=session)
    assert result["create"] is result["delete"] is None
    assert result["cleanup_complete"] is None and result["errors"]


@pytest.mark.parametrize("fault", ["truncated", "correlation"])
def test_invalid_preflight_is_unverified_and_never_mutates(monkeypatch, fault):
    from redposture_core.modules.kafka.topic_lifecycle import probe_topic_lifecycle

    calls = []

    def send(sock, **kw):
        calls.append(kw["api_key"])
        return b"\x00" if fault == "truncated" else struct.pack(">ii", kw["correlation_id"] + 1, 0)

    monkeypatch.setattr(kafka, "_send_kafka_request", send)
    session = kafka.KafkaSession(Socket(), "plaintext", ("a", "b"), api_versions={3: (0, 12), 19: (0, 7), 20: (0, 6)})
    result = probe_topic_lifecycle("broker", 9092, 0.1, username="a", password="b", existing_session=session)
    assert calls == [3] and result["create"] is result["delete"] is None


def test_each_successful_pair_keeps_its_own_capabilities():
    record = {
        "host": "broker",
        "port": 9092,
        "topic_count": 99,
        "attempted_credentials": [
            {
                "username": "a",
                "password": "one",
                "status": "valid_credentials",
                "topic_count": 4,
                "topic_lifecycle": {"create": True, "delete": True},
            },
            {
                "username": "b",
                "password": "two",
                "status": "weak_default_creds",
                "topic_count": 0,
                "topic_lifecycle": {"create": False, "delete": None},
            },
            {"username": "c", "password": "wrong", "status": "auth_required", "provided_credentials_ok": False},
        ],
    }
    lines = actions._format_credential_attempts_records(record, "txt")
    assert lines[0].endswith("[+] a:one (Topics:4) (Topic create:True) (Topic delete:True)")
    assert lines[1].endswith("[+] b:two (Topics:0) (Topic create:False) (Topic delete:unknown)")
    assert lines[2].endswith("[-] c:wrong")
    assert not any("Topics:99" in line for line in lines)


@pytest.mark.parametrize("create,delete", [(True, True), (False, False), (None, None)])
def test_new_markers_use_airflow_palette_and_saved_values_are_plain(create, delete, capsys):
    import json

    from redposture_core.console import Console

    record = {
        "host": "broker",
        "port": 9092,
        "status": "valid_credentials",
        "provided_username": "user",
        "provided_password": "pass",
        "topic_count": 4,
        "topic_lifecycle": {"create": create, "delete": delete},
    }
    line = actions._format_record(record, "txt")
    assert actions._render_colored_kafka_line(Console(no_color=False), line)
    colored = capsys.readouterr().out
    assert "\x1b[1;92m[+]" in colored
    assert "\x1b[1;38;5;196muser:pass" in colored
    color = "\x1b[1;38;5;196m" if create is True else "\x1b[1;92m" if create is False else "\x1b[1;38;5;208m"
    text = str(create) if type(create) is bool else "unknown"
    assert color + "Topic create:" + text in colored
    actions._render_colored_kafka_line(Console(no_color=True), line)
    assert "\x1b" not in capsys.readouterr().out
    assert "\x1b" not in line + actions._format_record(record, "json")
    assert json.loads(actions._format_record(record, "json"))["topic_lifecycle"]["create"] is create


def test_probe_topic_on_http_surface_reports_unsupported_without_mutation():
    from redposture_core.modules.kafka import http_surfaces

    record = {"ui_vendor": "kafka_rest_proxy", "http_inventory": ["orders"]}
    assert "ui_unsupported_actions" not in http_surfaces.collect(record, {})
    actual = http_surfaces.collect(record, {"probe_topic": True})
    assert "topic lifecycle probe is unavailable" in actual["ui_unsupported_actions"]
    assert "topic_lifecycle" not in actual
