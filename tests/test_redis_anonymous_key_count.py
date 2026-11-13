"""Anonymous key counts are available before version in sync and async detect."""

import json
from types import SimpleNamespace

import pytest

from redposture_core.console import Console
from redposture_core.modules.redis import actions
from redposture_core.stage_runtime import AuditCredentialRun
from tests.test_redis_detection_review import BULK_INFO, detect


@pytest.mark.parametrize("route", ["sync", "native"])
@pytest.mark.parametrize("count", [0, 7])
def test_anonymous_detect_has_exact_count_and_keeps_it_through_auth(monkeypatch, route, count):
    record, wire = detect(b"+PONG\r\n" + BULK_INFO + f":{count}\r\n".encode(), route, monkeypatch)
    assert record["auth_required"] is False and record["key_count"] == count
    assert b"DBSIZE" in wire.sent[-1]
    text = actions._format_detect_record(record, "txt")
    assert text.endswith(f"(auth required:False) (keys:{count}) (version:7.4.0)")
    assert json.loads(actions._format_detect_record(record, "json"))["key_count"] == count
    state = actions.RedisAuditLifecycleState("qa", 6379, 1, 0, False, None, 0)
    state.is_redis, state.auth_required, state.status, state.key_count = True, False, "open_no_auth", count
    ctx = SimpleNamespace(
        lifecycle_state=state, args=SimpleNamespace(), credential=AuditCredentialRun(source="anonymous")
    )
    assert actions.redis_auth_hook(ctx, None).extra["key_count"] == count


@pytest.mark.parametrize("route", ["sync", "native"])
@pytest.mark.parametrize("response", [b"-NOPERM DBSIZE denied\r\n", b":-1\r\n", b":", b"", b"+OK\r\n"])
def test_count_failure_keeps_confirmed_redis_and_does_not_invent_zero(monkeypatch, route, response):
    record, _ = detect(b"+PONG\r\n" + BULK_INFO + response, route, monkeypatch)
    assert record["is_redis"] and record["auth_required"] is False
    assert record["key_count"] is None and record["key_count_error"]
    assert "(keys:unknown) (version:7.4.0)" in actions._format_detect_record(record, "txt")


@pytest.mark.parametrize("auth", [True, None])
def test_count_not_displayed_when_anonymous_access_is_unconfirmed(auth):
    record = {"host": "qa", "port": 6379, "auth_required": auth, "key_count": 9, "server_version": "8.4.0"}
    assert "(keys:" not in actions._format_detect_record(record, "txt")
    assert "key_count" not in json.loads(actions._format_detect_record(record, "json"))


@pytest.mark.parametrize("count,color", [(0, "\x1b[1;92m"), (7, "\x1b[1;38;5;196m"), (None, "\x1b[1;38;5;208m")])
def test_anonymous_count_color_and_plain_saved_output(capsys, count, color):
    record = {
        "host": "qa",
        "port": 6379,
        "is_redis": True,
        "auth_required": False,
        "key_count": count,
        "server_version": "8.4.0",
    }
    line = actions._format_detect_record(record, "txt")
    actions._render_colored_redis_line(Console(no_color=False), line)
    assert color + "keys:" in capsys.readouterr().out
    actions._render_colored_redis_line(Console(no_color=True), line)
    plain = capsys.readouterr().out
    assert "\x1b" not in plain + line + actions._format_detect_record(record, "json")


@pytest.mark.parametrize("route", ["sync", "native"])
@pytest.mark.parametrize(
    "response", [b"-NOAUTH Authentication required.\r\n", b"-LOADING Redis is loading the dataset\r\n"]
)
def test_no_anonymous_count_request_when_access_is_required_or_unknown(monkeypatch, route, response):
    record, wire = detect(response, route, monkeypatch)
    assert record["is_redis"] and record["auth_required"] is not False
    assert not any(b"DBSIZE" in frame for frame in wire.sent)


@pytest.mark.parametrize("route", ["sync", "native"])
def test_count_after_info_confirms_redis_when_ping_is_disabled(monkeypatch, route):
    record, wire = detect(b"-ERR PING disabled\r\n" + BULK_INFO + b":3\r\n", route, monkeypatch)
    assert record["is_redis"] and record["auth_required"] is False
    assert record["key_count"] == 3 and b"DBSIZE" in wire.sent[-1]


def test_partial_count_response_closes_socket_before_auth_or_data(monkeypatch):
    class Socket:
        closed = False

        def close(self):
            self.closed = True

    sock = Socket()
    state = actions.RedisAuditLifecycleState("qa", 6379, 1, 0, False, None, 0)
    state.sock, state.is_redis, state.auth_required, state.status = sock, True, False, "open_no_auth"

    def interrupted(*args):
        raise TimeoutError("partial DBSIZE response")

    monkeypatch.setattr(actions, "_send_cmd", interrupted)
    actions._capture_anonymous_redis_keys(state)
    assert sock.closed and state.sock is None
    assert state.key_count is None and state.key_count_error == "partial DBSIZE response"
    assert state.is_redis and state.auth_required is False and state.status == "open_no_auth"
