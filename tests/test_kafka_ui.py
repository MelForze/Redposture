"""Network regressions for Kafka UI detection on the Kafka command."""

from __future__ import annotations

import json
import subprocess
import sys
import threading
from collections.abc import Generator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

import pytest
from hypothesis import given
from hypothesis import strategies as st

from redposture_core.clients.http_api import HttpResponse
from redposture_core.modules.kafka import render as kafka_render
from redposture_core.modules.kafka import ui


class _UiHandler(BaseHTTPRequestHandler):
    mode = "ui"
    posts = 0

    def log_message(self, *_args: object) -> None:
        return

    def _send(self, status: int, value: object, *, headers: dict[str, str] | None = None) -> None:
        body = json.dumps(value).encode() if not isinstance(value, bytes) else value
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for key, item in (headers or {}).items():
            self.send_header(key, item)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        path = self.path.split("?", 1)[0].removeprefix("/prefix")
        if self.mode == "foreign":
            self._send(200, {"version": "1.2.3", "name": "other"})
        elif path == "/api/info":
            brand = "Provectus Kafka UI" if self.mode == "provectus" else "Kafbat UI"
            self._send(200, {"build": {"version": "1.4.2", "commitId": "abc123"}, "name": brand})
        elif path == "/api/config/authentication":
            if self.mode == "provectus":
                self._send(404, {})
            else:
                self._send(200, {"authType": "LOGIN_FORM"})
        elif path == "/api/authorization":
            if self.mode == "protected" and "session=ok" not in self.headers.get("Cookie", ""):
                self._send(401, {"message": "Unauthorized"})
                return
            logged_in = "session=ok" in self.headers.get("Cookie", "")
            self._send(200, {"rbacEnabled": False, "userInfo": {"username": "admin"} if logged_in else None})
        elif path == "/api/clusters":
            if "session=ok" not in self.headers.get("Cookie", ""):
                self._send(401, {"message": "Unauthorized"})
            else:
                self._send(200, [{"name": "local", "brokerCount": 1, "topicCount": 2, "readOnly": False}])
        elif path == "/api/clusters/local/topics":
            self._send(200, {"topics": [{"name": "events"}]})
        elif path == "/api/clusters/local/brokers":
            self._send(200, [{"id": 1, "host": "broker"}])
        elif path == "/api/clusters/local/consumer-groups":
            self._send(200, [{"groupId": "workers"}])
        elif path == "/api/clusters/local/consumer-groups/paged":
            self._send(200, {"consumerGroups": [{"groupId": "workers"}]})
        elif path == "/login":
            self._send(
                200,
                b'<input name="username"><input name="password"><input name="_csrf" value="token">',
                headers={"Set-Cookie": "session=start; Path=/"},
            )
        else:
            self._send(404, {})

    def do_POST(self) -> None:
        type(self).posts += 1
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        fields = parse_qs(body.decode())
        if self.mode == "limited":
            self._send(429, {"message": "Too many requests"})
            return
        if self.mode == "forbidden":
            self._send(403, {"message": "CSRF denied"})
            return
        if (
            self.path.endswith("/login")
            and fields.get("username") == ["admin"]
            and fields.get("password") == ["admin"]
            and fields.get("_csrf") == ["token"]
        ):
            self._send(302, b"", headers={"Location": "/", "Set-Cookie": "session=ok; Path=/"})
        else:
            self._send(302, b"", headers={"Location": "/login?error"})


@pytest.fixture
def ui_server() -> Generator[tuple[str, type[_UiHandler]], None, None]:
    handler = type("Handler", (_UiHandler,), {"mode": "ui", "posts": 0})
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"127.0.0.1:{server.server_port}", handler
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "redposture.py", "kafka", *args, "--timeout", "0.5"],
        cwd=Path(__file__).resolve().parents[1],
        capture_output=True,
        text=True,
        timeout=20,
    )


def test_host_port_auto_detects_ui_and_reads_inventory(ui_server: tuple[str, type[_UiHandler]]) -> None:
    target, handler = ui_server
    result = _run(
        "-t",
        target,
        "-u",
        "admin",
        "-p",
        "admin",
        "--show-clusters",
        "--show-topics",
        "--show-brokers",
        "--show-consumer-groups",
    )
    assert result.returncode == 0, result.stderr
    assert "Kafbat UI" in result.stdout
    assert "admin:admin" in result.stdout
    assert "Clusters Enumeration" in result.stdout
    assert "Topics Enumeration" in result.stdout
    assert "Brokers Enumeration" in result.stdout
    assert "Consumer Groups Enumeration" in result.stdout
    assert handler.posts == 1


def test_url_prefix_and_json_are_preserved(ui_server: tuple[str, type[_UiHandler]], tmp_path: Path) -> None:
    target, _ = ui_server
    result = _run("-t", f"http://{target}/prefix", "-u", "admin", "-p", "admin", "--format", "json")
    assert result.returncode == 0, result.stderr
    record = json.loads(result.stdout.splitlines()[-1])
    assert record["is_kafka_ui"] is True
    assert record["detection_status"] == "confirmed"
    assert record["ui_base"] == f"http://{target}/prefix"
    assert "\x1b[" not in result.stdout
    output = tmp_path / "kafka-ui.txt"
    text_result = _run("-t", f"http://{target}/prefix", "-u", "admin", "-p", "admin", "-o", str(output))
    assert text_result.returncode == 0, text_result.stderr
    assert "Kafbat UI" in output.read_text()
    assert "\x1b[" not in output.read_text()


def test_foreign_http_response_does_not_trigger_login(ui_server: tuple[str, type[_UiHandler]]) -> None:
    target, handler = ui_server
    handler.mode = "foreign"
    result = _run("-t", target, "-u", "admin", "-p", "admin")
    assert "Kafka UI" not in result.stdout
    assert handler.posts == 0


def test_provectus_without_new_auth_config_is_detected(ui_server: tuple[str, type[_UiHandler]]) -> None:
    target, handler = ui_server
    handler.mode = "provectus"
    result = _run("-t", target, "-u", "admin", "-p", "admin", "--no-color")
    assert result.returncode == 0, result.stderr
    assert "Provectus Kafka UI" in result.stdout
    assert "[+] admin:admin" in result.stdout
    assert "\x1b[" not in result.stdout


def test_protected_kafbat_still_detected_by_login_form(ui_server: tuple[str, type[_UiHandler]]) -> None:
    target, handler = ui_server
    handler.mode = "protected"
    result = _run("-t", target, "-u", "admin", "-p", "admin", "--no-color")
    assert result.returncode == 0, result.stderr
    assert "Kafbat UI" in result.stdout
    assert "[+] admin:admin" in result.stdout


def test_failed_ui_login_is_not_reported_valid(ui_server: tuple[str, type[_UiHandler]]) -> None:
    target, handler = ui_server
    result = _run("-t", target, "-u", "admin", "-p", "bad", "--no-color")
    assert result.returncode == 0, result.stderr
    assert "[-] admin:bad" in result.stdout
    assert "[+] admin:bad" not in result.stdout
    assert handler.posts == 1


def test_ambiguous_403_does_not_claim_invalid_password(ui_server: tuple[str, type[_UiHandler]]) -> None:
    target, handler = ui_server
    handler.mode = "forbidden"
    result = _run("-t", target, "-u", "admin", "-p", "admin", "--no-color")
    assert result.returncode == 0, result.stderr
    assert "Kafbat UI" in result.stdout
    assert "admin:admin" not in result.stdout
    assert handler.posts == 1


def test_default_sweep_stops_on_rate_limit(ui_server: tuple[str, type[_UiHandler]]) -> None:
    target, handler = ui_server
    handler.mode = "limited"
    result = _run("-t", target, "--defcreds", "--no-color")
    assert result.returncode == 0, result.stderr
    assert "Kafbat UI" in result.stdout
    assert handler.posts == 1


def test_broker_write_flags_never_mutate_ui(ui_server: tuple[str, type[_UiHandler]]) -> None:
    target, handler = ui_server
    result = _run("-t", target, "-u", "admin", "-p", "admin", "--topic", "events", "--probe-write", "--no-color")
    assert result.returncode == 0, result.stderr
    assert "broker-only topic data and writes" in result.stdout
    assert handler.posts == 1


def test_ui_color_contract() -> None:
    class _Colors:
        def __init__(self) -> None:
            self.line = ""

        def _paint(self, value: str, color: str, _stream: object) -> str:
            return f"<{color}>{value}</{color}>"

        def plain(self, value: str) -> None:
            self.line = value

    console = _Colors()
    assert kafka_render._render_colored_kafka_line(
        console, "KAFKA\t127.0.0.1\t8080\t [*] Kafbat UI (auth required:True) (version:1.4.2)"
    )
    assert "bright_green" in console.line
    assert "orange" in console.line
    assert kafka_render._render_colored_kafka_line(
        console, "KAFKA\t127.0.0.1\t8080\t [*] Clusters Enumeration (clusters:0)"
    )
    assert "bright_green" in console.line


def test_ui_fingerprint_requires_independent_signals() -> None:
    assert ui._info({"build": {"version": "1.2.3"}})[0] is False
    assert ui._auth_type({"authType": "LOGIN_FORM"}) == "LOGIN_FORM"
    assert ui._auth_type({"authType": "anything"}) is None
    assert ui._clusters([{"name": "local", "brokerCount": 1}]) is not None
    assert ui._clusters([{"name": "local"}]) is None


@given(
    st.recursive(
        st.none() | st.booleans() | st.integers() | st.text(max_size=32),
        lambda child: st.lists(child, max_size=5) | st.dictionaries(st.text(max_size=12), child, max_size=5),
        max_leaves=20,
    )
)
def test_malformed_ui_json_never_crashes_fingerprint(value: object) -> None:
    ui._info(value)
    ui._auth_type(value)
    ui._authorization(value)
    ui._clusters(value)


def _response(status: int, payload: object, *, headers: dict[str, str] | None = None, **extra: object) -> HttpResponse:
    body = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
    return HttpResponse(status=status, body=body, headers=headers or {}, **extra)


class _Pool:
    def __init__(self, replies: dict[tuple[str, str], HttpResponse]) -> None:
        self.replies = replies
        self.calls: list[tuple[str, str, dict[str, object]]] = []

    def request(self, method: str, url: str, **kwargs: object) -> HttpResponse:
        self.calls.append((method, url, kwargs))
        path = urlsplit(url).path.removeprefix("/prefix")
        return self.replies.get((method, path), _response(404, {}))

    def request_once(self, method: str, url: str, **kwargs: object) -> HttpResponse:
        return self.request(method, url, **kwargs)


def _ui_context(*, path: str = "/prefix/api/info", source: str = "provided") -> SimpleNamespace:
    return SimpleNamespace(
        host="example.test",
        port=8080,
        target=SimpleNamespace(path=path, scheme="http"),
        args=SimpleNamespace(timeout=0.2, _proxy_config=None),
        credential=SimpleNamespace(username="admin", password="secret", source=source),
    )


def test_direct_ui_detection_preserves_prefix_and_requires_product_evidence() -> None:
    replies = {
        ("GET", "/api/info"): _response(200, {"build": {"version": "1.4.2", "commitId": "abc"}, "name": "Kafbat UI"}),
        ("GET", "/api/config/authentication"): _response(200, {"authType": "LOGIN_FORM"}),
        ("GET", "/api/authorization"): _response(200, {"rbacEnabled": False, "userInfo": None}),
        ("GET", "/api/clusters"): _response(401, {}),
    }
    pool = _Pool(replies)
    state = SimpleNamespace(ui_http=pool, ui_base=None, ui_auth_type=None, ui_anonymous_clusters=None, ui_vendor=None)
    record = ui.detect_ui(_ui_context(), state)
    assert record["detection_status"] == "confirmed"
    assert record["ui_vendor"] == "kafbat"
    assert record["version"] == "1.4.2"
    assert record["auth_required"] is True
    assert state.ui_base == "http://example.test:8080/prefix"
    assert all(urlsplit(url).path.startswith("/prefix/") for _, url, _ in pool.calls)
    assert {"ui_info_build", "ui_auth_config", "ui_authorization"} <= set(record["detection_signals"])

    foreign_pool = _Pool({("GET", "/api/info"): _response(200, {"version": "1.4.2", "name": "foreign"})})
    state.ui_http = foreign_pool
    foreign = ui.detect_ui(_ui_context(), state)
    assert foreign["detection_status"] == "not_service"
    assert foreign["is_kafka_ui"] is False


@pytest.mark.parametrize(
    ("post_response", "expected"),
    [
        (_response(302, b"", headers={"Location": "/", "Set-Cookie": "session=ok; Path=/"}), "valid_credentials"),
        (_response(302, b"", headers={"Location": "/login?error"}), "invalid_credentials"),
        (_response(429, {"message": "Too many requests"}), "rate_limited"),
        (_response(403, b"CAPTCHA required"), "rate_limited"),
    ],
)
def test_direct_ui_login_needs_verified_identity(post_response: HttpResponse, expected: str) -> None:
    pool = _Pool(
        {
            ("GET", "/login"): _response(
                200,
                b'<input name="_csrf" value="token">',
                headers={"Set-Cookie": "session=start; Path=/"},
            ),
            ("POST", "/login"): post_response,
            ("GET", "/api/authorization"): _response(200, {"rbacEnabled": False, "userInfo": {"username": "admin"}}),
        }
    )
    state = SimpleNamespace(
        ui_http=pool, ui_base="http://example.test:8080/prefix", ui_auth_type="LOGIN_FORM", ui_cookie=""
    )
    result = ui.authenticate_ui(_ui_context(), {"status": "auth_required"}, state)
    assert result["status"] == expected
    expected_credential_result = (
        True if expected == "valid_credentials" else False if expected == "invalid_credentials" else None
    )
    assert result["provided_credentials_ok"] is expected_credential_result
    assert bool(state.ui_cookie) is (expected == "valid_credentials")
    posts = [call for call in pool.calls if call[0] == "POST"]
    assert len(posts) == 1
    assert b"_csrf=token" in posts[0][2]["body"]
    identity_checked = any("/api/authorization" in url for _, url, _ in pool.calls)
    assert identity_checked is (expected == "valid_credentials")


def test_direct_ui_collect_bounds_inventory_and_marks_broker_only_actions() -> None:
    pool = _Pool(
        {
            ("GET", "/api/clusters"): _response(
                200, [{"name": "local", "brokerCount": 1, "topicCount": 2, "readOnly": False}]
            ),
            ("GET", "/api/clusters/local/topics"): _response(200, {"topics": [{"name": "first"}, {"name": "second"}]}),
            ("GET", "/api/clusters/local/brokers"): _response(200, [{"id": 1, "host": "broker"}]),
            ("GET", "/api/clusters/local/consumer-groups/paged"): _response(
                200, {"consumerGroups": [{"groupId": "workers"}]}
            ),
        }
    )
    state = SimpleNamespace(ui_http=pool, ui_base="http://example.test:8080/prefix", ui_cookie="session=ok")
    result = ui.collect_ui(
        _ui_context(),
        {"status": "valid_credentials"},
        state,
        {
            "show_clusters": True,
            "show_topics": True,
            "show_topics_limit": 1,
            "show_brokers": True,
            "show_consumer_groups": True,
            "probe_write": True,
        },
    )
    assert result["cluster_count"] == 1
    assert result["ui_clusters"][0]["name"] == "local"
    assert result["ui_topics"] == [{"cluster": "local", "name": "first"}]
    assert result["ui_brokers"] == [{"cluster": "local", "id": 1, "host": "broker"}]
    assert result["ui_consumer_groups"] == [{"cluster": "local", "name": "workers"}]
    assert "broker-only" in result["ui_unsupported_actions"]
    assert all(call[0] == "GET" for call in pool.calls)


def test_direct_ui_rendering_covers_detection_credentials_and_inventory() -> None:
    record = {
        "host": "127.0.0.1",
        "port": 8080,
        "is_kafka_ui": True,
        "ui_vendor": "provectus",
        "auth_required": True,
        "version": "1.4.2",
        "status": "valid_credentials",
        "provided_username": "admin",
        "provided_password": "secret",
        "attempted_credentials": [
            {"status": "valid_credentials", "username": "admin", "password": "secret"},
            {"status": "invalid_credentials", "username": "admin", "password": "bad"},
            {"status": "unknown_auth", "username": "admin", "password": "unknown"},
        ],
        "show_clusters": True,
        "show_brokers": True,
        "show_topics": True,
        "show_consumer_groups": True,
        "ui_clusters": [{"name": "local"}],
        "ui_brokers": [{"cluster": "local", "host": "broker"}],
        "ui_topics": [{"cluster": "local", "name": "events"}],
        "ui_consumer_groups": [{"cluster": "local", "name": "workers"}],
        "ui_unsupported_actions": "writes unavailable",
    }
    assert "Provectus Kafka UI" in kafka_render._format_detect_record(record, "txt")
    assert kafka_render._format_detect_record(record, "json") == ""
    assert kafka_render._format_record(record, "txt") == ""
    credential_lines = kafka_render._format_credential_attempts_records(record, "txt")
    assert len(credential_lines) == 2
    assert credential_lines[0].endswith("[+] admin:secret")
    assert credential_lines[1].endswith("[-] admin:bad")
    lines = kafka_render._format_ui_detail_records(record, "txt")
    assert [
        name for name in ("Clusters", "Brokers", "Topics", "Consumer Groups") if any(name in line for line in lines)
    ] == ["Clusters", "Brokers", "Topics", "Consumer Groups"]
    assert any("local/events" in line for line in lines)
    assert any("writes unavailable" in line for line in lines)
    assert kafka_render._format_ui_detail_records(record, "json") == []
    assert kafka_render._format_topics_detail_records(record, "txt") == []
    single = {**record, "attempted_credentials": []}
    assert "[+] admin:secret" in kafka_render._format_record(single, "txt")
    assert kafka_render._format_record({**single, "status": "unknown_auth"}, "txt") == ""
    assert "[-] admin:secret" in kafka_render._format_record({**single, "status": "invalid_credentials"}, "txt")


def test_direct_ui_response_validation_rejects_malformed_content() -> None:
    assert ui._json(_response(200, b"not json")) is None
    assert ui._json(_response(401, {})) is None
    assert ui._json(_response(200, {}, truncated=True)) is None
    assert ui._json(_response(200, {}, error="timeout")) is None
    assert ui._cookie(_response(200, {}, headers={"Set-Cookie": "session=ok; Path=/"})) == "session=ok"
    assert ui._header(_response(200, {}, headers={"x-test": "value"}), "X-Test") == "value"
    assert ui._authorization({"rbacEnabled": False, "userInfo": {"username": "admin"}})
    assert not ui._authorization({"rbacEnabled": "false"})
    assert ui._info({"build": {"buildTime": "today", "commitId": "abc"}, "name": "Kafbat UI"}) == (True, None, "kafbat")
