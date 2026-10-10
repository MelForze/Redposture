"""Jenkins detection, authentication, inventory, CVE and rendering regressions."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from redposture_core import cli
from redposture_core.cli_args import parse_args
from redposture_core.clients.http_api import HttpResponse
from redposture_core.cve import enumerate_record, load_catalog
from redposture_core.modules.jenkins import actions, policy, render
from redposture_core.modules.jenkins.stage import build_jenkins_plan


def _response(status: int, body: str = "", headers: dict[str, str] | None = None) -> HttpResponse:
    return HttpResponse(status=status, body=body.encode(), headers=headers or {})


def _ctx() -> SimpleNamespace:
    return SimpleNamespace(host="127.0.0.1", port=8080, args=SimpleNamespace(timeout=1, retries=0), credential=None)


def test_defcreds_expanded_without_duplicate_explicit_pair() -> None:
    args = parse_args(["jenkins", "-t", "127.0.0.1:8080", "-u", "admin", "-p", "admin", "--defcreds"])
    runs = build_jenkins_plan(args).credential_runs
    pairs = [(item.username, item.password) for item in runs if item.username is not None]
    assert len(pairs) == 18
    assert len(set(pairs)) == len(pairs)
    assert pairs[0] == ("admin", "admin")
    assert ("admin", "changeme") in pairs
    assert ("jenkins", "admin") in pairs
    assert ("service", "service") in pairs
    assert runs[0].source == "provided"


def test_api_token_file_becomes_one_provided_credential(tmp_path: Any) -> None:
    token_file = tmp_path / "jenkins-token.txt"
    token_file.write_text("  test-api-token\n", encoding="utf-8")
    args = parse_args(["jenkins", "-t", "127.0.0.1:8080", "-u", "admin", "--api-token-file", str(token_file)])
    errors: list[str] = []
    assert policy.validate_args(args, SimpleNamespace(error=errors.append)) is None
    runs = build_jenkins_plan(args).credential_runs
    assert [(run.username, run.password, run.source) for run in runs] == [("admin", "test-api-token", "api_token")]
    assert not errors


@pytest.mark.parametrize(
    ("extra_args", "file_body", "expected_error"),
    [
        (["-u", "admin", "--api-token-file", "{file}"], None, "cannot read --api-token-file"),
        (["-u", "admin", "--api-token-file", "{file}"], " \n", "--api-token-file is empty"),
        (["-u", "admin", "--api-token", ""], None, "--api-token is empty"),
        (["--api-token", "token"], None, "--api-token requires -u"),
        (["-u", "admin", "-p", "pass", "--api-token", "token"], None, "cannot be combined with -p"),
        (["-u", "admin", "--api-token", "first\nsecond"], None, "API token contains a line break"),
        (["-u", "admin"], None, "requires both -u and -p"),
        (["-p", "pass"], None, "requires both -u and -p"),
    ],
)
def test_jenkins_rejects_invalid_credential_options(
    tmp_path: Any, extra_args: list[str], file_body: str | None, expected_error: str
) -> None:
    token_file = tmp_path / "jenkins-token.txt"
    if file_body is not None:
        token_file.write_text(file_body, encoding="utf-8")
    args = parse_args(
        ["jenkins", "-t", "127.0.0.1:8080", *(str(token_file) if item == "{file}" else item for item in extra_args)]
    )
    errors: list[str] = []
    assert policy.validate_args(args, SimpleNamespace(error=errors.append)) == 2
    assert len(errors) == 1 and expected_error in errors[0]


@pytest.mark.parametrize(
    ("api", "who", "login", "headers", "expected"),
    [
        (
            '{"_class":"hudson.model.Hudson","jobs":[]}',
            '{"authenticated":false,"name":"anonymous","authorities":[]}',
            "",
            {"X-Jenkins": "2.555.2"},
            True,
        ),
        (
            '{"_class":"hudson.model.Hudson","jobs":[]}',
            '{"authenticated":false,"name":"anonymous","authorities":[]}',
            "<form>j_username j_password Jenkins</form>",
            {},
            True,
        ),
        (
            '{"version":"2.555.2","jobs":[]}',
            '{"authenticated":false,"name":"anonymous","authorities":[]}',
            "<form>j_username j_password Jenkins</form>",
            {},
            True,
        ),
        (
            "{}",
            "{}",
            "<form>j_username j_password Jenkins</form>",
            {"X-Jenkins": "2.555.2"},
            True,
        ),
        ('{"version":"2.555.2"}', "{}", "<form>sign in</form>", {}, False),
        ('{"_class":"com.other.Product","jobs":[]}', "{}", "<form>sign in</form>", {}, False),
    ],
)
def test_detection_requires_independent_product_signals(
    monkeypatch: pytest.MonkeyPatch, api: str, who: str, login: str, headers: dict[str, str], expected: bool
) -> None:
    replies = {
        "/": _response(200, "", headers),
        "/api/json": _response(200, api),
        "/whoAmI/api/json": _response(200, who),
        "/login": _response(200, login),
    }
    monkeypatch.setattr(
        actions,
        "_get",
        lambda _client, _base, path, _basic=None: next(
            value for key, value in replies.items() if path.startswith(key) and (key != "/" or path == "/")
        ),
    )
    record = actions.detect_record(_ctx())
    assert record["is_jenkins"] is expected
    assert record["detection_status"] == ("confirmed" if expected else "not_service")


@pytest.mark.parametrize(
    ("api", "who", "login", "headers", "expected_paths", "expected_status"),
    [
        (
            '{"_class":"hudson.model.Hudson","jobs":[]}',
            "{}",
            "",
            {"X-Jenkins": "2.555.2"},
            ["/", "/api/json?tree=_class,jobs[name],mode,nodeDescription"],
            "confirmed",
        ),
        (
            '{"_class":"hudson.model.Hudson","jobs":[]}',
            '{"authenticated":false,"name":"anonymous","authorities":[]}',
            "",
            {},
            ["/", "/api/json?tree=_class,jobs[name],mode,nodeDescription", "/whoAmI/api/json", "/login"],
            "confirmed",
        ),
        (
            '{"version":"2.555.2"}',
            "{}",
            "<form>sign in</form>",
            {},
            ["/", "/api/json?tree=_class,jobs[name],mode,nodeDescription", "/whoAmI/api/json", "/login"],
            "not_service",
        ),
    ],
)
def test_detection_skips_only_redundant_jenkins_probes(
    monkeypatch: pytest.MonkeyPatch,
    api: str,
    who: str,
    login: str,
    headers: dict[str, str],
    expected_paths: list[str],
    expected_status: str,
) -> None:
    paths: list[str] = []
    replies = {
        "/": _response(200, "", headers),
        "/api/json": _response(200, api),
        "/whoAmI/api/json": _response(200, who),
        "/login": _response(200, login),
    }

    def fake_get(_client: object, _base: str, path: str, _basic: str | None = None) -> HttpResponse:
        paths.append(path)
        return next(value for key, value in replies.items() if path.startswith(key) and (key != "/" or path == "/"))

    monkeypatch.setattr(actions, "_get", fake_get)
    record = actions.detect_record(_ctx())
    assert paths == expected_paths
    assert record["detection_status"] == expected_status


@given(
    api_body=st.booleans(),
    who_body=st.booleans(),
    login_body=st.booleans(),
    version_at=st.sampled_from(("none", "root", "api", "who", "login")),
    api_status=st.sampled_from((200, 401, 403)),
    who_status=st.sampled_from((200, 401, 403)),
)
def test_jenkins_short_circuit_matches_full_evidence_decision(
    api_body: bool,
    who_body: bool,
    login_body: bool,
    version_at: str,
    api_status: int,
    who_status: int,
) -> None:
    paths: list[str] = []
    replies = {
        "/": _response(200, "", {"X-Jenkins": "2.555.2"} if version_at == "root" else {}),
        "/api/json": _response(
            api_status,
            '{"_class":"hudson.model.Hudson","jobs":[]}' if api_body else '{"version":"2.555.2"}',
            {"X-Jenkins": "2.555.2"} if version_at == "api" else {},
        ),
        "/whoAmI/api/json": _response(
            who_status,
            '{"authenticated":false,"name":"anonymous","authorities":[]}' if who_body else "{}",
            {"X-Jenkins": "2.555.2"} if version_at == "who" else {},
        ),
        "/login": _response(
            200,
            "<form>j_username j_password Jenkins</form>" if login_body else "<form>Corporate SSO</form>",
            {"X-Jenkins": "2.555.2"} if version_at == "login" else {},
        ),
    }

    def fake_get(_client: object, _base: str, path: str, _basic: str | None = None) -> HttpResponse:
        paths.append(path)
        return next(value for key, value in replies.items() if path.startswith(key) and (key != "/" or path == "/"))

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(actions, "_get", fake_get)
        result = actions.detect_record(_ctx())
    api_signal = api_body and api_status == 200
    who_signal = who_body and who_status == 200
    login_signal = login_body
    version_signal = version_at != "none"
    expected = (
        (api_signal and (version_signal or who_signal or login_signal))
        or (who_signal and login_signal)
        or (version_signal and login_signal)
    )
    assert result["is_jenkins"] is expected
    if api_signal and version_at in {"root", "api"}:
        assert len(paths) == 2
    elif api_signal and who_signal and version_at == "who":
        assert len(paths) == 4
    if api_signal and who_signal and version_at == "login":
        assert result["version"] == "2.555.2"


def test_auth_does_not_accept_public_200_or_ambiguous_403(monkeypatch: pytest.MonkeyPatch) -> None:
    ctx = _ctx()
    ctx.credential = SimpleNamespace(username="admin", password="bad", source="provided")
    prior = {"api_endpoint": "http://example", "is_jenkins": True}
    monkeypatch.setattr(
        actions, "_get", lambda *_args: _response(200, '{"authenticated":false,"name":"anonymous","authorities":[]}')
    )
    assert actions.auth_record(ctx, prior)["credential_state"] == "unknown"
    monkeypatch.setattr(actions, "_get", lambda *_args: _response(403, ""))
    assert actions.auth_record(ctx, prior)["credential_state"] == "unknown"
    monkeypatch.setattr(actions, "_get", lambda *_args: _response(401, ""))
    assert actions.auth_record(ctx, prior)["credential_state"] == "invalid"
    monkeypatch.setattr(actions, "_get", lambda *_args: _response(429, ""))
    assert actions.auth_record(ctx, prior)["status"] == "rate_limited"


def test_cve_jenkins_requires_exact_version_and_low_privilege_evidence() -> None:
    catalog = load_catalog()
    anonymous = enumerate_record(
        "jenkins", {"version": "2.440", "auth_required": True}, catalog=catalog, confirmed=True
    )
    assert {item["id"] for item in anonymous["findings"]} == {"CVE-2024-23897"}
    restricted = enumerate_record(
        "jenkins", {"version": "2.555.2", "auth_required": True}, catalog=catalog, confirmed=True
    )
    assert restricted["findings"] == []
    verified = enumerate_record(
        "jenkins",
        {"version": "2.555.2", "auth_required": True},
        catalog=catalog,
        confirmed=True,
        credentials_provided=True,
    )
    assert {item["id"] for item in verified["findings"]} == {"CVE-2026-53435"}
    fixed = enumerate_record(
        "jenkins",
        {"version": "2.555.3", "auth_required": True},
        catalog=catalog,
        confirmed=True,
        credentials_provided=True,
    )
    assert fixed["findings"] == []
    unknown = enumerate_record("jenkins", {"version": None, "auth_required": True}, catalog=catalog, confirmed=True)
    assert {item["id"] for item in unknown["findings"]} == {"CVE-2024-23897"}
    assert unknown["findings"][0]["version_assessment"] == "unknown"
    plugin_record = {
        "version": "2.600",
        "auth_required": True,
        "plugins": [{"short_name": "allure-jenkins-plugin", "version": "2.35.2"}],
    }
    plugin = enumerate_record("jenkins", plugin_record, catalog=catalog, confirmed=True, credentials_provided=True)
    assert {item["id"] for item in plugin["findings"]} == {"CVE-2026-84669"}
    plugin_record["plugins"] = [{"short_name": "allure-jenkins-plugin", "version": "unknown"}]
    assert enumerate_record("jenkins", plugin_record, catalog=catalog, confirmed=True)["findings"] == []
    plugin_record["plugins"] = [{"short_name": "allure-jenkins-plugin", "version": "2.35.2", "active": False}]
    assert (
        enumerate_record("jenkins", plugin_record, catalog=catalog, confirmed=True, credentials_provided=True)[
            "findings"
        ]
        == []
    )


class _JenkinsHandler(BaseHTTPRequestHandler):
    version = "2.440"
    requests: list[tuple[str, str | None]] = []

    def log_message(self, *_args: Any) -> None:
        pass

    def do_GET(self) -> None:
        path = self.path
        auth = self.headers.get("Authorization")
        type(self).requests.append((path, auth))
        if not path.startswith("/ci/"):
            self.send_error(404)
            return
        if path.startswith("/ci/api/json"):
            if auth != "Basic YWRtaW46cGFzcw==":
                self.send_response(403)
                self.send_header("X-Jenkins", self.version)
                self.end_headers()
                return
            payload: dict[str, Any] = {"_class": "hudson.model.Hudson", "jobs": []}
        elif path.startswith("/ci/whoAmI/api/json"):
            valid = auth == "Basic YWRtaW46cGFzcw=="
            payload = {"authenticated": valid, "name": "admin" if valid else "anonymous", "authorities": []}
        elif path.startswith("/ci/pluginManager/api/json"):
            payload = {"plugins": [{"shortName": "git", "version": "5.0.0", "active": True}]}
        elif path == "/ci/login":
            body = b"<form>j_username j_password Jenkins</form>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("X-Jenkins", self.version)
            self.end_headers()
            self.wfile.write(body)
            return
        else:
            payload = {}
        body = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("X-Jenkins", self.version)
        self.end_headers()
        self.wfile.write(body)


class _InventoryHandler(_JenkinsHandler):
    requests: list[tuple[str, str | None]] = []

    def do_GET(self) -> None:
        path = self.path
        auth = self.headers.get("Authorization")
        if path.startswith(("/ci/computer/api/json", "/ci/queue/api/json", "/ci/job/qa/api/json")) or path.startswith(
            "/ci/api/json?tree=jobs[name,url,color,lastBuild"
        ):
            type(self).requests.append((path, auth))
            if auth != "Basic YWRtaW46cGFzcw==":
                self.send_response(403)
                self.end_headers()
                return
            if path.startswith("/ci/computer/api/json"):
                payload = {
                    "computer": [
                        {
                            "displayName": "agent-1",
                            "offline": False,
                            "numExecutors": 2,
                            "executors": [{"currentExecutable": {"url": "build"}}, {"currentExecutable": None}],
                        },
                        {"displayName": "agent-2", "offline": True, "numExecutors": 1, "executors": []},
                    ]
                }
            elif path.startswith("/ci/queue/api/json"):
                payload = {"items": [{"id": 7, "task": {"name": "qa"}, "why": "Waiting for next available executor"}]}
            elif path.startswith("/ci/job/qa/api/json"):
                payload = {
                    "builds": [
                        {
                            "number": 2,
                            "result": "SUCCESS",
                            "artifacts": [
                                {"fileName": "report.txt", "relativePath": "reports/report.txt"},
                                {"fileName": "bad.txt", "relativePath": "../../bad.txt"},
                            ],
                        }
                    ]
                }
            else:
                payload = {"jobs": [{"name": "qa", "color": "blue"}]}
            body = json.dumps(payload).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body)
            return
        super().do_GET()

    def do_HEAD(self) -> None:
        type(self).requests.append((self.path, self.headers.get("Authorization")))
        if self.path == "/ci/job/qa/2/artifact/reports/report.txt":
            self.send_response(200)
            self.send_header("Content-Length", "512")
        else:
            self.send_response(404)
        self.end_headers()


class _KeepAliveJenkinsHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    connections = 0
    calls: list[tuple[str, str | None]] = []

    def log_message(self, *_args: Any) -> None:
        pass

    def setup(self) -> None:
        super().setup()
        type(self).connections += 1

    def do_GET(self) -> None:
        auth = self.headers.get("Authorization")
        type(self).calls.append((self.path, auth))
        if self.path.startswith("/api/json"):
            body = b'{"_class":"hudson.model.Hudson","jobs":[]}'
        elif self.path == "/whoAmI/api/json":
            body = json.dumps(
                {"authenticated": bool(auth), "name": "admin" if auth else "anonymous", "authorities": []}
            ).encode()
        elif self.path == "/login":
            body = b"<form>j_username j_password Jenkins</form>"
        elif self.path.startswith("/computer/api/json"):
            body = b'{"computer":[]}'
        elif self.path.startswith("/queue/api/json"):
            body = b'{"items":[]}'
        else:
            body = b"{}"
        self.send_response(200)
        self.send_header("X-Jenkins", "2.541.3")
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def test_http_connection_reused_across_jenkins_phases(capsys: Any) -> None:
    _KeepAliveJenkinsHandler.connections = 0
    _KeepAliveJenkinsHandler.calls = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _KeepAliveJenkinsHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        target = f"http://127.0.0.1:{server.server_port}"
        assert (
            cli.main(
                ["jenkins", "-t", target, "-u", "admin", "-p", "pass", "--show-nodes", "--show-queue", "--no-color"]
            )
            == 0
        )
        output = capsys.readouterr().out
        assert "Jenkins (auth required:False)" in output
        assert "Nodes Enumeration (nodes:0)" in output
        assert "Queue Enumeration (queue:0)" in output
        assert len(_KeepAliveJenkinsHandler.calls) >= 6
        assert _KeepAliveJenkinsHandler.connections == 1
        assert not any(auth for path, auth in _KeepAliveJenkinsHandler.calls if path == "/login")
        assert not any(path == "/login" for path, _auth in _KeepAliveJenkinsHandler.calls)
        assert any(auth for path, auth in _KeepAliveJenkinsHandler.calls if path == "/whoAmI/api/json")
    finally:
        server.shutdown()
        thread.join(timeout=3)
        server.server_close()


def test_cli_prefix_inventory_cve_and_no_ansi(tmp_path: Any, capsys: Any) -> None:
    _JenkinsHandler.requests = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _JenkinsHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        output = tmp_path / "jenkins.txt"
        target = f"http://127.0.0.1:{server.server_port}/ci"
        code = cli.main(
            [
                "jenkins",
                "-t",
                target,
                "-u",
                "admin",
                "-p",
                "pass",
                "--show-jobs",
                "--show-plugins",
                "--enum-cve",
                "--no-color",
                "-o",
                str(output),
            ]
        )
        assert code == 0
        text = output.read_text()
        stdout = capsys.readouterr().out
        assert "Jenkins (auth required:True)" in text
        assert "admin:pass (Jobs:0)" in text
        assert text.count("admin:pass (Jobs:0)") == 1
        assert text.index("admin:pass (Jobs:0)") < text.index("CVE's Enumeration")
        assert text.index("CVE's Enumeration") < text.index("Jobs Enumeration")
        assert "CVE-2024-23897" in text
        assert "Plugins Enumeration (plugins:1)" in text
        assert "\x1b[" not in text + stdout
        assert all(len(line.split("\t")) == 4 for line in text.splitlines())
        assert all(path.startswith("/ci/") for path, _auth in _JenkinsHandler.requests)
        token_output = tmp_path / "token.txt"
        assert (
            cli.main(
                ["jenkins", "-t", target, "-u", "admin", "--api-token", "pass", "--no-color", "-o", str(token_output)]
            )
            == 0
        )
        token_text = token_output.read_text()
        assert "admin (API token)" in token_text
        assert "admin:pass" not in token_text
        json_output = tmp_path / "jenkins.jsonl"
        assert (
            cli.main(
                [
                    "jenkins",
                    "-t",
                    target,
                    "-u",
                    "admin",
                    "--api-token",
                    "pass",
                    "--enum-cve",
                    "--format",
                    "json",
                    "--no-color",
                    "-o",
                    str(json_output),
                ]
            )
            == 0
        )
        json_text = json_output.read_text()
        assert "\x1b[" not in json_text
        parsed = [json.loads(line) for line in json_text.splitlines()]
        assert parsed[0]["detection_status"] == "confirmed"
        assert any(item["id"] == "CVE-2024-23897" for item in parsed[0]["cve_enumeration"]["findings"])
        assert '"password": "pass"' not in json_text
        assert '"credential_password": "pass"' not in json_text
    finally:
        server.shutdown()
        thread.join(timeout=3)
        server.server_close()


def test_inventory_nodes_queue_and_artifact_metadata_are_read_only(tmp_path: Any, capsys: Any) -> None:
    _InventoryHandler.requests = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _InventoryHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        target = f"http://127.0.0.1:{server.server_port}/ci"
        output = tmp_path / "jenkins_inventory.txt"
        assert (
            cli.main(
                [
                    "jenkins",
                    "-t",
                    target,
                    "-u",
                    "admin",
                    "-p",
                    "pass",
                    "--show-nodes",
                    "--show-queue",
                    "--show-artifacts",
                    "2",
                    "--no-color",
                    "-o",
                    str(output),
                ]
            )
            == 0
        )
        text = output.read_text()
        stdout = capsys.readouterr().out
        assert "Nodes Enumeration (nodes:2)" in text
        assert 'Node Name="agent-1" (online:True) (executors:2) (busy:1)' in text
        assert "Queue Enumeration (queue:1)" in text
        assert 'Queue Task="qa" (id:7)' in text
        assert "Builds Enumeration (builds:1)" in text
        assert "Artifacts Enumeration (artifacts:1)" in text
        assert 'Artifact Name="report.txt"' in text and "(size_bytes:512)" in text
        assert "bad.txt" not in text
        assert "\x1b[" not in text + stdout
        assert all(len(line.split("\t")) == 4 for line in text.splitlines())
        assert any(path == "/ci/job/qa/2/artifact/reports/report.txt" for path, _ in _InventoryHandler.requests)
        assert not any("bad.txt" in path for path, _ in _InventoryHandler.requests)
        assert not any(
            path == "/ci/job/qa/2/artifact/reports/report.txt" and auth is None
            for path, auth in _InventoryHandler.requests
        )
        json_output = tmp_path / "jenkins_inventory.jsonl"
        assert (
            cli.main(
                [
                    "jenkins",
                    "-t",
                    target,
                    "-u",
                    "admin",
                    "-p",
                    "pass",
                    "--show-nodes",
                    "--show-queue",
                    "--show-artifacts",
                    "2",
                    "--format",
                    "json",
                    "--no-color",
                    "-o",
                    str(json_output),
                ]
            )
            == 0
        )
        payload = json.loads(json_output.read_text().splitlines()[0])
        assert payload["nodes_count"] == 2
        assert payload["queue_count"] == 1
        assert payload["artifacts"][0]["size_bytes"] == 512
        assert "\x1b[" not in json_output.read_text()
    finally:
        server.shutdown()
        thread.join(timeout=3)
        server.server_close()


def test_inventory_access_denied_does_not_claim_zero(monkeypatch: pytest.MonkeyPatch) -> None:
    ctx = _ctx()
    ctx.args.show_nodes = True
    ctx.args.show_queue = True
    ctx.args.show_artifacts = False
    ctx.args.show_jobs = False
    ctx.args.show_builds = False
    ctx.args.show_plugins = False
    ctx.args.enum_cve = False
    monkeypatch.setattr(actions, "_get", lambda *_args: _response(403))
    record = actions.data_record(ctx, {"api_endpoint": "http://example"})
    assert record["nodes_access"] == "denied"
    assert record["queue_access"] == "denied"
    assert "nodes_count" not in record and "queue_count" not in record
    lines = render._format_inventory_records(record, "txt")
    assert "Nodes Enumeration (access:Access Denied)" in "\n".join(lines)
    assert "Queue Enumeration (access:Access Denied)" in "\n".join(lines)


def test_incomplete_node_and_missing_artifact_length_remain_unknown() -> None:
    assert actions._busy_executors({"executors": [{"idle": False}]}) is None
    assert actions._busy_executors({"executors": [{"currentExecutable": None}]}) == 0

    class HeadClient:
        def request(self, method: str, _url: str, *, headers: Any = None) -> HttpResponse:
            assert method == "HEAD"
            return _response(200)

    assert actions._artifact_size(HeadClient(), "http://example/artifact/report.txt", None) is None


class _Console:
    def __init__(self) -> None:
        self.lines: list[str] = []

    def _paint(self, text: str, color: str, _s: Any) -> str:
        return f"<{color}>{text}</{color}>"

    def plain(self, line: str) -> None:
        self.lines.append(line)


def test_color_contract() -> None:
    console = _Console()
    assert render._render_colored_jenkins_line(
        console, "JENKINS\th\t8080\t [*] Jenkins (auth required:True) (jobs allowed anonymously:False) (version:-)"
    )
    assert "<bright_green>jobs allowed anonymously:False</bright_green>" in console.lines[0]
    console.lines.clear()
    assert render._render_colored_jenkins_line(console, "JENKINS\th\t8080\t [*] Jobs Enumeration (jobs:2)")
    assert "<true_red>jobs:2</true_red>" in console.lines[0]
    console.lines.clear()
    assert render._render_colored_jenkins_line(console, 'JENKINS\th\t8080\t [+] Job Name="ci" (state:blue)')
    assert '<orange>Job Name="ci" (state:blue)</orange>' in console.lines[0]
    console.lines.clear()
    assert render._render_colored_jenkins_line(console, "JENKINS\th\t8080\t [*] CVE's Enumeration")
    assert "<white>CVE's Enumeration</white>" in console.lines[0]
    console.lines.clear()
    assert render._render_colored_jenkins_line(console, "JENKINS\th\t8080\t [*] Queue Enumeration (queue:1)")
    assert "<true_red>queue:1</true_red>" in console.lines[0]
    console.lines.clear()
    assert render._render_colored_jenkins_line(console, "JENKINS\th\t8080\t [*] Artifacts Enumeration (artifacts:0)")
    assert "<bright_green>artifacts:0</bright_green>" in console.lines[0]
    console.lines.clear()
    assert render._render_colored_jenkins_line(
        console, 'JENKINS\th\t8080\t [+] Node Name="agent-1" (online:True) (executors:2) (busy:1)'
    )
    assert "<true_red>online:True</true_red>" in console.lines[0]
    assert "<true_red>busy:1</true_red>" in console.lines[0]
    console.lines.clear()
    assert render._render_colored_jenkins_line(
        console, 'JENKINS\th\t8080\t [+] Artifact Name="report.txt" (job:"qa") (build:1) (size_bytes:512)'
    )
    assert '<orange>Artifact Name="report.txt"' in console.lines[0]
    assert "<true_red>size_bytes:512</true_red>" in console.lines[0]
