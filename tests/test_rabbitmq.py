from __future__ import annotations

import base64
import json
from copy import deepcopy
from types import SimpleNamespace
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest

from redposture_core.audit_models import AuditRecord
from redposture_core.cli_args import parse_args
from redposture_core.clients.http_api import HttpResponse
from redposture_core.clients.rabbitmq_api import RESPONSE_CAP, RabbitMQClient
from redposture_core.modules.rabbitmq import actions, policy, render, stage
from redposture_core.stage_runtime import AuditCommandRunner


def response(status: int = 200, data: Any = None, **kwargs: Any) -> HttpResponse:
    return HttpResponse(status, json.dumps(data).encode(), kwargs.pop("headers", {}), **kwargs)


class FakePool:
    def __init__(self, replies: list[HttpResponse] | None = None, **kwargs: Any) -> None:
        self.replies = list(replies or [])
        self.calls: list[dict[str, Any]] = []
        self.closed = False

    def request(self, method: str, url: str, **kwargs: Any) -> HttpResponse:
        self.calls.append({"method": method, "url": url, **kwargs})
        return self.replies.pop(0)

    def close(self) -> None:
        self.closed = True


def client(pool: Any, **kwargs: Any) -> RabbitMQClient:
    return RabbitMQClient(pool, host="::1", port=15672, scheme="http", **kwargs)


def test_client_basic_empty_password_ipv6_prefix_and_transport_contract():
    pool = FakePool([response(data={"name": "alice", "tags": []})])
    result = client(pool, base_path="/rabbit/", username="alice", password="").get("/api/whoami")
    assert result.outcome == "ok"
    call = pool.calls[0]
    assert call["url"] == "http://[::1]:15672/rabbit/api/whoami"
    assert call["headers"]["Authorization"] == "Basic " + base64.b64encode(b"alice:").decode()
    assert call["method"] == "GET"
    assert call["response_size_cap"] == RESPONSE_CAP
    assert call["allow_cross_origin_redirects"] is True


@pytest.mark.parametrize(
    ("reply", "outcome"),
    [
        (response(401), "denied"),
        (response(403), "denied"),
        (response(404), "unavailable"),
        (response(503), "unexpected_response"),
        (response(error="timeout"), "transport_error"),
        (response(data=[{"name": "q"}], truncated=True), "response_limit"),
        (HttpResponse(200, b"<html>login</html>", {}), "unexpected_response"),
    ],
)
def test_client_normalizes_errors(reply, outcome):
    result = client(FakePool([reply])).get("/api/vhosts")
    assert result.outcome == outcome


def test_collection_paginates_and_marks_limit():
    pool = FakePool(
        [
            response(data={"items": [{"name": "a"}, {"name": "b"}], "page_count": 3}),
            response(data={"items": [{"name": "c"}, {"name": "d"}], "page_count": 3}),
        ]
    )
    result = client(pool).collection("/api/queues/%2F", limit=3, page_size=2)
    assert [item["name"] for item in result.items] == ["a", "b", "c"]
    assert result.truncated and result.status == "ok"
    assert parse_qs(urlsplit(pool.calls[1]["url"]).query)["page"] == ["2"]
    assert "/api/queues/%2F?" in pool.calls[0]["url"]


@pytest.mark.parametrize(
    ("data", "status", "truncated"),
    [
        ([], "ok", False),
        ([{"name": "a"}, {"name": "b"}], "ok", True),
        ({"items": [], "page_count": 0}, "ok", False),
        ({"items": [], "page_count": 3}, "unexpected_response", True),
        ({"items": ["bad"], "page_count": 1}, "unexpected_response", False),
        ({"items": [{"name": "a"}]}, "unexpected_response", True),
    ],
)
def test_collection_handles_legacy_empty_and_malformed_pages(data, status, truncated):
    result = client(FakePool([response(data=data)])).collection("/api/vhosts", limit=1)
    assert result.status == status
    assert result.truncated is truncated


def test_collection_retains_partial_data_after_error():
    pool = FakePool([response(data={"items": [{"name": "a"}], "page_count": 2}), response(403)])
    result = client(pool).collection("/api/queues", limit=10)
    assert result.items == [{"name": "a"}]
    assert result.status == "denied" and result.truncated


class BrokerPool(FakePool):
    def __init__(self, *, anonymous: bool = False, proxy_identity: bool = False, denied_permissions: bool = False):
        super().__init__()
        self.anonymous = anonymous
        self.proxy_identity = proxy_identity
        self.denied_permissions = denied_permissions

    def request(self, method: str, url: str, **kwargs: Any) -> HttpResponse:
        self.calls.append({"method": method, "url": url, **kwargs})
        path = urlsplit(url).path.removeprefix("/rabbit")
        if path in {"/api/vhosts", "/api/nodes"} or path.endswith(("/permissions", "/topic-permissions")):
            assert "pagination" not in parse_qs(urlsplit(url).query)
        authorization = kwargs.get("headers", {}).get("Authorization")
        good = authorization == "Basic " + base64.b64encode(b"guest:guest").decode()
        if path == "/api/whoami":
            if self.proxy_identity:
                return response(data={"name": "proxy-user", "tags": "monitoring"})
            if good:
                return response(data={"name": "guest", "tags": ["administrator"]})
        elif good or self.anonymous:
            if path == "/api/nodes":
                if self.denied_permissions:
                    return response(403)
                return response(
                    data=[
                        {
                            "name": "rabbit@one",
                            "running": True,
                            "mem_alarm": False,
                            "disk_free_alarm": False,
                            "partitions": [],
                            "unexpected_secret": "do not retain",
                        },
                        {"name": "rabbit@two", "running": False},
                    ]
                )
            if path == "/api/global-parameters/internal_cluster_id":
                return response(data={"name": "internal_cluster_id", "value": "rabbitmq-cluster-id-test"})
            if path == "/api/users":
                if self.denied_permissions:
                    return response(403)
                return response(data=[{"name": "guest"}])
            if path == "/api/overview":
                return response(
                    data={"rabbitmq_version": "4.1.8", "management_version": "4.1.8", "cluster_name": "lab"}
                )
            if path.endswith(("/permissions", "/topic-permissions")):
                if self.denied_permissions:
                    return response(403)
                return response(data=[{"vhost": "/", "configure": "", "read": "^visible", "write": ""}])
            if path == "/api/vhosts/%2F":
                if self.denied_permissions:
                    return response(401)
                return response(data={"name": "/"})
            if path == "/api/vhosts":
                return response(data=[{"name": "/"}])
            if path.startswith("/api/queues"):
                return response(
                    data=[
                        {
                            "name": "visible",
                            "vhost": "/",
                            "messages": 3,
                            "consumers": 1,
                            "unexpected_secret": "do not retain",
                        }
                    ]
                )
            if path.startswith(("/api/exchanges", "/api/bindings")):
                return response(data=[])
        return response(
            401,
            {"error": "not_authorised", "reason": "Not authorized"},
            headers={"www-authenticate": 'Basic realm="RabbitMQ Management"'},
        )


def run_broker(monkeypatch: pytest.MonkeyPatch, pool: FakePool, *flags: str):
    monkeypatch.setattr(actions, "HttpSessionPool", lambda **kwargs: pool)
    args = parse_args(["rabbitmq", "-t", "http://127.0.0.1:15672/rabbit", "-r", "0", *flags])
    lines: list[str] = []
    result = AuditCommandRunner(args=args, spec=stage.build_rabbitmq_spec(args), emit_line=lines.append).run_plan(
        stage.build_rabbitmq_plan(args)
    )
    assert pool.closed
    assert all(call["method"] == "GET" for call in pool.calls)
    assert all("/get" not in call["url"] for call in pool.calls)
    assert len(result.records) == 1
    return result.records[0], lines


def test_runtime_valid_default_tags_permissions_enum_and_scope(monkeypatch):
    pool = BrokerPool()
    record, lines = run_broker(monkeypatch, pool, "--defcreds", "--enum", "--vhost", "/")
    assert record["auth_required"] is True
    assert record["provided_credentials_ok"] is True
    assert record["tags"] == ["administrator"]
    assert record["admin"] is True
    assert record["permissions"][0]["write"] == ""  # admin tag does not imply data permissions
    assert record["version"] == "4.1.8"
    assert record["cluster_id"] == "rabbitmq-cluster-id-test"
    assert record["enumeration"]["queues"]["items"][0]["messages"] == 3
    assert "unexpected_secret" not in str(record)
    assert any("guest" in line and "[+]" in line for line in lines)
    assert any("Show Queues" in line for line in lines)
    assert any("/api/queues/%2F?" in call["url"] for call in pool.calls)


def test_runtime_invalid_credentials_do_not_enumerate(monkeypatch):
    pool = BrokerPool()
    record, lines = run_broker(monkeypatch, pool, "-u", "bad", "-p", "bad", "--enum")
    assert record["credential_state"] == "rejected"
    assert "enumeration" not in record
    assert any("[-] bad" in line for line in lines)
    assert not any("/api/queues" in call["url"] for call in pool.calls)


def test_runtime_keeps_failed_attempt_and_successful_default(monkeypatch):
    record, lines = run_broker(monkeypatch, BrokerPool(), "-u", "bad", "-p", "bad", "--defcreds")
    attempts = record["attempted_credentials"]
    assert len(attempts) == 1 + len(actions.DEFAULT_CREDENTIALS)
    assert attempts[0]["credential_state"] == "rejected"
    assert sum(attempt["credential_state"] == "valid" for attempt in attempts) == 1
    assert any(attempt["credential_state"] == "valid" and attempt["admin"] is True for attempt in attempts)
    assert any("[-] bad" in line for line in lines)
    assert record["credential_username"] == "guest"


def test_runtime_anonymous_fallback_after_rejected_credentials(monkeypatch):
    record, _ = run_broker(monkeypatch, BrokerPool(anonymous=True), "-u", "bad", "-p", "bad", "--enum")
    assert record["auth_required"] is False
    assert record["enumeration"]["queues"]["status"] == "ok"
    assert record.get("provided_credentials_ok") is not True


def test_runtime_proxy_identity_does_not_validate_arbitrary_password(monkeypatch):
    pool = BrokerPool(anonymous=True, proxy_identity=True)
    record, _ = run_broker(monkeypatch, pool, "--defcreds", "--enum")
    assert record["credential_verification_status"] == "unavailable"
    assert record["anonymous_username"] == "proxy-user"
    assert record["tags"] == ["monitoring"]
    assert record["anonymous_admin"] is True  # actual admin API access overrides the reported tag
    assert not any(call["headers"].get("Authorization") for call in pool.calls)


def test_runtime_json_contains_statuses_and_partial_permissions(monkeypatch):
    record, lines = run_broker(monkeypatch, BrokerPool(denied_permissions=True), "--defcreds", "--enum", "-f", "json")
    assert record["permissions_status"] == "denied"
    assert record["provided_credentials_ok"] is True
    assert record["admin"] is False  # administrator tag alone is insufficient
    documents = [json.loads(line) for line in lines if line.startswith("{")]
    assert documents
    assert any(document.get("enumeration", {}).get("queues", {}).get("status") == "ok" for document in documents)


def test_scoped_vhosts_fall_back_to_visible_list_for_restricted_user(monkeypatch):
    record, _ = run_broker(monkeypatch, BrokerPool(denied_permissions=True), "--defcreds", "--enum", "--vhost", "/")
    assert record["permissions_status"] == "denied"
    assert record["enumeration"]["vhosts"]["status"] == "ok"
    assert record["enumeration"]["vhosts"]["items"] == [{"name": "/"}]


@pytest.mark.parametrize(
    "reply",
    [
        response(401, headers={"www-authenticate": 'Basic realm="Other"'}),
        response(data={"version": "4.1.8"}),
        response(data={"rabbitmq_version": "4.1.8"}),
    ],
)
def test_detection_does_not_send_credentials_to_unrelated_http(monkeypatch, reply):
    pool = FakePool([reply, HttpResponse(200, b"<html>login</html>", {})])
    record, _ = run_broker(monkeypatch, pool, "--defcreds")
    assert record["detection_status"] == "not_rabbitmq"
    assert not any(call["headers"].get("Authorization") for call in pool.calls)


def test_detection_ui_only_is_probable_without_verifier(monkeypatch):
    pool = FakePool([response(404), HttpResponse(200, b"<title>RabbitMQ Management</title>", {})])
    record, _ = run_broker(monkeypatch, pool, "--defcreds")
    assert record["detection_status"] == "probable"
    assert record["credential_verification_status"] == "unavailable"


@pytest.mark.parametrize("suffix", [b"", b" - lab cluster"])
def test_detection_accepts_title_attributes_and_whitespace(monkeypatch, suffix):
    pool = FakePool(
        [response(404), HttpResponse(200, b'<TITLE lang="en">\n RabbitMQ   Management' + suffix + b" </TITLE>", {})]
    )
    record, _ = run_broker(monkeypatch, pool, "--defcreds")
    assert record["detection_status"] == "probable"
    assert not any(call["headers"].get("Authorization") for call in pool.calls)


@pytest.mark.parametrize("status", [403, 429, 500])
def test_auth_does_not_accept_http_errors(monkeypatch, status):
    ctx = SimpleNamespace(
        args=SimpleNamespace(timeout=1, retries=0),
        host="h",
        port=15672,
        credential=SimpleNamespace(username="guest", password="guest"),
    )
    pool = FakePool([response(status)])
    monkeypatch.setattr(actions, "HttpSessionPool", lambda **kwargs: pool)
    ctx.lifecycle_state = actions.RabbitMQLifecycleState(ctx)
    record = actions.auth_record(ctx, {})
    assert record["provided_credentials_ok"] is False
    assert record["credential_state"] == ("denied" if status == 403 else "unverified")


def test_transport_auto_switch_and_explicit_scheme(monkeypatch):
    pool = FakePool([response(error="Remote end closed connection"), response(401)])
    monkeypatch.setattr(actions, "HttpSessionPool", lambda **kwargs: pool)
    ctx = SimpleNamespace(args=SimpleNamespace(timeout=1, retries=0), host="h", port=12345)
    state = actions.RabbitMQLifecycleState(ctx)
    state.resolve()
    state.resolve()
    assert state.scheme == "https" and len(pool.calls) == 2
    assert "Authorization" not in pool.calls[0]["headers"]
    pool.replies = [response(error="Remote end closed connection")]
    ctx.target = SimpleNamespace(scheme="http", path="")
    state = actions.RabbitMQLifecycleState(ctx)
    state.resolve()
    assert state.scheme == "http" and len(pool.calls) == 3


def test_cli_plan_default_ports_deduplicates_guest_and_preserves_empty_password():
    args = parse_args(["rabbitmq", "-t", "h", "-u", "guest", "-p", "guest", "--defcreds"])
    plan = stage.build_rabbitmq_plan(args)
    assert plan.ports == (15672, 15671)
    assert len(plan.credential_runs) == len(actions.DEFAULT_CREDENTIALS) == 16
    assert len({(run.username, run.password) for run in plan.credential_runs}) == 16
    assert (plan.credential_runs[0].username, plan.credential_runs[0].password) == ("guest", "guest")
    args = parse_args(["rabbitmq", "-t", "h", "-u", "guest", "-p", ""])
    assert stage.build_rabbitmq_plan(args).credential_runs[0].password == ""


@pytest.mark.parametrize("flags", [["-u", "guest"], ["-p", "guest"], ["--page-size", "501"], ["-u", "a:b", "-p", "x"]])
def test_policy_rejects_invalid_arguments(flags):
    args = parse_args(["rabbitmq", "-t", "h", *flags])
    errors = []
    assert policy.validate_args(args, SimpleNamespace(error=errors.append)) == 2
    assert errors


def test_text_escapes_server_control_characters():
    line = render._format_record(
        {"provided_credentials_ok": True, "credential_username": "bad\n\x1b[31m", "tags": []}, "txt"
    )
    assert "\n" not in line and "\x1b" not in line


@pytest.mark.parametrize(
    ("reply", "expected"),
    [
        (response(data=[{"name": "guest", "password_hash": "must-not-retain"}]), True),
        (response(data=[]), True),
        (response(401), False),
        (response(403), False),
        (response(404), None),
        (response(429), None),
        (response(503), None),
        (response(error="timeout"), None),
        (response(data=[{"name": "guest"}], truncated=True), None),
        (response(data=[{"other": "value"}]), None),
        (HttpResponse(200, b"<html>login</html>", {}), None),
    ],
)
def test_admin_probe_requires_actual_admin_api_access(reply, expected):
    pool = FakePool([reply])
    result = actions.check_admin(client(pool))
    assert result["admin"] is expected
    assert "must-not-retain" not in str(result)
    assert result["admin_evidence"]["endpoint"] == "/api/users"
    query = parse_qs(urlsplit(pool.calls[0]["url"]).query)
    assert query["page_size"] == ["1"] and query["columns"] == ["name"]
    assert pool.calls[0]["method"] == "GET"


def test_defcreds_checks_and_renders_admin_for_each_accepted_identity(monkeypatch):
    class TwoUsersPool(BrokerPool):
        def request(self, method, url, **kwargs):
            authorization = kwargs.get("headers", {}).get("Authorization")
            path = urlsplit(url).path.removeprefix("/rabbit")
            if authorization == "Basic " + base64.b64encode(b"admin:admin").decode():
                self.calls.append({"method": method, "url": url, **kwargs})
                if path == "/api/whoami":
                    return response(data={"name": "admin", "tags": ["administrator"]})
                return response(403)
            return super().request(method, url, **kwargs)

    record, lines = run_broker(monkeypatch, TwoUsersPool(), "--defcreds")
    accepted = [attempt for attempt in record["attempted_credentials"] if attempt["credential_state"] == "valid"]
    assert [(attempt["username"], attempt["admin"]) for attempt in accepted] == [("admin", False), ("guest", True)]
    assert any("admin:admin (admin:False)" in line for line in lines)
    assert any("guest:guest (admin:True)" in line for line in lines)
    assert len(record["attempted_credentials"]) == 16


def test_admin_unknown_is_rendered_without_falling_back_to_tag():
    record = {"provided_credentials_ok": True, "credential_username": "guest", "tags": ["administrator"], "admin": None}
    assert "(admin:unknown)" in render._format_record(record, "txt")


@pytest.fixture
def enumeration_record():
    return {
        "host": "localhost",
        "port": 15672,
        "api_endpoint": "http://localhost:15672",
        "detection_status": "confirmed",
        "auth_required": True,
        "provided_credentials_ok": True,
        "credential_username": "guest",
        "effective_username": "guest",
        "admin": True,
        "cluster_id": "rabbitmq-cluster-id-test",
        "cluster_name": "lab",
        "permissions_status": "ok",
        "permissions": [{"vhost": "/", "read": ".*", "write": ".*", "configure": ".*"}],
        "enumeration": {
            "queues": {
                "status": "ok",
                "truncated": False,
                "items": [
                    {"vhost": "/", "name": "orders", "type": "quorum", "messages": 3, "consumers": 1},
                    {"vhost": "/", "name": "archive", "type": "classic", "messages": 7},
                ],
            }
        },
    }


def text_record(payload):
    return AuditRecord.from_mapping(payload, module="rabbitmq", service="rabbitmq")


def test_enum_dedup_keeps_endpoint_verdicts_and_first_snapshot(enumeration_record):
    renderer = render.RabbitMQTextRenderer()
    first = renderer(text_record(enumeration_record))
    second = deepcopy(enumeration_record)
    second.update(port=15671, api_endpoint="https://localhost:15671")
    second["enumeration"]["queues"]["items"].reverse()
    second["enumeration"]["queues"]["items"][1].update(messages=100, consumers=2)
    original = deepcopy(second)
    lines = renderer(text_record(second))
    assert sum("Show Queues" in line for line in first + lines) == 1
    assert any("Same cluster; enumeration shown at http://localhost:15672" in line for line in lines)
    assert any("RabbitMQ Management" in line for line in lines)
    assert any("guest (admin:True)" in line for line in lines)
    assert second == original
    # A new command has no cross-run/global suppression state.
    assert any("Show Queues" in line for line in render.RabbitMQTextRenderer()(text_record(second)))


@pytest.mark.parametrize(
    "difference",
    ["cluster_id", "missing_id", "user", "permissions", "objects", "type", "truncated", "denied", "host", "path"],
)
def test_enum_dedup_never_hides_unconfirmed_or_different_views(enumeration_record, difference):
    renderer = render.RabbitMQTextRenderer()
    renderer(text_record(enumeration_record))
    second = deepcopy(enumeration_record)
    second.update(port=15671, api_endpoint="https://localhost:15671")
    queues = second["enumeration"]["queues"]
    if difference == "cluster_id":
        second["cluster_id"] = "different-cluster-with-same-name"
    elif difference == "missing_id":
        second.pop("cluster_id")
    elif difference == "user":
        second["effective_username"] = "observer"
    elif difference == "permissions":
        second["permissions"][0]["write"] = ""
    elif difference == "objects":
        queues["items"].pop()
    elif difference == "type":
        queues["items"][0]["type"] = "classic"
    elif difference == "truncated":
        queues["truncated"] = True
    elif difference == "denied":
        queues["status"] = "denied"
    elif difference == "host":
        second["api_endpoint"] = "https://other-host:15671"
    elif difference == "path":
        second["api_endpoint"] += "/other-broker"
    lines = renderer(text_record(second))
    assert any("Show Queues" in line for line in lines)
    assert not any("Same cluster" in line for line in lines)


@pytest.mark.parametrize("mode", ["normal", "debug", "json"])
def test_multiport_enum_runtime_preserves_records_and_full_debug_json(monkeypatch, mode):
    pools = []

    def pool_factory(**kwargs):
        pool = BrokerPool()
        pools.append(pool)
        return pool

    monkeypatch.setattr(actions, "HttpSessionPool", pool_factory)
    extra = ["--debug"] if mode == "debug" else ["-f", "json"] if mode == "json" else []
    args = parse_args(["rabbitmq", "-t", "localhost", "-u", "guest", "-p", "guest", "--enum", *extra])
    lines = []
    result = AuditCommandRunner(args=args, spec=stage.build_rabbitmq_spec(args), emit_line=lines.append).run_plan(
        stage.build_rabbitmq_plan(args)
    )
    assert len(result.records) == 2
    assert all(record["enumeration"]["queues"]["items"] for record in result.records)
    assert all(pool.closed for pool in pools)
    if mode == "json":
        records = [json.loads(line) for line in lines]
        assert len(records) == 2
        assert all(record["enumeration"]["queues"]["items"] for record in records)
    else:
        assert sum("Show Queues" in line for line in lines) == (2 if mode == "debug" else 1)
        assert sum("RabbitMQ Management" in line for line in lines) == 2


@pytest.mark.parametrize(
    "reply",
    [
        response(403),
        response(404),
        response(error="timeout"),
        response(data={"value": "unverified"}),
        response(data={"name": "internal_cluster_id", "value": ""}),
        response(data={"name": "internal_cluster_id", "value": "id"}, truncated=True),
    ],
)
def test_unavailable_cluster_id_does_not_block_enumeration(monkeypatch, reply):
    class UnidentifiedBroker(BrokerPool):
        def request(self, method, url, **kwargs):
            if urlsplit(url).path.endswith("/global-parameters/internal_cluster_id"):
                return reply
            return super().request(method, url, **kwargs)

    record, lines = run_broker(monkeypatch, UnidentifiedBroker(), "-u", "guest", "-p", "guest", "--enum")
    assert "cluster_id" not in record
    assert any("Show Queues" in line for line in lines)


@pytest.mark.parametrize("section", ["vhosts", "queues", "exchanges", "bindings", "nodes", "permissions"])
def test_show_flags_select_only_requested_sections(monkeypatch, section):
    pool = BrokerPool()
    record, lines = run_broker(monkeypatch, pool, "-u", "guest", "-p", "guest", f"--show-{section}")
    assert set(record["enumeration"]) == (set() if section == "permissions" else {section})
    for other in ("queues", "exchanges", "bindings", "nodes"):
        assert any(urlsplit(call["url"]).path.endswith("/api/" + other) for call in pool.calls) == (other == section)
    assert any("Show Permissions" in line for line in lines) == (section == "permissions")
    assert record["permissions"]  # Evidence stays available in structured records.


def test_show_flags_combine_and_vhost_scope_does_not_filter_nodes(monkeypatch):
    pool = BrokerPool()
    record, lines = run_broker(
        monkeypatch,
        pool,
        "-u",
        "guest",
        "-p",
        "guest",
        "--show-vhosts",
        "--show-queues",
        "--show-nodes",
        "--vhost",
        "/",
    )
    assert set(record["enumeration"]) == {"vhosts", "queues", "nodes"}
    assert any(urlsplit(call["url"]).path.endswith("/api/queues/%2F") for call in pool.calls)
    assert any(urlsplit(call["url"]).path.endswith("/api/nodes") for call in pool.calls)
    assert any("rabbit@one (running:True) (memory alarm:False) (disk alarm:False)" in line for line in lines)
    offline = next(line for line in lines if "rabbit@two" in line)
    assert "(running:False)" in offline
    assert "alarm" not in offline
    assert "unexpected_secret" not in str(record)


def test_enum_includes_all_sections_and_explicit_flag_does_not_duplicate(monkeypatch):
    record, lines = run_broker(monkeypatch, BrokerPool(), "-u", "guest", "-p", "guest", "--enum", "--show-nodes")
    assert set(record["enumeration"]) == {"vhosts", "queues", "exchanges", "bindings", "nodes"}
    assert sum("Show Nodes" in line for line in lines) == 1
    assert any("Show Permissions" in line for line in lines)


def test_show_nodes_reports_denied_instead_of_empty_success(monkeypatch):
    record, lines = run_broker(
        monkeypatch, BrokerPool(denied_permissions=True), "-u", "guest", "-p", "guest", "--show-nodes"
    )
    assert record["enumeration"]["nodes"]["status"] == "denied"
    assert any("Show Nodes (Count:0) (status:denied)" in line for line in lines)
    assert not any("Show Permissions" in line for line in lines)


def test_show_nodes_limit_and_debug_permissions(monkeypatch):
    record, lines = run_broker(
        monkeypatch, BrokerPool(), "-u", "guest", "-p", "guest", "--show-nodes", "--limit", "1", "--debug"
    )
    assert record["enumeration"]["nodes"]["truncated"]
    assert len(record["enumeration"]["nodes"]["items"]) == 1
    assert any("Show Nodes (Count:1) (status:ok) (truncated:True)" in line for line in lines)
    assert any("Show Permissions" in line for line in lines)


def test_node_health_detail_colors():
    line = "RABBITMQ\thost\t15672\t rabbit@one (running:False) (memory alarm:True) (disk alarm:False)"
    spans = render._detail_spans(line)
    payload = line.rsplit("\t", 1)[-1]
    assert [(payload[start:end], color) for start, end, color in spans] == [
        ("(running:False)", "true_red"),
        ("(memory alarm:True)", "true_red"),
        ("(disk alarm:False)", "bright_green"),
    ]
    assert "(running:unknown)" in render._object_detail("nodes", {"name": "rabbit@missing"}, debug=False)
