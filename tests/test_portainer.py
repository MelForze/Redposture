"""Portainer protocol proof and read-only module contracts."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from redposture_core import web_panels
from redposture_core.clients.http_api import HttpResponse
from redposture_core.stage_runtime import AuditCredentialRun


def response(status, payload):
    return HttpResponse(
        status=status, body=(payload.encode() if isinstance(payload, str) else json.dumps(payload).encode()), headers={}
    )


def context(**kwargs):
    return SimpleNamespace(
        host="qa",
        port=9443,
        target=SimpleNamespace(path="/tenant/api/system/status", scheme="https", explicit_port=9443),
        args=SimpleNamespace(timeout=1, secure=False, _proxy_config=None),
        credential=AuditCredentialRun(username="admin", password="secret"),
        lifecycle_state=None,
        **kwargs,
    )


def panel():
    return {
        "host": "qa",
        "port": 9443,
        "module": "portainer",
        "service": "portainer",
        "surface": "ui",
        "ui_product": "portainer",
        "status": "auth_required",
        "auth_required": True,
        "ui": {"endpoint": "https://qa:9443/tenant", "inventory": {}},
    }


@pytest.mark.parametrize(
    "token,header",
    [("ptr_secret", {"X-API-Key": "ptr_secret"}), ("eyJ.test.jwt", {"Authorization": "Bearer eyJ.test.jwt"})],
)
def test_token_verifies_identity_using_product_header(monkeypatch, token, header):
    observed = []
    monkeypatch.setattr(web_panels, "HttpSessionPool", lambda **kw: SimpleNamespace(close=lambda: None))

    def get(pool, base, path, **kwargs):
        observed.append((base, path, kwargs["headers"]))
        return (
            response(200, {"Id": 1, "Username": "admin", "Role": 1})
            if kwargs["headers"]
            else response(401, {"message": "Unauthorized"})
        )

    monkeypatch.setattr(web_panels, "_get", get)
    verifier = getattr(web_panels, "authenticate_portainer_token", None)
    assert callable(verifier), "Portainer token verifier is missing"
    result = verifier(context(), panel(), token)
    assert result["provided_credentials_ok"] is True
    assert result["status"] == "valid_credentials"
    assert observed == [
        ("https://qa:9443/tenant", "/api/users/me", header),
        ("https://qa:9443/tenant", "/api/users/me", {}),
    ]
    assert result.get("is_docker") is not True


@pytest.mark.parametrize(
    "payload",
    [{}, [], {"Username": "admin"}, {"Id": True, "Username": "admin", "Role": 1}, {"Id": 1, "Username": "", "Role": 1}],
)
def test_token_200_without_real_identity_is_unverified(monkeypatch, payload):
    monkeypatch.setattr(web_panels, "HttpSessionPool", lambda **kw: SimpleNamespace(close=lambda: None))
    monkeypatch.setattr(web_panels, "_get", lambda *a, **kw: response(200, payload))
    verifier = getattr(web_panels, "authenticate_portainer_token", None)
    assert callable(verifier), "Portainer token verifier is missing"
    result = verifier(context(), panel(), "ptr_secret")
    assert result["provided_credentials_ok"] is None
    assert result["status"] != "valid_credentials"


def test_pair_requires_real_matching_identity(monkeypatch):
    monkeypatch.setattr(web_panels, "HttpSessionPool", lambda **kw: SimpleNamespace(close=lambda: None))
    monkeypatch.setattr(web_panels, "_post", lambda *a, **kw: response(200, {"jwt": "issued"}))
    monkeypatch.setattr(web_panels, "_get", lambda *a, **kw: response(200, {"Username": "admin"}))
    result = web_panels.authenticate_panel(context(), panel())
    assert result["provided_credentials_ok"] is None
    assert result["status"] != "valid_credentials"


@pytest.mark.parametrize("payload", [{}, "<html>login</html>", [{"Name": "no id"}]])
def test_detection_does_not_claim_anonymous_access_from_arbitrary_200(monkeypatch, payload):
    monkeypatch.setattr(web_panels, "HttpSessionPool", lambda **kw: SimpleNamespace(close=lambda: None))
    answers = {
        "/api/system/status": response(200, {"Version": "2.45.2", "InstanceID": "qa"}),
        "/": response(200, "<title>Portainer</title>"),
        "/api/endpoints": response(200, payload),
    }
    monkeypatch.setattr(web_panels, "_get", lambda pool, base, path, **kw: answers.get(path, response(404, {})))
    record = web_panels.detect_panel("portainer", context())
    assert record["auth_required"] is None
    assert record["status"] != "open_no_auth"


@pytest.mark.parametrize("payload", [[], [{"Id": 1, "Name": "local"}]])
def test_detection_proves_anonymous_environment_list(monkeypatch, payload):
    monkeypatch.setattr(web_panels, "HttpSessionPool", lambda **kw: SimpleNamespace(close=lambda: None))
    answers = {
        "/api/system/status": response(200, {"Version": "2.45.2", "InstanceID": "qa"}),
        "/": response(200, "<title>Portainer</title>"),
        "/api/endpoints": response(200, payload),
    }
    monkeypatch.setattr(web_panels, "_get", lambda pool, base, path, **kw: answers.get(path, response(404, {})))
    record = web_panels.detect_panel("portainer", context())
    assert record["auth_required"] is False
    assert record["status"] == "open_no_auth"


def test_module_detection_keeps_portainer_principal_separate(monkeypatch):
    from redposture_core.modules.portainer import actions

    monkeypatch.setattr(
        web_panels,
        "detect_panel",
        lambda module, ctx, **kwargs: {
            **panel(),
            "status": "auth_required",
            "version": "2.45.2",
            "detection_status": "confirmed",
        },
    )
    record = actions.detect_record(context())
    assert record["is_portainer"] is True
    assert record.get("is_docker") is not True
    assert record["service"] == "portainer"
    assert record["surface"] == "ui"
    assert record["credential_verification_status"] == "available"


def test_module_sessions_stay_in_lifecycle_and_not_records(monkeypatch):
    from redposture_core.modules.portainer import actions

    ctx = context()
    ctx.lifecycle_state = actions.lifecycle_state_factory(ctx)
    monkeypatch.setattr(
        web_panels,
        "authenticate_panel",
        lambda ctx, record: {
            **record,
            "status": "valid_credentials",
            "credential_state": "valid",
            "provided_credentials_ok": True,
            "ui": {**record["ui"], "session_token": "secret-issued"},
        },
    )
    result = actions.auth_record(ctx, panel())
    assert "secret-issued" not in json.dumps(result)
    assert ctx.lifecycle_state.ui_session_token == "secret-issued"
    assert result["provided_credentials_ok"] is True


def test_module_429_stops_later_auth_calls(monkeypatch):
    from redposture_core.modules.portainer import actions

    ctx = context()
    ctx.lifecycle_state = actions.lifecycle_state_factory(ctx)
    calls = []

    def auth(ctx, record):
        calls.append(ctx.credential.password)
        return {
            **record,
            "status": "rate_limited",
            "credential_state": "rate_limited",
            "provided_credentials_ok": None,
            "ui": record["ui"],
        }

    monkeypatch.setattr(web_panels, "authenticate_panel", auth)
    actions.auth_record(ctx, panel())
    ctx.credential = AuditCredentialRun(username="admin", password="next")
    result = actions.auth_record(ctx, panel())
    assert calls == ["secret"]
    assert result["status"] == "rate_limited"


@pytest.mark.parametrize("selector", ["2", "prod"])
def test_endpoint_selector_never_reads_unselected_engine(monkeypatch, selector):
    monkeypatch.setattr(web_panels, "HttpSessionPool", lambda **kw: SimpleNamespace(close=lambda: None))
    requested = []

    def get(pool, base, path, **kw):
        requested.append(path)
        if path.startswith("/api/endpoints?"):
            return response(200, [{"Id": 1, "Name": "dev"}, {"Id": 2, "Name": "prod"}])
        if path == "/api/endpoints/2/docker/containers/json?all=1":
            return response(200, [{"Id": "container", "Names": ["/app"], "Image": "qa", "State": "running"}])
        raise AssertionError("unselected or mutating route " + path)

    monkeypatch.setattr(web_panels, "_get", get)
    ctx = context()
    ctx.args.containers = True
    ctx.args.endpoint = selector
    result = web_panels.enumerate_panel(ctx, panel())
    assert result["ui"]["inventory"]["containers"]["count"] == 1
    assert result["ui"]["inventory"]["environments"]["count"] == 1
    assert not any("/1/docker/" in path for path in requested)


def test_unknown_endpoint_selector_is_not_empty_success(monkeypatch):
    monkeypatch.setattr(web_panels, "HttpSessionPool", lambda **kw: SimpleNamespace(close=lambda: None))
    monkeypatch.setattr(web_panels, "_get", lambda *a, **kw: response(200, [{"Id": 1, "Name": "dev"}]))
    ctx = context()
    ctx.args.containers = True
    ctx.args.endpoint = "missing"
    result = web_panels.enumerate_panel(ctx, panel())
    section = result["ui"]["inventory"]["containers"]
    assert section.get("status") == "endpoint_not_found"
    assert section.get("count") is None


def test_api_key_is_used_for_inventory(monkeypatch):
    monkeypatch.setattr(web_panels, "HttpSessionPool", lambda **kw: SimpleNamespace(close=lambda: None))

    def get(pool, base, path, **kw):
        assert kw["headers"] == {"X-API-Key": "ptr_secret"}
        return response(200, [])

    monkeypatch.setattr(web_panels, "_get", get)
    ctx = context()
    ctx.args.endpoints = True
    record = panel()
    record["ui"]["session_api_key"] = "ptr_secret"
    assert web_panels.enumerate_panel(ctx, record)["ui"]["inventory"]["environments"]["count"] == 0


@pytest.mark.parametrize(
    "target,port_args,ports",
    [
        ("qa", (), (9443, 9000)),
        ("https://qa/tenant", (), (443,)),
        ("http://qa/tenant", (), (80,)),
        ("https://qa:18443/tenant", (), (18443,)),
        ("https://qa/tenant", ("--port", "9000"), (9000,)),
    ],
)
def test_plan_respects_origin_and_port_precedence(target, port_args, ports):
    from redposture_core.cli_args import parse_args
    from redposture_core.modules.portainer.stage import build_portainer_plan

    plan = build_portainer_plan(parse_args(["portainer", "-t", target, *port_args]))
    assert tuple(port for i, host, port, spec in plan.iter_target_specs()) == ports


def test_token_file_loads_real_candidate_and_rejects_multiline(tmp_path):
    from redposture_core.modules.portainer import policy

    token_file = tmp_path / "token"
    token_file.write_text("ptr_secret\n")
    args = SimpleNamespace(
        token=None, token_file=str(token_file), targets="qa", username=None, password=None, endpoint=None
    )
    messages = []
    console = SimpleNamespace(error=messages.append)
    assert policy.validate_args(args, console) is None
    assert args.token == "ptr_secret"
    token_file.write_text("one\ntwo")
    assert policy.validate_args(args, console) == 2


def test_policy_validation_order_and_execution_surface_guards(monkeypatch):
    from redposture_core.modules.portainer import policy

    messages = []
    console = SimpleNamespace(error=messages.append)
    args = SimpleNamespace(
        targets="qa",
        username=None,
        password=None,
        token=None,
        token_file=None,
        endpoint="engine",
        container="worker",
        execute=None,
    )

    monkeypatch.setattr(policy, "validate_basic_module_args", lambda *_a, **_k: 7)
    assert policy.validate_args(args, console) == 7

    monkeypatch.setattr(policy, "validate_basic_module_args", lambda *_a, **_k: None)
    monkeypatch.setattr(policy, "validate_execution", lambda *_a, **_k: 6)
    assert policy.validate_args(args, console) == 6

    monkeypatch.setattr(policy, "validate_execution", lambda *_a, **_k: None)
    monkeypatch.setattr(policy, "validate_token_args", lambda value, _console, _module: 5)
    assert policy.validate_args(args, console) == 5

    def valid_token(value, _console, _module):
        value._portainer_token = "ptr-secret"
        return None

    monkeypatch.setattr(policy, "validate_token_args", valid_token)
    args.endpoint = ""
    assert policy.validate_args(args, console) == 2
    args.endpoint = "engine\n"
    assert policy.validate_args(args, console) == 2
    args.endpoint = "engine"
    args.container = ""
    assert policy.validate_args(args, console) == 2
    args.container = "worker\x00"
    assert policy.validate_args(args, console) == 2

    args.container = "worker"
    args.execute = "id"
    args.endpoint = None
    assert policy.validate_args(args, console) == 2
    args.endpoint = "engine"
    args.container = None
    assert policy.validate_args(args, console) == 2

    args.container = "worker"
    args.execute = None
    assert policy.validate_args(args, console) is None
    assert args.token == "ptr-secret"


def test_default_pairs_cover_multiple_weak_accounts_without_duplicates():
    from redposture_core.cli_args import parse_args
    from redposture_core.modules.portainer.stage import build_portainer_plan

    args = parse_args(["portainer", "-t", "qa", "--defcreds"])
    runs = build_portainer_plan(args).credential_runs
    assert [(r.username, r.password, r.token) for r in runs[:3]] == [
        ("admin", "admin", None),
        ("admin", "password", None),
        ("admin", "12345678", None),
    ]
    pairs = [(r.username, r.password) for r in runs]
    assert len(pairs) >= 20
    assert len(pairs) == len(set(pairs))
    assert {r.username for r in runs} == {"admin", "portainer", "root", "administrator"}
    assert {("portainer", "portainer123"), ("root", "root"), ("administrator", "administrator")} <= set(pairs)
    assert all(r.source == "default" and r.token is None for r in runs)


def test_token_outcome_render_never_echoes_token():
    from redposture_core.audit_models import AuditRecord
    from redposture_core.modules.portainer import render

    record = {
        **panel(),
        "status": "valid_credentials",
        "provided_credentials_ok": True,
        "credential_state": "valid",
        "token_provided": True,
        "auth_username": "admin",
    }
    lines = list(render.render_record(AuditRecord.from_mapping(record, module="portainer", service="portainer")))
    assert any("[+] Token accepted" in line and "(UI)" not in line for line in lines)
    assert any("Portainer" in line and "(UI)" in line for line in lines)


def test_inventory_uses_selected_identity_after_multiple_successes(monkeypatch):
    from redposture_core.modules.portainer import actions

    ctx = context()
    ctx.lifecycle_state = actions.lifecycle_state_factory(ctx)

    def authenticate(ctx, record):
        pw = ctx.credential.password
        return {
            **record,
            "status": "valid_credentials" if pw != "wrong" else "invalid_credentials",
            "credential_state": "valid" if pw != "wrong" else "invalid",
            "provided_credentials_ok": pw != "wrong",
            "ui": {**record["ui"], **({"session_token": "session-" + pw} if pw != "wrong" else {})},
        }

    monkeypatch.setattr(web_panels, "authenticate_panel", authenticate)
    first = actions.auth_record(ctx, panel())
    ctx.credential = AuditCredentialRun(username="other", password="second")
    actions.auth_record(ctx, panel())
    ctx.credential = AuditCredentialRun(username="other", password="wrong")
    actions.auth_record(ctx, panel())
    ctx.credential = AuditCredentialRun(username="admin", password="secret")

    def enumerate_selected(ctx, record):
        assert record["ui"]["session_token"] == "session-secret"
        return record

    monkeypatch.setattr(web_panels, "enumerate_panel", enumerate_selected)
    result = actions.data_record(ctx, first)
    assert "session-secret" not in json.dumps(result)


def test_discover_collects_metadata_and_marks_denied_sections_partial(monkeypatch):
    from redposture_core.modules.portainer import actions

    ctx = context()
    ctx.args.discover = True

    def enumerate_data(ctx, record):
        assert ctx.args.containers and ctx.args.images and ctx.args.system
        return {
            **record,
            "ui": {
                **record["ui"],
                "inventory": {
                    "containers": {"count": 1, "records": [{"Labels": {"password": "secret"}}]},
                    "images": {"status": "denied", "partial": True},
                },
            },
        }

    monkeypatch.setattr(web_panels, "enumerate_panel", enumerate_data)
    result = actions.data_record(ctx, {**panel(), "status": "valid_credentials"})
    assert result["portainer_metadata"] == {"containers": [{"Labels": {"password": "secret"}}]}
    assert result["content_discovery_partial"] is True
    assert result["ui"]["inventory"] == {}


def test_identity_rate_limit_blocks_further_pairs(monkeypatch):
    monkeypatch.setattr(web_panels, "HttpSessionPool", lambda **kw: SimpleNamespace(close=lambda: None))
    monkeypatch.setattr(web_panels, "_post", lambda *a, **kw: response(200, {"jwt": "issued"}))
    monkeypatch.setattr(web_panels, "_get", lambda *a, **kw: response(429, {"message": "too many requests"}))
    assert web_panels.authenticate_panel(context(), panel())["status"] == "rate_limited"


def test_requested_endpoint_heading_has_no_spurious_unsupported_status(monkeypatch):
    monkeypatch.setattr(web_panels, "HttpSessionPool", lambda **kw: SimpleNamespace(close=lambda: None))
    monkeypatch.setattr(web_panels, "_get", lambda *a, **kw: response(200, []))
    ctx = context()
    ctx.args.endpoints = True
    result = web_panels.enumerate_panel(ctx, panel())
    assert result["ui"]["inventory"] == {"environments": {"count": 0, "items": [], "records": [], "partial": False}}


def test_malformed_environment_page_is_unavailable_not_zero(monkeypatch):
    monkeypatch.setattr(web_panels, "HttpSessionPool", lambda **kw: SimpleNamespace(close=lambda: None))
    monkeypatch.setattr(web_panels, "_get", lambda *a, **kw: response(200, [{"Name": "missing-id"}]))
    ctx = context()
    ctx.args.containers = True
    result = web_panels.enumerate_panel(ctx, panel())
    assert result["ui"]["inventory"]["environments"].get("count") is None
    assert result["ui"]["inventory"]["environments"].get("partial") is True


class ColorConsole:
    def __init__(self):
        self.paints = []

    def _paint(self, text, color, stream):
        self.paints.append((text, color))
        return text

    def plain(self, text):
        pass


@pytest.mark.parametrize("marker,color", [("[+]", "bright_green"), ("[-]", "true_red")])
def test_credential_color_follows_pair_verdict_and_semantic_marker(marker, color):
    from redposture_core.modules.portainer import render

    console = ColorConsole()
    assert render.colorize(console, f"PORTAINER\tqa\t9443\t {marker} admin:secret (UI)")
    assert (marker, color) in console.paints
    assert ("admin:secret", "true_red" if marker == "[+]" else "white") in console.paints
    assert ("UI", "white") in console.paints


@pytest.mark.parametrize("count,color", [(0, "bright_green"), (2, "true_red")])
def test_inventory_heading_white_count_semantic(count, color):
    from redposture_core.modules.portainer import render

    console = ColorConsole()
    assert render.colorize(console, f"PORTAINER\tqa\t9443\t [*] Containers Enumeration (count:{count})")
    assert any("Containers Enumeration" in text and shade == "white" for text, shade in console.paints)
    assert any(f"count:{count}" in text and shade == color for text, shade in console.paints)


@pytest.mark.parametrize("token", ["", "contains space", "contains\ttab", "nonascii-ы", "x" * 16385, "abc\x7f"])
def test_invalid_tokens_rejected_before_network(monkeypatch, token):
    from redposture_core.modules.portainer import policy

    args = SimpleNamespace(token=token, token_file=None, targets="qa", username=None, password=None, endpoint=None)
    errors = []
    assert policy.validate_args(args, SimpleNamespace(error=errors.append)) == 2
    monkeypatch.setattr(web_panels, "HttpSessionPool", lambda **kw: pytest.fail("invalid token reached network"))
    result = web_panels.authenticate_portainer_token(context(), panel(), token)
    assert result["provided_credentials_ok"] is None


@pytest.mark.parametrize("suffix", ["/api/auth", "/api/users/me", "/api/endpoints"])
def test_portainer_api_target_preserves_tenant_prefix(suffix):
    ctx = context()
    ctx.target.path = "/tenant" + suffix
    assert web_panels._base(ctx, "https") == "https://qa:9443/tenant"


@pytest.mark.parametrize(
    "category,payload",
    [
        ("containers", [None]),
        ("containers", [{"unrelated": "object"}]),
        ("images", ["foreign"]),
        ("networks", [{"Name": "qa"}]),
        ("volumes", {"Volumes": [{"Name": "qa"}]}),
        ("system", {}),
    ],
)
def test_invalid_proxy_inventory_never_claims_successful_count(monkeypatch, category, payload):
    monkeypatch.setattr(web_panels, "HttpSessionPool", lambda **kw: SimpleNamespace(close=lambda: None))

    def get(pool, base, path, **kw):
        if path.startswith("/api/endpoints?"):
            return response(200, [{"Id": 1, "Name": "qa"}])
        return response(200, payload)

    monkeypatch.setattr(web_panels, "_get", get)
    ctx = context()
    setattr(ctx.args, category, True)
    section = web_panels.enumerate_panel(ctx, panel())["ui"]["inventory"][category]
    assert section.get("count") is None
    assert section["partial"] is True


def test_mixed_proxy_inventory_keeps_valid_rows_and_reports_partial(monkeypatch):
    monkeypatch.setattr(web_panels, "HttpSessionPool", lambda **kw: SimpleNamespace(close=lambda: None))

    def get(pool, base, path, **kw):
        if path.startswith("/api/endpoints?"):
            return response(200, [{"Id": 1, "Name": "qa"}])
        return response(200, [{"Id": "real", "Names": ["/app"]}, {"unrelated": "object"}, None])

    monkeypatch.setattr(web_panels, "_get", get)
    ctx = context()
    ctx.args.containers = True
    section = web_panels.enumerate_panel(ctx, panel())["ui"]["inventory"]["containers"]
    assert section["count"] == 1
    assert section["partial"] is True


@pytest.mark.parametrize(
    "budget", [{"discover_max_bytes": 1, "discover_time": 300}, {"discover_max_bytes": 100000, "discover_time": 1e-9}]
)
def test_discovery_budget_stops_additional_proxy_requests(monkeypatch, budget):
    monkeypatch.setattr(web_panels, "HttpSessionPool", lambda **kw: SimpleNamespace(close=lambda: None))
    calls = []

    def get(pool, base, path, **kwargs):
        calls.append(path)
        if path.startswith("/api/endpoints?"):
            return response(200, [{"Id": 1, "Name": "qa"}])
        return response(200, [{"Id": "real"}])

    monkeypatch.setattr(web_panels, "_get", get)
    from redposture_core.modules.portainer import actions

    ctx = context()
    ctx.args.discover = True
    for key, value in budget.items():
        setattr(ctx.args, key, value)
    result = actions.data_record(ctx, {**panel(), "status": "valid_credentials"})
    assert len(calls) <= 1
    assert result["content_discovery_partial"] is True


def test_mixed_token_and_pair_outcomes_keep_attempt_order_without_duplicate_final():
    from redposture_core.modules.portainer import render

    record = {
        **panel(),
        "status": "valid_credentials",
        "credential_state": "valid",
        "token_provided": False,
        "provided_username": "admin",
        "provided_password": "secret",
        "attempted_credentials": [
            {"token_provided": True, "credential_state": "invalid", "status": "invalid_credentials"},
            {"username": "admin", "password": "secret", "credential_state": "valid", "status": "valid_credentials"},
        ],
    }
    lines = render.render_record(record)
    token = next(i for i, line in enumerate(lines) if "Token rejected" in line)
    pair = next(i for i, line in enumerate(lines) if "admin:secret" in line)
    assert token < pair
    assert sum("admin:secret" in line for line in lines) == 1


@pytest.mark.parametrize(
    "status,home",
    [
        ({"Version": "definitely-not-a-version", "InstanceID": None}, "<html>Portainer is unavailable</html>"),
        ({"Version": "2.39.7", "InstanceID": None}, "<title>Portainer</title>"),
        ({"Version": "2.39.7", "InstanceID": "qa"}, "<html>Portainer is unavailable</html>"),
    ],
)
def test_detection_rejects_invalid_status_or_unrelated_portainer_mention(monkeypatch, status, home):
    monkeypatch.setattr(web_panels, "HttpSessionPool", lambda **kw: SimpleNamespace(close=lambda: None))
    answers = {
        "/api/system/status": response(200, status),
        "/": response(200, home),
        "/api/endpoints": response(200, []),
    }
    monkeypatch.setattr(web_panels, "_get", lambda pool, base, path, **kwargs: answers[path])
    assert web_panels.detect_panel("portainer", context()) is None


@pytest.mark.parametrize(
    "anonymous_status,anonymous_payload,state",
    [
        (200, {"Id": 1, "Username": "admin", "Role": 1}, "unverified"),
        (200, {"Id": 2, "Username": "guest", "Role": 2}, "valid"),
        (200, {}, "unverified"),
        (500, {}, "unverified"),
        (429, {"message": "too many requests"}, "rate_limited"),
    ],
)
def test_token_must_change_identity_or_cross_protected_boundary(
    monkeypatch, anonymous_status, anonymous_payload, state
):
    monkeypatch.setattr(web_panels, "HttpSessionPool", lambda **kw: SimpleNamespace(close=lambda: None))
    seen = []

    def get(pool, base, path, **kwargs):
        headers = kwargs.get("headers", {})
        seen.append(headers)
        return (
            response(200, {"Id": 1, "Username": "admin", "Role": 1})
            if headers
            else response(anonymous_status, anonymous_payload)
        )

    monkeypatch.setattr(web_panels, "_get", get)
    result = web_panels.authenticate_portainer_token(context(), panel(), "ptr_secret")
    assert result["credential_state"] == state
    assert result["provided_credentials_ok"] is (True if state == "valid" else None)
    assert seen == [{"X-API-Key": "ptr_secret"}, {}]
    if state != "valid":
        assert "session_api_key" not in result["ui"]


@pytest.mark.parametrize("truncated,error", [(True, None), (False, "connection reset")])
def test_ambiguous_anonymous_comparison_does_not_verify_token(monkeypatch, truncated, error):
    monkeypatch.setattr(web_panels, "HttpSessionPool", lambda **kw: SimpleNamespace(close=lambda: None))

    def get(pool, base, path, **kwargs):
        if kwargs.get("headers"):
            return response(200, {"Id": 1, "Username": "admin"})
        return HttpResponse(status=401, body=b"", headers={}, truncated=truncated, error=error)

    monkeypatch.setattr(web_panels, "_get", get)
    result = web_panels.authenticate_portainer_token(context(), panel(), "ptr_secret")
    assert result["credential_state"] == "unverified"
    assert result["provided_credentials_ok"] is None
