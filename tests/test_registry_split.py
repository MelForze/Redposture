from __future__ import annotations

import base64
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace

import pytest

from redposture_core.audit_models import AuditRecord
from redposture_core.cli_args import parse_args
from redposture_core.module_registry import AUDIT_MODULE_NAMES
from redposture_core.modules.gitlab import actions as gitlab_actions
from redposture_core.modules.gitlab import render as gitlab_render
from redposture_core.modules.gitlab import stage as gitlab_stage
from redposture_core.modules.kubeapi import actions as kube_actions
from redposture_core.modules.kubeapi import stage as kube_stage
from redposture_core.modules.registry import actions as oci_actions
from redposture_core.modules.registry import stage as oci_stage
from redposture_core.stage_runtime import AuditCommandRunner, ModuleAuditSpec, render_record_with_module


def test_registry_commands_are_product_specific() -> None:
    for command in ("gitlab", "harbor", "nexus", "docker-registry"):
        args = parse_args([command, "-t", "127.0.0.1", "--defcreds"])
        assert args.command == command
        assert args.defcreds is True
        assert command in AUDIT_MODULE_NAMES

    assert "registry" not in AUDIT_MODULE_NAMES
    with pytest.raises(SystemExit):
        parse_args(["registry", "-t", "127.0.0.1"])


def test_registry_vendor_flags_are_removed_and_gitlab_tokens_are_distinct() -> None:
    args = parse_args(["gitlab", "-t", "127.0.0.1", "--token", "web-pat", "--registry-token", "oci-token", "--images"])
    assert (args.token, args.registry_token, args.images) == ("web-pat", "oci-token", True)
    for flag in ("--docker", "--harbor", "--nexus", "--gitlab"):
        with pytest.raises(SystemExit):
            parse_args(["docker-registry", "-t", "127.0.0.1", flag])


def test_kubeapi_accepts_default_credentials_flag() -> None:
    assert parse_args(["kubeapi", "-t", "127.0.0.1", "--defcreds"]).defcreds is True


def test_harbor_checks_documented_initial_pair_first() -> None:
    plan = oci_stage.build_registry_plan(parse_args(["harbor", "-t", "host", "--defcreds"]), product="harbor")
    assert (plan.credential_runs[0].username, plan.credential_runs[0].password) == ("admin", "Harbor12345")


@pytest.mark.parametrize(
    ("command", "added_pairs", "expected_count"),
    [
        (
            "gitlab",
            {
                ("root", "changeme"),
                ("root", "gitlab"),
                ("root", "admin123"),
                ("admin", "changeme"),
                ("admin", "gitlab"),
                ("gitlab", "password"),
                ("gitlab", "admin"),
                ("guest", "guest"),
                ("dev", "dev"),
                ("user", "password"),
            },
            18,
        ),
        (
            "harbor",
            {
                ("admin", "admin123"),
                ("admin", "123456"),
                ("root", "admin"),
                ("root", "changeme"),
                ("user", "password"),
                ("guest", "guest"),
                ("dev", "dev"),
                ("service", "service"),
                ("admin", "harbor"),
                ("admin", "harbor123"),
                ("admin", "Harbor123"),
                ("harbor", "harbor"),
                ("harbor", "password"),
            },
            21,
        ),
        (
            "nexus",
            {
                ("admin", "123456"),
                ("root", "admin"),
                ("root", "changeme"),
                ("user", "password"),
                ("guest", "guest"),
                ("dev", "dev"),
                ("service", "service"),
                ("admin", "nexus"),
                ("admin", "nexus123"),
                ("admin", "sonatype"),
                ("nexus", "password"),
                ("nexus", "admin"),
            },
            21,
        ),
        (
            "docker-registry",
            {
                ("admin", "admin123"),
                ("admin", "123456"),
                ("root", "admin"),
                ("root", "changeme"),
                ("user", "password"),
                ("guest", "guest"),
                ("dev", "dev"),
                ("service", "service"),
                ("registry", "admin"),
                ("registry", "changeme"),
                ("registry", "registry123"),
                ("docker", "docker"),
                ("docker", "password"),
            },
            22,
        ),
    ],
)
def test_registry_default_candidates_include_expanded_weak_pairs_without_duplicates(
    command: str, added_pairs: set[tuple[str, str]], expected_count: int
) -> None:
    args = parse_args([command, "-t", "host", "--defcreds"])
    plan = (
        gitlab_stage.build_gitlab_plan(args)
        if command == "gitlab"
        else oci_stage.build_registry_plan(args, product=command)
    )
    pairs = [(run.username, run.password) for run in plan.credential_runs]
    assert added_pairs <= set(pairs)
    assert len(pairs) == len(set(pairs)) == expected_count
    assert all(run.source == "default" for run in plan.credential_runs)


@pytest.mark.parametrize(
    ("command", "username", "password"),
    [
        ("gitlab", "root", "changeme"),
        ("harbor", "admin", "harbor"),
        ("nexus", "admin", "nexus"),
        ("docker-registry", "registry", "changeme"),
    ],
)
def test_explicit_registry_pair_precedes_matching_default_without_duplicate(
    command: str, username: str, password: str
) -> None:
    args = parse_args([command, "-t", "host", "-u", username, "-p", password, "--defcreds"])
    plan = (
        gitlab_stage.build_gitlab_plan(args)
        if command == "gitlab"
        else oci_stage.build_registry_plan(args, product=command)
    )
    matching = [run for run in plan.credential_runs if (run.username, run.password) == (username, password)]
    assert len(matching) == 1
    assert plan.credential_runs[0] == matching[0]
    assert matching[0].source == "provided"


def test_generic_registry_rejects_confirmed_harbor_and_harbor_accepts_it(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        oci_actions,
        "_http_request",
        lambda *_args, **_kwargs: (
            401,
            b'{"errors":[{"code":"UNAUTHORIZED"}]}',
            {"www-authenticate": 'Bearer realm="https://host/service/token",service="harbor-registry"'},
            None,
        ),
    )
    monkeypatch.setattr(
        oci_actions, "_fetch_harbor_info", lambda *_args, **_kwargs: ({"harbor_version": "v2.11.1"}, None)
    )
    monkeypatch.setattr(oci_actions, "_fetch_nexus_info", lambda *_args, **_kwargs: (None, "not nexus"))
    ctx = SimpleNamespace(
        host="host",
        port=5000,
        target=SimpleNamespace(scheme="http"),
        args=SimpleNamespace(timeout=1.0, retries=0, debug=False),
        credential=SimpleNamespace(username=None, password=None, token=None),
        lifecycle_state=oci_actions.RegistryLifecycleState(),
    )
    generic_spec = oci_stage.build_registry_spec(
        parse_args(["docker-registry", "-t", "host"]), product="docker-registry"
    )
    assert generic_spec.detect is not None
    generic = generic_spec.detect(ctx)
    assert generic.extra["is_registry"] is False
    harbor_spec = oci_stage.build_registry_spec(parse_args(["harbor", "-t", "host"]), product="harbor")
    assert harbor_spec.detect is not None
    harbor = harbor_spec.detect(ctx)
    assert harbor.extra["is_registry"] is True
    assert harbor.extra["is_harbor"] is True


def test_public_v2_does_not_verify_basic_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        oci_actions,
        "_http_request",
        lambda *_args, **_kwargs: (200, b"{}", {"docker-distribution-api-version": "registry/2.0"}, None),
    )
    verified, reason = oci_actions._verify_registry_credential(
        "docker-registry",
        "host",
        5000,
        1.0,
        "admin",
        "admin",
        None,
        anonymous_probe=(200, b"{}", {"docker-distribution-api-version": "registry/2.0"}, None),
    )
    assert verified is None
    assert "anonymous" in reason


def test_gitlab_registry_bearer_token_requires_protected_v2_access(monkeypatch: pytest.MonkeyPatch) -> None:
    probe = (
        401,
        b"",
        {
            "docker-distribution-api-version": "registry/2.0",
            "www-authenticate": 'Bearer realm="http://gitlab.example/jwt/auth",service="container_registry"',
        },
        None,
    )
    monkeypatch.setattr(
        oci_actions,
        "_http_request",
        lambda *_args, **_kwargs: (200, b"{}", {"docker-distribution-api-version": "registry/2.0"}, None),
    )
    verified, _reason = oci_actions._verify_registry_credential(
        "gitlab", "host", 5000, 1.0, None, None, "issued-jwt", anonymous_probe=probe
    )
    assert verified is True


def test_harbor_current_user_proves_basic_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    def response(_host: str, _port: int, _method: str, path: str, _timeout: float, **_kwargs: object):
        assert path == "/api/v2.0/users/current"
        return 200, b'{"user_id":1,"username":"admin"}', {}, None

    monkeypatch.setattr(oci_actions, "_http_request", response)
    verified, reason = oci_actions._verify_registry_credential(
        "harbor",
        "host",
        80,
        1.0,
        "admin",
        "Harbor12345",
        None,
        anonymous_probe=None,
    )
    assert verified is True
    assert reason is None


def test_public_nexus_user_listing_does_not_verify_basic_pair(monkeypatch: pytest.MonkeyPatch) -> None:
    def response(_host: str, _port: int, _method: str, path: str, _timeout: float, **_kwargs: object):
        assert path == "/service/rest/v1/security/users"
        return 200, b'[{"userId":"admin"}]', {}, None

    monkeypatch.setattr(oci_actions, "_http_request", response)
    verified, reason = oci_actions._verify_registry_credential(
        "nexus", "host", 8081, 1.0, "admin", "wrong", None, anonymous_probe=None
    )
    assert verified is None
    assert reason is not None and "anonymous" in reason


def test_kubeapi_default_pairs_are_planned_but_basic_403_requires_identity_proof(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    args = parse_args(["kubeapi", "-t", "127.0.0.1", "--defcreds"])
    plan = kube_stage.build_kubeapi_plan(args)
    assert any(run.username == "admin" and run.password == "admin" for run in plan.credential_runs)
    state = kube_actions.KubeApiLifecycleState()
    state.anonymous_access = "disabled"
    monkeypatch.setattr(kube_actions, "_probe_namespace_access", lambda *_args, **_kwargs: (False, 403, "forbidden"))
    monkeypatch.setattr(
        kube_actions, "_verify_self_subject_review", lambda *_args, **_kwargs: (None, None, "RBAC denied review")
    )
    ctx = SimpleNamespace(
        host="127.0.0.1",
        port=6443,
        args=SimpleNamespace(timeout=1.0, retries=0),
        credential=SimpleNamespace(username="admin", password="admin", token=None, source="provided"),
        lifecycle_state=state,
    )
    record = kube_actions.authenticate_kubeapi(ctx, {"status": "auth_required"}, {})
    assert record["auth_valid"] is None
    assert record["status"] == "auth_unverified"


def test_kubeapi_defaults_do_not_probe_when_basic_is_not_advertised(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        kube_actions, "_probe_namespace_access", lambda *_args, **_kwargs: pytest.fail("unexpected auth probe")
    )
    ctx = SimpleNamespace(
        host="host",
        port=6443,
        args=SimpleNamespace(timeout=1.0),
        credential=SimpleNamespace(username="admin", password="admin", token=None, source="default"),
        lifecycle_state=kube_actions.KubeApiLifecycleState(),
    )
    result = kube_actions.authenticate_kubeapi(
        ctx, {"status": "auth_required", "credential_verification_status": "unavailable"}, {}
    )
    assert result["auth_valid"] is None
    assert result["auth_verification_method"] == "unsupported_basic"


def test_gitlab_command_confirms_container_registry_without_web_surface(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        gitlab_actions,
        "detect_gitlab",
        lambda *_args, **_kwargs: {"host": "host", "port": 5050, "status": "not_gitlab", "is_gitlab": False},
    )
    monkeypatch.setattr(
        oci_actions,
        "detect_registry",
        lambda *_args, **_kwargs: {
            "host": "host",
            "port": 5050,
            "status": "auth_required",
            "is_registry": True,
            "is_gitlab": True,
            "gitlab_info": {"version": "17.8.1"},
            "auth_required": True,
        },
    )
    args = parse_args(["gitlab", "-t", "host:5050"])
    ctx = SimpleNamespace(
        host="host",
        port=5050,
        args=args,
        target=SimpleNamespace(scheme="http"),
        credential=SimpleNamespace(username=None, password=None, token=None, source="anonymous"),
        lifecycle_state=gitlab_stage.gitlab_combined_state_factory(
            SimpleNamespace(host="host", port=5050, args=args, target=SimpleNamespace(scheme="http"))
        ),
    )
    spec = gitlab_stage.build_gitlab_spec(args)
    assert spec.detect is not None
    record = spec.detect(ctx)
    assert record.extra["is_gitlab"] is True
    assert record.extra["gitlab_surface"] == "container_registry"
    assert record.extra["container_registry"]["is_registry"] is True


def test_gitlab_nested_registry_data_never_serializes_password(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_registry_spec = ModuleAuditSpec(
        module="gitlab",
        label="GITLAB",
        default_port=5000,
        data=lambda _ctx, record: AuditRecord.from_mapping(
            {**record.to_dict(), "provided_password": "qa-secret"}, module="gitlab"
        ),
    )
    monkeypatch.setattr(oci_stage, "build_registry_spec", lambda *_args, **_kwargs: fake_registry_spec)
    args = parse_args(["gitlab", "-t", "host"])
    spec = gitlab_stage.build_gitlab_spec(args)
    assert spec.data is not None
    ctx = SimpleNamespace(
        host="host",
        port=5050,
        args=args,
        target=SimpleNamespace(scheme="http"),
        credential=SimpleNamespace(username="root", password="qa-secret", token=None, source="provided"),
        lifecycle_state=gitlab_stage.GitLabCombinedState(
            web=gitlab_actions.GitLabLifecycleState(), registry=oci_actions.RegistryLifecycleState()
        ),
    )
    record = AuditRecord.from_mapping(
        {"gitlab_surface": "container_registry", "container_registry": {"is_registry": True}}, module="gitlab"
    )
    updated = spec.data(ctx, record).to_dict()
    assert "provided_password" not in updated["container_registry"]


@pytest.mark.parametrize(
    ("source", "web_token", "registry_token"),
    [("web_token", "web-pat", None), ("registry_token", None, "oci-jwt")],
)
def test_gitlab_data_keeps_web_and_registry_tokens_on_their_own_surface(
    monkeypatch: pytest.MonkeyPatch, source: str, web_token: str | None, registry_token: str | None
) -> None:
    seen: dict[str, str | None] = {}

    def web_data(ctx: object, record: AuditRecord, _options: object) -> dict[str, object]:
        seen["web"] = ctx.credential.token
        return record.to_dict()

    def registry_data(ctx: object, record: AuditRecord) -> AuditRecord:
        seen["registry"] = ctx.credential.token
        return record

    monkeypatch.setattr(gitlab_actions, "collect_gitlab_data", web_data)
    monkeypatch.setattr(
        oci_stage,
        "build_registry_spec",
        lambda *_args, **_kwargs: ModuleAuditSpec(
            module="gitlab", label="GITLAB", default_port=5000, data=registry_data
        ),
    )
    args = parse_args(["gitlab", "-t", "host", "--token", "web-pat", "--registry-token", "oci-jwt"])
    spec = gitlab_stage.build_gitlab_spec(args)
    assert spec.data is not None
    ctx = SimpleNamespace(
        host="host",
        port=5050,
        args=args,
        target=SimpleNamespace(scheme="http"),
        credential=SimpleNamespace(username=None, password=None, token=web_token or registry_token, source=source),
        lifecycle_state=gitlab_stage.gitlab_combined_state_factory(
            SimpleNamespace(host="host", port=5050, args=args, target=SimpleNamespace(scheme="http"))
        ),
    )
    record = AuditRecord.from_mapping(
        {"gitlab_surface": "web_and_registry", "container_registry": {"is_registry": True}}, module="gitlab"
    )
    spec.data(ctx, record)
    assert seen == {"web": web_token, "registry": registry_token}


def test_gitlab_web_default_login_requires_authenticated_identity() -> None:
    responses = iter(
        [
            SimpleNamespace(
                status=200,
                body=b'gon.recaptcha_sitekey=null;<form action="/users/sign_in"><input name="authenticity_token" value="csrf"></form>',
                headers={"set-cookie": "_gitlab_session=before; Path=/"},
                error=None,
            ),
            SimpleNamespace(
                status=302,
                body=b"",
                headers={"set-cookie": "_gitlab_session=after; Path=/", "location": "/"},
                error=None,
            ),
            SimpleNamespace(
                status=200, body=b'{"id":7,"username":"root","name":"Root","state":"active"}', headers={}, error=None
            ),
        ]
    )

    class Pool:
        def request_once(self, *_args: object, **_kwargs: object):
            return next(responses)

    state = gitlab_actions.GitLabLifecycleState(http=Pool(), scheme="http", host="host", port=80)
    ctx = SimpleNamespace(host="host", port=80, args=SimpleNamespace(timeout=1.0), lifecycle_state=state)
    assert gitlab_actions.verify_gitlab_web_credentials(ctx, "root", "password") == (True, None)


@pytest.mark.parametrize(
    "reply",
    [
        SimpleNamespace(status=302, body=b"", headers={"location": "https://idp.example/login"}, error=None),
        SimpleNamespace(status=429, body=b"", headers={}, error=None),
        SimpleNamespace(
            status=200,
            body=b'gon.recaptcha_sitekey="active-key";<form action="/users/sign_in"><input name="authenticity_token" value="csrf"></form>',
            headers={"set-cookie": "_gitlab_session=before; Path=/"},
            error=None,
        ),
    ],
)
def test_gitlab_web_login_stops_after_sso_captcha_or_rate_limit(reply: SimpleNamespace) -> None:
    calls = 0

    class Pool:
        def request_once(self, *_args: object, **_kwargs: object):
            nonlocal calls
            calls += 1
            return reply

    state = gitlab_actions.GitLabLifecycleState(http=Pool(), scheme="http", host="host", port=80)
    ctx = SimpleNamespace(host="host", port=80, args=SimpleNamespace(timeout=1.0), lifecycle_state=state)
    assert gitlab_actions.verify_gitlab_web_credentials(ctx, "root", "password")[0] is None
    assert state.web_auth_blocked is True
    assert gitlab_actions.verify_gitlab_web_credentials(ctx, "root", "password")[0] is None
    assert calls == 1


def test_kubeapi_basic_proxy_requires_identity_proof_for_default_pair() -> None:
    seen: list[tuple[str, str, str | None]] = []
    good = "Basic " + base64.b64encode(b"admin:admin").decode("ascii")

    class Proxy(BaseHTTPRequestHandler):
        def _reply(self, status: int, payload: dict[str, object], *, basic: bool = False) -> None:
            body = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            if basic:
                self.send_header("WWW-Authenticate", 'Basic realm="Kubernetes QA proxy"')
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:  # noqa: N802
            auth = self.headers.get("Authorization")
            seen.append(("GET", self.path, auth))
            if self.path == "/version":
                self._reply(200, {"major": "1", "minor": "30", "gitVersion": "v1.30.0"})
            elif self.path == "/api":
                self._reply(200, {"kind": "APIVersions", "apiVersion": "v1", "versions": ["v1"]})
            elif self.path.startswith("/api/v1/namespaces"):
                code = 403 if auth == good else 401
                self._reply(code, {"kind": "Status", "apiVersion": "v1", "status": "Failure", "code": code}, basic=True)
            else:
                self._reply(404, {})

        def do_POST(self) -> None:  # noqa: N802
            auth = self.headers.get("Authorization")
            seen.append(("POST", self.path, auth))
            if self.path == "/apis/authentication.k8s.io/v1/selfsubjectreviews" and auth == good:
                self._reply(
                    201,
                    {
                        "apiVersion": "authentication.k8s.io/v1",
                        "kind": "SelfSubjectReview",
                        "status": {"userInfo": {"username": "admin"}},
                    },
                )
            else:
                self._reply(401, {"kind": "Status", "apiVersion": "v1", "status": "Failure", "code": 401})

        def log_message(self, *_args: object) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Proxy)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        args = parse_args(["kubeapi", "-t", f"http://127.0.0.1:{server.server_port}", "--defcreds", "--format", "json"])
        lines: list[str] = []
        AuditCommandRunner(args=args, spec=kube_stage.build_kubeapi_spec(args), emit_line=lines.append).run_plan(
            kube_stage.build_kubeapi_plan(args)
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
    records = [json.loads(line) for line in lines if line.startswith("{")]
    assert any(
        record.get("auth_valid") is True and record.get("auth_verified_identity") == "admin" for record in records
    ), (records, seen)
    assert any(method == "POST" and auth == good for method, _path, auth in seen)
    assert not any("provided_password" in record for record in records)
    assert "admin:admin" not in "\n".join(lines)
    assert all(
        item.get("password") == "<redacted>" for record in records for item in record.get("attempted_credentials", [])
    )


def test_gitlab_registry_only_renders_registry_service_and_oci_details() -> None:
    payload = {
        "host": "host",
        "port": 5050,
        "status": "detected",
        "is_gitlab": True,
        "gitlab_surface": "container_registry",
        "auth_required": True,
        "container_registry": {
            "host": "host",
            "port": 5050,
            "status": "auth_required",
            "is_registry": True,
            "is_gitlab": True,
            "auth_required": True,
            "images": [],
            "show_images": False,
        },
    }
    lines = render_record_with_module(gitlab_render, AuditRecord.from_mapping(payload, module="gitlab"), "txt")
    assert any("GitLab Container Registry" in line for line in lines)
    assert not any("GitLab Service (login page" in line for line in lines)
