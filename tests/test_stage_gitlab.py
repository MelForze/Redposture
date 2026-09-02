from __future__ import annotations

import io
import json
import pathlib
import subprocess
import urllib.error
import urllib.request
from types import SimpleNamespace

import pytest

from redposture_core import stage_gitlab as gitlab
from tests.stage_runtime_helpers import run_module_targets_for_test


def test_normalize_path_and_base_url_helpers() -> None:
    assert gitlab._normalize_path("") == "/"
    assert gitlab._normalize_path("api/v4/version") == "/api/v4/version"
    assert gitlab._normalize_path("http://example.com/x") == "http://example.com/x"
    assert gitlab._build_base_url("127.0.0.1", 8080, use_https=False) == "http://127.0.0.1:8080"
    assert gitlab._build_base_url("127.0.0.1", 443, use_https=True) == "https://127.0.0.1:443"


def test_gitlab_spec_hides_undetected_records_only_from_normal_text() -> None:
    spec = gitlab.build_gitlab_spec(SimpleNamespace())

    assert spec.suppress_undetected_records_in_text is True


def test_gitlab_undetected_record_is_normal_text_suppressed_but_debug_and_json_visible(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_audit(host: str, _port: int, *_args: object, **_kwargs: object) -> dict[str, object]:
        return {
            "host": host,
            "port": 8080,
            "service": "gitlab",
            "status": "not_gitlab",
            "is_gitlab": False,
            "error": None,
        }

    monkeypatch.setattr(gitlab, "_audit_gitlab_host", fake_audit)
    common = {
        "hosts": ["127.0.0.1"],
        "port": 8080,
        "timeout": 1.0,
        "retries": 0,
        "workers": 1,
        "use_https": False,
        "token": None,
        "project_filters": [],
        "clone": False,
        "clone_dir": "/tmp/gitlab",
    }

    normal_lines: list[str] = []
    run_module_targets_for_test("gitlab", emit_line=normal_lines.append, output_format="txt", **common)
    assert all("not a GitLab service" not in line for line in normal_lines)

    debug_lines: list[str] = []
    run_module_targets_for_test(
        "gitlab",
        emit_line=debug_lines.append,
        output_format="txt",
        debug=True,
        **common,
    )
    assert any("not a GitLab service" in line for line in debug_lines)

    json_lines: list[str] = []
    run_module_targets_for_test("gitlab", emit_line=json_lines.append, output_format="json", **common)
    payloads = [json.loads(line) for line in json_lines]
    assert any(payload.get("status") == "not_gitlab" for payload in payloads)


def test_detect_login_page() -> None:
    assert gitlab._detect_login_page("<title>GitLab</title> users/sign_in") is True
    assert gitlab._detect_login_page("Welcome") is False


def test_normalize_project_filters_deduplicates_and_splits() -> None:
    values = ["group/app,group/app", "42", "  "]
    assert gitlab._normalize_project_filters(values) == ["group/app", "42"]


def test_project_matches_filters_by_path_and_id() -> None:
    project = {"id": 42, "path_with_namespace": "group/app"}
    assert gitlab._project_matches_filters(project, ["group/app"]) is True
    assert gitlab._project_matches_filters(project, ["42"]) is True
    assert gitlab._project_matches_filters(project, ["nope"]) is False


def test_extract_access_level_prefers_max_level() -> None:
    project = {
        "permissions": {
            "project_access": {"access_level": 30},
            "group_access": {"access_level": "40"},
        }
    }
    assert gitlab._extract_access_level(project) == 40


def test_status_to_access_flag() -> None:
    assert gitlab._status_to_access_flag(200) is True
    assert gitlab._status_to_access_flag(401) is False
    assert gitlab._status_to_access_flag(500) is None


def test_safe_slug_and_clone_url_with_token() -> None:
    assert gitlab._safe_slug("group/app name") == "group_app_name"

    with_token = gitlab._clone_url_with_token("https://gitlab.local/group/app.git", "tok+en")
    assert "oauth2:tok%2Ben@" in with_token

    unchanged = gitlab._clone_url_with_token("git@gitlab.local:group/app.git", "token")
    assert unchanged == "git@gitlab.local:group/app.git"


def test_safe_repo_relative_path_sanitizes_escape_segments() -> None:
    assert gitlab._safe_repo_relative_path("../group//../../app") == "group/app"
    assert gitlab._safe_repo_relative_path("/../../") == "item"


def test_clone_project_sanitizes_path_traversal_destination(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    clone_root = tmp_path / "gitlab-clones"
    clone_root.mkdir()
    captured: dict[str, object] = {}

    monkeypatch.setattr(gitlab.shutil, "which", lambda _name: "/usr/bin/git")

    def fake_run(
        cmd: list[str],
        capture_output: bool,
        text: bool,
        timeout: float,
        check: bool,
        env: dict[str, str],
    ) -> subprocess.CompletedProcess[str]:
        _ = (capture_output, text, timeout, check)
        captured["cmd"] = list(cmd)
        captured["env"] = dict(env)
        pathlib.Path(cmd[-1]).mkdir(parents=True)
        return subprocess.CompletedProcess(cmd, 0, stdout="ok", stderr="")

    monkeypatch.setattr(gitlab.subprocess, "run", fake_run)
    project = {
        "id": 11,
        "path_with_namespace": "../../escape/repo",
        "http_url_to_repo": "https://gitlab.local/escape/repo.git",
    }

    result = gitlab._clone_project(
        project,
        "127.0.0.1",
        8080,
        use_https=False,
        token=None,
        clone_dir=str(clone_root),
    )

    assert result["status"] == "cloned"
    command = captured.get("cmd")
    assert isinstance(command, list)
    dest_path = str(command[-1])
    assert dest_path.startswith(str(clone_root))
    assert ".." not in dest_path
    assert captured["env"] == {**dict(gitlab.os.environ), "GIT_TERMINAL_PROMPT": "0", "GIT_SSL_NO_VERIFY": "true"}


def test_format_record_for_statuses() -> None:
    base = {"host": "127.0.0.1", "port": 8080}

    fail = gitlab._format_record({**base, "status": "fail", "error": "connection timeout"}, "txt")
    assert "[!] connection failed" in fail

    not_gitlab = gitlab._format_record({**base, "status": "not_gitlab"}, "txt")
    assert "[-] not a GitLab service" in not_gitlab

    detected = gitlab._format_record({**base, "status": "detected", "login_page": True, "version": "16.7"}, "txt")
    assert "[*] GitLab Service" in detected
    assert "(login page:True)" in detected


def test_project_and_token_access_summary_lines() -> None:
    project_line = gitlab._project_summary_line({"path_with_namespace": "group/app", "visibility": "public"})
    assert "group/app" in project_line
    assert "(visibility:public)" in project_line

    access_line = gitlab._token_access_summary_line(
        {
            "path_with_namespace": "group/app",
            "access_level": 30,
            "repo_read": True,
            "issues_read": False,
            "members_read": None,
            "merge_requests_enabled": True,
            "wiki_enabled": False,
            "snippets_enabled": True,
        }
    )
    assert "(access:developer)" in access_line
    assert "(repo:True)" in access_line


def test_format_detail_records_with_invalid_token_and_clone_results() -> None:
    record = {
        "host": "127.0.0.1",
        "port": 8080,
        "status": "detected",
        "clone_requested": True,
        "clone_scope": "token",
        "clone_results": [
            {"project": "group/app", "status": "cloned", "dest": "/tmp/group/app", "error": None},
            {"project": "group/miss", "status": "failed", "dest": None, "error": "not found"},
        ],
        "project_filters": [],
        "open_endpoints": [],
        "public_projects": [],
        "public_projects_error": None,
        "token_provided": True,
        "token_valid": False,
        "token_projects_error": "invalid token",
        "token_access": [],
    }
    lines = gitlab._format_detail_records(record, "txt")
    assert any("[-] token invalid err=invalid token" in line for line in lines)
    assert any("[+] group/app -> /tmp/group/app" in line for line in lines)
    assert any("[-] clone failed group/miss err=not found" in line for line in lines)


def test_audit_gitlab_host_detects_public_projects_and_open_endpoints(monkeypatch) -> None:
    def fake_http_request(
        host: str,
        port: int,
        method: str,
        path: str,
        timeout: float,
        *,
        use_https: bool,
        headers: dict[str, str] | None = None,
        data: bytes | None = None,
    ) -> tuple[int, bytes, dict[str, str], str | None]:
        _ = (host, port, method, timeout, use_https, headers, data)
        if path == "/users/sign_in":
            return 200, b"<title>GitLab</title> users/sign_in", {}, None
        if path == "/api/v4/version":
            return 200, b'{"version":"16.9.0","revision":"abc123"}', {}, None
        return 200, b"[]", {}, None

    def fake_paginate_projects(
        host: str,
        port: int,
        timeout: float,
        *,
        use_https: bool,
        token: str | None,
        public_only: bool,
    ) -> tuple[list[dict[str, object]] | None, str | None]:
        _ = (host, port, timeout, use_https, token, public_only)
        return [
            {"id": 1, "path_with_namespace": "group/app", "visibility": "public", "archived": False},
            {"id": 2, "path_with_namespace": "other/miss", "visibility": "public", "archived": False},
        ], None

    monkeypatch.setattr(gitlab, "_http_request", fake_http_request)
    monkeypatch.setattr(gitlab, "_paginate_projects", fake_paginate_projects)

    record = gitlab._audit_gitlab_host(
        host="127.0.0.1",
        port=8080,
        timeout=1.0,
        retries=0,
        use_https=False,
        token=None,
        project_filters=["group/app"],
        clone=False,
        clone_dir="/tmp/gitlab",
        workers=4,
    )

    assert record["status"] == "detected"
    assert record["login_page"] is True
    assert record["version"] == "16.9.0"
    assert record["public_projects"] == [
        {"id": 1, "path_with_namespace": "group/app", "visibility": "public", "archived": False}
    ]
    open_endpoints = record.get("open_endpoints")
    assert isinstance(open_endpoints, list)
    assert any(item.get("path") == "/api/v4/version" for item in open_endpoints if isinstance(item, dict))
    detail_lines = gitlab._format_detail_records(record, "txt")
    assert any("[+] public access (projects:1,filtered:True)" in line for line in detail_lines)
    assert any("group/app (visibility:public)" in line for line in detail_lines)


def test_audit_gitlab_host_valid_token_probes_access_and_clones(monkeypatch) -> None:
    def fake_http_request(
        host: str,
        port: int,
        method: str,
        path: str,
        timeout: float,
        *,
        use_https: bool,
        headers: dict[str, str] | None = None,
        data: bytes | None = None,
    ) -> tuple[int, bytes, dict[str, str], str | None]:
        _ = (host, port, method, timeout, use_https, headers, data)
        if path == "/users/sign_in":
            return 200, b"<title>GitLab</title> users/sign_in", {}, None
        if path == "/api/v4/version":
            return 200, b'{"version":"16.9.0","revision":"abc123"}', {}, None
        return 404, b"{}", {}, None

    def fake_api_get_json(
        host: str,
        port: int,
        path: str,
        timeout: float,
        *,
        use_https: bool,
        token: str | None,
    ) -> tuple[int, dict[str, object] | None, dict[str, str], str | None]:
        _ = (host, port, path, timeout, use_https, token)
        return 200, {"id": 7, "username": "scanner"}, {}, None

    def fake_paginate_projects(
        host: str,
        port: int,
        timeout: float,
        *,
        use_https: bool,
        token: str | None,
        public_only: bool,
    ) -> tuple[list[dict[str, object]] | None, str | None]:
        _ = (host, port, timeout, use_https, public_only)
        if token:
            return [
                {
                    "id": 42,
                    "path_with_namespace": "group/app",
                    "visibility": "private",
                    "archived": False,
                    "permissions": {"project_access": {"access_level": 30}},
                    "merge_requests_enabled": True,
                    "wiki_enabled": False,
                    "snippets_enabled": True,
                }
            ], None
        return [], None

    def fake_probe_project_capabilities(
        host: str,
        port: int,
        timeout: float,
        *,
        use_https: bool,
        token: str,
        project: dict[str, object],
    ) -> dict[str, object]:
        _ = (host, port, timeout, use_https, token)
        return {
            "path_with_namespace": project["path_with_namespace"],
            "access_level": 30,
            "repo_read": True,
            "issues_read": True,
            "members_read": False,
            "merge_requests_enabled": True,
            "wiki_enabled": False,
            "snippets_enabled": True,
        }

    def fake_clone_project(
        project: dict[str, object],
        host: str,
        port: int,
        *,
        use_https: bool,
        token: str | None,
        clone_dir: str,
    ) -> dict[str, object]:
        _ = (host, port, use_https, token, clone_dir)
        return {
            "project": project["path_with_namespace"],
            "project_id": project["id"],
            "status": "cloned",
            "dest": "/tmp/gitlab/group_app",
            "error": None,
        }

    monkeypatch.setattr(gitlab, "_http_request", fake_http_request)
    monkeypatch.setattr(gitlab, "_api_get_json", fake_api_get_json)
    monkeypatch.setattr(gitlab, "_paginate_projects", fake_paginate_projects)
    monkeypatch.setattr(gitlab, "_probe_project_capabilities", fake_probe_project_capabilities)
    monkeypatch.setattr(gitlab, "_clone_project", fake_clone_project)

    record = gitlab._audit_gitlab_host(
        host="127.0.0.1",
        port=8080,
        timeout=1.0,
        retries=0,
        use_https=False,
        token="glpat-token",
        project_filters=["group/app"],
        clone=True,
        clone_dir="/tmp/gitlab",
        workers=4,
    )

    # E2E-batch fix: a valid token now yields `valid_credentials` (was
    # unconditionally `detected` regardless of token verdict).
    assert record["status"] == "valid_credentials"
    assert record["token_valid"] is True
    assert record["token_user"] == {"id": 7, "username": "scanner"}
    assert record["clone_scope"] == "token"
    token_access = record.get("token_access")
    assert isinstance(token_access, list) and token_access[0]["path_with_namespace"] == "group/app"
    clone_results = record.get("clone_results")
    assert isinstance(clone_results, list) and clone_results[0]["status"] == "cloned"
    detail_lines = gitlab._format_detail_records(record, "txt")
    assert any("[+] token valid user=scanner id=7" in line for line in detail_lines)
    assert any("[+] group/app -> /tmp/gitlab/group_app" in line for line in detail_lines)


def test_audit_gitlab_host_marks_not_gitlab_and_retries_failures(monkeypatch) -> None:
    def fake_not_gitlab(
        host: str,
        port: int,
        method: str,
        path: str,
        timeout: float,
        *,
        use_https: bool,
        headers: dict[str, str] | None = None,
        data: bytes | None = None,
    ) -> tuple[int, bytes, dict[str, str], str | None]:
        _ = (host, port, method, path, timeout, use_https, headers, data)
        return 404, b"{}", {}, None

    monkeypatch.setattr(gitlab, "_http_request", fake_not_gitlab)
    monkeypatch.setattr(gitlab, "_paginate_projects", lambda *args, **kwargs: (None, "authentication required"))

    record = gitlab._audit_gitlab_host(
        host="127.0.0.1",
        port=8080,
        timeout=1.0,
        retries=0,
        use_https=False,
        token=None,
        project_filters=[],
        clone=False,
        clone_dir="/tmp/gitlab",
        workers=1,
    )
    assert record["status"] == "not_gitlab"

    attempts = {"count": 0}

    def fake_fail(
        host: str,
        port: int,
        method: str,
        path: str,
        timeout: float,
        *,
        use_https: bool,
        headers: dict[str, str] | None = None,
        data: bytes | None = None,
    ) -> tuple[int, bytes, dict[str, str], str | None]:
        _ = (host, port, method, path, timeout, use_https, headers, data)
        attempts["count"] += 1
        return 0, b"", {}, "timed out"

    monkeypatch.setattr(gitlab, "_http_request", fake_fail)
    monkeypatch.setattr(gitlab, "_retry_delay", lambda _attempt: 0.0)
    failed_record = gitlab._audit_gitlab_host(
        host="127.0.0.1",
        port=8080,
        timeout=1.0,
        retries=1,
        use_https=False,
        token=None,
        project_filters=[],
        clone=False,
        clone_dir="/tmp/gitlab",
        workers=1,
    )
    assert attempts["count"] == 2
    assert failed_record["status"] == "fail"
    assert failed_record["error"] == "connection timeout"


def test_http_and_api_helpers_cover_success_error_and_invalid_json(monkeypatch: pytest.MonkeyPatch) -> None:
    class _FakeResponse:
        def __init__(self, status: int, body: bytes, headers: dict[str, str] | None = None) -> None:
            self.status = status
            self._body = body
            self.headers = headers or {}

        def read(self) -> bytes:
            return self._body

        def __enter__(self) -> _FakeResponse:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

    monkeypatch.setattr(
        urllib.request,
        "urlopen",
        lambda *_args, **_kwargs: _FakeResponse(200, b'{"ok":1}', {"X-Next-Page": "2"}),
    )
    status, payload, headers, error = gitlab._http_request("127.0.0.1", 8080, "GET", "/api", 1.0, use_https=False)
    assert (status, payload, headers, error) == (200, b'{"ok":1}', {"x-next-page": "2"}, None)

    http_error = urllib.error.HTTPError(
        "http://127.0.0.1:8080/api",
        404,
        "not found",
        {"X-Test": "1"},
        io.BytesIO(b'{"message":"missing"}'),
    )

    def _raise_http_error(*_args: object, **_kwargs: object) -> object:
        raise http_error

    monkeypatch.setattr(urllib.request, "urlopen", _raise_http_error)
    status, payload, headers, error = gitlab._http_request("127.0.0.1", 8080, "GET", "/api", 1.0, use_https=False)
    assert (status, payload, headers, error) == (404, b'{"message":"missing"}', {"x-test": "1"}, None)
    http_error.close()

    monkeypatch.setattr(
        urllib.request,
        "urlopen",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(TimeoutError("timed out")),
    )
    status, payload, headers, error = gitlab._http_request("127.0.0.1", 8080, "GET", "/api", 1.0, use_https=False)
    assert status == 0
    assert payload == b""
    assert headers == {}
    assert "connection timeout" in str(error)

    monkeypatch.setattr(
        gitlab,
        "_http_request",
        lambda *_args, **_kwargs: (200, b'{"id":1}', {"x-next-page": "2"}, None),
    )
    status, payload, headers, error = gitlab._api_get_json("127.0.0.1", 8080, "/api", 1.0, use_https=False)
    assert (status, payload, headers, error) == (200, {"id": 1}, {"x-next-page": "2"}, None)

    monkeypatch.setattr(gitlab, "_http_request", lambda *_args, **_kwargs: (200, b"not-json", {}, None))
    status, payload, headers, error = gitlab._api_get_json("127.0.0.1", 8080, "/api", 1.0, use_https=False)
    assert (status, payload, headers, error) == (200, None, {}, None)


def test_http_request_uses_insecure_tls_and_allows_cross_origin_redirects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    class _Client:
        def __init__(self, config: object) -> None:
            captured["config"] = config

        def request(self, *_args: object, **_kwargs: object) -> SimpleNamespace:
            captured["headers"] = dict(_kwargs.get("headers") or {})
            return SimpleNamespace(
                status=200,
                body=b'{"version":"17.0"}',
                headers={"X-GitLab-Meta": "ok"},
                error=None,
            )

    monkeypatch.setattr(gitlab, "HttpApiClient", _Client)
    status, payload, headers, error = gitlab._http_request(
        "proxy.local",
        443,
        "GET",
        "/api/v4/version",
        1.0,
        use_https=True,
        headers={"PRIVATE-TOKEN": "secret"},
    )

    config = captured["config"]
    assert isinstance(config, gitlab.HttpClientConfig)
    assert config.insecure is True
    assert config.allow_cross_origin_redirects is True
    assert captured["headers"] == {"User-Agent": "RedPosture/1.0", "PRIVATE-TOKEN": "secret"}
    assert (status, payload, headers, error) == (200, b'{"version":"17.0"}', {"x-gitlab-meta": "ok"}, None)


def test_paginate_project_lookup_and_capability_helpers(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []

    def fake_api_get_json(
        host: str,
        port: int,
        path: str,
        timeout: float,
        *,
        use_https: bool,
        token: str | None = None,
    ) -> tuple[int, object | None, dict[str, str], str | None]:
        _ = (host, port, timeout, use_https, token)
        calls.append(path)
        if path.startswith("/api/v4/projects?"):
            if "page=2" in path:
                return 200, [{"id": 2, "path_with_namespace": "group/api"}], {}, None
            if "page=1" in path:
                return 200, [{"id": 1, "path_with_namespace": "group/app"}], {"x-next-page": "2"}, None
        if path == "/api/v4/projects/7":
            return 200, {"id": 7, "path_with_namespace": "group/app"}, {}, None
        if path == "/api/v4/projects/missing":
            return 404, None, {}, None
        if path.endswith("/repository/tree?per_page=1"):
            return 200, [], {}, None
        if path.endswith("/issues?per_page=1"):
            return 403, None, {}, None
        if path.endswith("/members/all?per_page=1"):
            return 0, None, {}, "timed out"
        return 500, None, {}, None

    monkeypatch.setattr(gitlab, "_api_get_json", fake_api_get_json)

    projects, error = gitlab._paginate_projects("127.0.0.1", 8080, 1.0, use_https=False, token=None, public_only=True)
    assert error is None
    assert projects == [
        {"id": 1, "path_with_namespace": "group/app"},
        {"id": 2, "path_with_namespace": "group/api"},
    ]

    project, error = gitlab._fetch_project_by_ref(
        "127.0.0.1",
        8080,
        1.0,
        use_https=False,
        token=None,
        project_ref="7",
    )
    assert error is None
    assert project == {"id": 7, "path_with_namespace": "group/app"}

    project, error = gitlab._fetch_project_by_ref(
        "127.0.0.1",
        8080,
        1.0,
        use_https=False,
        token=None,
        project_ref="missing",
    )
    assert project is None
    assert error == "project not found"

    access = gitlab._probe_project_capabilities(
        "127.0.0.1",
        8080,
        1.0,
        use_https=False,
        token="glpat",
        project={
            "id": 7,
            "path_with_namespace": "group/app",
            "permissions": {"project_access": {"access_level": 30}},
            "issues_enabled": False,
            "merge_requests_enabled": True,
            "wiki_enabled": False,
            "snippets_enabled": True,
        },
    )
    assert access["repo_read"] is True
    assert access["issues_read"] is False
    assert access["members_read"] is None
    assert access["members_error"] == "timed out"
    assert "/api/v4/projects/7/repository/tree?per_page=1" in calls


def test_clone_project_handles_missing_git_existing_dir_and_fallback(
    monkeypatch: pytest.MonkeyPatch, tmp_path: pytest.TempPathFactory
) -> None:
    clone_root = tmp_path / "gitlab"
    clone_root.mkdir()
    project = {"id": 7, "path_with_namespace": "group/app", "http_url_to_repo": "https://gitlab/group/app.git"}

    monkeypatch.setattr(gitlab.shutil, "which", lambda _name: None)
    result = gitlab._clone_project(project, "127.0.0.1", 8080, use_https=False, token=None, clone_dir=str(clone_root))
    assert result["status"] == "failed"
    assert result["error"] == "git binary not found in PATH"

    dest_path = clone_root / "127.0.0.1_8080" / "group" / "app"
    dest_path.mkdir(parents=True)
    monkeypatch.setattr(gitlab.shutil, "which", lambda _name: "/usr/bin/git")
    result = gitlab._clone_project(project, "127.0.0.1", 8080, use_https=False, token=None, clone_dir=str(clone_root))
    assert result["status"] == "failed"
    assert result["error"] == "destination exists but is not a complete git repository"

    (dest_path / ".git").mkdir()
    result = gitlab._clone_project(project, "127.0.0.1", 8080, use_https=False, token=None, clone_dir=str(clone_root))
    assert result["status"] == "exists"
    assert result["dest"] == str(dest_path)

    clone_root_retry = tmp_path / "gitlab-retry"
    clone_root_retry.mkdir()
    run_calls: list[list[str]] = []

    def fake_run(
        cmd: list[str],
        *,
        check: bool,
        capture_output: bool,
        text: bool,
        timeout: int,
        env: dict[str, str],
    ) -> subprocess.CompletedProcess[str]:
        _ = (check, capture_output, text, timeout)
        assert env["GIT_TERMINAL_PROMPT"] == "0"
        assert env["GIT_SSL_NO_VERIFY"] == "true"
        run_calls.append(cmd)
        if len(run_calls) == 1:
            return subprocess.CompletedProcess(
                cmd, 1, "", "fatal: dumb http transport does not support shallow capabilities"
            )
        pathlib.Path(cmd[-1]).mkdir(parents=True)
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(gitlab.subprocess, "run", fake_run)
    result = gitlab._clone_project(
        project,
        "127.0.0.1",
        8080,
        use_https=False,
        token="tok",
        clone_dir=str(clone_root_retry),
    )
    assert result["status"] == "cloned"
    assert len(run_calls) == 2
    assert run_calls[0][2] == "--depth"
    assert "oauth2:tok@" in run_calls[0][4]

    probe_calls: list[dict[str, str]] = []

    def fake_probe_run(*_args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        probe_calls.append(dict(kwargs["env"]))
        return subprocess.CompletedProcess(["git"], 0, "", "")

    monkeypatch.setattr(gitlab.subprocess, "run", fake_probe_run)
    ok, error = gitlab._probe_repository_token(
        "gitlab.local",
        443,
        use_https=True,
        token="tok",
        project_ref="group/app",
    )
    assert (ok, error) == (True, None)
    assert probe_calls[0]["GIT_TERMINAL_PROMPT"] == "0"
    assert probe_calls[0]["GIT_SSL_NO_VERIFY"] == "true"

    monkeypatch.setattr(
        gitlab.subprocess,
        "run",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(subprocess.TimeoutExpired(cmd=["git"], timeout=1)),
    )
    clone_root_timeout = tmp_path / "gitlab-timeout"
    clone_root_timeout.mkdir()
    result = gitlab._clone_project(
        project,
        "127.0.0.1",
        8080,
        use_https=False,
        token=None,
        clone_dir=str(clone_root_timeout),
    )
    assert result["status"] == "failed"
    assert result["error"] == "git clone timeout"


def test_gitlab_identity_schema_and_repository_only_token(monkeypatch: pytest.MonkeyPatch) -> None:
    assert gitlab._looks_like_gitlab_user({"id": 7, "username": "alice"}) is True
    assert gitlab._looks_like_gitlab_user({}) is False
    assert gitlab._looks_like_gitlab_user("<html>sign in</html>") is False

    state = gitlab.GitLabLifecycleState()
    ctx = SimpleNamespace(
        host="gitlab.local",
        port=443,
        args=SimpleNamespace(timeout=1.0),
        credential=SimpleNamespace(token="repo-token"),
        lifecycle_state=state,
    )
    monkeypatch.setattr(gitlab, "_api_get_json", lambda *_args, **_kwargs: (401, {}, {}, None))
    monkeypatch.setattr(gitlab, "_probe_repository_token", lambda *_args, **_kwargs: (True, None))

    record = gitlab.authenticate_gitlab(
        ctx,
        {"host": "gitlab.local", "port": 443, "https": True, "status": "auth_required"},
        {"project_filters": ["group/app"]},
    )

    assert record["token_valid"] is True
    assert record["token_capability"] == "repository"


def test_gitlab_pagination_keeps_completed_pages_on_later_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    responses = iter(
        [
            (200, [{"id": 1, "path_with_namespace": "group/app"}], {"x-next-page": "2"}, None),
            (500, None, {}, None),
        ]
    )
    monkeypatch.setattr(gitlab, "_api_get_json", lambda *_args, **_kwargs: next(responses))

    projects, error = gitlab._paginate_projects(
        "gitlab.local",
        443,
        1.0,
        use_https=True,
        token="token",
        public_only=False,
    )

    assert projects == [{"id": 1, "path_with_namespace": "group/app"}]
    assert str(error).startswith("partial:")


def test_audit_gitlab_targets_and_run_stage_paths(
    monkeypatch: pytest.MonkeyPatch, tmp_path: pytest.TempPathFactory
) -> None:
    def fake_audit(
        host: str,
        port: int,
        timeout: float,
        retries: int,
        *,
        use_https: bool,
        token: str | None,
        project_filters: list[str],
        clone: bool,
        clone_dir: str,
        workers: int,
    ) -> dict[str, object]:
        _ = (port, timeout, retries, use_https, token, project_filters, clone, clone_dir, workers)
        if host == "127.0.0.1":
            return {
                "timestamp": "2026-03-27T00:00:00Z",
                "host": host,
                "port": 8080,
                "https": False,
                "is_gitlab": True,
                "status": "detected",
                "login_page": True,
                "version": "16.9.0",
                "open_endpoints": [],
                "public_projects": [],
                "public_projects_error": None,
                "project_filters": [],
                "token_provided": False,
                "token_valid": None,
                "token_user": None,
                "token_projects": [],
                "token_projects_error": None,
                "token_access": [],
                "clone_requested": False,
                "clone_scope": None,
                "clone_dir": None,
                "clone_results": [],
                "elapsed_ms": 5,
                "error": None,
            }
        return {
            "timestamp": "2026-03-27T00:00:00Z",
            "host": host,
            "port": 8080,
            "https": False,
            "is_gitlab": False,
            "status": "fail",
            "login_page": None,
            "version": None,
            "open_endpoints": [],
            "public_projects": [],
            "public_projects_error": None,
            "project_filters": [],
            "token_provided": False,
            "token_valid": None,
            "token_user": None,
            "token_projects": [],
            "token_projects_error": None,
            "token_access": [],
            "clone_requested": False,
            "clone_scope": None,
            "clone_dir": None,
            "clone_results": [],
            "elapsed_ms": None,
            "error": "connection timeout",
        }

    monkeypatch.setattr(gitlab, "_audit_gitlab_host", fake_audit)
    emitted: list[str] = []
    logged: list[tuple[tuple[object, ...], dict[str, object]]] = []
    output_path = tmp_path / "gitlab.txt"
    totals = run_module_targets_for_test(
        "gitlab",
        hosts=["127.0.0.1", "127.0.0.2"],
        port=8080,
        timeout=1.0,
        retries=0,
        workers=2,
        use_https=False,
        token=None,
        project_filters=[],
        clone=False,
        clone_dir=str(tmp_path),
        output_path=str(output_path),
        output_format="txt",
        emit_line=emitted.append,
        logger=SimpleNamespace(log=lambda *a, **k: logged.append((a, k))),
        suppress_timeout_status_lines=True,
    )
    assert totals == (2, 1, 1)
    assert any("GitLab Service" in line for line in emitted)
    assert not any("connection failed" in line for line in emitted)
    assert len(logged) == 2
    assert output_path.read_text(encoding="utf-8")

    class _FakeConsole:
        def __init__(self, debug: bool = False) -> None:
            self.debug = debug
            self.errors: list[str] = []
            self.infos: list[str] = []

        def error(self, message: str) -> None:
            self.errors.append(message)

        def info(self, message: str) -> None:
            self.infos.append(message)

        def plain(self, _message: str, color: str | None = None) -> None:
            _ = color
            return

        def render_tagged_payload_line(self, *_args: object, **_kwargs: object) -> bool:
            return False

    fake_console = _FakeConsole()
    monkeypatch.setattr(gitlab, "Console", lambda debug=False: fake_console)
    base_args = dict(
        debug=False,
        timeout=1.0,
        retries=0,
        workers=1,
        port=8080,
        ports=None,
        targets="127.0.0.1",
        hosts=None,
        hosts_file=None,
        project=None,
        clone=False,
        clone_dir=str(tmp_path),
        https=False,
        token=None,
        output=None,
        output_format="txt",
    )

    assert (
        gitlab.run_gitlab_stage(
            SimpleNamespace(**{**base_args, "timeout": 0}), logger=SimpleNamespace(log=lambda *_a, **_k: None)
        )
        == 2
    )
    assert any("--timeout must be > 0" in msg for msg in fake_console.errors)

    monkeypatch.setattr(
        "redposture_core.stage_runtime.AuditCommandRunner.run_plan",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("write failed")),
    )
    fake_console.errors.clear()
    assert (
        gitlab.run_gitlab_stage(SimpleNamespace(**base_args), logger=SimpleNamespace(log=lambda *_a, **_k: None)) == 2
    )
    assert any("failed to process gitlab output" in msg for msg in fake_console.errors)


def test_audit_gitlab_targets_emits_stage_debug_markers(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, tuple[str, ...], bool]] = []

    def fake_audit(
        host: str,
        port: int,
        timeout: float,
        retries: int,
        *,
        use_https: bool,
        token: str | None,
        project_filters: list[str],
        clone: bool,
        clone_dir: str,
        workers: int,
    ) -> dict[str, object]:
        _ = (port, timeout, retries, use_https, token, clone_dir, workers)
        calls.append((host, tuple(project_filters), clone))
        return {
            "timestamp": "2026-03-27T00:00:00Z",
            "host": host,
            "port": 8080,
            "https": False,
            "is_gitlab": True,
            "status": "detected",
            "login_page": True,
            "version": "16.9.0",
            "open_endpoints": [],
            "public_projects": [],
            "public_projects_error": None,
            "project_filters": list(project_filters),
            "token_provided": False,
            "token_valid": None,
            "token_user": None,
            "token_projects": [],
            "token_projects_error": None,
            "token_access": [],
            "clone_requested": clone,
            "clone_scope": None,
            "clone_dir": clone_dir if clone else None,
            "clone_results": [],
            "elapsed_ms": 5,
            "error": None,
        }

    monkeypatch.setattr(gitlab, "_audit_gitlab_host", fake_audit)
    debug_lines: list[str] = []
    totals = run_module_targets_for_test(
        "gitlab",
        hosts=["127.0.0.1"],
        port=8080,
        timeout=1.0,
        retries=0,
        workers=1,
        use_https=False,
        token=None,
        project_filters=["group/app"],
        clone=True,
        clone_dir="/tmp/gitlab-clones",
        output_path=None,
        output_format="txt",
        emit_line=None,
        logger=None,
        append_output=False,
        suppress_timeout_status_lines=False,
        debug_emit=debug_lines.append,
        show_progress=False,
    )
    assert totals == (1, 1, 0)
    assert calls == [("127.0.0.1", (), False), ("127.0.0.1", ("group/app",), True)]
    assert any(line.startswith("pass=1 detect start total=1") for line in debug_lines)
    assert any("stage2_gate=run reason=status=detected" in line for line in debug_lines)
    assert any("pass=2 deep complete processed=1" in line for line in debug_lines)


def test_fix_e2e_gitlab_invalid_token_yields_invalid_credentials_status(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """E2E revealed that GitLab returned `status='detected'` even when the
    supplied token was rejected — operators had to parse `token_valid` to
    tell success from failure. Pin the new tri-state (valid/invalid/detected).
    """

    def _fake_http(host, port, method, path, timeout, *, use_https=False, headers=None, body=None):
        _ = (host, port, method, timeout, use_https, headers, body)
        if path == "/users/sign_in":
            return 200, b"<title>GitLab</title> users/sign_in", {}, None
        if path == "/api/v4/version":
            return 200, b'{"version":"16.7.0"}', {"content-type": "application/json"}, None
        if path == "/api/v4/user":
            return 401, b"", {}, None
        if path.startswith("/api/v4/projects"):
            return 401, b"", {}, None
        return 200, b"[]", {}, None

    monkeypatch.setattr("redposture_core.stage_gitlab._http_request", _fake_http)

    record = gitlab._audit_gitlab_host(
        host="127.0.0.1",
        port=8080,
        timeout=1.0,
        retries=0,
        use_https=False,
        token="glpat-bogus",
        project_filters=[],
        clone=False,
        clone_dir="/tmp/gitlab-noop",
        workers=1,
    )
    assert record["token_provided"] is True
    assert record["token_valid"] is False
    assert record["status"] == "invalid_credentials"
