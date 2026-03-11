from __future__ import annotations

from redposture_core import stage_gitlab as gitlab


def test_normalize_path_and_base_url_helpers() -> None:
    assert gitlab._normalize_path("") == "/"
    assert gitlab._normalize_path("api/v4/version") == "/api/v4/version"
    assert gitlab._normalize_path("http://example.com/x") == "http://example.com/x"
    assert gitlab._build_base_url("127.0.0.1", 8080, use_https=False) == "http://127.0.0.1:8080"
    assert gitlab._build_base_url("127.0.0.1", 443, use_https=True) == "https://127.0.0.1:443"


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
