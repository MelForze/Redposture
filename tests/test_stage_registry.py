from __future__ import annotations

from redposture_core import stage_registry as registry


def test_human_bytes_and_path_helpers() -> None:
    assert registry._human_bytes(None) == "-"
    assert registry._human_bytes(10) == "10B"
    assert registry._human_bytes(1024) == "1.0KB"
    assert registry._normalize_path("v2") == "/v2"
    assert registry._normalize_path("") == "/"


def test_slug_quote_and_reference_helpers() -> None:
    assert registry._safe_slug("group/app name") == "group_app_name"
    assert registry._quote_repo("group/app") == "group/app"
    assert registry._quote_ref("sha256:abc") == "sha256:abc"


def test_parse_link_next_extracts_relative_next_path() -> None:
    header = '<https://registry.local/v2/_catalog?n=1000&last=a>; rel="next"'
    assert registry._parse_link_next(header) == "/v2/_catalog?n=1000&last=a"
    assert registry._parse_link_next(None) is None


def test_image_reference_helpers() -> None:
    assert registry._split_image_reference("repo/app:1.0") == ("repo/app", "1.0")
    assert registry._split_image_reference("repo/app@sha256:abc") == ("repo/app", "sha256:abc")
    assert registry._split_image_reference("repo/app") == ("repo/app", "latest")

    assert registry._display_image("repo/app", "latest") == "repo/app:latest"
    assert registry._display_image("repo/app", "sha256:abc") == "repo/app@sha256:abc"


def test_pick_latest_tag_prefers_latest() -> None:
    assert registry._pick_latest_tag(["1.0", "latest", "2.0"]) == "latest"
    assert registry._pick_latest_tag(["1.0", "2.0"]) == "2.0"
    assert registry._pick_latest_tag([]) is None


def test_parse_www_authenticate() -> None:
    scheme, params = registry._parse_www_authenticate(
        'Bearer realm="https://auth.local/token",service="registry",scope="registry:catalog:*"'
    )
    assert scheme == "bearer"
    assert params["realm"] == "https://auth.local/token"
    assert params["service"] == "registry"


def test_format_detect_record_service_labels() -> None:
    base = {
        "timestamp": "2026-01-01T00:00:00Z",
        "host": "127.0.0.1",
        "port": 5000,
        "is_registry": True,
        "auth_required": False,
    }
    plain = registry._format_detect_record(base, "txt")
    assert "[*] Docker Registry Service" in plain

    gitlab = registry._format_detect_record({**base, "is_gitlab": True}, "txt")
    assert "GitLab Container Registry" in gitlab


def test_format_record_statuses() -> None:
    base = {"host": "127.0.0.1", "port": 5000, "image_count": 2}

    open_line = registry._format_record({**base, "status": "open_no_auth"}, "txt")
    assert "[+] anonymous access (images:2)" in open_line

    valid_token_line = registry._format_record({**base, "status": "valid_credentials", "token_provided": True}, "txt")
    assert "[+] token auth" in valid_token_line

    valid_creds_line = registry._format_record(
        {
            **base,
            "status": "valid_credentials",
            "token_provided": False,
            "provided_username": "admin",
            "provided_password": "admin",
        },
        "txt",
    )
    assert "[+] admin:admin" in valid_creds_line

    auth_required_line = registry._format_record(
        {
            **base,
            "status": "auth_required",
            "token_provided": False,
            "provided_credentials": True,
            "provided_username": "admin",
            "provided_password": "bad",
        },
        "txt",
    )
    assert "[-] admin:bad" in auth_required_line

    not_registry_line = registry._format_record(
        {"host": "127.0.0.1", "port": 5000, "status": "not_registry", "probe_status": 404},
        "txt",
    )
    assert "[-] not a Docker Registry v2 endpoint (status:404)" in not_registry_line

    unknown_line = registry._format_record(
        {"host": "127.0.0.1", "port": 5000, "status": "unknown_auth", "error": "weird"},
        "txt",
    )
    assert "[!] auth status unknown" in unknown_line

    fail_line = registry._format_record(
        {"host": "127.0.0.1", "port": 5000, "status": "fail", "error": "connection timeout"},
        "txt",
    )
    assert "[!] connection failed" in fail_line
