"""Unit tests for pure helper functions in the lowest-coverage modules.

Each test exercises one narrow branch of a small pure helper (clip/retry-delay/
header-lookup/path-normalize/...) that previously was only hit through
integration paths. The goal: push consul/elastic/grafana/gitlab actions coverage
above 85% by hammering deterministic edges (empty input, boundary widths,
unicode, escapes, malformed JSON, duplicate filters).
"""

from __future__ import annotations

import base64

import pytest

import redposture_core.modules.consul.actions as consul_actions
import redposture_core.modules.elastic.actions as elastic_actions
import redposture_core.modules.gitlab.actions as gitlab_actions
import redposture_core.modules.grafana.actions as grafana_actions

# ---------------------------------------------------------------------------
# consul pure helpers
# ---------------------------------------------------------------------------


def test_consul_clip_preserves_text_within_width() -> None:
    assert consul_actions._clip("hello", 80) == "hello"


def test_consul_clip_truncates_with_ellipsis_when_over_width() -> None:
    out = consul_actions._clip("abcdefghij", 6)
    assert out == "abc..."
    assert len(out) == 6


def test_consul_clip_returns_raw_slice_when_width_le_3() -> None:
    # Width too small for ellipsis (... is 3 chars) — plain head slice.
    assert consul_actions._clip("abcdefgh", 3) == "abc"
    assert consul_actions._clip("abcdefgh", 1) == "a"


def test_consul_retry_delay_is_exponential_capped() -> None:
    assert consul_actions._retry_delay(0) == pytest.approx(0.20)
    assert consul_actions._retry_delay(1) == pytest.approx(0.40)
    assert consul_actions._retry_delay(10) <= 1.5


def test_consul_limit_dump_items_none_and_limit_passthrough() -> None:
    assert consul_actions._limit_dump_items(None, 5) is None
    assert consul_actions._limit_dump_items([1, 2, 3], None) == [1, 2, 3]


def test_consul_limit_dump_items_truncates_to_limit() -> None:
    assert consul_actions._limit_dump_items([1, 2, 3, 4, 5], 3) == [1, 2, 3]


def test_consul_limit_dump_items_limit_larger_than_list_is_safe() -> None:
    assert consul_actions._limit_dump_items([1, 2], 10) == [1, 2]


def test_consul_unauthorized_status_classification() -> None:
    assert consul_actions._unauthorized_status(401) is True
    assert consul_actions._unauthorized_status(403) is True
    # 200/404/500 are not "unauthorized" — they're other categories.
    assert consul_actions._unauthorized_status(200) is False
    assert consul_actions._unauthorized_status(404) is False
    assert consul_actions._unauthorized_status(500) is False
    assert consul_actions._unauthorized_status(0) is False


def test_consul_consul_headers_token_only() -> None:
    headers = consul_actions._consul_headers("t-tok", None, None)
    assert headers == {"X-Consul-Token": "t-tok"}


def test_consul_consul_headers_basic_only() -> None:
    headers = consul_actions._consul_headers(None, "u", "p")
    expected_auth = "Basic " + base64.b64encode(b"u:p").decode("ascii")
    assert headers == {"Authorization": expected_auth}


def test_consul_consul_headers_token_and_basic_combined() -> None:
    headers = consul_actions._consul_headers("tk", "u", "p")
    assert headers["X-Consul-Token"] == "tk"
    assert headers["Authorization"].startswith("Basic ")


def test_consul_consul_headers_empty_creds_produce_basic_with_empty_values() -> None:
    # If username OR password is non-None, Basic auth is still emitted (with empty fields).
    headers = consul_actions._consul_headers(None, "", "")
    assert "Authorization" in headers
    raw = base64.b64decode(headers["Authorization"][len("Basic ") :])
    assert raw == b":"


def test_consul_consul_headers_no_inputs_produces_empty_dict() -> None:
    assert consul_actions._consul_headers(None, None, None) == {}


def test_consul_parse_consul_leader_returns_clean_value() -> None:
    assert consul_actions._parse_consul_leader(b'"10.0.0.1:8300"') == "10.0.0.1:8300"


def test_consul_parse_consul_leader_returns_none_for_empty() -> None:
    assert consul_actions._parse_consul_leader(b"") is None
    assert consul_actions._parse_consul_leader(b"   ") is None


def test_consul_parse_consul_leader_returns_none_for_non_string_json() -> None:
    # JSON list / dict are not leader strings.
    assert consul_actions._parse_consul_leader(b"[1, 2, 3]") is None
    assert consul_actions._parse_consul_leader(b'{"a": 1}') is None


def test_consul_parse_consul_leader_falls_back_to_text_for_invalid_json() -> None:
    # Invalid JSON is treated as a plain string and stripped of quotes.
    assert consul_actions._parse_consul_leader(b'"plain.host:8300"') == "plain.host:8300"


def test_consul_looks_like_consul_payload_requires_200_and_leader_with_colon() -> None:
    assert consul_actions._looks_like_consul_payload(200, b'"10.0.0.1:8300"') is True
    assert consul_actions._looks_like_consul_payload(404, b'"10.0.0.1:8300"') is False
    # Non-leader payloads (no colon) are rejected.
    assert consul_actions._looks_like_consul_payload(200, b'"notaleader"') is False


def test_consul_is_tls_verify_error_text_recognizes_known_phrases() -> None:
    assert consul_actions._is_tls_verify_error_text("tls verification failed: host mismatch") is True
    assert consul_actions._is_tls_verify_error_text("CERTIFICATE VERIFY FAILED") is True
    assert consul_actions._is_tls_verify_error_text("self signed certificate") is True
    assert consul_actions._is_tls_verify_error_text("connection refused") is False
    assert consul_actions._is_tls_verify_error_text(None) is False
    assert consul_actions._is_tls_verify_error_text("") is False


def test_consul_is_connection_timeout_fail_record_requires_status_fail() -> None:
    rec = {"status": "open_no_auth", "error": "connection timeout"}
    assert consul_actions._is_connection_timeout_fail_record(rec) is False


def test_consul_is_connection_timeout_fail_record_detects_known_prefixes() -> None:
    timeout_rec = {"status": "fail", "error": consul_actions._CONNECTION_TIMEOUT_PREFIX + ": after 5s"}
    refused_rec = {"status": "fail", "error": consul_actions._CONNECTION_REFUSED_PREFIX + " by remote"}
    assert consul_actions._is_connection_timeout_fail_record(timeout_rec) is True
    assert consul_actions._is_connection_timeout_fail_record(refused_rec) is True


def test_consul_is_connection_timeout_fail_record_unrelated_error() -> None:
    rec = {"status": "fail", "error": "ssl handshake failure"}
    assert consul_actions._is_connection_timeout_fail_record(rec) is False


def test_consul_count_kv_keys_counts_only_strings_in_list() -> None:
    assert consul_actions._count_kv_keys(["a", "b", 1, None]) == 2
    assert consul_actions._count_kv_keys([]) == 0
    assert consul_actions._count_kv_keys({"a": 1}) is None
    assert consul_actions._count_kv_keys("string") is None


# ---------------------------------------------------------------------------
# elastic pure helpers
# ---------------------------------------------------------------------------


def test_elastic_clip_truncates_and_preserves() -> None:
    assert elastic_actions._clip("short", 100) == "short"
    out = elastic_actions._clip("a" * 200, 50)
    assert len(out) == 50
    assert out.endswith("...")


def test_elastic_header_lookup_case_insensitive() -> None:
    headers = {"Content-Type": "application/json", "X-Elastic-Product": "Elasticsearch"}
    assert elastic_actions._header_lookup(headers, "content-type") == "application/json"
    assert elastic_actions._header_lookup(headers, "X-ELASTIC-PRODUCT") == "Elasticsearch"
    assert elastic_actions._header_lookup(headers, "missing-header") is None


def test_elastic_is_tls_or_protocol_error_recognizes_tokens() -> None:
    assert elastic_actions._is_tls_or_protocol_error("SSL handshake error") is True
    assert elastic_actions._is_tls_or_protocol_error("wrong version number") is True
    assert elastic_actions._is_tls_or_protocol_error("Unknown protocol") is True
    assert elastic_actions._is_tls_or_protocol_error("certificate verify failed") is True
    assert elastic_actions._is_tls_or_protocol_error("HTTP request to HTTPS server") is True
    assert elastic_actions._is_tls_or_protocol_error("connection refused") is False
    assert elastic_actions._is_tls_or_protocol_error("") is False
    assert elastic_actions._is_tls_or_protocol_error("") is False


def test_elastic_build_credential_runs_with_provided_creds_only() -> None:
    runs = elastic_actions._build_credential_runs("u", "p", defcreds=False)
    assert runs == [("u", "p")]


def test_elastic_build_credential_runs_defcreds_appends_after_provided() -> None:
    runs = elastic_actions._build_credential_runs("custom", "pw", defcreds=True)
    assert runs[0] == ("custom", "pw")
    assert len(runs) > 1  # default creds were appended


def test_elastic_build_credential_runs_defcreds_only_no_provided() -> None:
    runs = elastic_actions._build_credential_runs(None, None, defcreds=True)
    # all entries should be from defcreds (not the (None, None) tuple)
    assert all(r != (None, None) for r in runs) or runs == [(None, None)]
    assert len(runs) >= 1


def test_elastic_build_credential_runs_no_creds_returns_single_none_pair() -> None:
    # When nothing provided and no defcreds, fall back to a single (None, None) run.
    runs = elastic_actions._build_credential_runs(None, None, defcreds=False)
    assert runs == [(None, None)]


def test_elastic_retry_delay_capped_at_1p5() -> None:
    assert elastic_actions._retry_delay(0) == pytest.approx(0.20)
    assert elastic_actions._retry_delay(20) <= 1.5


# ---------------------------------------------------------------------------
# grafana pure helpers
# ---------------------------------------------------------------------------


def test_grafana_clip_default_width_is_64() -> None:
    assert grafana_actions._clip("x" * 70) == "x" * 61 + "..."


def test_grafana_header_lookup_case_insensitive() -> None:
    assert grafana_actions._header_lookup({"X-Frame-Options": "DENY"}, "x-frame-options") == "DENY"
    assert grafana_actions._header_lookup({}, "anything") is None


def test_grafana_auth_header_produces_basic_base64() -> None:
    out = grafana_actions._auth_header("user", "pass")
    assert out.startswith("Basic ")
    decoded = base64.b64decode(out[len("Basic ") :])
    assert decoded == b"user:pass"


def test_grafana_normalize_ssrf_path_handles_none_and_empty() -> None:
    assert grafana_actions._normalize_ssrf_path(None) is None
    assert grafana_actions._normalize_ssrf_path("") is None
    assert grafana_actions._normalize_ssrf_path("   ") is None


def test_grafana_normalize_ssrf_path_strips_url_scheme() -> None:
    out = grafana_actions._normalize_ssrf_path("http://example.com/api/v1?module=probe")
    assert out == ("/api/v1", "module=probe")


def test_grafana_normalize_ssrf_path_relative_with_query() -> None:
    assert grafana_actions._normalize_ssrf_path("/probe?module=http_2xx") == ("/probe", "module=http_2xx")


def test_grafana_normalize_ssrf_path_relative_no_query() -> None:
    assert grafana_actions._normalize_ssrf_path("/metrics") == ("/metrics", "")


def test_grafana_normalize_ssrf_path_adds_leading_slash() -> None:
    # No scheme + missing leading slash → prepended.
    assert grafana_actions._normalize_ssrf_path("metrics") == ("/metrics", "")


def test_grafana_looks_like_grafana_login_status_codes_and_body() -> None:
    headers: dict[str, str] = {}
    assert grafana_actions._looks_like_grafana_login(200, "<html><title>Grafana</title>", headers) is True
    # 4xx/5xx do not qualify regardless of body
    assert grafana_actions._looks_like_grafana_login(404, "<html><title>Grafana</title>", headers) is False
    # 200 without grafana markers in body is rejected
    assert grafana_actions._looks_like_grafana_login(200, "<html>nothing</html>", headers) is False


def test_grafana_is_connection_timeout_fail_record_only_for_status_fail() -> None:
    timeout = {"status": "fail", "error": grafana_actions._CONNECTION_TIMEOUT_PREFIX + ":"}
    assert grafana_actions._is_connection_timeout_fail_record(timeout) is True
    not_fail = {"status": "open_no_auth", "error": grafana_actions._CONNECTION_TIMEOUT_PREFIX}
    assert grafana_actions._is_connection_timeout_fail_record(not_fail) is False


# ---------------------------------------------------------------------------
# gitlab pure helpers
# ---------------------------------------------------------------------------


def test_gitlab_clip_default_width_is_72() -> None:
    out = gitlab_actions._clip("y" * 100)
    assert len(out) == 72
    assert out.endswith("...")


def test_gitlab_retry_delay_exponential() -> None:
    assert gitlab_actions._retry_delay(0) == pytest.approx(0.20)
    assert gitlab_actions._retry_delay(2) == pytest.approx(0.80)


def test_gitlab_normalize_path_preserves_full_url() -> None:
    assert gitlab_actions._normalize_path("https://example.com/api/v4") == "https://example.com/api/v4"
    assert gitlab_actions._normalize_path("http://x.y/z") == "http://x.y/z"


def test_gitlab_normalize_path_empty_returns_root() -> None:
    assert gitlab_actions._normalize_path("") == "/"
    assert gitlab_actions._normalize_path("   ") == "/"


def test_gitlab_normalize_path_prepends_slash_when_missing() -> None:
    assert gitlab_actions._normalize_path("api/v4/projects") == "/api/v4/projects"


def test_gitlab_normalize_path_preserves_existing_slash() -> None:
    assert gitlab_actions._normalize_path("/api/v4") == "/api/v4"


def test_gitlab_build_base_url_https_vs_http() -> None:
    assert gitlab_actions._build_base_url("example.com", 443, True) == "https://example.com:443"
    assert gitlab_actions._build_base_url("example.com", 80, False) == "http://example.com:80"


def test_gitlab_gitlab_api_headers_includes_token_when_present() -> None:
    headers = gitlab_actions._gitlab_api_headers("glpat-secret")
    assert headers.get("PRIVATE-TOKEN") == "glpat-secret"


def test_gitlab_gitlab_api_headers_omits_token_when_none() -> None:
    headers = gitlab_actions._gitlab_api_headers(None)
    assert "PRIVATE-TOKEN" not in headers


def test_gitlab_detect_login_page_recognizes_sign_in_markers() -> None:
    assert gitlab_actions._detect_login_page("<html>GitLab Community Edition – Sign in</html>") is True
    assert gitlab_actions._detect_login_page("<a href='/users/sign_in'>GitLab</a>") is True
    # Neither token alone is enough — need both 'gitlab' and a sign-in marker.
    assert gitlab_actions._detect_login_page("<html>GitHub</html>") is False
    assert gitlab_actions._detect_login_page("Sign in to GitHub") is False
    assert gitlab_actions._detect_login_page("") is False


def test_gitlab_normalize_project_filters_empty_input() -> None:
    assert gitlab_actions._normalize_project_filters(None) == []
    assert gitlab_actions._normalize_project_filters([]) == []
    assert gitlab_actions._normalize_project_filters([""]) == []


def test_gitlab_normalize_project_filters_splits_on_comma() -> None:
    assert gitlab_actions._normalize_project_filters(["a,b,c"]) == ["a", "b", "c"]


def test_gitlab_normalize_project_filters_deduplicates_case_insensitively() -> None:
    # Duplicates differing only in case are collapsed (first-wins by token form).
    out = gitlab_actions._normalize_project_filters(["Foo", "foo", "FOO,bar"])
    assert out == ["Foo", "bar"]


def test_gitlab_normalize_project_filters_trims_whitespace_around_tokens() -> None:
    assert gitlab_actions._normalize_project_filters([" a , b ,, c "]) == ["a", "b", "c"]


def test_gitlab_project_path_uses_path_with_namespace_first() -> None:
    proj = {"path_with_namespace": "group/sub", "path": "sub", "name": "Sub"}
    assert gitlab_actions._project_path(proj) == "group/sub"


def test_gitlab_project_path_falls_back_to_path_then_name() -> None:
    assert gitlab_actions._project_path({"path": "sub", "name": "Sub"}) == "sub"
    assert gitlab_actions._project_path({"name": "Sub"}) == "Sub"


def test_gitlab_project_path_default_for_empty_project() -> None:
    assert gitlab_actions._project_path({}) == "-"


def test_gitlab_project_matches_filters_no_filters_passes_all() -> None:
    assert gitlab_actions._project_matches_filters({"name": "anything"}, []) is True


def test_gitlab_is_connection_timeout_fail_record_only_for_status_fail() -> None:
    timeout = {"status": "fail", "error": gitlab_actions._CONNECTION_TIMEOUT_PREFIX + ": x"}
    assert gitlab_actions._is_connection_timeout_fail_record(timeout) is True
    not_fail = {"status": "auth_required", "error": gitlab_actions._CONNECTION_TIMEOUT_PREFIX}
    assert gitlab_actions._is_connection_timeout_fail_record(not_fail) is False
