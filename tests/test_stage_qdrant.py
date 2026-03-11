from __future__ import annotations

import pytest

from redposture_core import stage_qdrant as qdrant


def test_inline_and_json_compact_helpers() -> None:
    assert qdrant._normalize_inline_text("a\n  b\t c") == "a b c"
    assert qdrant._json_compact({"a": 1, "b": 2}) == '{"a":1,"b":2}'


def test_qdrant_headers_and_version_extraction() -> None:
    assert qdrant._qdrant_headers(None) is None
    assert qdrant._qdrant_headers(" key ") == {"api-key": "key"}

    assert qdrant._qdrant_extract_version({"version": "1.15.0"}) == "1.15.0"
    assert qdrant._qdrant_extract_version({"result": {"version": "1.14.0"}}) == "1.14.0"
    assert qdrant._qdrant_extract_version({}) is None


@pytest.mark.parametrize(
    ("raw", "parsed"),
    [
        ("1.15.2", (1, 15, 2)),
        ("v1.9.3", (1, 9, 3)),
        ("bad", None),
    ],
)
def test_parse_semver_triplet(raw: str, parsed: tuple[int, int, int] | None) -> None:
    assert qdrant._parse_semver_triplet(raw) == parsed


def test_semver_in_half_open_range() -> None:
    assert qdrant._semver_in_half_open_range((1, 10, 0), min_incl=(1, 9, 3), max_excl=(1, 15, 6)) is True
    assert qdrant._semver_in_half_open_range((1, 15, 6), min_incl=(1, 9, 3), max_excl=(1, 15, 6)) is False
    assert qdrant._semver_in_half_open_range(None, min_incl=(1, 9, 3), max_excl=(1, 15, 6)) is None


def test_qdrant_payload_helpers() -> None:
    assert qdrant._qdrant_is_root_payload({"title": "Qdrant - Vector DB"}) is True
    assert qdrant._qdrant_is_root_payload({"version": "1.0", "result": {}}) is True
    assert qdrant._qdrant_is_root_payload({"hello": "world"}) is False

    assert qdrant._qdrant_error_text({"status": {"error": " failed  reason "}}) == "failed reason"
    assert qdrant._qdrant_error_text("  timeout \n now ") == "timeout now"
    assert qdrant._qdrant_error_text(None, fallback_status=500) == "status=500"


def test_qdrant_collections_from_payload_deduplicates() -> None:
    payload = {"result": {"collections": [{"name": "a"}, {"name": "a"}, {"name": "b"}]}}
    assert qdrant._qdrant_collections_from_payload(payload) == ["a", "b"]


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("/a/b?x=1", ("/a/b", "x=1")),
        ("a/b", ("/a/b", "")),
        ("http://host/x?y=2", ("/x", "y=2")),
    ],
)
def test_normalize_ssrf_path(raw: str, expected: tuple[str, str]) -> None:
    assert qdrant._normalize_ssrf_path(raw) == expected


def test_normalize_ssrf_urls_builds_expected_urls() -> None:
    urls = qdrant._normalize_ssrf_urls("127.0.0.1", "6333,6334", "/metrics?x=1")
    assert urls == [
        "http://127.0.0.1:6333/metrics?x=1",
        "http://127.0.0.1:6334/metrics?x=1",
    ]


def test_normalize_ssrf_urls_returns_empty_on_invalid_path() -> None:
    assert qdrant._normalize_ssrf_urls("127.0.0.1", "6333", "http://[::1") == []


def test_format_detect_and_summary_records() -> None:
    detect = qdrant._format_detect_record(
        {
            "timestamp": "2026-01-01T00:00:00Z",
            "host": "127.0.0.1",
            "port": 6333,
            "is_qdrant": True,
            "version": "1.15.0",
            "auth_required": False,
            "anonymous_access": True,
        },
        "txt",
    )
    assert "[*] Qdrant API" in detect
    assert "(auth required:False)" in detect

    open_line = qdrant._format_record(
        {
            "host": "127.0.0.1",
            "port": 6333,
            "status": "open_no_auth",
            "collections_count": 2,
            "edit_probe": {"source": "anonymous", "ok": True},
            "ghsa_f632_vm87_2m2f": {"assessment": "potentially_vulnerable"},
        },
        "txt",
    )
    assert "[+] anonymous access" in open_line
    assert "RCE!" in open_line

    auth_line = qdrant._format_record(
        {
            "host": "127.0.0.1",
            "port": 6333,
            "status": "auth_required",
            "collections_list_error": "forbidden",
        },
        "txt",
    )
    assert "[-] authentication required for collections" in auth_line
    assert "err=forbidden" in auth_line

    fail_line = qdrant._format_record(
        {"host": "127.0.0.1", "port": 6333, "status": "fail", "error": "connection timeout"},
        "txt",
    )
    assert "[!] connection failed" in fail_line
