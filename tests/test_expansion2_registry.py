"""Registry inventory and identity continuation contracts with in-process doubles."""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import Mock

import pytest

from redposture_core.console import Console
from redposture_core.modules.registry import actions as registry


def _options(**changes: Any) -> dict[str, Any]:
    options: dict[str, Any] = dict(
        username=None,
        password=None,
        token=None,
        docker=True,
        show_images=False,
        show_tags=False,
        repository=None,
        tag=None,
        metadata=False,
        harbor=False,
        gitlab=False,
        nexus=False,
        assets=False,
        inspect=False,
        image=None,
        download=False,
        download_dir="unused",
        console=Console(),
        debug=False,
    )
    options.update(changes)
    return options


@pytest.fixture
def open_registry(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        registry,
        "_http_request",
        Mock(return_value=(200, b"{}", {"docker-distribution-api-version": "registry/2.0"}, None)),
    )
    for vendor in ("gitlab", "harbor", "nexus"):
        monkeypatch.setattr(registry, f"_fetch_{vendor}_info", Mock(return_value=(None, f"not {vendor}")))


@pytest.mark.parametrize("partial", [False, True])
@pytest.mark.parametrize(
    ("response", "expected"),
    [
        ((0, b"", {}, "timeout"), "timeout"),
        ((401, b"", {}, None), "authentication required"),
        ((403, b"", {}, None), "authentication required"),
        ((404, b"", {}, None), "nexus components API unavailable"),
        ((503, b"", {}, None), "returned status 503"),
        ((200, b"broken", {}, None), "returned invalid JSON"),
        ((200, b"[]", {}, None), "payload is invalid"),
        ((200, b'{"items":{}}', {}, None), "returned invalid items list"),
        ((200, b'{"items":[null]}', {}, None), "returned invalid items list"),
    ],
)
def test_component_pagination_retains_only_valid_completed_pages(
    monkeypatch: pytest.MonkeyPatch, partial: bool, response: Any, expected: str
) -> None:
    completed = {"name": "library/demo", "version": "1"}
    replies = (
        [(200, json.dumps({"items": [completed], "continuationToken": "a +/?"}).encode(), {}, None)] if partial else []
    ) + [response]
    request = Mock(side_effect=replies)
    monkeypatch.setattr(registry, "_http_request", request)
    rows, error = registry._fetch_nexus_components("nexus", 8081, "docker hosted", 1, headers={})
    assert rows == ([completed] if partial else None)
    assert error and expected in error
    assert error.startswith("partial: ") is partial
    assert "repository=docker+hosted" in request.call_args.args[3]
    if partial:
        assert "continuationToken=a+%2B%2F%3F" in request.call_args.args[3]


@pytest.mark.parametrize("record_mode", [False, True])
@pytest.mark.parametrize(
    ("response", "message"),
    [
        ((0, b"", {}, "offline"), "offline"),
        ((401, b"", {}, None), "authentication required"),
        ((403, b"", {}, None), "authentication required"),
        ((404, b"", {}, None), "not nexus"),
        ((500, b"", {}, None), "/service/rest/v1/repositories returned status 500"),
        ((200, b"invalid", {}, None), "nexus repositories payload is invalid JSON"),
        ((200, b"{}", {}, None), "nexus repositories payload is invalid"),
    ],
)
def test_repository_inventory_denial_is_distinct_from_empty(
    monkeypatch: pytest.MonkeyPatch, record_mode: bool, response: Any, message: str
) -> None:
    monkeypatch.setattr(registry, "_http_request", Mock(return_value=response))
    fetch = registry._fetch_nexus_repository_records if record_mode else registry._fetch_nexus_repositories
    assert fetch("nexus", 8081, 1, headers={}) == (None, message)


def test_repository_inventory_ignores_invalid_siblings_and_sorts(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = [
        None,
        {},
        {"name": "z"},
        {"name": " a ", "format": " docker ", "type": "hosted", "url": "http://n/repository/a", "online": False},
        {"name": "b", "online": "true"},
    ]
    monkeypatch.setattr(registry, "_http_request", Mock(return_value=(200, json.dumps(payload).encode(), {}, None)))
    records, error = registry._fetch_nexus_repository_records("n", 8081, 1, headers={})
    assert error is None and records is not None
    assert [row["name"] for row in records] == ["a", "b", "z"]
    assert records[0]["online"] is False and records[1]["online"] is None
    lines, error = registry._fetch_nexus_repositories("n", 8081, 1, headers={})
    assert error is None
    assert lines == ["a (format=docker, type=hosted, url=http://n/repository/a)", "b", "z"]


@pytest.mark.parametrize(
    ("response", "status", "error"),
    [
        ((0, b"", {}, "offline"), "failed", "offline"),
        ((401, b"", {}, None), "authentication required", None),
        ((403, b"", {}, None), "authentication required", None),
        ((503, b"", {}, None), "failed", "realm returned status 503"),
        ((200, b"broken", {}, None), "failed", "realm returned invalid JSON"),
        ((200, b"[]", {}, None), "failed", "realm JSON payload is invalid"),
        ((200, b'{"access_token":"token","expires_in":30,"issued_at":"now","scope":"read"}', {}, None), "ok", None),
    ],
)
def test_gitlab_identity_probe_retains_challenge_on_realm_failure(
    monkeypatch: pytest.MonkeyPatch, response: Any, status: str, error: str | None
) -> None:
    request = Mock(return_value=response)
    monkeypatch.setattr(registry, "_http_request_url", request)
    info, probe_error = registry._fetch_gitlab_info(
        "registry",
        5000,
        'Bearer realm="https://gitlab/jwt/auth?service=existing",service="container_registry"',
        1,
        headers={"Authorization": "Basic xx"},
        deep=True,
    )
    assert probe_error is None and info is not None
    assert info["token_probe_status"] == status and info.get("token_probe_error") == error
    assert "service=existing" in request.call_args.args[0]
    assert "scope=registry%3Acatalog%3A%2A" in request.call_args.args[0]
    if status == "ok":
        assert info["token_received"] is True
        assert info["token_expires_in"] == 30 and info["token_scope"] == "read"


@pytest.mark.parametrize(
    "response",
    [
        (0, b"", {}, "offline"),
        (403, b"", {}, None),
        (200, b"bad", {}, None),
        (200, b"[]", {}, None),
        (200, b"{}", {}, None),
    ],
)
def test_gitlab_fallback_does_not_claim_vendor_without_token(monkeypatch: pytest.MonkeyPatch, response: Any) -> None:
    monkeypatch.setattr(registry, "_http_request", Mock(return_value=response))
    info, error = registry._fetch_gitlab_info("r", 5000, "", 1, headers={}, deep=True)
    assert info is None and error == ("offline" if response[3] else "not gitlab")


@pytest.mark.parametrize("show_tags", [False, True])
def test_catalog_continues_after_per_repository_denial(
    open_registry: None, monkeypatch: pytest.MonkeyPatch, show_tags: bool
) -> None:
    monkeypatch.setattr(registry, "_fetch_registry_catalog", Mock(return_value=(["c", "a", "b"], None)))
    monkeypatch.setattr(
        registry,
        "_fetch_repository_tags",
        Mock(side_effect=[(None, "Forbidden"), (["1", "1"], "partial: timeout"), ([], None)]),
    )
    record = registry._audit_registry_host_core("r", 5000, 1, 0, **_options(show_images=True, show_tags=show_tags))
    assert record["images"] == ["b:1", "c:<untagged>"]
    assert record["images_error"] == "a: Forbidden"
    if show_tags:
        assert record["repository_tags"] == {"b": ["1"], "c": []}
        assert record["repository_tag_errors"] == {"a": "Forbidden", "b": "partial: timeout"}


@pytest.mark.parametrize("tags", [(None, "Forbidden"), (["2", "1", "2"], "partial: timeout")])
def test_selected_tags_skip_catalog_and_preserve_partial_error(
    open_registry: None, monkeypatch: pytest.MonkeyPatch, tags: Any
) -> None:
    catalog = Mock(side_effect=AssertionError("selected repository must not enumerate catalog"))
    monkeypatch.setattr(registry, "_fetch_registry_catalog", catalog)
    monkeypatch.setattr(registry, "_fetch_repository_tags", Mock(return_value=tags))
    result = registry._audit_registry_host_core("r", 5000, 1, 0, **_options(show_tags=True, repository="private/app"))
    assert result["selected_repository_tags"] == (None if tags[0] is None else ["1", "2"])
    assert result["images_error"] == f"private/app: {tags[1]}"


@pytest.mark.parametrize("action", ["metadata", "inspect", "download"])
def test_denied_registry_records_requested_action_failure(
    open_registry: None, monkeypatch: pytest.MonkeyPatch, action: str
) -> None:
    monkeypatch.setattr(
        registry,
        "_http_request",
        Mock(
            return_value=(
                401,
                b'{"errors":[{"code":"UNAUTHORIZED"}]}',
                {"docker-distribution-api-version": "registry/2.0"},
                None,
            )
        ),
    )
    inspect = Mock(side_effect=AssertionError("denied registry cannot inspect"))
    monkeypatch.setattr(registry, "_inspect_image", inspect)
    result = registry._audit_registry_host_core(
        "r", 5000, 1, 0, **_options(**{action: True}, repository="app", tag="1", image="app:1")
    )
    assert result["status"] == "auth_required"
    if action == "metadata":
        assert result["metadata_result"]["error"] == "cannot fetch metadata without registry access"
    elif action == "inspect":
        assert result["inspection_error"] == "cannot inspect images without registry access"
    else:
        assert result["download_result"] == {"status": "fail", "error": "registry access denied"}


@pytest.mark.parametrize("inspection_error", [None, "manifest unavailable"])
def test_download_reuses_selected_inspection(
    open_registry: None, monkeypatch: pytest.MonkeyPatch, inspection_error: str | None
) -> None:
    inspect = Mock(return_value={"image": "app:1", "error": inspection_error})
    download = Mock(return_value={"status": "ok", "directory": "result"})
    monkeypatch.setattr(registry, "_inspect_image", inspect)
    monkeypatch.setattr(registry, "_download_image", download)
    result = registry._audit_registry_host_core("r", 5000, 1, 0, **_options(download=True, image="app:1"))
    inspect.assert_called_once()
    if inspection_error:
        download.assert_not_called()
        assert result["download_result"] == {"status": "fail", "error": inspection_error}
    else:
        download.assert_called_once()
        assert result["download_result"]["status"] == "ok"


@pytest.mark.parametrize(
    ("changes", "expected"),
    [
        ({"harbor": True, "is_harbor": None, "harbor_error": "timeout"}, "Harbor presence unknown: timeout"),
        ({"gitlab": True, "is_gitlab": None, "gitlab_error": "timeout"}, "GitLab presence unknown: timeout"),
        ({"nexus": True, "is_nexus": None, "nexus_error": "timeout"}, "Nexus presence unknown: timeout"),
        ({"gitlab": True, "is_gitlab": True, "gitlab_info": {}, "show_images": True}, "<no repositories>"),
        (
            {
                "gitlab": True,
                "is_gitlab": True,
                "gitlab_info": {},
                "show_images": True,
                "images_error": "partial timeout",
            },
            "GitLab repositories unavailable: partial timeout",
        ),
        (
            {
                "gitlab": True,
                "is_gitlab": True,
                "show_images": True,
                "gitlab_repositories": ["team/app"],
                "gitlab_info": {},
            },
            "team/app",
        ),
        ({"show_tags": True, "repository": "app", "selected_repository_tags": []}, "<no tags>"),
        ({"show_tags": True, "repository": "app", "images_error": "Forbidden"}, "app: Forbidden"),
        (
            {"show_tags": True, "repository_tags": {"a": []}, "repository_tag_errors": {"b": "Forbidden"}},
            "b: Forbidden",
        ),
        ({"show_tags": True, "images_error": "timeout"}, "Tags enumeration partial: timeout"),
        ({"show_tags": True}, "Tags Enumeration (repositories:0)"),
        ({"metadata": True, "repository": "app", "tag": "1"}, "Metadata unavailable for app:1"),
        (
            {"metadata": True, "repository": "app", "tag": "1", "metadata_result": {"error": "missing manifest"}},
            "Metadata app:1 err=missing manifest",
        ),
        ({"metadata": True, "repository": "app", "tag": "1", "metadata_result": {"cmd": []}}, "<empty>"),
        (
            {"nexus": True, "is_nexus": True, "show_repositories": True, "nexus_repositories": ["plain-repo"]},
            "plain-repo",
        ),
        ({"nexus": True, "is_nexus": True, "assets": True, "nexus_error": "partial components"}, "partial components"),
        ({"nexus": True, "is_nexus": True, "assets": True, "nexus_assets": []}, "<no assets>"),
        (
            {"nexus": True, "is_nexus": True, "assets": True, "nexus_assets": [{"checksums": {"blake2": "abc"}}]},
            "checksum=blake2:abc",
        ),
        (
            {"inspect": True, "inspections": [{"image": "app:1", "error": "manifest unavailable"}]},
            "Inspect app:1 err=manifest unavailable",
        ),
        ({"inspect": True, "inspections": [{"image": "app:1", "cmd": []}]}, "<empty>"),
        ({"download": True, "download_result": {"status": "skipped", "size": 10}}, "Download skipped"),
        ({"download": True, "download_result": {"status": "fail"}}, "Download failed err=download failed"),
    ],
)
def test_requested_detail_output_explains_missing_and_partial_results(changes: dict[str, Any], expected: str) -> None:
    record = {"is_registry": True, "host": "r", "port": 5000, "status": "open_no_auth", **changes}
    lines = registry._format_detail_records(record, "txt")
    assert any(expected in line for line in lines)
    assert all("\x1b" not in line for line in lines)
    json_lines = registry._format_detail_records(record, "json")
    assert all(isinstance(json.loads(line), dict) and "\x1b" not in line for line in json_lines)


@pytest.mark.parametrize(
    "line",
    ["", "REGISTRY no tabs", "REGISTRY\tr\t5000\t", "REGISTRY\tr\t5000\t[!] failure", "REGISTRY\tr\t5000\t<no images>"],
)
def test_image_reference_classifier_rejects_non_image_output(line: str) -> None:
    assert registry._looks_like_registry_image_ref(line) is False


@pytest.mark.parametrize("payload", ["team/app:<untagged>", "team/app@sha256:abc", "team/app:1"])
def test_image_reference_classifier_accepts_rendered_references(payload: str) -> None:
    assert registry._looks_like_registry_image_ref(f"REGISTRY\tr\t5000\t{payload}") is True


@pytest.mark.parametrize(
    "payload",
    [
        "downloadUrl=http://n/a",
        "checksum=sha256:a",
        "RUN echo ok",
        "/app/run --safe",
        "KEY=value",
        "team/app (tags:1) (latest:1)",
        "repo (type:hosted) (online:True)",
        "team/app",
        "1.0.0",
    ],
)
def test_data_classifier_recognizes_discovered_values(payload: str) -> None:
    assert registry._looks_like_registry_data_row(f"REGISTRY\tr\t5000\t{payload}") is True


@pytest.mark.parametrize(
    "line",
    [
        "",
        "no tabs",
        "REGISTRY\tr\t5000\t",
        "REGISTRY\tr\t5000\t<no data>",
        "REGISTRY\tr\t5000\t[*] section",
        "REGISTRY\tr\t5000\tordinary words",
    ],
)
def test_data_classifier_rejects_empty_sections_and_prose(line: str) -> None:
    assert registry._looks_like_registry_data_row(line) is False


@pytest.mark.parametrize("deep", [False, True])
def test_gitlab_jwt_fallback_retains_expiry_without_exposing_token(monkeypatch: pytest.MonkeyPatch, deep: bool) -> None:
    monkeypatch.setattr(
        registry,
        "_http_request",
        Mock(
            return_value=(200, b'{"access_token":"secret","expires_in":60,"issued_at":"now","scope":"read"}', {}, None)
        ),
    )
    info, error = registry._fetch_gitlab_info("r", 5000, "", 1, headers={}, deep=deep)
    assert error is None and info is not None
    assert info["detected_by"] == "jwt_auth_probe"
    assert "secret" not in json.dumps(info)
    if deep:
        assert info["token_received"] is True and info["token_expires_in"] == 60
        assert info["token_issued_at"] == "now" and info["token_scope"] == "read"
    else:
        assert "token_received" not in info


@pytest.mark.parametrize(
    "body",
    [
        b"<other/>",
        b"<status/>",
        b'{"data":[]}',
        b'{"data":{"appName":"Sonatype Nexus","version":"3.1.0"}}',
        b'{"data":{"appName":"Other","version":"2.15.0"}}',
        b"<status><data><appName>Sonatype Nexus</appName><version>nonsense</version></data></status>",
    ],
)
def test_nexus_legacy_fingerprint_requires_product_and_major_release(body: bytes) -> None:
    assert registry._nexus_2_status_info(body) is None


@pytest.mark.parametrize(
    "response", [(0, b"", {}, "offline"), (503, b"", {}, None), (200, b"broken", {}, None), (200, b"[]", {}, None)]
)
def test_optional_gitlab_version_enrichment_keeps_confirmed_identity_on_api_failure(
    monkeypatch: pytest.MonkeyPatch, response: Any
) -> None:
    request = Mock(return_value=response)
    monkeypatch.setattr(registry, "_http_request_url", request)
    info = {"realm": "https://gitlab/prefix/jwt/auth", "service": "container_registry"}
    registry._enrich_registry_gitlab_version(info, 1, "private")
    assert info == {"realm": "https://gitlab/prefix/jwt/auth", "service": "container_registry"}
    assert request.call_args.args[0] == "https://gitlab/prefix/api/v4/version"
    assert request.call_args.kwargs["headers"] == {"PRIVATE-TOKEN": "private"}
