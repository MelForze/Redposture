"""Boundaries and access contracts for the selected 2026-10 catalog expansion."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from redposture_core.cve import enumerate_record, load_catalog, version_in_range
from redposture_core.modules.grafana import actions as grafana_actions
from redposture_core.modules.registry import actions as registry_actions

SELECTED = {
    "CVE-2025-14847": "mongodb",
    "CVE-2020-13933": "nexus_repository",
    "CVE-2025-9868": "nexus_repository",
    "CVE-2026-14504": "nexus_repository",
    "CVE-2025-3260": "grafana",
    "CVE-2025-31489": "minio",
    "CVE-2026-14668": "postgresql",
    "CVE-2025-41115": "grafana_enterprise",
    "CVE-2025-11539": "grafana_image_renderer",
    "CVE-2026-77124": "nexus_repository",
    "CVE-2026-10748": "nexus_repository",
}


@pytest.mark.parametrize(("cve_id", "product"), sorted(SELECTED.items()))
def test_selected_cve_is_shipped_once_for_the_correct_product(cve_id: str, product: str) -> None:
    matches = [entry for entry in load_catalog().entries if entry["id"] == cve_id]
    assert len(matches) == 1
    assert matches[0]["product"] == product


@pytest.mark.parametrize(
    ("version", "affected"),
    [
        ("11.6.0", True),
        ("11.6.1", True),
        ("11.6.1+security-01", False),
        ("11.6.2", False),
        ("11.5.9", False),
    ],
)
def test_grafana_security_build_is_not_reported_as_vulnerable(version: str, affected: bool) -> None:
    entry = next(entry for entry in load_catalog().entries if entry["id"] == "CVE-2025-3260")
    assert any(version_in_range(version, boundary) for boundary in entry["affected"]) is affected


@pytest.mark.parametrize(
    ("version", "affected"),
    [
        ("4.4.29", True),
        ("4.4.30", False),
        ("5.0.31", True),
        ("5.0.32", False),
        ("6.0.26", True),
        ("6.0.27", False),
        ("7.0.27", True),
        ("7.0.28", False),
        ("8.0.16", True),
        ("8.0.17", False),
        ("8.2.2", True),
        ("8.2.3", False),
    ],
)
def test_mongodb_branched_security_releases(version: str, affected: bool) -> None:
    entry = next(entry for entry in load_catalog().entries if entry["id"] == "CVE-2025-14847")
    assert any(version_in_range(version, boundary) for boundary in entry["affected"]) is affected


@pytest.mark.parametrize(
    ("version", "affected"),
    [
        ("2.14.18", True),
        ("2.14.19", False),
        ("2.15.2", False),
        ("3.26.1", True),
        ("3.27.0", False),
    ],
)
def test_nexus_shiro_cve_has_separate_major_branches(version: str, affected: bool) -> None:
    entry = next(entry for entry in load_catalog().entries if entry["id"] == "CVE-2020-13933")
    assert any(version_in_range(version, boundary) for boundary in entry["affected"]) is affected


def test_nexus_2_ssrf_never_matches_nexus_3() -> None:
    entry = next(entry for entry in load_catalog().entries if entry["id"] == "CVE-2025-9868")
    assert any(version_in_range("2.15.2", boundary) for boundary in entry["affected"])
    assert not any(version_in_range("3.0.0", boundary) for boundary in entry["affected"])


def test_renderer_cve_uses_plugin_version_and_not_server_version() -> None:
    catalog = load_catalog()
    server_only = enumerate_record(
        "grafana", {"server_version": "4.0.16", "auth_required": False}, catalog=catalog, confirmed=True
    )
    with_plugin = enumerate_record(
        "grafana",
        {"server_version": "12.0.0", "renderer_plugin_version": "4.0.16", "auth_required": False},
        catalog=catalog,
        confirmed=True,
    )
    assert "CVE-2025-11539" not in {item["id"] for item in server_only["findings"]}
    assert "CVE-2025-11539" in {item["id"] for item in with_plugin["findings"]}

    # The plugin's own token is not a Grafana user credential; its prerequisite
    # is stated in the finding title rather than inferred from Grafana auth.
    with_plugin_protected = enumerate_record(
        "grafana",
        {"server_version": "12.0.0", "renderer_plugin_version": "4.0.16", "auth_required": True},
        catalog=catalog,
        confirmed=True,
    )
    finding = next(item for item in with_plugin_protected["findings"] if item["id"] == "CVE-2025-11539")
    assert finding["access_basis"] == "renderer_token_required"


def test_nexus_high_privilege_cves_are_explicit_version_only_exceptions() -> None:
    result = enumerate_record(
        "nexus",
        {"is_nexus": True, "nexus_info": {"version": "3.91.0"}, "auth_required": False},
        catalog=load_catalog(),
        confirmed=True,
        credentials_provided=True,
    )
    ids = {item["id"] for item in result["findings"]}
    assert "CVE-2026-77124" in ids
    assert "CVE-2026-10748" in ids
    for item in result["findings"]:
        if item["id"] in {"CVE-2026-77124", "CVE-2026-10748"}:
            assert item["privileges_required"] == "H"
            assert item["access_basis"] == "privileged_account_required"


def test_enterprise_scim_cve_is_potential_for_unknown_grafana_edition_only() -> None:
    catalog = load_catalog()
    unknown = enumerate_record(
        "grafana", {"server_version": "12.2.0", "auth_required": True}, catalog=catalog, confirmed=True
    )
    oss = enumerate_record(
        "grafana",
        {"server_version": "12.2.0", "edition": "oss", "auth_required": True},
        catalog=catalog,
        confirmed=True,
    )
    assert "CVE-2025-41115" in {item["id"] for item in unknown["findings"]}
    assert "CVE-2025-41115" not in {item["id"] for item in oss["findings"]}


def test_nexus_2_status_endpoint_confirms_product_and_version(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []
    status = (
        b"<status><data><appName>Sonatype Nexus Professional</appName>"
        b"<version>2.15.2</version><state>STARTED</state></data></status>"
    )

    def request(_host: str, _port: int, _method: str, path: str, _timeout: float, **_kwargs: object):
        calls.append(path)
        if path == "/service/rest/v1/status":
            return 404, b"", {}, None
        return 200, status, {"Content-Type": "application/xml"}, None

    monkeypatch.setattr(registry_actions, "_http_request", request)
    info, error = registry_actions._fetch_nexus_info("127.0.0.1", 8081, 1.0, headers={})
    assert error is None
    assert info is not None and info["version"] == "2.15.2"
    assert info["major_version"] == 2
    assert calls == ["/service/rest/v1/status", "/service/local/status"]


def test_nexus_2_status_rejects_generic_xml(monkeypatch: pytest.MonkeyPatch) -> None:
    def request(_host: str, _port: int, _method: str, path: str, _timeout: float, **_kwargs: object):
        if path == "/service/rest/v1/status":
            return 404, b"", {}, None
        return 200, b"<status><data><version>2.15.2</version></data></status>", {}, None

    monkeypatch.setattr(registry_actions, "_http_request", request)
    info, _error = registry_actions._fetch_nexus_info("127.0.0.1", 8081, 1.0, headers={})
    assert info is None


def test_renderer_probe_requires_exact_plugin_id_and_version(monkeypatch: pytest.MonkeyPatch) -> None:
    def request(_host: str, _port: int, _path: str, _timeout: float, **_kwargs: object):
        return (
            200,
            '[{"id":"other-plugin","info":{"version":"1.0.0"}},'
            '{"id":"grafana-image-renderer","info":{"version":"4.0.16"}}]',
            {"Content-Type": "application/json"},
        )

    monkeypatch.setattr(grafana_actions, "_http_request", request)
    assert grafana_actions._fetch_renderer_plugin_version("127.0.0.1", 3000, 1.0, None) == "4.0.16"


@pytest.mark.parametrize(
    "body",
    [
        "{}",
        '[{"id":"other-plugin","info":{"version":"4.0.16"}}]',
        '[{"id":"grafana-image-renderer","info":{"version":"unknown"}}]',
        '[{"id":"grafana-image-renderer","info":{"version":4}}]',
        '[{"id":"grafana-image-renderer"}]',
        "<html>login</html>",
    ],
)
def test_renderer_probe_ignores_unconfirmed_versions(monkeypatch: pytest.MonkeyPatch, body: str) -> None:
    monkeypatch.setattr(grafana_actions, "_http_request", lambda *_args, **_kwargs: (200, body, {}))
    assert grafana_actions._fetch_renderer_plugin_version("127.0.0.1", 3000, 1.0, None) is None


def test_renderer_probe_is_retried_with_verified_grafana_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(grafana_actions, "_verify_credentials", lambda *_args: (True, None))
    monkeypatch.setattr(grafana_actions, "_activate_grafana_transport", lambda _state: None)
    observed: list[str | None] = []

    def probe(_host: str, _port: int, _timeout: float, authorization: str | None) -> str | None:
        observed.append(authorization)
        return "4.0.16"

    monkeypatch.setattr(grafana_actions, "_fetch_renderer_plugin_version", probe)
    ctx = SimpleNamespace(
        host="127.0.0.1",
        port=3000,
        args=SimpleNamespace(timeout=1.0, enum_cve=True, defcreds=False),
        lifecycle_state=grafana_actions.GrafanaLifecycleState(),
        credential=SimpleNamespace(token=None, username="viewer", password="secret", source="provided"),
    )
    record = grafana_actions.authenticate_grafana(ctx, {"auth_required": True}, {})
    assert record["renderer_plugin_version"] == "4.0.16"
    assert observed == [grafana_actions._auth_header("viewer", "secret")]


@pytest.mark.parametrize(
    ("cve_id", "vulnerable", "fixed"),
    [
        ("CVE-2026-14504", "3.93.0", "3.94.0"),
        ("CVE-2026-77124", "3.95.0", "3.96.0"),
        ("CVE-2026-10748", "3.91.0", "3.92.0"),
        ("CVE-2025-41115", "12.2.0", "12.2.1"),
        ("CVE-2025-11539", "4.0.16", "4.0.17"),
        ("CVE-2026-14668", "14.23", "14.24"),
        (
            "CVE-2025-31489",
            "RELEASE.2025-04-02T00-00-00Z",
            "RELEASE.2025-04-03T14-56-28Z",
        ),
    ],
)
def test_remaining_selected_cves_have_fixed_version_boundary(cve_id: str, vulnerable: str, fixed: str) -> None:
    entry = next(entry for entry in load_catalog().entries if entry["id"] == cve_id)
    assert any(version_in_range(vulnerable, boundary) for boundary in entry["affected"])
    assert not any(version_in_range(fixed, boundary) for boundary in entry["affected"])
