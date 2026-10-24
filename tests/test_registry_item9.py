"""Explicit registry inventory and compatible display flag names."""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any

import pytest

from redposture_core.audit_models import AuditRecord
from redposture_core.cli_args import parse_args
from redposture_core.modules.gitlab import actions as gitlab_actions
from redposture_core.modules.gitlab import render as gitlab_render
from redposture_core.modules.gitlab import stage as gitlab_stage
from redposture_core.modules.registry import actions, policy, product_render, stage
from redposture_core.stage_runtime import AuditCredentialRun, render_record_with_module


@pytest.mark.parametrize("product", ["docker-registry", "harbor", "nexus", "gitlab"])
@pytest.mark.parametrize("flag", ["--images", "--show-images"])
def test_image_display_aliases(product: str, flag: str) -> None:
    assert parse_args([product, "-t", "host", flag]).images is True


def test_nexus_storage_repository_flag_is_separate_from_images() -> None:
    storage = parse_args(["nexus", "-t", "host", "--show-repositories"])
    images = parse_args(["nexus", "-t", "host", "--show-images"])
    assert storage.show_repositories is True and storage.images is False
    assert images.images is True and images.show_repositories is False


@pytest.mark.parametrize("product", ["docker-registry", "harbor", "gitlab"])
def test_nexus_storage_repository_flag_not_offered_on_other_products(product: str) -> None:
    with pytest.raises(SystemExit):
        parse_args([product, "-t", "host", "--show-repositories"])


@pytest.mark.parametrize("flag", ["--metadata", "--show-metadata"])
def test_metadata_aliases(flag: str) -> None:
    assert parse_args(["harbor", "-t", "host", flag]).metadata is True


@pytest.mark.parametrize("flag", ["--inspect", "--show-manifest"])
def test_manifest_aliases(flag: str) -> None:
    assert parse_args(["docker-registry", "-t", "host", flag]).inspect is True


@pytest.mark.parametrize("flag", ["--assets", "--show-assets"])
def test_nexus_assets_aliases(flag: str) -> None:
    assert parse_args(["nexus", "-t", "host", flag]).assets is True


def test_asset_selector_is_nexus_only_and_implies_inventory() -> None:
    args = parse_args(["nexus", "-t", "host", "--asset", "/team/app.jar"])
    assert args.asset == "/team/app.jar"
    assert stage.build_registry_spec(args, product="nexus").data is not None
    for product in ("docker-registry", "harbor", "gitlab"):
        with pytest.raises(SystemExit):
            parse_args([product, "-t", "host", "--asset", "/team/app.jar"])


def _core_options(product: str, *, show_images: bool) -> dict[str, Any]:
    return {
        "username": None,
        "password": None,
        "token": None,
        "docker": product == "docker-registry",
        "show_images": show_images,
        "show_tags": False,
        "repository": None,
        "tag": None,
        "metadata": False,
        "harbor": product == "harbor",
        "gitlab": product == "gitlab",
        "nexus": product == "nexus",
        "assets": False,
        "inspect": False,
        "image": None,
        "download": False,
        "download_dir": "/tmp",
        "console": SimpleNamespace(),
        "debug": False,
    }


@pytest.mark.parametrize("product", ["nexus", "harbor", "gitlab"])
def test_bare_product_skips_deep_repository_inventory(monkeypatch: pytest.MonkeyPatch, product: str) -> None:
    calls: list[str] = []

    def no_inventory(*_args: Any, **_kwargs: Any) -> Any:
        calls.append("inventory")
        raise AssertionError("bare detection requested full inventory")

    monkeypatch.setattr(
        actions,
        "_fetch_nexus_info",
        lambda *_a, **_kw: ({"version": "3.72.0"}, None) if product == "nexus" else (None, "not nexus"),
    )
    monkeypatch.setattr(
        actions,
        "_fetch_harbor_info",
        lambda *_a, **_kw: ({"harbor_version": "v2.11.1"}, None) if product == "harbor" else (None, "not harbor"),
    )
    monkeypatch.setattr(
        actions,
        "_fetch_gitlab_info",
        lambda *_a, **_kw: ({"service": "container_registry"}, None) if product == "gitlab" else (None, "not gitlab"),
    )
    for name in (
        "_fetch_nexus_repository_records",
        "_fetch_nexus_components",
        "_fetch_harbor_projects",
        "_fetch_harbor_repositories",
        "_fetch_harbor_artifacts",
        "_fetch_registry_catalog",
    ):
        monkeypatch.setattr(actions, name, no_inventory)
    probe = (
        (404, b"", {}, None)
        if product == "nexus"
        else (200, b"{}", {"docker-distribution-api-version": "registry/2.0"}, None)
    )
    result = actions._audit_registry_host_core(
        "host",
        8081,
        1.0,
        0,
        **_core_options(product, show_images=False),
        initial_probe=probe,
        initial_nexus=({"version": "3.72.0"}, None) if product == "nexus" else None,
    )
    assert result[f"is_{product}"] is True
    assert result["nexus_repositories"] is None
    assert result["harbor_projects"] is None
    assert result["gitlab_repositories"] is None
    assert not calls


@pytest.mark.parametrize("product", ["harbor", "gitlab"])
def test_explicit_repository_flag_fetches_vendor_inventory(monkeypatch: pytest.MonkeyPatch, product: str) -> None:
    calls: list[str] = []
    monkeypatch.setattr(actions, "_fetch_nexus_info", lambda *_a, **_kw: (None, "not nexus"))
    monkeypatch.setattr(
        actions,
        "_fetch_harbor_info",
        lambda *_a, **_kw: ({"harbor_version": "v2.11.1"}, None) if product == "harbor" else (None, "not harbor"),
    )
    monkeypatch.setattr(
        actions,
        "_fetch_gitlab_info",
        lambda *_a, **_kw: ({"service": "container_registry"}, None) if product == "gitlab" else (None, "not gitlab"),
    )

    def catalog(*_args: Any, **_kwargs: Any) -> tuple[list[str], None]:
        calls.append("catalog")
        return ["team/app"] if product == "gitlab" else [], None

    def projects(*_args: Any, **_kwargs: Any) -> tuple[list[str], None]:
        calls.append("projects")
        return ["library"], None

    monkeypatch.setattr(actions, "_fetch_registry_catalog", catalog)
    monkeypatch.setattr(actions, "_fetch_harbor_projects", projects)
    monkeypatch.setattr(actions, "_fetch_harbor_repositories", lambda *_a, **_kw: (["library/app"], None))
    monkeypatch.setattr(actions, "_fetch_harbor_artifacts", lambda *_a, **_kw: (["library/app:latest"], None))
    monkeypatch.setattr(actions, "_fetch_repository_tags", lambda *_a, **_kw: (["latest"], None))
    monkeypatch.setattr(actions, "_inspect_image", lambda *_a, **_kw: {"created": "2026-01-01"})
    probe = (200, b"{}", {"docker-distribution-api-version": "registry/2.0"}, None)
    result = actions._audit_registry_host_core(
        "host",
        5000,
        1.0,
        0,
        **_core_options(product, show_images=True),
        initial_probe=probe,
    )
    assert "catalog" in calls
    if product == "harbor":
        assert "projects" in calls
        assert result["harbor_projects"] == ["library"]
    else:
        assert result["gitlab_repositories"] == ["team/app"]
    lines = render_record_with_module(product_render, AuditRecord.from_mapping(result, module=product), "txt")
    assert any(
        ("Harbor Projects Enumeration" if product == "harbor" else "GitLab Repositories Enumeration") in line
        for line in lines
    )
    if product == "harbor":
        assert not any("Harbor Repositories Enumeration" in line for line in lines)


def test_nexus_bare_count_and_flagged_details_do_not_leak(monkeypatch: pytest.MonkeyPatch) -> None:
    args = parse_args(["nexus", "-t", "http://host:8081", "--no-color"])
    state = actions.RegistryLifecycleState()
    ctx = SimpleNamespace(
        host="host",
        port=8081,
        args=args,
        target=None,
        credential=AuditCredentialRun(source="anonymous"),
        lifecycle_state=state,
    )
    repositories = [
        {"name": "docker-hosted", "format": "docker", "type": "hosted", "url": None, "online": True},
        {"name": "maven-public", "format": "maven2", "type": "group", "url": None, "online": True},
    ]
    calls: list[str] = []

    def fetch_repositories(*_args: Any, **_kwargs: Any) -> tuple[list[dict[str, Any]], None]:
        calls.append("repositories")
        return repositories, None

    def fetch_components(*_args: Any, **_kwargs: Any) -> tuple[list[dict[str, Any]], None]:
        calls.append("components")
        return [], None

    monkeypatch.setattr(actions, "_http_request", lambda *_a, **_kw: (404, b"", {}, None))
    monkeypatch.setattr(actions, "_fetch_nexus_info", lambda *_a, **_kw: ({"version": "3.72.0"}, None))
    monkeypatch.setattr(actions, "_fetch_gitlab_info", lambda *_a, **_kw: (None, "not gitlab"))
    monkeypatch.setattr(actions, "_fetch_harbor_info", lambda *_a, **_kw: (None, "not harbor"))
    monkeypatch.setattr(actions, "_fetch_nexus_repository_records", fetch_repositories)
    monkeypatch.setattr(actions, "_fetch_nexus_components", fetch_components)

    spec = stage.build_registry_spec(args, product="nexus")
    assert spec.detect is not None and spec.data is not None
    detected = spec.detect(ctx)
    assert detected.extra["nexus_repository_count"] == 2
    bare = spec.data(ctx, detected)
    bare_payload = bare.to_dict()
    bare_lines = render_record_with_module(product_render, bare, "txt")
    assert "(repositories:2)" in bare_lines[0]
    assert not any("Repositories Enumeration" in line or "docker-hosted" in line for line in bare_lines)
    assert bare_payload["nexus_repositories"] is None
    assert bare_payload["nexus_repository_details"] is None
    assert "\x1b[" not in "\n".join(bare_lines) + json.dumps(bare_payload)
    assert calls == ["repositories"]

    flagged_args = parse_args(["nexus", "-t", "http://host:8081", "--show-repositories"])
    flagged_ctx = SimpleNamespace(**{**vars(ctx), "args": flagged_args})
    flagged_spec = stage.build_registry_spec(flagged_args, product="nexus")
    assert flagged_spec.data is not None
    flagged = flagged_spec.data(flagged_ctx, detected)
    flagged_lines = render_record_with_module(product_render, flagged, "txt")
    assert any("Nexus Repositories Enumeration (repositories:2)" in line for line in flagged_lines), flagged_lines
    assert any("docker-hosted" in line for line in flagged_lines)
    assert calls.count("components") == 0


@pytest.mark.parametrize(
    "product,count_field",
    [
        ("harbor", "harbor_project_count"),
        ("gitlab", "gitlab_repository_count"),
    ],
)
def test_open_vendor_detection_counts_without_exposing_names(
    monkeypatch: pytest.MonkeyPatch, product: str, count_field: str
) -> None:
    challenge = (
        'Bearer realm="https://host/jwt/auth",service="container_registry"'
        if product == "gitlab"
        else 'Bearer realm="https://host/service/token",service="harbor-registry"'
    )
    monkeypatch.setattr(
        actions,
        "_http_request",
        lambda *_a, **_kw: (
            200,
            b"{}",
            {"docker-distribution-api-version": "registry/2.0", "www-authenticate": challenge},
            None,
        ),
    )
    monkeypatch.setattr(actions, "_fetch_nexus_info", lambda *_a, **_kw: (None, "not nexus"))
    monkeypatch.setattr(
        actions,
        "_fetch_harbor_info",
        lambda *_a, **_kw: ({"harbor_version": "v2.11.1"}, None) if product == "harbor" else (None, "not harbor"),
    )
    monkeypatch.setattr(actions, "_fetch_harbor_projects", lambda *_a, **_kw: (["private-project"], None))
    monkeypatch.setattr(actions, "_fetch_registry_catalog", lambda *_a, **_kw: (["private-repository"], None))
    ctx = SimpleNamespace(
        host="host",
        port=5000,
        args=SimpleNamespace(timeout=1.0, retries=0),
        credential=AuditCredentialRun(source="anonymous"),
        lifecycle_state=actions.RegistryLifecycleState(),
    )
    options = {"product": product, "nexus": False, "harbor": product == "harbor", "gitlab": product == "gitlab"}
    # Detection's payload needs the shared inventory options, but they stay disabled.
    options.update(
        {key: value for key, value in _core_options(product, show_images=False).items() if key not in options}
    )
    detected = actions.detect_registry(ctx, options)
    assert detected[f"is_{product}"] is True
    assert detected[count_field] == 1
    assert detected["harbor_projects"] is None
    assert detected["gitlab_repositories"] is None


@pytest.mark.parametrize(
    "product,count_field,label",
    [
        ("harbor", "harbor_project_count", "projects"),
        ("nexus", "nexus_repository_count", "repositories"),
        ("gitlab", "gitlab_repository_count", "repositories"),
    ],
)
def test_product_count_only_on_bare_detection(product: str, count_field: str, label: str) -> None:
    payload = {
        "host": "host",
        "port": 8081,
        "module": product,
        "is_registry": True,
        f"is_{product}": True,
        "status": "open_no_auth",
        "auth_required": False,
        count_field: 3,
        "show_images": False,
        "nexus": product == "nexus",
        "harbor": product == "harbor",
        "gitlab": product == "gitlab",
        "nexus_repositories": ["private-name"],
        "harbor_projects": ["private-name"],
        "gitlab_repositories": ["private-name"],
    }
    lines = render_record_with_module(product_render, AuditRecord.from_mapping(payload, module=product), "txt")
    assert f"({label}:3)" in lines[0]
    assert not any("private-name" in line or "Enumeration" in line for line in lines)


def test_gitlab_web_count_without_project_list() -> None:
    payload = {
        "host": "host",
        "port": 80,
        "module": "gitlab",
        "is_gitlab": True,
        "gitlab_surface": "web",
        "status": "detected",
        "auth_required": False,
        "public_projects_count": 4,
        "public_projects": None,
        "token_projects": None,
    }
    lines = render_record_with_module(gitlab_render, AuditRecord.from_mapping(payload, module="gitlab"), "txt")
    assert any("Public Projects (projects:4)" in line for line in lines)
    assert not any("Repositories Enumeration" in line for line in lines)


@pytest.mark.parametrize("show", [False, True])
def test_gitlab_web_json_hides_projects_until_requested(monkeypatch: pytest.MonkeyPatch, show: bool) -> None:
    args = parse_args(["gitlab", "-t", "http://host:80", *(["--show-images"] if show else [])])
    spec = gitlab_stage.build_gitlab_spec(args)
    assert spec.data is not None
    seen_options: list[dict[str, Any]] = []

    def collect(_ctx: Any, _record: Any, options: dict[str, Any]) -> dict[str, Any]:
        seen_options.append(options)
        return {
            "host": "host",
            "port": 80,
            "status": "detected",
            "is_gitlab": True,
            "gitlab_surface": "web",
            "auth_required": False,
            "public_projects": [{"path_with_namespace": "team/private"}],
            "token_projects": [],
            "token_access": [],
        }

    monkeypatch.setattr(gitlab_actions, "collect_gitlab_data", collect)
    ctx = SimpleNamespace(
        host="host",
        port=80,
        target=None,
        args=args,
        credential=AuditCredentialRun(source="anonymous"),
        lifecycle_state=gitlab_stage.GitLabCombinedState(
            web=gitlab_actions.GitLabLifecycleState(), registry=actions.RegistryLifecycleState()
        ),
    )
    prior = AuditRecord.from_mapping(
        {"host": "host", "port": 80, "status": "detected", "is_gitlab": True, "gitlab_surface": "web"},
        module="gitlab",
    )
    result = spec.data(ctx, prior).to_dict()
    assert seen_options[0]["show_repositories"] is show
    if show:
        assert result["public_projects"] == [{"path_with_namespace": "team/private"}]
    else:
        assert result["public_projects_count"] == 1
        assert result["public_projects"] is None
        assert "team/private" not in json.dumps(result)


@pytest.mark.parametrize("product,label", [("nexus", "repositories"), ("harbor", "projects")])
def test_registry_count_follows_airflow_colors(product: str, label: str) -> None:
    class RecordingConsole:
        def __init__(self) -> None:
            self.paints: list[tuple[str, str]] = []

        def _paint(self, value: str, color: str, _stream: Any) -> str:
            self.paints.append((value, color))
            return value

        def plain(self, _value: str, color: str | None = None) -> None:
            _ = color

    console = RecordingConsole()
    for count, expected in ((2, "true_red"), (0, "bright_green")):
        line = f"{product.upper()}\thost\t8081\t [*] Product (auth required:False) ({label}:{count})"
        assert product_render._render_colored_registry_line(console, line) is True
        assert (f"{label}:{count}", expected) in console.paints
    assert any(color == "white" for _value, color in console.paints)


@pytest.mark.parametrize("product", ["docker-registry", "harbor", "nexus", "gitlab"])
def test_show_tags_without_repository_is_valid(product: str) -> None:
    args = parse_args([product, "-t", "host:5000", "--show-tags"])
    errors: list[str] = []
    assert policy.validate_args(args, SimpleNamespace(error=errors.append), product=product) is None
    assert not errors


@pytest.mark.parametrize("product", ["docker-registry", "gitlab"])
def test_show_tags_all_oci_repositories_in_order(monkeypatch: pytest.MonkeyPatch, product: str) -> None:
    calls: list[str] = []
    monkeypatch.setattr(actions, "_fetch_nexus_info", lambda *_a, **_kw: (None, "not nexus"))
    monkeypatch.setattr(actions, "_fetch_harbor_info", lambda *_a, **_kw: (None, "not harbor"))
    monkeypatch.setattr(
        actions,
        "_fetch_gitlab_info",
        lambda *_a, **_kw: ({"service": "container_registry"}, None) if product == "gitlab" else (None, "not gitlab"),
    )
    monkeypatch.setattr(actions, "_fetch_registry_catalog", lambda *_a, **_kw: (["z/app", "a/app", "z/app"], None))

    def tags(_host: str, _port: int, repo: str, _timeout: float, **_kwargs: Any) -> tuple[list[str] | None, str | None]:
        calls.append(repo)
        if repo == "a/app":
            return ["latest", "1.0", "latest"], None
        return None, "authentication required"

    monkeypatch.setattr(actions, "_fetch_repository_tags", tags)
    options = _core_options(product, show_images=False)
    options["show_tags"] = True
    record = actions._audit_registry_host_core(
        "host",
        5000,
        1.0,
        0,
        **options,
        initial_probe=(200, b"{}", {"docker-distribution-api-version": "registry/2.0"}, None),
    )
    assert calls == ["a/app", "z/app"]
    assert record["repository_tags"] == {"a/app": ["1.0", "latest"]}
    assert record["repository_tag_errors"] == {"z/app": "authentication required"}
    assert record["images"] is None
    lines = render_record_with_module(product_render, AuditRecord.from_mapping(record, module=product), "txt")
    text = "\n".join(lines)
    assert "Tags Enumeration a/app (tags:2)" in text
    assert text.index("Tags Enumeration a/app") < text.index("Tags Enumeration z/app")
    assert "z/app: authentication required" in text
    assert "\x1b[" not in text
    json_lines = render_record_with_module(product_render, AuditRecord.from_mapping(record, module=product), "json")
    assert any('"type": "tags"' in line and '"a/app"' in line for line in json_lines)
    assert "\x1b[" not in "\n".join(json_lines)


def test_show_tags_harbor_falls_back_to_vendor_api(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(actions, "_fetch_nexus_info", lambda *_a, **_kw: (None, "not nexus"))
    monkeypatch.setattr(actions, "_fetch_gitlab_info", lambda *_a, **_kw: (None, "not gitlab"))
    monkeypatch.setattr(actions, "_fetch_harbor_info", lambda *_a, **_kw: ({"harbor_version": "v2.11.1"}, None))
    monkeypatch.setattr(actions, "_fetch_registry_catalog", lambda *_a, **_kw: (None, "catalog unavailable"))
    monkeypatch.setattr(actions, "_fetch_harbor_projects", lambda *_a, **_kw: (["team"], None))
    monkeypatch.setattr(actions, "_fetch_harbor_repositories", lambda *_a, **_kw: (["team/app"], None))
    monkeypatch.setattr(
        actions,
        "_fetch_harbor_artifacts",
        lambda *_a, **_kw: (["team/app:latest@sha256:abcd", "team/app:1.0@sha256:efgh"], None),
    )
    options = _core_options("harbor", show_images=False)
    options["show_tags"] = True
    record = actions._audit_registry_host_core(
        "host",
        5000,
        1.0,
        0,
        **options,
        initial_probe=(200, b"{}", {"docker-distribution-api-version": "registry/2.0"}, None),
    )
    assert record["repository_tags"] == {"team/app": ["1.0", "latest"]}
    assert record["images_error"] is None


def test_show_tags_nexus_uses_docker_components_only(monkeypatch: pytest.MonkeyPatch) -> None:
    queried_repositories: list[str] = []

    def components(
        _host: str, _port: int, repo: str, _timeout: float, **_kwargs: Any
    ) -> tuple[list[dict[str, str]], None]:
        queried_repositories.append(repo)
        if repo == "docker-hosted":
            return [{"name": "team/app", "version": "latest"}, {"name": "team/app", "version": "1.0"}], None
        return [{"name": "library", "version": "1.2"}], None

    monkeypatch.setattr(actions, "_fetch_gitlab_info", lambda *_a, **_kw: (None, "not gitlab"))
    monkeypatch.setattr(actions, "_fetch_harbor_info", lambda *_a, **_kw: (None, "not harbor"))
    monkeypatch.setattr(actions, "_fetch_nexus_info", lambda *_a, **_kw: ({"version": "3.72.0"}, None))
    monkeypatch.setattr(
        actions,
        "_fetch_nexus_repository_records",
        lambda *_a, **_kw: (
            [{"name": "docker-hosted", "format": "docker"}, {"name": "maven", "format": "maven2"}],
            None,
        ),
    )
    monkeypatch.setattr(actions, "_fetch_nexus_components", components)
    options = _core_options("nexus", show_images=False)
    options["show_tags"] = True
    record = actions._audit_registry_host_core(
        "host",
        8081,
        1.0,
        0,
        **options,
        initial_probe=(404, b"", {}, None),
    )
    assert record["repository_tags"] == {"docker-hosted/team/app": ["1.0", "latest"]}
    assert queried_repositories == ["docker-hosted"]
    lines = render_record_with_module(product_render, AuditRecord.from_mapping(record, module="nexus"), "txt")
    assert any("Tags Enumeration docker-hosted/team/app (tags:2)" in line for line in lines)
    assert all("maven" not in line for line in lines)


def test_show_tags_empty_catalog_and_failed_repository_are_distinct() -> None:
    base: dict[str, Any] = {
        "host": "host",
        "port": 5000,
        "is_registry": True,
        "status": "open_no_auth",
        "show_tags": True,
        "repository": None,
        "repository_tags": {},
        "repository_tag_errors": {},
    }
    empty = render_record_with_module(product_render, AuditRecord.from_mapping(base, module="docker-registry"), "txt")
    assert any("Tags Enumeration (repositories:0)" in line for line in empty)
    failed = render_record_with_module(
        product_render,
        AuditRecord.from_mapping(
            {**base, "repository_tag_errors": {"team/app": "authentication required"}}, module="docker-registry"
        ),
        "txt",
    )
    assert any("Tags Enumeration team/app (tags:unknown)" in line for line in failed)
    assert not any("<no tags>" in line for line in failed)


def test_show_tags_bulk_colors_follow_airflow_convention() -> None:
    class RecordingConsole:
        def __init__(self) -> None:
            self.paints: list[tuple[str, str]] = []

        def _paint(self, value: str, color: str, _stream: Any) -> str:
            self.paints.append((value, color))
            return value

        def plain(self, _value: str, color: str | None = None) -> None:
            _ = color

    console = RecordingConsole()
    for line in (
        "NEXUS\thost\t8081\t [*] Tags Enumeration docker-hosted/team/app (tags:2)",
        "NEXUS\thost\t8081\t [*] Tags Enumeration docker-hosted/blocked (tags:unknown)",
        "NEXUS\thost\t8081\t latest",
    ):
        assert product_render._render_colored_registry_line(console, line)
    assert ("tags:2", "true_red") in console.paints
    assert ("tags:unknown", "orange") in console.paints
    assert any(color == "white" for _value, color in console.paints)
    assert any(color == "orange" and "docker-hosted/team/app" in value for value, color in console.paints)


def test_nexus_storage_and_docker_images_are_distinct_in_txt_and_json(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(actions, "_fetch_gitlab_info", lambda *_a, **_kw: (None, "not gitlab"))
    monkeypatch.setattr(actions, "_fetch_harbor_info", lambda *_a, **_kw: (None, "not harbor"))
    monkeypatch.setattr(actions, "_fetch_nexus_info", lambda *_a, **_kw: ({"version": "3.72.0"}, None))
    monkeypatch.setattr(
        actions,
        "_fetch_nexus_repository_records",
        lambda *_a, **_kw: (
            [{"name": "docker-hosted", "format": "docker", "type": "hosted"}, {"name": "maven", "format": "maven2"}],
            None,
        ),
    )
    queried: list[str] = []

    def components(
        _host: str, _port: int, repo: str, _timeout: float, **_kwargs: Any
    ) -> tuple[list[dict[str, str]], None]:
        queried.append(repo)
        return ([{"name": "team/app", "version": "latest"}], None) if repo == "docker-hosted" else ([], None)

    monkeypatch.setattr(actions, "_fetch_nexus_components", components)
    probe = (404, b"", {}, None)
    images = actions._audit_registry_host_core(
        "host", 8081, 1.0, 0, **_core_options("nexus", show_images=True), initial_probe=probe
    )
    assert images["images"] == ["docker-hosted/team/app:latest"]
    assert images["nexus_repositories"] is None
    assert queried == ["docker-hosted"]
    image_lines = render_record_with_module(product_render, AuditRecord.from_mapping(images, module="nexus"), "txt")
    assert any("Images Enumeration (images:1)" in line for line in image_lines)
    assert not any("Nexus Repositories Enumeration" in line for line in image_lines)

    options = _core_options("nexus", show_images=False)
    storage = actions._audit_registry_host_core(
        "host", 8081, 1.0, 0, **options, show_repositories=True, initial_probe=probe
    )
    assert storage["images"] is None
    assert len(storage["nexus_repositories"]) == 2
    assert queried == ["docker-hosted"]
    storage_record = AuditRecord.from_mapping(storage, module="nexus")
    storage_lines = render_record_with_module(product_render, storage_record, "txt")
    assert any("Nexus Repositories Enumeration (repositories:2)" in line for line in storage_lines)
    assert any("maven (format:maven2)" in line for line in storage_lines)
    assert not any("Images Enumeration" in line for line in storage_lines)
    assert "\x1b[" not in "\n".join(storage_lines)
    json_lines = render_record_with_module(product_render, storage_record, "json")
    assert any('"nexus_repositories"' in line for line in json_lines)
    assert "\x1b[" not in "\n".join(json_lines)


def test_nexus_storage_inventory_colors_follow_airflow_convention() -> None:
    class RecordingConsole:
        def __init__(self) -> None:
            self.paints: list[tuple[str, str]] = []

        def _paint(self, value: str, color: str, _stream: Any) -> str:
            self.paints.append((value, color))
            return value

        def plain(self, _value: str, color: str | None = None) -> None:
            _ = color

    console = RecordingConsole()
    assert product_render._render_colored_registry_line(
        console, "NEXUS\thost\t8081\t [*] Nexus Repositories Enumeration (repositories:2)"
    )
    assert ("repositories:2", "true_red") in console.paints
    assert any(color == "white" and "Nexus Repositories Enumeration" in value for value, color in console.paints)
    console.paints.clear()
    assert product_render._render_colored_registry_line(
        console, "NEXUS\thost\t8081\t docker-hosted (format:docker) (type:hosted) (online:True)"
    )
    assert any(color == "orange" and "docker-hosted" in value for value, color in console.paints)
    console.paints.clear()
    assert product_render._render_colored_registry_line(
        console, "NEXUS\thost\t8081\t [*] Nexus Assets Enumeration (assets:1)"
    )
    assert ("assets:1", "true_red") in console.paints
    assert any(color == "white" and "Nexus Assets Enumeration" in value for value, color in console.paints)
    console.paints.clear()
    assert product_render._render_colored_registry_line(console, "NEXUS\thost\t8081\t [-] asset not found: /missing")
    assert ("[-]", "true_red") in console.paints


def test_nexus_asset_selector_filters_exact_path_and_reports_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(actions, "_http_request", lambda *_a, **_kw: (404, b"", {}, None))
    monkeypatch.setattr(actions, "_fetch_nexus_info", lambda *_a, **_kw: ({"version": "3.72.0"}, None))
    monkeypatch.setattr(actions, "_fetch_gitlab_info", lambda *_a, **_kw: (None, "not gitlab"))
    monkeypatch.setattr(actions, "_fetch_harbor_info", lambda *_a, **_kw: (None, "not harbor"))
    monkeypatch.setattr(
        actions,
        "_fetch_nexus_repository_records",
        lambda *_a, **_kw: ([{"name": "maven-hosted", "format": "maven2", "type": "hosted"}], None),
    )
    monkeypatch.setattr(
        actions,
        "_fetch_nexus_components",
        lambda *_a, **_kw: (
            [
                {
                    "name": "team/app",
                    "version": "1.0",
                    "assets": [
                        {"path": "/team/app.jar", "downloadUrl": "https://nexus/repository/maven-hosted/app.jar"},
                        {"path": "/team/app.pom", "downloadUrl": "https://nexus/repository/maven-hosted/app.pom"},
                    ],
                }
            ],
            None,
        ),
    )

    def scan(selector: str) -> dict[str, Any]:
        args = parse_args(["nexus", "-t", "http://host:8081", "--asset", selector])
        ctx = SimpleNamespace(
            host="host",
            port=8081,
            args=args,
            target=None,
            credential=AuditCredentialRun(source="anonymous"),
            lifecycle_state=actions.RegistryLifecycleState(),
        )
        spec = stage.build_registry_spec(args, product="nexus")
        assert spec.detect is not None and spec.data is not None
        detected = spec.detect(ctx)
        return spec.data(ctx, detected).to_dict()

    found = scan("/team/app.jar")
    assert found["assets"] is True
    assert [item["path"] for item in found["nexus_assets"]] == ["/team/app.jar"]
    assert found["asset_error"] is None
    lines = render_record_with_module(product_render, AuditRecord.from_mapping(found, module="nexus"), "txt")
    assert any("Nexus Assets Enumeration (assets:1)" in line for line in lines)
    assert all("app.pom" not in line for line in lines)
    assert "\x1b[" not in "\n".join(lines)
    json_lines = render_record_with_module(product_render, AuditRecord.from_mapping(found, module="nexus"), "json")
    assert "\x1b[" not in "\n".join(json_lines)
    assert any('"asset": "/team/app.jar"' in line for line in json_lines)

    by_url = scan("https://nexus/repository/maven-hosted/app.pom")
    assert [item["path"] for item in by_url["nexus_assets"]] == ["/team/app.pom"]

    missing = scan("/team/missing.jar")
    assert missing["nexus_assets"] == []
    assert missing["asset_error"] == "asset not found: /team/missing.jar"
    missing_lines = render_record_with_module(product_render, AuditRecord.from_mapping(missing, module="nexus"), "txt")
    assert any("[-] asset not found: /team/missing.jar" in line for line in missing_lines)
    assert not any("<no assets>" in line for line in missing_lines)


def test_nexus_combined_inventory_follows_help_order_with_details_attached() -> None:
    record = AuditRecord.from_mapping(
        {
            "host": "host",
            "port": 8081,
            "is_registry": True,
            "is_nexus": True,
            "status": "open_no_auth",
            "nexus": True,
            "nexus_info": {"version": "3.72.0"},
            "show_repositories": True,
            "nexus_repositories": ["docker-hosted"],
            "nexus_repository_details": [{"name": "docker-hosted", "format": "docker", "type": "hosted"}],
            "show_images": True,
            "images": ["docker-hosted/team/app:latest"],
            "show_tags": True,
            "repository": "docker-hosted/team/app",
            "selected_repository_tags": ["latest"],
            "tag": "latest",
            "inspect": True,
            "inspections": [{"image": "docker-hosted/team/app:latest", "layer_count": 1, "env": ["MANIFEST=1"]}],
            "metadata": True,
            "metadata_result": {"env": ["METADATA=1"]},
            "assets": True,
            "nexus_assets": [{"path": "/team/app.tar", "download_url": "https://nexus/app.tar"}],
            "download": True,
            "download_result": {"status": "skipped", "error": "test fixture"},
        },
        module="nexus",
    )
    lines = render_record_with_module(product_render, record, "txt")
    text = "\n".join(lines)
    headings = (
        "Nexus Repositories Enumeration",
        "Images Enumeration",
        "Tags Enumeration",
        "Inspect docker-hosted/team/app:latest",
        "Metadata docker-hosted/team/app:latest",
        "Nexus Assets Enumeration",
        "Download skipped",
    )
    offsets = [text.index(heading) for heading in headings]
    assert offsets == sorted(offsets)
    assert text.index("MANIFEST=1") < text.index("Metadata docker-hosted/team/app:latest")
    assert text.index("METADATA=1") < text.index("Nexus Assets Enumeration")
    assert "\x1b[" not in text


@pytest.mark.parametrize(
    ("product", "vendor_fields", "heading"),
    [
        (
            "harbor",
            {"is_harbor": True, "harbor": True, "harbor_projects": ["team"], "harbor_repositories": ["team/app"]},
            "Harbor Projects Enumeration",
        ),
        (
            "gitlab",
            {
                "is_gitlab": True,
                "gitlab": True,
                "gitlab_info": {"service": "container_registry"},
                "gitlab_repositories": ["team/app"],
            },
            "GitLab Repositories Enumeration",
        ),
    ],
)
def test_vendor_repository_sections_precede_images(product: str, vendor_fields: dict[str, Any], heading: str) -> None:
    record = AuditRecord.from_mapping(
        {
            "host": "host",
            "port": 443,
            "is_registry": True,
            "status": "open_no_auth",
            "show_images": True,
            "images": ["team/app:latest"],
            **vendor_fields,
        },
        module=product,
    )
    text = "\n".join(render_record_with_module(product_render, record, "txt"))
    assert text.index(heading) < text.index("Images Enumeration")
    if product == "harbor":
        assert "Harbor Repositories Enumeration" not in text
