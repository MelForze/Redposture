from __future__ import annotations

import pytest

from redposture_core.audit_models import AuditRecord
from redposture_core.cli_args import parse_args
from redposture_core.modules.gitlab import render as gitlab_render
from redposture_core.modules.gitlab import stage as gitlab_stage
from redposture_core.modules.registry import stage as registry_stage
from redposture_core.stage_runtime import render_record_with_module


@pytest.mark.parametrize(
    ("product", "flag", "name", "version_info", "version"),
    [
        ("docker-registry", None, "Docker Registry", {}, "unknown"),
        ("harbor", "is_harbor", "Harbor", {"harbor_info": {"harbor_version": "v2.11.1"}}, "v2.11.1"),
        ("nexus", "is_nexus", "Nexus Repository", {"nexus_info": {"version": "3.72.0"}}, "3.72.0"),
    ],
)
def test_product_service_line_has_airflow_style_and_no_duplicate_presence(
    product: str, flag: str | None, name: str, version_info: dict[str, object], version: str | None
) -> None:
    args = parse_args([product, "-t", "http://host:5000"])
    spec = registry_stage.build_registry_spec(args, product=product)
    payload: dict[str, object] = {
        "host": "host",
        "port": 5000,
        "is_registry": True,
        "status": "detected",
        "auth_required": True,
        **version_info,
    }
    if flag:
        payload[flag] = True
    lines = render_record_with_module(spec.render_module, AuditRecord.from_mapping(payload, module=product), "txt")
    expected = f"{product.upper()}\thost\t5000\t [*] {name} (auth required:True)"
    expected += f" (version:{version})"
    assert lines[0] == expected
    assert len([line for line in lines if "detected" in line.lower()]) == 0
    assert all(len(line.split("\t", 3)) == 4 for line in lines)


def test_product_inventory_is_counted_and_auth_block_does_not_show_empty_sections() -> None:
    args = parse_args(["harbor", "-t", "http://host:5000", "--images"])
    spec = registry_stage.build_registry_spec(args, product="harbor")
    payload = {
        "host": "host",
        "port": 5000,
        "module": "harbor",
        "is_registry": True,
        "is_harbor": True,
        "status": "valid_credentials",
        "auth_required": True,
        "provided_username": "admin",
        "provided_password": "Harbor12345",
        "images": ["core/control-plane"],
        "show_images": True,
        "harbor": True,
        "harbor_projects": ["core"],
        "harbor_repositories": ["core/control-plane"],
    }
    lines = render_record_with_module(spec.render_module, AuditRecord.from_mapping(payload, module="harbor"), "txt")
    assert lines[0].endswith("[*] Harbor (auth required:True) (version:unknown)")
    assert lines[1].endswith("[+] admin:Harbor12345")
    assert any("[*] Images Enumeration (images:1)" in line for line in lines)
    assert any("[*] Harbor Projects Enumeration (projects:1)" in line for line in lines)
    assert not any("Harbor detected" in line for line in lines)
    assert all(len(line.split("\t", 3)) == 4 for line in lines)

    blocked = {**payload, "status": "auth_required", "images": [], "harbor_projects": [], "harbor_repositories": []}
    blocked.pop("provided_username")
    blocked.pop("provided_password")
    blocked_lines = render_record_with_module(
        spec.render_module, AuditRecord.from_mapping(blocked, module="harbor"), "txt"
    )
    assert blocked_lines == ["HARBOR\thost\t5000\t [*] Harbor (auth required:True) (version:unknown)"]


def test_registry_detection_and_credential_stages_do_not_claim_empty_inventory() -> None:
    spec = registry_stage.build_registry_spec(
        parse_args(["docker-registry", "-t", "http://host:5000", "--images"]), product="docker-registry"
    )
    base = {
        "host": "host",
        "port": 5000,
        "module": "docker-registry",
        "is_registry": True,
        "auth_required": True,
        "show_images": True,
        "show_tags": True,
        "repository": "team/app",
        "tag": "latest",
        "metadata": True,
        "harbor_error": "not harbor",
        "harbor": True,
    }
    detected = render_record_with_module(
        spec.render_module,
        AuditRecord.from_mapping({**base, "status": "auth_required"}, module="docker-registry"),
        "txt",
    )
    assert detected == ["DOCKER-REGISTRY\thost\t5000\t [*] Docker Registry (auth required:True) (version:unknown)"]
    authenticated = render_record_with_module(
        spec.render_module,
        AuditRecord.from_mapping(
            {**base, "status": "valid_credentials", "provided_username": "registry", "provided_password": "registry"},
            module="docker-registry",
        ),
        "txt",
    )
    assert authenticated == [
        "DOCKER-REGISTRY\thost\t5000\t [*] Docker Registry (auth required:True) (version:unknown)",
        "DOCKER-REGISTRY\thost\t5000\t [+] registry:registry",
    ]

    nexus = registry_stage.build_registry_spec(
        parse_args(["nexus", "-t", "http://host:8081", "--assets"]), product="nexus"
    )
    nexus_detection = render_record_with_module(
        nexus.render_module,
        AuditRecord.from_mapping(
            {
                "host": "host",
                "port": 8081,
                "module": "nexus",
                "status": "open_no_auth",
                "is_registry": True,
                "is_nexus": True,
                "auth_required": False,
                "nexus": True,
                "assets": True,
                "nexus_info": {"version": "3.72.0"},
            },
            module="nexus",
        ),
        "txt",
    )
    assert nexus_detection == ["NEXUS\thost\t8081\t [*] Nexus Repository (auth required:False) (version:3.72.0)"]


def test_gitlab_web_and_registry_have_single_service_line_and_ordered_details() -> None:
    args = parse_args(["gitlab", "-t", "http://host:8080"])
    spec = gitlab_stage.build_gitlab_spec(args)
    payload = {
        "host": "host",
        "port": 8080,
        "is_gitlab": True,
        "status": "valid_credentials",
        "gitlab_surface": "web_and_registry",
        "auth_required": True,
        "login_page": True,
        "version": "17.11.0",
        "provided_credentials_ok": True,
        "provided_username": "root",
        "provided_password": "secret",
        "public_projects": [{"path_with_namespace": "team/app", "visibility": "public"}],
        "container_registry": {
            "host": "host",
            "port": 8080,
            "module": "gitlab",
            "is_registry": True,
            "is_gitlab": True,
            "status": "valid_credentials",
            "auth_required": True,
            "images": ["team/app"],
            "show_images": True,
        },
    }
    lines = render_record_with_module(spec.render_module, AuditRecord.from_mapping(payload, module="gitlab"), "txt")
    assert lines[0] == "GITLAB\thost\t8080\t [*] GitLab (auth required:True) (version:17.11.0)"
    assert lines[1] == "GITLAB\thost\t8080\t [+] root:secret"
    assert any("[*] Container Registry (auth required:True)" in line for line in lines)
    assert any("[*] Images Enumeration (images:1)" in line for line in lines)
    assert sum("root:secret" in line for line in lines) == 1
    assert all(len(line.split("\t", 3)) == 4 for line in lines)


def test_gitlab_registry_only_has_one_service_line() -> None:
    payload = {
        "host": "host",
        "port": 5050,
        "is_gitlab": True,
        "status": "detected",
        "gitlab_surface": "container_registry",
        "auth_required": True,
        "container_registry": {
            "host": "host",
            "port": 5050,
            "is_registry": True,
            "is_gitlab": True,
            "auth_required": True,
            "status": "auth_required",
        },
    }
    lines = render_record_with_module(gitlab_render, AuditRecord.from_mapping(payload, module="gitlab"), "txt")
    assert lines == ["GITLAB\thost\t5050\t [*] GitLab Container Registry (auth required:True) (version:unknown)"]


def test_gitlab_credential_stage_does_not_emit_empty_web_or_oci_inventory() -> None:
    args = parse_args(["gitlab", "-t", "http://host:8080", "--token", "lab-token", "--images", "--enum-cve"])
    spec = gitlab_stage.build_gitlab_spec(args)
    assert spec.defer_detect_output_until_auth is True
    web_record = AuditRecord.from_mapping(
        {
            "host": "host",
            "port": 8080,
            "is_gitlab": True,
            "status": "valid_credentials",
            "gitlab_surface": "web",
            "auth_required": None,
            "token_valid": True,
            "provided_credentials_ok": True,
            "token_provided": True,
            "public_projects": [],
            "token_access": [],
        },
        module="gitlab",
    )
    web_lines = render_record_with_module(spec.render_module, web_record, "txt")
    assert not any("projects:0" in line for line in web_lines)
    assert not any("Token Project Access" in line for line in web_lines)

    registry_record = AuditRecord.from_mapping(
        {
            "host": "host",
            "port": 5050,
            "is_gitlab": True,
            "status": "valid_credentials",
            "gitlab_surface": "container_registry",
            "auth_required": True,
            "provided_credentials_ok": True,
            "provided_username": "root",
            "provided_password": "secret",
            "container_registry": {
                "host": "host",
                "port": 5050,
                "status": "valid_credentials",
                "is_registry": True,
                "is_gitlab": True,
                "auth_required": True,
                "gitlab": True,
                "gitlab_repositories": [],
                "show_images": True,
            },
        },
        module="gitlab",
    )
    registry_lines = render_record_with_module(spec.render_module, registry_record, "txt")
    assert registry_lines == [
        "GITLAB\thost\t5050\t [*] GitLab Container Registry (auth required:True) (version:unknown)",
        "GITLAB\thost\t5050\t [+] root:secret",
    ]


def test_gitlab_definitively_rejected_pair_has_one_negative_line() -> None:
    payload = {
        "host": "host",
        "port": 8080,
        "is_gitlab": True,
        "status": "invalid_credentials",
        "gitlab_surface": "web",
        "provided_credentials_ok": False,
        "provided_username": "root",
        "provided_password": "wrong",
        "auth_required": True,
    }
    lines = render_record_with_module(gitlab_render, AuditRecord.from_mapping(payload, module="gitlab"), "txt")
    assert lines == [
        "GITLAB\thost\t8080\t [*] GitLab (auth required:True) (version:unknown)",
        "GITLAB\thost\t8080\t [-] root:wrong",
    ]


class _RecordingConsole:
    def __init__(self) -> None:
        self.paint_calls: list[tuple[str, str]] = []

    def _paint(self, value: str, color: str, _stream: object) -> str:
        self.paint_calls.append((value, color))
        return value

    def plain(self, _value: str, _color: str | None = None) -> None:
        pass


@pytest.mark.parametrize("product", ("docker-registry", "harbor", "nexus", "gitlab"))
def test_product_output_color_follows_airflow_rules(product: str) -> None:
    args = parse_args([product, "-t", "http://host:5000"])
    spec = (
        gitlab_stage.build_gitlab_spec(args)
        if product == "gitlab"
        else registry_stage.build_registry_spec(args, product=product)
    )
    console = _RecordingConsole()
    assert spec.colorize is not None
    tag = product.upper()
    assert spec.colorize(console, f"{tag}\thost\t5000\t [*] Service (auth required:True)")
    assert ("auth required:True", "bright_green") in console.paint_calls
    console.paint_calls.clear()
    assert spec.colorize(console, f"{tag}\thost\t5000\t [*] Images Enumeration (images:2)")
    assert ("images:2", "true_red") in console.paint_calls
    assert any(color == "white" and "Images Enumeration" in text for text, color in console.paint_calls)
    console.paint_calls.clear()
    assert spec.colorize(console, f"{tag}\thost\t5000\t [*] Images Enumeration (images:0)")
    assert ("images:0", "bright_green") in console.paint_calls


@pytest.mark.parametrize("product", ("docker-registry", "harbor", "nexus", "gitlab"))
@pytest.mark.parametrize("value", ("redposture/demo-api:latest", "DB_PASSWORD=postgres"))
def test_product_inventory_values_are_orange_in_terminal(product: str, value: str) -> None:
    args = parse_args([product, "-t", "http://host:5000"])
    spec = (
        gitlab_stage.build_gitlab_spec(args)
        if product == "gitlab"
        else registry_stage.build_registry_spec(args, product=product)
    )
    console = _RecordingConsole()
    assert spec.colorize is not None
    assert spec.colorize(console, f"{product.upper()}\thost\t5000\t {value}")
    assert (f" {value}", "orange") in console.paint_calls
    assert ("\thost\t5000", "white") in console.paint_calls


@pytest.mark.parametrize("product", ("docker-registry", "harbor", "nexus", "gitlab"))
@pytest.mark.parametrize(
    ("payload", "value"),
    [
        ("[*] Tags Enumeration redposture/demo-api (tags:3)", "redposture/demo-api"),
        ("[*] Metadata redposture/demo-api:latest", "redposture/demo-api:latest"),
        ("[*] Inspect redposture/demo-api:latest (layers:1)", "redposture/demo-api:latest"),
        ("[+] Download complete path=/tmp/image size=1.5KB", "/tmp/image"),
    ],
)
def test_product_section_references_are_orange_but_headings_remain_white(
    product: str, payload: str, value: str
) -> None:
    args = parse_args([product, "-t", "http://host:5000"])
    spec = (
        gitlab_stage.build_gitlab_spec(args)
        if product == "gitlab"
        else registry_stage.build_registry_spec(args, product=product)
    )
    console = _RecordingConsole()
    assert spec.colorize is not None
    assert spec.colorize(console, f"{product.upper()}\thost\t5000\t {payload}")
    assert (value, "orange") in console.paint_calls
    assert any(
        color == "white" and any(name in text for name in ("Enumeration", "Metadata", "Inspect", "Download complete"))
        for text, color in console.paint_calls
    )


def test_gitlab_web_unknown_version_is_on_service_line_only() -> None:
    record = AuditRecord.from_mapping(
        {"host": "host", "port": 8080, "is_gitlab": True, "status": "valid_credentials", "auth_required": True},
        module="gitlab",
    )
    lines = render_record_with_module(gitlab_render, record, "txt")
    assert lines == ["GITLAB\thost\t8080\t [*] GitLab (auth required:True) (version:unknown)"]


def test_registry_protocol_version_is_not_mistaken_for_server_version() -> None:
    spec = registry_stage.build_registry_spec(
        parse_args(["docker-registry", "-t", "http://host:5000"]), product="docker-registry"
    )
    record = AuditRecord.from_mapping(
        {
            "host": "host",
            "port": 5000,
            "is_registry": True,
            "status": "valid_credentials",
            "auth_required": True,
            "registry_api_version": "registry/2.0",
            "provided_username": "registry",
            "provided_password": "registry",
        },
        module="docker-registry",
    )
    lines = render_record_with_module(spec.render_module, record, "txt")
    assert lines[0].endswith("Docker Registry (auth required:True) (version:unknown)")
    assert not any("(version:2.0)" in line for line in lines)


def test_product_renderers_leave_json_payloads_unchanged() -> None:
    args = parse_args(["harbor", "-t", "http://host:5000"])
    spec = registry_stage.build_registry_spec(args, product="harbor")
    record = AuditRecord.from_mapping(
        {
            "host": "host",
            "port": 5000,
            "status": "detected",
            "is_registry": True,
            "is_harbor": True,
            "auth_required": True,
            "harbor_info": {"harbor_version": "v2.11.1"},
        },
        module="harbor",
    )
    from redposture_core.modules.registry import actions as legacy

    assert render_record_with_module(spec.render_module, record, "json") == render_record_with_module(
        legacy, record, "json"
    )
