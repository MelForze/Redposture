from __future__ import annotations

from collections.abc import Callable

import pytest

from redposture_core.console import Console
from redposture_core.stage_clickhouse import _render_colored_clickhouse_line
from redposture_core.stage_consul import _render_colored_consul_line
from redposture_core.stage_elastic import _render_colored_elastic_line
from redposture_core.stage_etcd import _render_colored_etcd_line
from redposture_core.stage_gitlab import _render_colored_gitlab_line
from redposture_core.stage_grafana import _render_colored_grafana_line
from redposture_core.stage_grpc import _render_colored_grpc_line
from redposture_core.stage_kafka import _render_colored_kafka_line
from redposture_core.stage_kubeapi import _render_colored_kubeapi_line
from redposture_core.stage_postgres import _render_colored_postgres_line
from redposture_core.stage_proxmox import _render_colored_proxmox_line
from redposture_core.stage_qdrant import _render_colored_qdrant_line
from redposture_core.stage_redis import _render_colored_redis_line
from redposture_core.stage_registry import _render_colored_registry_line
from redposture_core.stage_zookeeper import _render_colored_zookeeper_line


class _RecordingConsole:
    def __init__(self) -> None:
        self.paint_calls: list[tuple[str, str]] = []
        self.rendered_lines: list[str] = []

    def _paint(self, text: str, color: str, stream) -> str:
        _ = stream
        self.paint_calls.append((text, color))
        return text

    def plain(self, text: str, color: str | None = None) -> None:
        _ = color
        self.rendered_lines.append(text)


def _contains_paint(calls: list[tuple[str, str]], text_fragment: str, color: str) -> bool:
    fragments = [text_fragment]
    if text_fragment.startswith("(") and text_fragment.endswith(")"):
        fragments.append(text_fragment[1:-1])
    return any(color_name == color and any(fragment in text for fragment in fragments) for text, color_name in calls)


def _assert_parentheses_are_not_colored(calls: list[tuple[str, str]]) -> None:
    for text, color in calls:
        if color == "white":
            continue
        assert "(" not in text
        assert ")" not in text


_Renderer = Callable[[_RecordingConsole, str], bool]


@pytest.mark.parametrize(
    ("renderer", "tag"),
    [
        (_render_colored_redis_line, "REDIS"),
        (_render_colored_etcd_line, "ETCD"),
        (_render_colored_kafka_line, "KAFKA"),
        (_render_colored_zookeeper_line, "ZOOKEEPER"),
        (_render_colored_postgres_line, "POSTGRES"),
        (_render_colored_clickhouse_line, "CLICKHOUSE"),
        (_render_colored_qdrant_line, "QDRANT"),
        (_render_colored_consul_line, "CONSUL"),
        (_render_colored_elastic_line, "ELASTIC"),
        (_render_colored_kubeapi_line, "KUBEAPI"),
        (_render_colored_grafana_line, "GRAFANA"),
        (_render_colored_gitlab_line, "GITLAB"),
        (_render_colored_registry_line, "REGISTRY"),
        (_render_colored_proxmox_line, "PROXMOX"),
        (_render_colored_grpc_line, "GRPC"),
    ],
)
def test_stage_colored_renderers_map_marker_colors(renderer: _Renderer, tag: str) -> None:
    expected_marker_colors = {
        "[*]": "cyan",
        "[+]": "bright_green",
        "[-]": "red",
        "[!]": "red",
    }
    for marker, expected_color in expected_marker_colors.items():
        console = _RecordingConsole()
        line = f"{tag}\t127.0.0.1\t9999\t {marker} test payload"
        assert renderer(console, line) is True
        assert (marker, expected_color) in console.paint_calls
        assert console.rendered_lines


@pytest.mark.parametrize(
    "renderer",
    [
        _render_colored_redis_line,
        _render_colored_etcd_line,
        _render_colored_kafka_line,
        _render_colored_zookeeper_line,
        _render_colored_postgres_line,
        _render_colored_clickhouse_line,
        _render_colored_qdrant_line,
        _render_colored_consul_line,
        _render_colored_elastic_line,
        _render_colored_kubeapi_line,
        _render_colored_grafana_line,
        _render_colored_gitlab_line,
        _render_colored_registry_line,
        _render_colored_proxmox_line,
        _render_colored_grpc_line,
    ],
)
def test_stage_colored_renderers_ignore_other_service_tags(renderer: _Renderer) -> None:
    console = _RecordingConsole()
    assert renderer(console, "OTHER\t127.0.0.1\t9999\t [+] test payload") is False
    assert console.paint_calls == []
    assert console.rendered_lines == []


def test_render_colored_redis_colors_auth_false_and_keys() -> None:
    console = _RecordingConsole()
    line = "REDIS\t127.0.0.1\t6379\t [*] Redis Database (auth required:False) (keys:2)"
    assert _render_colored_redis_line(console, line) is True
    assert _contains_paint(console.paint_calls, "(auth required:False)", "red")
    assert _contains_paint(console.paint_calls, "(keys:2)", "red")
    _assert_parentheses_are_not_colored(console.paint_calls)


def test_render_colored_etcd_colors_auth_unknown_yellow() -> None:
    console = _RecordingConsole()
    line = "ETCD\t127.0.0.1\t2379\t [*] etcd Database (auth required:unknown)"
    assert _render_colored_etcd_line(console, line) is True
    assert _contains_paint(console.paint_calls, "(auth required:unknown)", "yellow")


def test_render_colored_kafka_colors_topics_red() -> None:
    console = _RecordingConsole()
    line = "KAFKA\t127.0.0.1\t9092\t [+] anonymous access (topics:3)"
    assert _render_colored_kafka_line(console, line) is True
    assert _contains_paint(console.paint_calls, "(topics:3)", "red")


def test_render_colored_zookeeper_colors_znodes_red() -> None:
    console = _RecordingConsole()
    line = "ZOOKEEPER\t127.0.0.1\t2181\t [+] anonymous access (znodes:4)"
    assert _render_colored_zookeeper_line(console, line) is True
    assert _contains_paint(console.paint_calls, "(znodes:4)", "red")


@pytest.mark.parametrize(
    ("renderer", "tag", "port"),
    [
        (_render_colored_zookeeper_line, "ZOOKEEPER", 2181),
    ],
)
def test_zookeeper_compatible_detail_metadata_is_white(
    renderer: _Renderer,
    tag: str,
    port: int,
) -> None:
    console = _RecordingConsole()
    metadata = "(children:0,bytes:18)"
    line = f"{tag}\t127.0.0.1\t{port}\t /clickhouse {metadata}"

    assert renderer(console, line) is True
    assert (metadata, "white") in console.paint_calls
    assert any("/clickhouse" in text and color == "orange" for text, color in console.paint_calls)


def test_render_colored_postgres_colors_caps_and_dbs() -> None:
    console = _RecordingConsole()
    line = (
        "POSTGRES\t127.0.0.1\t5432\t [+] postgres:postgres (DBs:2) "
        "(superuser:False) (execute:unknown) (read:True) (auth required:unknown)"
    )
    assert _render_colored_postgres_line(console, line) is True
    assert _contains_paint(console.paint_calls, "(superuser:False)", "bright_green")
    assert _contains_paint(console.paint_calls, "(execute:unknown)", "yellow")
    assert _contains_paint(console.paint_calls, "(read:True)", "red")
    assert _contains_paint(console.paint_calls, "(DBs:2)", "orange")
    assert _contains_paint(console.paint_calls, "(auth required:unknown)", "yellow")


def test_render_colored_clickhouse_colors_caps_and_dbs() -> None:
    console = _RecordingConsole()
    line = (
        "CLICKHOUSE\t127.0.0.1\t9000\t [+] default:<empty> "
        "(read:false) (execute:unknown) (admin:true) (DBs:2) (auth required:unknown)"
    )
    assert _render_colored_clickhouse_line(console, line) is True
    assert _contains_paint(console.paint_calls, "(read:false)", "bright_green")
    assert _contains_paint(console.paint_calls, "(execute:unknown)", "yellow")
    assert _contains_paint(console.paint_calls, "(admin:true)", "red")
    assert _contains_paint(console.paint_calls, "(DBs:2)", "orange")
    assert _contains_paint(console.paint_calls, "(auth required:unknown)", "yellow")


def test_render_colored_qdrant_colors_rce_and_idor() -> None:
    console = _RecordingConsole()
    line = "QDRANT\t127.0.0.1\t6333\t [!] possible issue RCE! (idor:true) (collections:1)"
    assert _render_colored_qdrant_line(console, line) is True
    assert _contains_paint(console.paint_calls, "RCE!", "orange")
    assert _contains_paint(console.paint_calls, "(idor:true)", "red")
    assert _contains_paint(console.paint_calls, "(collections:1)", "red")


def test_render_colored_consul_colors_pwned_and_counts() -> None:
    console = _RecordingConsole()
    line = "CONSUL\t127.0.0.1\t8500\t [!] check result Pwned! (kv:2) (services:1) (agents:1) (auth required:unknown)"
    assert _render_colored_consul_line(console, line) is True
    assert _contains_paint(console.paint_calls, "Pwned!", "orange")
    assert _contains_paint(console.paint_calls, "(kv:2)", "red")
    assert _contains_paint(console.paint_calls, "(services:1)", "orange")
    assert _contains_paint(console.paint_calls, "(agents:1)", "orange")
    assert _contains_paint(console.paint_calls, "(auth required:unknown)", "yellow")


def test_render_colored_elastic_colors_access_and_capabilities() -> None:
    console = _RecordingConsole()
    line = (
        "ELASTIC\t127.0.0.1\t9200\t [+] apikey auth "
        "(read:True) (write:False) (manage:unknown) (manage_security:False) "
        "(auth required:unknown)"
    )
    assert _render_colored_elastic_line(console, line) is True
    assert _contains_paint(console.paint_calls, "(read:True)", "red")
    assert _contains_paint(console.paint_calls, "(write:False)", "bright_green")
    assert _contains_paint(console.paint_calls, "(manage:unknown)", "yellow")
    assert _contains_paint(console.paint_calls, "(manage_security:False)", "bright_green")


def test_render_colored_elastic_highlights_complete_secret_finding() -> None:
    console = _RecordingConsole()
    line = (
        "ELASTIC\t127.0.0.1\t9200\t [+] secret_type=bearer_token "
        'value="line one\\nsource_kind=\\"fake\\"" source_kind="document" '
        'object="logs/doc-1" index="logs" id="doc-1" path="/event/original"'
    )

    assert _render_colored_elastic_line(console, line) is True
    assert _contains_paint(
        console.paint_calls,
        (
            'secret_type=bearer_token value="line one\\nsource_kind=\\"fake\\"" '
            'source_kind="document" object="logs/doc-1" index="logs" '
            'id="doc-1" path="/event/original"'
        ),
        "orange",
    )


def test_render_colored_elastic_no_color_preserves_plain_finding(capsys: pytest.CaptureFixture[str]) -> None:
    console = Console(no_color=True)
    line = (
        'ELASTIC\t127.0.0.1\t9200\t [+] secret_type=password value="S3cr3t!" '
        'source_kind="document" object="logs/doc-1" path="/password"'
    )

    assert _render_colored_elastic_line(console, line) is True

    captured = capsys.readouterr()
    assert captured.out == f"{line}\n"
    assert "\x1b[" not in captured.out
    assert captured.err == ""


def test_render_colored_kubeapi_colors_resources() -> None:
    console = _RecordingConsole()
    line = "KUBEAPI\t127.0.0.1\t6443\t [+] token access (pods:2) (namespaces:1) (secrets:5)"
    assert _render_colored_kubeapi_line(console, line) is True
    assert _contains_paint(console.paint_calls, "(pods:2)", "orange")
    assert _contains_paint(console.paint_calls, "(namespaces:1)", "orange")
    assert _contains_paint(console.paint_calls, "(secrets:5)", "red")


def test_render_colored_grafana_colors_datasources_and_auth() -> None:
    console = _RecordingConsole()
    line = "GRAFANA\t127.0.0.1\t3000\t [+] admin:admin (datasources:4) (auth required:True)"
    assert _render_colored_grafana_line(console, line) is True
    assert _contains_paint(console.paint_calls, "(datasources:4)", "red")
    assert _contains_paint(console.paint_calls, "(auth required:True)", "bright_green")


def test_render_colored_gitlab_colors_login_page_and_repo_capabilities() -> None:
    console = _RecordingConsole()
    line = "GITLAB\t127.0.0.1\t8080\t [+] token valid (login page:False) (repo:True) (issues:True) (members:True)"
    assert _render_colored_gitlab_line(console, line) is True
    assert _contains_paint(console.paint_calls, "(login page:False)", "yellow")
    assert _contains_paint(console.paint_calls, "(repo:True)", "red")
    assert _contains_paint(console.paint_calls, "(issues:True)", "red")
    assert _contains_paint(console.paint_calls, "(members:True)", "red")


def test_render_colored_registry_colors_auth_unknown_and_images() -> None:
    console = _RecordingConsole()
    line = "REGISTRY\t127.0.0.1\t5000\t [+] anonymous access (auth required:unknown) (images:7)"
    assert _render_colored_registry_line(console, line) is True
    assert _contains_paint(console.paint_calls, "(auth required:unknown)", "yellow")
    assert _contains_paint(console.paint_calls, "(images:7)", "red")


def test_render_colored_proxmox_colors_capabilities_and_finding_payload() -> None:
    console_caps = _RecordingConsole()
    caps_line = (
        "PROXMOX\t127.0.0.1\t8006\t [+] token accepted (adduser:false) (modify:true) (backup:unknown) (read:true)"
    )
    assert _render_colored_proxmox_line(console_caps, caps_line) is True
    assert _contains_paint(console_caps.paint_calls, "(adduser:false)", "bright_green")
    assert _contains_paint(console_caps.paint_calls, "(modify:true)", "red")
    assert _contains_paint(console_caps.paint_calls, "(backup:unknown)", "yellow")
    assert _contains_paint(console_caps.paint_calls, "(read:true)", "red")

    console_finding = _RecordingConsole()
    finding_line = "PROXMOX\t127.0.0.1\t8006\t [!] credential candidate reason=jwt path=$.token sample=abc"
    assert _render_colored_proxmox_line(console_finding, finding_line) is True
    assert _contains_paint(console_finding.paint_calls, "credential candidate reason=jwt", "orange")


def test_render_colored_grpc_colors_status_and_protocol() -> None:
    console = _RecordingConsole()
    line = (
        "GRPC\t127.0.0.1\t50051\t [*] gRPC Service "
        "(transport:plaintext) (protocol:grpc-web) (reflection:enabled) "
        "(health_access:anonymous) (reflection_access:auth_required) (invoke_access:not_tested)"
    )
    assert _render_colored_grpc_line(console, line) is True
    assert _contains_paint(console.paint_calls, "(transport:plaintext)", "yellow")
    assert _contains_paint(console.paint_calls, "(protocol:grpc-web)", "orange")
    assert _contains_paint(console.paint_calls, "(reflection:enabled)", "red")
    assert _contains_paint(console.paint_calls, "(health_access:anonymous)", "red")
    assert _contains_paint(console.paint_calls, "(reflection_access:auth_required)", "bright_green")
    assert _contains_paint(console.paint_calls, "(invoke_access:not_tested)", "yellow")

    disabled_console = _RecordingConsole()
    disabled_line = line.replace("reflection:enabled", "reflection:disable")
    assert _render_colored_grpc_line(disabled_console, disabled_line) is True
    assert _contains_paint(disabled_console.paint_calls, "(reflection:disable)", "bright_green")

    unknown_console = _RecordingConsole()
    unknown_line = line.replace("reflection:enabled", "reflection:unknown")
    assert _render_colored_grpc_line(unknown_console, unknown_line) is True
    assert _contains_paint(unknown_console.paint_calls, "(reflection:unknown)", "yellow")


def test_render_colored_grpc_detail_lines_color_entities_precisely() -> None:
    console = _RecordingConsole()
    line = "GRPC\t127.0.0.1\t50061\t service=grpc.health.v1.Health grpc=OK status=SERVING"
    assert _render_colored_grpc_line(console, line) is True
    assert _contains_paint(console.paint_calls, "service=grpc.health.v1.Health", "orange")
    assert _contains_paint(console.paint_calls, "OK", "orange")
    assert _contains_paint(console.paint_calls, "SERVING", "orange")
    assert not _contains_paint(console.paint_calls, "grpc=OK", "bright_green")
    assert not _contains_paint(console.paint_calls, "status=SERVING", "bright_green")
    assert not _contains_paint(
        console.paint_calls, "service=grpc.health.v1.Health grpc=OK status=SERVING", "bright_green"
    )


def test_render_colored_grpc_detail_lines_color_methods_files_and_results() -> None:
    method_console = _RecordingConsole()
    method_line = (
        "GRPC\t127.0.0.1\t50051\t /grpc.health.v1.Health/Check "
        "input=grpc.health.v1.HealthCheckRequest output=grpc.health.v1.HealthCheckResponse"
    )
    assert _render_colored_grpc_line(method_console, method_line) is True
    assert _contains_paint(method_console.paint_calls, "/grpc.health.v1.Health/Check", "orange")

    file_console = _RecordingConsole()
    assert _render_colored_grpc_line(
        file_console,
        "GRPC\t127.0.0.1\t50051\t file=grpc_health/v1/health.proto package=grpc.health.v1 services=1",
    )
    assert _contains_paint(file_console.paint_calls, "file=grpc_health/v1/health.proto", "orange")

    invoke_console = _RecordingConsole()
    assert _render_colored_grpc_line(
        invoke_console,
        "GRPC\t127.0.0.1\t50051\t method=/grpc.health.v1.Health/Check result=ok grpc=OK elapsed_ms=1",
    )
    assert _contains_paint(invoke_console.paint_calls, "method=/grpc.health.v1.Health/Check", "orange")
    assert _contains_paint(invoke_console.paint_calls, "ok", "orange")
    assert _contains_paint(invoke_console.paint_calls, "OK", "orange")
    assert not _contains_paint(invoke_console.paint_calls, "result=ok", "bright_green")
    assert not _contains_paint(invoke_console.paint_calls, "grpc=OK", "bright_green")

    response_console = _RecordingConsole()
    assert _render_colored_grpc_line(
        response_console,
        'GRPC\t127.0.0.1\t50051\t response={"status": "SERVING"}',
    )
    assert _contains_paint(response_console.paint_calls, 'response={"status": "SERVING"}', "orange")
