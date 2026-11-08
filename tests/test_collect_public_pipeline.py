"""The public CLI must use the same streaming pipeline as large target lists."""

from __future__ import annotations

import json
import threading
from urllib.parse import urlsplit

from redposture_core import cli
from scripts.performance_http_fixtures import response
from scripts.performance_http_server import AsyncHttpFixture
from scripts.profile_workflow_performance import ENDPOINTS, fixture_body


def profiles(path, port):
    exporter = {"name": "mysqld_exporter", "port": port, "markers": ["mysql_exporter_build_info"]}
    path.write_text(
        json.dumps(
            {"discovery_exporters": [exporter], "collect_exporters": [exporter], "collect_debug_endpoints": ENDPOINTS}
        )
    )


def command(target, profile, output, ports):
    return [
        "exporters",
        "collect",
        "-t",
        target,
        "--profiles-file",
        str(profile),
        "--ports",
        ports,
        "--workers",
        "2",
        "--timeout",
        "1",
        "--retries",
        "0",
        "--no-color",
        "--format",
        "json",
        "-o",
        str(output),
    ]


def test_one_target_collect_reuses_the_detected_metrics_body(tmp_path, capsys):
    def router(method, path, headers, body, host):
        route = urlsplit(path).path
        return (
            response(200, fixture_body(route), headers={"Content-Type": "text/plain"})
            if route in ENDPOINTS
            else response(404, "not found")
        )

    fixture = AsyncHttpFixture(router)
    fixture.start()
    try:
        profile = tmp_path / "profiles.json"
        output = tmp_path / "result.jsonl"
        profiles(profile, fixture.port)
        assert cli.main(command(f"http://127.0.0.1:{fixture.port}", profile, output, str(fixture.port))) == 0
        rows = [json.loads(line) for line in output.read_text().splitlines()]
        data = [row for row in rows if "endpoint" in row]
        assert {row["endpoint"]: row["body"] for row in data} == {path: fixture_body(path) for path in ENDPOINTS}
        assert sum(n for (host, method, path), n in fixture.calls.items() if path == "/metrics") == 1
        assert "\x1b" not in output.read_text()
        capsys.readouterr()
    finally:
        fixture.close()


def test_public_collect_starts_data_before_the_last_detection_finishes(tmp_path, capsys):
    data_started = threading.Event()
    slow_checks = []

    def fast(method, path, headers, body, host):
        route = urlsplit(path).path
        if route == "/debug/vars":
            data_started.set()
        return (
            response(200, fixture_body(route), headers={"Content-Type": "text/plain"})
            if route in ENDPOINTS
            else response(404, "not found")
        )

    def slow(method, path, headers, body, host):
        if path == "/metrics" and not slow_checks:
            slow_checks.append(data_started.is_set())
        return fast(method, path, headers, body, host)

    first = AsyncHttpFixture(fast)
    second = AsyncHttpFixture(slow, delay=lambda host, path: 0.2 if path == "/metrics" else 0)
    first.start()
    second.start()
    try:
        profile = tmp_path / "profiles.json"
        output = tmp_path / "result.jsonl"
        profiles(profile, first.port)
        targets = f"http://127.0.0.1:{first.port},http://127.0.0.1:{second.port}"
        assert cli.main(command(targets, profile, output, f"{first.port},{second.port}")) == 0
        rows = [json.loads(line) for line in output.read_text().splitlines()]
        assert len([row for row in rows if "endpoint" in row]) == 6
        assert slow_checks == [True], "data waited for the complete discovery pass"
        capsys.readouterr()
    finally:
        first.close()
        second.close()


def test_adaptive_collect_reuses_one_connection_without_delaying_completed_metrics(tmp_path, capsys):
    output = tmp_path / "result.jsonl"
    saw_metrics_before_vars = []

    def router(method, path, headers, body, host):
        route = urlsplit(path).path
        if route == "/debug/vars":
            rows = [json.loads(line) for line in output.read_text().splitlines()] if output.exists() else []
            saw_metrics_before_vars.append(any(row.get("endpoint") == "/metrics" for row in rows))
        return response(200, fixture_body(route), headers={"Content-Type": "text/plain"})

    fixture = AsyncHttpFixture(router, delay=lambda host, path: 0.1 if path == "/debug/vars" else 0)
    fixture.start()
    try:
        profile = tmp_path / "profiles.json"
        profiles(profile, fixture.port)
        assert cli.main(command(f"http://127.0.0.1:{fixture.port}", profile, output, str(fixture.port))) == 0
        assert saw_metrics_before_vars == [True]
        assert fixture.stats["connections"] == 1
        assert fixture.stats["http_requests"] == 3
        capsys.readouterr()
    finally:
        fixture.close()
