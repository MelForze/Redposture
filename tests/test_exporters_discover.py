from __future__ import annotations

from redposture_core.exporters.discover import (
    fetch_fingerprint_bodies_default,
    scan_exporter_presence,
    scan_presence_port_task,
    scan_presence_task,
)


def _details(status: int | None, body: str, *, error: str | None = None) -> dict[str, object]:
    return {
        "status": status,
        "body": body,
        "elapsed_ms": 7,
        "content_type": "text/plain; version=0.0.4",
        "error": error,
        "truncated": False,
    }


def test_scan_presence_task_marker_and_negative_paths() -> None:
    exporter = {"name": "node_exporter", "port": 9100, "markers": ("node_cpu_seconds_total",)}

    record, hit = scan_presence_task(
        "node-1",
        exporter,
        1.0,
        0,
        http_get_details_fn=lambda *_a, **_k: _details(200, "node_cpu_seconds_total 1\n"),
    )
    assert record["detected"] is True
    assert record["method"] == "marker"
    assert hit == {
        "exporter": "node_exporter",
        "port": 9100,
        "url": "http://node-1:9100/metrics",
        "status": 200,
        "method": "marker",
    }

    negative, no_hit = scan_presence_task(
        "node-1",
        exporter,
        1.0,
        0,
        http_get_details_fn=lambda *_a, **_k: _details(503, "node_cpu_seconds_total 1\n"),
    )
    assert negative["detected"] is False
    assert no_hit is None


def test_scan_presence_port_task_resolution_paths() -> None:
    exporters = [
        {
            "name": "node_exporter",
            "port": 9100,
            "markers": (),
            "strong_markers": ("node_cpu_seconds_total",),
            "weak_markers": ("node_memory_MemAvailable_bytes",),
        },
        {
            "name": "blackbox_exporter",
            "port": 9115,
            "markers": (),
            "strong_markers": ("probe_success",),
        },
    ]

    record, hit = scan_presence_port_task(
        "node-1",
        9100,
        exporters,
        1.0,
        0,
        http_get_details_fn=lambda *_a, **_k: _details(
            200,
            "# HELP node_cpu_seconds_total x\n"
            "# TYPE node_cpu_seconds_total counter\n"
            'node_cpu_seconds_total{cpu="0"} 1\n',
        ),
        fetch_fingerprint_bodies_fn=lambda *_a, **_k: ("", ""),
    )
    assert record["detected"] is True
    assert record["exporter"] == "node_exporter"
    assert record["candidate_count"] == 1
    assert hit is not None and hit["exporter"] == "node_exporter"

    unknown, no_hit = scan_presence_port_task(
        "node-1",
        9100,
        exporters,
        1.0,
        0,
        http_get_details_fn=lambda *_a, **_k: _details(500, ""),
    )
    assert unknown["detected"] is False
    assert unknown["method"] == "none"
    assert no_hit is None


def test_fetch_fingerprint_bodies_default_uses_injected_client() -> None:
    calls: list[str] = []

    def fake_get(url: str, *_args, **_kwargs) -> dict[str, object]:
        calls.append(url)
        if url.endswith("/debug/vars"):
            return _details(200, '{"cmdline":["node_exporter"]}')
        return _details(200, "node_exporter --web.listen-address=:9100")

    debug_vars, cmdline = fetch_fingerprint_bodies_default("node-1", 9100, 1.0, 0, http_get_details_fn=fake_get)
    assert "node_exporter" in debug_vars
    assert "node_exporter" in cmdline
    assert calls == ["http://node-1:9100/debug/vars", "http://node-1:9100/debug/pprof/cmdline?debug=1"]


def test_scan_exporter_presence_handles_task_exceptions_and_summary() -> None:
    emitted: list[str] = []

    def raising_task(host: str, port: int, _exporters, _timeout: float, _retries: int):
        raise RuntimeError(f"boom {host}:{port}")

    checks, found, by_host = scan_exporter_presence(
        ["node-1"],
        1.0,
        None,
        output_format="txt",
        emit_line=emitted.append,
        workers=1,
        retries=0,
        discovery_exporters=[{"name": "node_exporter", "port": 9100, "markers": ("node_cpu_seconds_total",)}],
        custom_ports=[9100],
        scan_task_fn=raising_task,
        show_progress=False,
    )
    assert checks == 1
    assert found == 0
    assert by_host == {"node-1": []}
    assert any("boom node-1:9100" in line for line in emitted)
    assert emitted[-1].startswith("SCAN")
    assert "found=0" in emitted[-1]
