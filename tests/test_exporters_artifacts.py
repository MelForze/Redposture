from __future__ import annotations

from pathlib import Path

from redposture_core.exporters.artifacts import endpoint_slug, safe_fs_part, save_collect_body


def test_endpoint_slug_keeps_existing_collect_response_path_shape() -> None:
    assert endpoint_slug("") == "root"
    assert endpoint_slug("/") == "root"
    assert endpoint_slug("/debug/pprof/cmdline?debug=1") == "debug__pprof__cmdline__q__debug__1"


def test_safe_fs_part_sanitizes_and_limits_path_component() -> None:
    assert safe_fs_part("  ../bad host:9200  ", "fallback") == "bad_host_9200"
    assert safe_fs_part("!!!", "fallback") == "fallback"
    assert len(safe_fs_part("a" * 200, "fallback")) == 96


def test_save_collect_body_writes_sanitized_relative_path(tmp_path: Path) -> None:
    rel_path, size = save_collect_body(
        str(tmp_path),
        {
            "host": "../10.0.0.1",
            "exporter": "kafka/exporter",
            "port": 9308,
            "endpoint": "/debug/pprof/cmdline?debug=1",
            "body": "secret-body\n",
        },
    )

    assert rel_path == "10.0.0.1/kafka_exporter/9308_debug__pprof__cmdline__q__debug__1.txt"
    assert size == len(b"secret-body\n")
    assert (tmp_path / rel_path).read_text(encoding="utf-8") == "secret-body\n"
