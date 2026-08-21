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


def test_endpoint_slug_distinguishes_previously_colliding_paths() -> None:
    assert endpoint_slug("/a/b") != endpoint_slug("/a__b")
    assert endpoint_slug("/ümlaut") != endpoint_slug("/ämlaut")


def test_endpoint_slug_distinguishes_repeated_leading_slashes() -> None:
    assert endpoint_slug("/a") != endpoint_slug("//a")


def test_endpoint_slug_distinguishes_long_paths_with_the_same_prefix() -> None:
    prefix = "/" + ("a" * 120)
    first = endpoint_slug(prefix + "-first")
    second = endpoint_slug(prefix + "-second")

    assert first != second
    assert len(first) <= 96
    assert len(second) <= 96


def test_save_collect_body_preserves_binary_pprof_bytes(tmp_path: Path) -> None:
    raw = b"\x1f\x8b\x08\x00\xff\xfe\x80\x00\x01"
    rel_path, size = save_collect_body(
        str(tmp_path),
        {
            "host": "2001:db8::1",
            "exporter": "node_exporter",
            "port": 9100,
            "endpoint": "/debug/pprof/heap",
            "content_type": "application/octet-stream",
            "body": raw.decode("utf-8", errors="replace"),
            "raw_body": raw,
        },
    )

    assert rel_path is not None and rel_path.endswith(".bin")
    assert size == len(raw)
    assert (tmp_path / rel_path).read_bytes() == raw
