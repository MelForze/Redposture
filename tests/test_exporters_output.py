from __future__ import annotations

from redposture_core.exporters.output import (
    extract_display_port,
    format_collect_record,
    format_scan_record,
)


def test_format_scan_record_preserves_existing_text_contract() -> None:
    assert (
        format_scan_record(
            {
                "host": "127.0.0.1",
                "port": 9100,
                "exporter": "node_exporter",
                "detected": True,
            },
            "txt",
        )
        == "SCAN    \t127.0.0.1\t9100\t [+] Node Exporter"
    )


def test_format_collect_record_preserves_existing_text_contract() -> None:
    assert (
        format_collect_record(
            {
                "host": "127.0.0.1",
                "port": 9308,
                "exporter": "kafka_exporter",
                "endpoint": "/debug/pprof/cmdline?debug=1",
                "url": "http://127.0.0.1:9308/debug/pprof/cmdline?debug=1",
                "ok": True,
                "error": None,
            },
            "txt",
        )
        == "COLLECT \t127.0.0.1\t9308\t [+] Kafka Exporter url=http://127.0.0.1:9308/debug/pprof/cmdline?debug=1"
    )


def test_extract_display_port_handles_urls_and_plain_targets() -> None:
    assert extract_display_port("http://127.0.0.1:19100/metrics") == "19100"
    assert extract_display_port("https://example.local/path") == "443"
    assert extract_display_port("example.local:8080") == "8080"
    assert extract_display_port("example.local") == "-"
