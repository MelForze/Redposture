from __future__ import annotations

from pathlib import Path

from honeycore.utils import collect_scan_targets, normalize_ip_literal, normalize_scan_host


def test_normalize_scan_host_strips_scheme_and_port() -> None:
    assert normalize_scan_host("http://10.0.0.1:9115") == "10.0.0.1"
    assert normalize_scan_host(" 10.0.0.2 ") == "10.0.0.2"


def test_normalize_ip_literal_accepts_only_ip_addresses() -> None:
    assert normalize_ip_literal("10.0.0.1") == "10.0.0.1"
    assert normalize_ip_literal("http://10.0.0.2:9115") == "10.0.0.2"
    assert normalize_ip_literal("honeypot.example.com") is None


def test_collect_scan_targets_deduplicates_and_ignores_comments(tmp_path: Path) -> None:
    hosts_file = tmp_path / "hosts.txt"
    hosts_file.write_text(
        "# comment\n10.0.0.1\nhttp://10.0.0.2:9115\n10.0.0.1 # dup\n",
        encoding="utf-8",
    )

    hosts = collect_scan_targets(f"10.0.0.3,10.0.0.2,{hosts_file}")
    assert hosts == ["10.0.0.3", "10.0.0.2", "10.0.0.1"]


def test_collect_scan_targets_expands_cidr() -> None:
    hosts = collect_scan_targets("10.0.1.0/30")
    assert hosts == ["10.0.1.1", "10.0.1.2"]
