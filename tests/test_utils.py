from __future__ import annotations

from pathlib import Path

import pytest

from redposture_core.utils import (
    collect_scan_ports,
    collect_scan_targets,
    normalize_ip_literal,
    normalize_scan_host,
    parse_proxmox_api_token_auth,
)


def test_normalize_scan_host_strips_scheme_and_port() -> None:
    assert normalize_scan_host("http://10.0.0.1:9115") == "10.0.0.1"
    assert normalize_scan_host(" 10.0.0.2 ") == "10.0.0.2"


def test_normalize_ip_literal_accepts_only_ip_addresses() -> None:
    assert normalize_ip_literal("10.0.0.1") == "10.0.0.1"
    assert normalize_ip_literal("http://10.0.0.2:9115") == "10.0.0.2"
    assert normalize_ip_literal("redposture.example.com") is None


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


def test_collect_scan_targets_rejects_invalid_cidr() -> None:
    with pytest.raises(ValueError, match="invalid network target"):
        collect_scan_targets("10.0.0.0/999")


def test_collect_scan_targets_rejects_non_network_slash_tokens() -> None:
    with pytest.raises(ValueError, match="invalid network target"):
        collect_scan_targets("not_a_host/24")


def test_collect_scan_ports_deduplicates_and_expands_ranges() -> None:
    ports = collect_scan_ports("9100,9115,9200-9202,9115")
    assert ports == [9100, 9115, 9200, 9201, 9202]


def test_collect_scan_ports_accepts_single_port() -> None:
    ports = collect_scan_ports("9100")
    assert ports == [9100]


def test_collect_scan_ports_accepts_file_path(tmp_path: Path) -> None:
    ports_file = tmp_path / "ports.txt"
    ports_file.write_text("# list\n9100\n9115,9121\n9200-9201\n", encoding="utf-8")
    ports = collect_scan_ports(str(ports_file))
    assert ports == [9100, 9115, 9121, 9200, 9201]


def test_collect_scan_ports_rejects_invalid_values() -> None:
    with pytest.raises(ValueError):
        collect_scan_ports("abc")
    with pytest.raises(ValueError):
        collect_scan_ports("70000")
    with pytest.raises(ValueError):
        collect_scan_ports("9300-9200")


def test_parse_proxmox_api_token_auth_parses_standard_header() -> None:
    token_id, token_secret = parse_proxmox_api_token_auth("PVEAPIToken=prometheus@pve!metrics=super-secret-token-value")
    assert token_id == "prometheus@pve!metrics"
    assert token_secret == "super-secret-token-value"


def test_parse_proxmox_api_token_auth_accepts_space_variant() -> None:
    token_id, token_secret = parse_proxmox_api_token_auth("PVEAPIToken prometheus@pve!metrics=super-secret-token-value")
    assert token_id == "prometheus@pve!metrics"
    assert token_secret == "super-secret-token-value"


def test_parse_proxmox_api_token_auth_rejects_other_schemes() -> None:
    assert parse_proxmox_api_token_auth("Basic dXNlcjpwYXNz") == (None, None)
