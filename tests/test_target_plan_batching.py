"""Large mixed target files retain their identity while using bounded metadata."""

from __future__ import annotations

from pathlib import Path

import pytest

from redposture_core import targeting
from redposture_core.targeting import stream_scan_target_specs


def test_many_url_and_ipv6_lines_keep_order_sources_and_deduplication(tmp_path: Path) -> None:
    path = tmp_path / "targets.txt"
    lines: list[str] = []
    expected: list[str] = []
    first_lines: dict[str, int] = {}
    for index in range(2048):
        value = f"http://10.0.{index // 256}.{index % 256}:9200/root"
        lines.append(value)
        expected.append(value)
        first_lines[value] = len(lines)
        if index % 10 == 0:
            lines.append(value)
    ipv6 = "[2001:db8::1]:9200"
    lines.extend((ipv6, ipv6))
    expected.append(ipv6)
    first_lines[ipv6] = len(lines) - 1
    path.write_text("\n".join(lines) + "\n")

    plan = stream_scan_target_specs(str(path))
    specs = list(plan.iter_specs())

    assert plan.target_count == len(expected)
    assert [spec.raw for spec in specs] == expected
    assert [spec.source for spec in specs] == [f"{path}:{first_lines[value]}" for value in expected]
    assert plan.count_for_ports((80, 9200)) == len(expected)
    assert len(plan._entries) < 100


def test_explicit_port_matrix_visits_only_port_matches_without_rescanning_entries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "explicit.txt"
    lines = [
        "http://example.test:9200/root",
        "http://example.test:9300/root",
        "http://other.test:9200/root",
        "http://other.test:9300/root",
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    plan = stream_scan_target_specs(str(path))

    def unexpected_rescan(_self: object):
        raise AssertionError("explicit-port targets must not be rescanned for every matrix port")

    monkeypatch.setattr(targeting._ListTargetEntry, "iter_specs", unexpected_rescan)
    observed = {
        port: [spec.raw for spec in plan.iter_specs_for_port(port, (9200, 9300, 9400))] for port in (9200, 9300, 9400)
    }
    assert observed == {9200: lines[::2], 9300: lines[1::2], 9400: []}


def test_iter_hosts_expands_bare_ipv4_without_building_target_specs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "hosts.txt"
    path.write_text("10.0.0.1\n10.0.0.2\n10.0.0.1\n10.0.0.3\n", encoding="utf-8")
    plan = stream_scan_target_specs(str(path))

    def unexpected_spec_build(_self: object):
        raise AssertionError("host-only consumers should not build ScanTargetSpec for every IPv4 line")

    monkeypatch.setattr(targeting._IPv4LiteralTargetEntry, "iter_specs", unexpected_spec_build)
    assert list(plan.iter_hosts()) == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
