from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory

import pytest
from hypothesis import given
from hypothesis import strategies as st

from redposture_core.targeting import (
    TargetParsePolicy,
    _merge_ipv4_range,
    _range_contains,
    parse_scan_target_specs,
    parse_target_exclusions,
    stream_scan_target_specs,
)


def _specs(targets, streaming, **kwargs):
    if streaming:
        return list(stream_scan_target_specs(targets, **kwargs).iter_specs())
    return parse_scan_target_specs(targets, **kwargs)


@pytest.mark.parametrize("streaming", [False, True])
@pytest.mark.parametrize(
    "target, hosts",
    [
        ("127.0.0.1-127.0.0.3", ["127.0.0.1", "127.0.0.2", "127.0.0.3"]),
        ("0.0.0.0-0.0.0.0", ["0.0.0.0"]),
        ("255.255.255.254-255.255.255.255", ["255.255.255.254", "255.255.255.255"]),
        ("10.0.0.255 - 10.0.1.0", ["10.0.0.255", "10.0.1.0"]),
    ],
)
def test_ipv4_range_includes_both_endpoints(streaming, target, hosts):
    specs = _specs(target, streaming)
    assert [spec.host for spec in specs] == hosts
    assert all(spec.raw == target and spec.explicit_port is None for spec in specs)


@pytest.mark.parametrize("streaming", [False, True])
def test_ipv4_range_deduplicates_cidr_and_literal_overlaps(streaming):
    specs = _specs(
        "10.0.0.1,10.0.0.0/30,10.0.0.0-10.0.0.4,10.0.0.3-10.0.0.5,10.0.0.2",
        streaming,
        exclude_targets="10.0.0.2-10.0.0.3,10.0.0.5",
    )
    assert [spec.host for spec in specs] == ["10.0.0.1", "10.0.0.0", "10.0.0.4"]


@pytest.mark.parametrize("streaming", [False, True])
def test_ipv4_ranges_work_in_bom_files_and_exclusion_files(tmp_path, streaming):
    targets = tmp_path / "targets.txt"
    targets.write_text("\ufeff 10.0.0.1-10.0.0.4 # range\r\n", encoding="utf-8")
    exclusions = tmp_path / "exclude.txt"
    exclusions.write_text("\ufeff 10.0.0.2-10.0.0.3\r\n", encoding="utf-8")
    specs = _specs(str(targets), streaming, exclude_targets=str(exclusions))
    assert [spec.host for spec in specs] == ["10.0.0.1", "10.0.0.4"]
    assert all(spec.source == f"{targets.resolve()}:1" for spec in specs)


@pytest.mark.parametrize("streaming", [False, True])
def test_fully_excluded_range_is_empty(streaming):
    assert _specs("10.0.0.1-10.0.0.3", streaming, exclude_targets="10.0.0.0-10.0.0.4") == []


@pytest.mark.parametrize("streaming", [False, True])
@pytest.mark.parametrize("target", ["db-01.example.test", "10.0.0.1-node.example.test", "123-456.example.test"])
def test_dns_names_with_hyphens_remain_single_targets(streaming, target):
    assert [spec.host for spec in _specs(target, streaming)] == [target]
    assert parse_target_exclusions(target).matches(target)


@pytest.mark.parametrize("parse", [parse_scan_target_specs, stream_scan_target_specs, parse_target_exclusions])
@pytest.mark.parametrize(
    "target",
    [
        "10.0.0.3-10.0.0.1",
        "10.0.0.1-10.0.0.256",
        "10.0.0.1-3",
        "10.0.0.1-",
        "-10.0.0.1",
        "10.0.0.1-10.0.0.2-10.0.0.3",
        "10.0.0.1-10.0.0.3:8080",
    ],
)
def test_invalid_ipv4_ranges_are_rejected_before_networking(parse, target):
    with pytest.raises(ValueError, match="invalid IPv4 range"):
        parse(target)


def test_bad_range_in_file_reports_line(tmp_path):
    targets = tmp_path / "targets.txt"
    targets.write_text("# comment\n10.0.0.5-10.0.0.1\n", encoding="utf-8")
    with pytest.raises(ValueError, match=rf"{targets}:2"):
        stream_scan_target_specs(str(targets))


def test_entire_ipv4_range_is_lazy_and_exclusions_are_subtracted():
    plan = stream_scan_target_specs("0.0.0.0-255.255.255.255", exclude_targets="0.0.0.0-0.0.0.1,255.255.255.255")
    assert plan.target_count == 2**32 - 3
    assert plan.no_port_count == plan.target_count
    assert plan.hosts_sample(3) == ["0.0.0.2", "0.0.0.3", "0.0.0.4"]
    assert plan.contains_host("255.255.255.254")
    assert not plan.contains_host("255.255.255.255")


def test_large_literal_ipv4_file_is_compact_and_keeps_source_and_port_counts(tmp_path):
    targets = tmp_path / "targets.txt"
    lines = [f"10.{i // 65536}.{i // 256 % 256}.{i % 256}" for i in range(12_000)]
    targets.write_text("\n".join([*lines, lines[0], lines[-1]]) + "\n", encoding="utf-8")
    plan = stream_scan_target_specs(str(targets))
    assert plan.target_count == 12_000
    assert len(plan._entries) < 10
    assert plan.count_for_ports((80, 443)) == 24_000
    assert plan.unique_host_count() == 12_000
    first = plan.first_spec()
    assert first is not None and first.host == lines[0]
    assert first.source == f"{targets.resolve()}:1"
    assert [spec.host for spec in plan.iter_specs_for_port(443, (80, 443))][:2] == lines[:2]


def test_compact_ipv4_file_and_later_range_do_not_repeat_hosts(tmp_path):
    targets = tmp_path / "targets.txt"
    targets.write_text("10.0.0.1\n10.0.0.3\n10.0.0.0-10.0.0.4\n", encoding="utf-8")
    plan = stream_scan_target_specs(str(targets))
    assert [spec.host for spec in plan.iter_specs()] == ["10.0.0.1", "10.0.0.3", "10.0.0.0", "10.0.0.2", "10.0.0.4"]
    assert plan.count_for_ports((80,)) == 5


def test_compact_ipv4_file_deduplicates_additive_explicit_port(tmp_path):
    targets = tmp_path / "targets.txt"
    targets.write_text("10.0.0.1\n10.0.0.2:8080\n10.0.0.2\n", encoding="utf-8")
    plan = stream_scan_target_specs(str(targets)).with_additional_ports_for_bare_explicit_targets()
    assert plan.count_for_ports((8080, 8443)) == 4
    assert plan.unique_host_count() == 2
    assert [spec.host for spec in plan.iter_specs_for_port(8080, (8080, 8443))] == ["10.0.0.1", "10.0.0.2"]
    assert [spec.host for spec in plan.iter_specs_for_port(8443, (8080, 8443))] == ["10.0.0.1", "10.0.0.2"]


@given(st.lists(st.integers(0, 15), min_size=1, max_size=30))
def test_compact_file_matches_eager_parser_for_mixed_ipv4_inputs(values):
    lines = [f"10.0.0.{value}" for value in values]
    lines.extend(["10.0.0.4-10.0.0.9", "10.0.0.2:8080", "10.0.0.7:8080"])
    with TemporaryDirectory() as directory:
        targets = Path(directory) / "targets.txt"
        targets.write_text("\n".join(lines) + "\n", encoding="utf-8")
        eager = parse_scan_target_specs(str(targets))
        plan = stream_scan_target_specs(str(targets))
        expected = [(spec.host, spec.explicit_port, spec.scheme) for spec in eager]
        actual = [(spec.host, spec.explicit_port, spec.scheme) for spec in plan.iter_specs()]
        assert actual == expected
        assert plan.target_count == len(expected)
        for port in (8080, 8443):
            expanded = list(plan.iter_specs_for_port(port, (8080, 8443)))
            assert len(expanded) == len({spec.normalized_key for spec in expanded})
        assert plan.count_for_ports((8080, 8443)) == sum(
            len(list(plan.iter_specs_for_port(port, (8080, 8443)))) for port in (8080, 8443)
        )


def test_eager_range_expansion_respects_existing_host_limit():
    policy = TargetParsePolicy(max_network_hosts=2)
    assert len(parse_scan_target_specs("10.0.0.1-10.0.0.2", policy=policy)) == 2
    with pytest.raises(ValueError, match=r"expands to 3 hosts \(limit: 2\)"):
        parse_scan_target_specs("10.0.0.1-10.0.0.3", policy=policy)


def test_range_exclusion_applies_to_urls_and_explicit_ports():
    assert parse_scan_target_specs("http://10.0.0.1:8080/path,10.0.0.2:9000", exclude_targets="10.0.0.1-10.0.0.2") == []


@given(st.lists(st.tuples(st.integers(0, 127), st.integers(0, 127)), max_size=80))
def test_incremental_ipv4_intervals_match_independent_set_model(pairs):
    ranges: list[tuple[int, int]] = []
    expected: set[int] = set()
    for left, right in pairs:
        start, end = sorted((left, right))
        _merge_ipv4_range(ranges, (start, end))
        expected.update(range(start, end + 1))
        actual = {value for range_start, range_end in ranges for value in range(range_start, range_end + 1)}
        assert actual == expected
        assert all(ranges[index][1] + 1 < ranges[index + 1][0] for index in range(len(ranges) - 1))
    assert all(_range_contains(ranges, value) == (value in expected) for value in range(129))
