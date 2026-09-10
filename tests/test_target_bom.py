from __future__ import annotations

import pytest

from redposture_core.targeting import normalize_scan_host, parse_scan_target_specs, stream_scan_target_specs


def _specs(targets, *, streaming, exclude_targets=None):
    if streaming:
        return list(stream_scan_target_specs(targets, exclude_targets=exclude_targets).iter_specs())
    return parse_scan_target_specs(targets, exclude_targets=exclude_targets)


@pytest.mark.parametrize("streaming", [False, True])
@pytest.mark.parametrize(
    "target",
    ["127.0.0.1:8080", "example.test", "[::1]:8080", "http://example.test:8080/path?q=1", "127.0.0.0/30"],
)
def test_leading_bom_in_list_members_is_removed_before_parsing(streaming, target):
    expected = _specs(target, streaming=streaming)
    assert _specs(f" \ufeff \t\ufeff{target}\r\n, {target}", streaming=streaming) == expected


@pytest.mark.parametrize("streaming", [False, True])
def test_target_files_strip_bom_on_each_line_and_list_member(tmp_path, streaming):
    nested = tmp_path / "nested.txt"
    nested.write_text("\ufeff [::1]:8080\r\n", encoding="utf-8")
    targets = tmp_path / "targets.txt"
    targets.write_text(
        f"\ufeff # comment\n\ufeff 127.0.0.1:8080, \ufeff example.test\r\n\ufeff {nested}\n\ufeff \n",
        encoding="utf-8",
    )
    expected = _specs("127.0.0.1:8080,example.test,[::1]:8080", streaming=streaming)
    assert _specs(f"\ufeff {targets}", streaming=streaming) == expected


@pytest.mark.parametrize("streaming", [False, True])
@pytest.mark.parametrize("from_file", [False, True])
def test_bom_does_not_break_target_exclusions(tmp_path, streaming, from_file):
    exclusions = "\ufeff 127.0.0.0/30, \ufeff http://example.test:80/path, \ufeff [::1]:8080"
    if from_file:
        path = tmp_path / "exclusions.txt"
        path.write_text(exclusions, encoding="utf-8")
        exclusions = f"\ufeff {path}"
    actual = _specs(
        "127.0.0.0/29,example.test,[::1]:8080",
        streaming=streaming,
        exclude_targets=exclusions,
    )
    assert [spec.host for spec in actual] == ["127.0.0.4", "127.0.0.5", "127.0.0.6"]


@pytest.mark.parametrize("streaming", [False, True])
def test_bom_inside_url_path_or_query_is_preserved(streaming):
    spec = _specs("\ufeff http://example.test/a\ufeffb?q=x\ufeffy", streaming=streaming)[0]
    assert spec.path == "/a\ufeffb"
    assert spec.query == "q=x\ufeffy"


@pytest.mark.parametrize("value", ["\ufeff 127.0.0.1", " \ufeff http://127.0.0.1:8080/path"])
def test_normalize_scan_host_strips_leading_bom(value):
    assert normalize_scan_host(value) == "127.0.0.1"


def test_bom_only_is_not_a_host():
    assert normalize_scan_host(" \ufeff \r\n") is None
    assert parse_scan_target_specs("\ufeff , \ufeff") == []
