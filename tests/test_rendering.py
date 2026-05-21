from __future__ import annotations

import re

from redposture_core.rendering import (
    BooleanColorRule,
    CountColorRule,
    LiteralColorRule,
    RegexColorRule,
    collect_color_spans,
    collect_stage_payload_spans,
    colorize_spans,
    render_colored_marker_line,
    render_module_marker_line,
    render_tagged_detail_line,
)


class _Console:
    def __init__(self) -> None:
        self.paint_calls: list[tuple[str, str]] = []
        self.lines: list[str] = []

    def _paint(self, text: str, color: str, _stream: object) -> str:
        self.paint_calls.append((text, color))
        return f"<{color}>{text}</{color}>"

    def plain(self, text: str, color: str | None = None) -> None:
        _ = color
        self.lines.append(text)


def test_collect_color_spans_supports_literal_and_regex_rule_shapes() -> None:
    text = "token token count=0 count=2 compiled=7"

    spans = collect_color_spans(
        text,
        literals=(LiteralColorRule("token", "orange"), ("", "red")),
        regexes=(
            (r"count=(\d+)", "red", 1),
            RegexColorRule(re.compile(r"compiled=(\d+)"), "yellow"),
            (r"missing", "blue"),
        ),
    )

    colored_fragments = [(text[start:end], color) for start, end, color in spans]
    assert colored_fragments == [
        ("token", "orange"),
        ("token", "orange"),
        ("count=2", "red"),
        ("compiled=7", "yellow"),
    ]


def test_colorize_spans_skips_empty_and_overlapping_ranges() -> None:
    console = _Console()

    rendered = colorize_spans(console, "abcdef", [(1, 1, "red"), (1, 4, "orange"), (2, 5, "yellow")])

    assert rendered
    assert ("bcd", "orange") in console.paint_calls
    assert ("cde", "yellow") not in console.paint_calls


def test_colorize_spans_keeps_parentheses_uncolored_for_whole_token_span() -> None:
    console = _Console()

    rendered = colorize_spans(console, "prefix (auth required:True) suffix", [(7, 27, "bright_green")])

    assert rendered
    assert ("auth required:True", "bright_green") in console.paint_calls
    assert ("prefix (", "white") in console.paint_calls
    assert any(text.startswith(")") and color == "white" for text, color in console.paint_calls)
    assert ("(auth required:True)", "bright_green") not in console.paint_calls


def test_render_tagged_detail_line_and_marker_line_reject_invalid_lines() -> None:
    console = _Console()

    assert render_tagged_detail_line(console, "OTHER\t127\t1\tvalue", tag="GRPC") is False
    assert render_module_marker_line(console, "GRPC\t127\t1\tplain", tag="GRPC") is False
    assert render_module_marker_line(console, "OTHER\t127\t1\t [+] ok", tag="GRPC") is False


def test_render_tagged_detail_line_and_marker_line_apply_shared_layout() -> None:
    console = _Console()

    assert render_tagged_detail_line(
        console,
        "GRPC\t127.0.0.1\t50051\tservice=grpc.health.v1.Health grpc=OK",
        tag="GRPC",
        spans=[(0, len("service=grpc.health.v1.Health"), "orange")],
    )
    assert render_module_marker_line(
        console,
        "GRPC\t127.0.0.1\t50051\t [+] anonymous access",
        tag="GRPC",
        spans=[(0, len("anonymous access"), "bright_green")],
    )

    assert any(text == "GRPC" and color == "blue" for text, color in console.paint_calls)
    assert any("anonymous access" in text and color == "bright_green" for text, color in console.paint_calls)
    assert len(console.lines) == 2


def test_collect_stage_payload_spans_handles_common_auth_bool_and_count_rules() -> None:
    text = "(auth required:unknown) (read:True) (write:False) (keys:0) (items:3)"

    spans = collect_stage_payload_spans(
        text,
        booleans=(
            BooleanColorRule("read"),
            BooleanColorRule("write"),
        ),
        counts=(CountColorRule("keys", "red"), CountColorRule("items", "orange")),
    )

    colored_fragments = [(text[start:end], color) for start, end, color in spans]
    assert ("(auth required:unknown)", "yellow") in colored_fragments
    assert ("(read:True)", "red") in colored_fragments
    assert ("(write:False)", "bright_green") in colored_fragments
    assert ("(keys:0)", "red") not in colored_fragments
    assert ("(items:3)", "orange") in colored_fragments


def test_render_colored_marker_line_applies_declarative_rules_and_extra_spans() -> None:
    console = _Console()

    rendered = render_colored_marker_line(
        console,
        "REDIS\t127.0.0.1\t6379\t [+] anonymous access (keys:2) token=abc",
        tag="REDIS",
        counts=(CountColorRule("keys", "red"),),
        extra_spans=lambda _marker, payload: [(payload.index("token="), len(payload), "orange")],
    )

    assert rendered is True
    assert ("REDIS", "blue") in console.paint_calls
    assert ("[+]", "bright_green") in console.paint_calls
    assert any(text == "keys:2" and color == "red" for text, color in console.paint_calls)
    assert any("token=abc" in text and color == "orange" for text, color in console.paint_calls)
