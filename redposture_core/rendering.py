"""Shared text rendering helpers for stage modules."""

from __future__ import annotations

import re
import sys
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from re import Pattern

from .console import Console

_DEFAULT_MARKER_COLORS = {
    "[*]": "cyan",
    "[+]": "bright_green",
    "[-]": "red",
    "[!]": "red",
}


@dataclass(frozen=True)
class LiteralColorRule:
    fragment: str
    color: str


@dataclass(frozen=True)
class RegexColorRule:
    pattern: str | Pattern[str]
    color: str
    skip_zero_group: int | None = None


@dataclass(frozen=True)
class BooleanColorRule:
    field: str
    true_color: str = "red"
    false_color: str = "bright_green"
    unknown_color: str = "yellow"


@dataclass(frozen=True)
class CountColorRule:
    field: str
    color: str
    skip_zero: bool = True
    unknown_color: str = "yellow"


def format_count_value(value: object, *, state: str | None = None) -> str:
    """Render a text count without conflating unknown values with zero."""

    normalized_state = str(state or "").strip().lower()
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return f"{value}+" if normalized_state == "partial" else str(value)
    return "unknown partial" if normalized_state == "partial" else "unknown"


def collect_color_spans(
    text: str,
    *,
    literals: Iterable[LiteralColorRule | tuple[str, str]] = (),
    regexes: Iterable[
        RegexColorRule | tuple[str | Pattern[str], str] | tuple[str | Pattern[str], str, int | None]
    ] = (),
) -> list[tuple[int, int, str]]:
    """Collect stable color spans from literal and regex rules.

    Modules should describe *what* should be highlighted. This helper owns the
    repeated details: repeated literal matches, regex iteration, and optional
    "do not color zero counts" behavior.
    """

    spans: list[tuple[int, int, str]] = []
    for rule in literals:
        if isinstance(rule, LiteralColorRule):
            fragment = rule.fragment
            color = rule.color
        else:
            fragment, color = rule
        if not fragment:
            continue
        start = 0
        while True:
            idx = text.find(fragment, start)
            if idx < 0:
                break
            spans.append((idx, idx + len(fragment), color))
            start = idx + len(fragment)

    for regex_rule in regexes:
        if isinstance(regex_rule, RegexColorRule):
            pattern = regex_rule.pattern
            color = regex_rule.color
            skip_zero_group = regex_rule.skip_zero_group
        elif len(regex_rule) == 3:
            pattern, color, skip_zero_group = regex_rule
        else:
            pattern, color = regex_rule
            skip_zero_group = None
        compiled = re.compile(pattern) if isinstance(pattern, str) else pattern
        for match in compiled.finditer(text):
            if skip_zero_group is not None:
                candidate = match.group(skip_zero_group)
                if str(candidate).isdigit() and int(candidate) == 0:
                    continue
            spans.append((match.start(), match.end(), color))
    return spans


def collect_boolean_spans(text: str, rules: Iterable[BooleanColorRule | str]) -> list[tuple[int, int, str]]:
    spans: list[tuple[int, int, str]] = []
    for rule in rules:
        spec = BooleanColorRule(rule) if isinstance(rule, str) else rule
        pattern = re.compile(rf"\({re.escape(spec.field)}:(True|False|true|false|unknown)\)")
        for match in pattern.finditer(text):
            value = match.group(1).lower()
            if value == "true":
                color = spec.true_color
            elif value == "false":
                color = spec.false_color
            else:
                color = spec.unknown_color
            spans.append((match.start(), match.end(), color))
    return spans


def collect_count_spans(text: str, rules: Iterable[CountColorRule | tuple[str, str]]) -> list[tuple[int, int, str]]:
    spans: list[tuple[int, int, str]] = []
    for rule in rules:
        spec = CountColorRule(*rule) if isinstance(rule, tuple) else rule
        pattern = re.compile(rf"\({re.escape(spec.field)}:(\d+|unknown)(?:\+| partial)?(?: [^)]*)?\)")
        for match in pattern.finditer(text):
            raw_value = match.group(1)
            if raw_value == "unknown":
                spans.append((match.start(), match.end(), spec.unknown_color))
                continue
            value = int(raw_value)
            if spec.skip_zero and value == 0:
                continue
            spans.append((match.start(), match.end(), spec.color))
    return spans


def collect_stage_payload_spans(
    text: str,
    *,
    include_auth_required: bool = True,
    literals: Iterable[LiteralColorRule | tuple[str, str]] = (),
    regexes: Iterable[
        RegexColorRule | tuple[str | Pattern[str], str] | tuple[str | Pattern[str], str, int | None]
    ] = (),
    booleans: Iterable[BooleanColorRule | str] = (),
    counts: Iterable[CountColorRule | tuple[str, str]] = (),
) -> list[tuple[int, int, str]]:
    """Collect common stage payload spans using declarative field rules."""

    spans = collect_color_spans(text, literals=literals, regexes=regexes)
    if include_auth_required:
        spans.extend(
            collect_boolean_spans(
                text,
                (
                    BooleanColorRule(
                        "auth required",
                        true_color="bright_green",
                        false_color="red",
                        unknown_color="yellow",
                    ),
                ),
            )
        )
    spans.extend(collect_boolean_spans(text, booleans))
    spans.extend(collect_count_spans(text, counts))
    return spans


def colorize_spans(
    console: Console,
    text: str,
    spans: Iterable[tuple[int, int, str]],
    *,
    default_color: str = "white",
    strip_paren_wrappers: bool = True,
) -> str:
    """Color selected text spans while preserving uncolored gaps.

    ``strip_paren_wrappers`` (default True) preserves the historical
    behavior of `(auth required:True)`-style markers where the outer
    parens stay in the default color and only the inner payload is
    highlighted. Pass ``False`` when the whole `(name:value)` token
    should be painted uniformly (e.g. counts like `(topics:N)` where the
    brackets are visually part of the counter, not neutral structure).
    """

    normalized: list[tuple[int, int, str]] = []
    text_len = len(text)
    for start, end, color in spans:
        bounded_start = max(0, min(text_len, int(start)))
        bounded_end = max(bounded_start, min(text_len, int(end)))
        if bounded_start == bounded_end:
            continue
        if (
            strip_paren_wrappers
            and text[bounded_start : bounded_start + 1] == "("
            and text[bounded_end - 1 : bounded_end] == ")"
        ):
            bounded_start += 1
            bounded_end -= 1
        if bounded_start == bounded_end:
            continue
        normalized.append((bounded_start, bounded_end, str(color)))

    if not normalized:
        return console._paint(text, default_color, sys.stdout)

    chunks: list[str] = []
    cursor = 0
    for start, end, color in sorted(normalized, key=lambda item: item[0]):
        if start < cursor:
            continue
        if start > cursor:
            chunks.append(console._paint(text[cursor:start], default_color, sys.stdout))
        chunks.append(console._paint(text[start:end], color, sys.stdout))
        cursor = end
    if cursor < len(text):
        chunks.append(console._paint(text[cursor:], default_color, sys.stdout))
    return "".join(chunks)


_DETAIL_COUNT_PATTERN = re.compile(r"\(\w+:[^)]+\)")


def _detect_count_pattern_spans(text: str, color: str) -> list[tuple[int, int, str]]:
    """Auto-highlight parenthesised `(word:value)` count markers embedded in
    detail lines (e.g. `... users_table (rows:1234)`). Cross-module modules
    render their detail payloads in a warm default (currently orange); count
    markers are pushed to a neutral color so they don't shout as loudly as
    the resource name itself. Callers can override by passing explicit spans."""
    return [(m.start(), m.end(), color) for m in _DETAIL_COUNT_PATTERN.finditer(text)]


def render_tagged_detail_line(
    console: Console,
    line: str,
    *,
    tag: str,
    spans: Iterable[tuple[int, int, str]] = (),
    default_color: str = "white",
    count_pattern_color: str = "white",
    strip_paren_wrappers: bool = True,
) -> bool:
    """Render a standard TAG host port detail payload line without marker.

    When ``spans`` is empty, `(word:value)` fragments in the payload are
    auto-colorised in ``count_pattern_color`` (default white) — see
    ``_detect_count_pattern_spans``. Explicit spans win (used by gRPC).

    ``strip_paren_wrappers`` (default True) preserves the historical
    behavior where outer parens stay in the default color while the inner
    payload is highlighted. Pass ``False`` when the whole `(name:value)`
    token should be painted uniformly — e.g. `(topics:N)` on a Kafka
    detail line, where the parens are part of the counter, not neutral
    structure.
    """

    if not line.startswith(tag) or "\t" not in line:
        return False
    # Test doubles for Console may implement only `plain()` without the private
    # `_paint()` used for ANSI coloring. Fall through to a plain emit so the
    # colorizer stays no-op-safe in unit tests that stub out the console.
    if not hasattr(console, "_paint"):
        console.plain(line)
        return True
    left, right = line.rsplit("\t", 1)
    rest = left[len(tag) :] if left.startswith(tag) else left
    resolved_spans = list(spans) if spans else _detect_count_pattern_spans(right, count_pattern_color)
    right_colored = colorize_spans(
        console,
        right,
        resolved_spans,
        default_color=default_color,
        strip_paren_wrappers=strip_paren_wrappers,
    )
    colored = f"{console._paint(tag, 'blue', sys.stdout)}{console._paint(rest, 'white', sys.stdout)}\t{right_colored}"
    console.plain(colored)
    return True


def render_module_marker_line(
    console: Console,
    line: str,
    *,
    tag: str,
    spans: Iterable[tuple[int, int, str]] = (),
    marker_colors: dict[str, str] | None = None,
) -> bool:
    """Render a standard TAG host port marker payload line.

    Stage modules still own semantic span detection, but tag/marker/layout
    painting is centralized here to keep new modules visually consistent.
    """

    if not line.startswith(tag):
        return False

    colors = marker_colors or _DEFAULT_MARKER_COLORS
    for marker in ("[!]", "[-]", "[+]", "[*]"):
        token = f" {marker} "
        if token not in line:
            continue
        left, right = line.split(token, 1)
        rest = left[len(tag) :] if left.startswith(tag) else left
        right_colored = colorize_spans(console, right, spans)
        colored = (
            f"{console._paint(tag, 'blue', sys.stdout)}"
            f"{console._paint(rest, 'white', sys.stdout)} "
            f"{console._paint(marker, colors[marker], sys.stdout)} "
            f"{right_colored}"
        )
        console.plain(colored)
        return True
    return False


def render_colored_marker_line(
    console: Console,
    line: str,
    *,
    tag: str,
    include_auth_required: bool = True,
    literals: Iterable[LiteralColorRule | tuple[str, str]] = (),
    regexes: Iterable[
        RegexColorRule | tuple[str | Pattern[str], str] | tuple[str | Pattern[str], str, int | None]
    ] = (),
    booleans: Iterable[BooleanColorRule | str] = (),
    counts: Iterable[CountColorRule | tuple[str, str]] = (),
    extra_spans: Callable[[str, str], Iterable[tuple[int, int, str]]] | None = None,
) -> bool:
    """Render a standard module marker line from declarative color rules."""

    if not line.startswith(tag):
        return False
    for marker in ("[!]", "[-]", "[+]", "[*]"):
        token = f" {marker} "
        if token not in line:
            continue
        _left, right = line.split(token, 1)
        spans = collect_stage_payload_spans(
            right,
            include_auth_required=include_auth_required,
            literals=literals,
            regexes=regexes,
            booleans=booleans,
            counts=counts,
        )
        if extra_spans is not None:
            spans.extend(extra_spans(marker, right))
        return render_module_marker_line(console, line, tag=tag, spans=spans)
    return False
