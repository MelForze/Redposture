"""TOML 1.0 values are specified by tomllib, independently of the scanner."""

from __future__ import annotations

import hashlib
import json
import tomllib

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from redposture_core.discovery_engine import _scan_portioned_value, _scan_text_chunks
from redposture_core.discovery_rules import analyze_value
from redposture_core.discovery_values import DiskBackedText
from redposture_core.modules.elastic.discover import scan_value_tree


def plain(value):
    return "".join(value.iter_text_chunks()) if isinstance(value, DiskBackedText) else value


SOURCES = [
    'password="""Audit\nOnly2026!"""',
    'password="""\nAudit\\nOnly\\t2026!"""',
    "password='''\r\nAudit\\path\r\nOnly2026!'''",
    'password="""Audit \\ \t\n    Only \\u03bb \\U0001F512"""',
    'password="""Audit "quoted" value"""',
    'password="""Audit end quote""""',
    "password='''Audit end quotes'''''",
]


@pytest.mark.parametrize("source", SOURCES)
@pytest.mark.parametrize("entry", ["scalar", "common", "elastic", "stream-1", "stream-3", "stream-64"])
def test_toml_multiline_matches_independent_language_oracle(source, entry):
    expected = tomllib.loads(source)["password"]
    if entry == "scalar":
        values = [plain(m.value) for m in analyze_value(source) if m.available]
    elif entry == "elastic":
        result = scan_value_tree({"body": source}, source_kind="document", object_name="qa/config.toml")
        assert not result.truncated_reasons
        values = [plain(m.value) for m, _p in result.detections if m.available]
    else:
        if entry == "common":
            matches, _size, complete = _scan_portioned_value({"body": source}, "$", 65_536)
        else:
            size = int(entry.split("-")[1])
            matches, complete = _scan_text_chunks(
                (source[n : n + size] for n in range(0, len(source), size)), "$.body", 64, 0
            )
        assert complete, getattr(matches, "incomplete_reason", None)
        values = [plain(m.value) for m in matches]
    assert values == [expected]


@pytest.mark.parametrize(
    "tail,reason", [(r"broken\qvalue", "invalid_toml_escape"), (r"bad\uD800value", "invalid_toml_unicode_escape")]
)
def test_invalid_toml_escape_does_not_publish_an_invented_value(tail, reason):
    source = 'password="""' + tail + '"""\npassword="later-completed-password"\n'
    matches, complete = _scan_text_chunks((source[n : n + 3] for n in range(0, len(source), 3)), "$.body", 64, 0)
    assert not complete and getattr(matches, "incomplete_reason", None) == reason
    assert [plain(m.value) for m in matches] == ["later-completed-password"]


def test_large_toml_multiline_value_uses_disk_and_does_not_publish_interrupted_prefix():
    text = "Inactiveλ-2026!\n" * 10000
    source = 'password="""\n' + text + '"""'
    for closed in (False, True):
        body = source if closed else source[:-3]
        matches, complete = _scan_text_chunks(
            (body[n : n + 8191] for n in range(0, len(body), 8191)), "$.body", 1024, 0
        )
        assert complete is closed
        if closed:
            assert len(matches) == 1 and isinstance(matches[0].value, DiskBackedText)
            assert matches[0].value.digest == hashlib.sha256(text.encode()).hexdigest()
        else:
            assert not matches and getattr(matches, "incomplete_reason", None) == "unterminated_toml_value"


def test_equal_toml_literals_keep_both_field_locations():
    source = 'password="""inactive-shared-secret"""\nclient_secret="""inactive-shared-secret"""\n'
    matches, _size, complete = _scan_portioned_value({"body": source}, "$", 65_536)
    assert complete and {m.object_path for m in matches} == {"$.body.password", "$.body.client_secret"}
    assert [plain(m.value) for m in matches] == ["inactive-shared-secret", "inactive-shared-secret"]


@settings(max_examples=50, deadline=None, derandomize=True)
@given(st.text(alphabet=["A", "λ", "Z", '"', "'", "\\", "\n", "\r", "\t", "\0", "😀"], max_size=150))
def test_toml_basic_escape_and_chunk_parity_against_standard_parser(fragment):
    value = "inactive-prefix-" + fragment
    source = 'password="""' + json.dumps(value, ensure_ascii=False)[1:-1] + '"""'
    expected = tomllib.loads(source)["password"]
    for size in (1, 17, 4096):
        matches, complete = _scan_text_chunks(
            (source[n : n + size] for n in range(0, len(source), size)), "$.body", 64, 0
        )
        assert complete, getattr(matches, "incomplete_reason", None)
        assert [plain(match.value) for match in matches] == [expected]
