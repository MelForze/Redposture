"""Independent exact-value and negative controls from the accuracy audit."""

from __future__ import annotations

import json
import sys
from typing import Any

import pytest

from redposture_core.data_discovery import _scan_portioned_value, inspect_record
from redposture_core.discovery_values import DiskBackedText, iter_json_chunks
from redposture_core.modules.elastic.discover import scan_value_tree


def _text(value):
    return "".join(value.iter_text_chunks()) if isinstance(value, DiskBackedText) else value


def _values(document, engine):
    if engine == "common":
        matches, _, covered = _scan_portioned_value(document, "$", sys.maxsize)
        assert covered
        return {_text(match.value) for match in matches}
    result = scan_value_tree(document, source_kind="document", object_name="accuracy")
    assert not result.truncated_reasons
    return {_text(match.value) for match, _ in result.detections if match.available}


@pytest.mark.parametrize("engine", ["common", "elastic"])
@pytest.mark.parametrize("name", ["password", "client_secret", "api_token"])
@pytest.mark.parametrize(
    "literal,expected",
    [
        ('"Audit Only Phrase 2026!"', "Audit Only Phrase 2026!"),
        ('"Audit;Only;2026!"', "Audit;Only;2026!"),
        ('"Audit\\"Only2026!"', 'Audit\\"Only2026!'),
        ("'Audit\\'Only2026!'", "Audit\\'Only2026!"),
        ('"Audit\\\\Only2026!"', "Audit\\\\Only2026!"),
        ('"Audit,Only=2026!"', "Audit,Only=2026!"),
    ],
)
def test_completed_quoted_assignment_exports_only_the_full_value(engine, name, literal, expected):
    assert _values({"body": f"{name}={literal}"}, engine) == {expected}


@pytest.mark.parametrize("engine", ["common", "elastic"])
@pytest.mark.parametrize("name", ["password", "client_secret"])
def test_interrupted_quoted_assignment_does_not_export_a_prefix(engine, name):
    assert _values({"body": f'{name}="unfinished secret'}, engine) == set()


@pytest.mark.parametrize("engine", ["common", "elastic"])
@pytest.mark.parametrize(
    "name,value",
    [
        ("token_count", 42),
        ("password_length", 20),
        ("password_enabled", 1),
        ("secret_name", "deployment/database-password"),
        ("cookie_policy", "strict"),
        ("token_type", "access"),
        ("token_endpoint", "https://auth.invalid/oauth/token"),
        ("password_policy", "minimum 12 characters"),
        ("credential_status", "valid"),
        ("passwordLength", 20),
        ("is_password_enabled", True),
    ],
)
def test_secret_metadata_does_not_become_a_secret(engine, name, value):
    assert _values({name: value}, engine) == set()


@pytest.mark.parametrize("engine", ["common", "elastic"])
@pytest.mark.parametrize("value", ["1234", "admin", "1", 1234])
def test_metadata_filter_keeps_actual_short_and_numeric_passwords(engine, value):
    assert str(value) in _values({"password": value}, engine)


@pytest.mark.parametrize("engine", ["common", "elastic"])
def test_explicit_token_in_metadata_is_still_scanned(engine):
    token = "gh" + "p_" + "AuditOnly0123456789abcdefghijklmnop"
    assert token in _values({"token_description": token}, engine)


@pytest.mark.parametrize("depth", [33, 40])
def test_depth_stop_is_partial_and_keeps_completed_earlier_findings(depth):
    nested: dict[str, Any] = {"password": "hidden-depth-value"}
    for _ in range(depth):
        nested = {"nested": nested}
    record = {
        "status": "open_no_auth",
        "table_dumps": [
            {"database": "qa", "table": "objects", "rows": [{"password": "first-completed-value"}, nested]}
        ],
    }
    result = inspect_record("postgres", record)
    assert result["status"] == "partial"
    assert "max_depth" in result["partial_reasons"]
    assert [item["value"] for item in result["findings"]] == ["first-completed-value"]
    encoded = "".join(iter_json_chunks(result))
    assert "\x1b" not in encoded and "object at" not in encoded
    assert json.loads(encoded)["status"] == "partial"


@pytest.mark.parametrize("name", ["api_key", "client_secret", "api_token"])
def test_quoted_assignment_preserves_provider_before_generic_label(name):
    value = "sk_" + "live_" + "AccuracyOnlyProvider0123456789"
    matches, _, covered = _scan_portioned_value(f'{name}="{value}"', "$", sys.maxsize)
    assert covered and matches
    assert matches[0].detector == "stripe_key"
    assert matches[0].value == value
    assert {m.value for m in matches} == {value}
