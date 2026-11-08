"""Known credential carriers retain their complete source value across readers."""

from __future__ import annotations

import base64
import json

import pytest

from redposture_core.discovery_engine import _scan_portioned_value, _scan_text_chunks
from redposture_core.discovery_rules import analyze_value
from redposture_core.discovery_values import DiskBackedText, iter_json_chunks
from redposture_core.modules.elastic.discover import FindingAccumulator, scan_value_tree

SAS_SIGNATURE = base64.b64encode(bytes(range(32))).decode()
SAS = (
    "https://qa.blob.core.windows.net/private/a.txt?sv=2023-11-03&se=2030-01-01T00%3A00%3A00Z&sp=r&sr=b&sig="
    + SAS_SIGNATURE.replace("=", "%3D")
)
PRESIGNED = (
    "https://qa.s3.amazonaws.com/private/a.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256"
    "&X-Amz-Credential=AKIAQQQQQQQQQQQQQQQQ%2F20300101%2Feu-west-1%2Fs3%2Faws4_request"
    "&X-Amz-Date=20300101T000000Z&X-Amz-Expires=900&X-Amz-SignedHeaders=host&X-Amz-Signature=" + bytes(range(32)).hex()
)
BASIC = "Basic " + base64.b64encode(b"qa:inactive-basic-password").decode()
URI = "postgres://qa:p%40ss@db.invalid/db"
JDBC = "jdbc:postgresql://db.invalid:5432/app?user=qa&password=inactive-jdbc-password!42&sslmode=require"
ODBC = "DRIVER={ODBC Driver 18 for SQL Server};SERVER=db.invalid;DATABASE=app;UID=qa;PWD={Inactive;Odbc Password!42};Encrypt=yes"
SQLSERVER = (
    "jdbc:sqlserver://db.invalid:1433;databaseName=app;user=qa;password={Inactive;Jdbc Password!42};encrypt=true"
)
AZURE = (
    "DefaultEndpointsProtocol=https;AccountName=qaaccount;AccountKey="
    + base64.b64encode(bytes(range(64))).decode()
    + ";EndpointSuffix=core.windows.net"
)


def scalar(value):
    return json.loads("".join(iter_json_chunks(value)))


def scan(text, route, *, field="body", portion=65536):
    if route == "scalar":
        return [(scalar(d.value), d.secret_type) for d in analyze_value(text, path=field) if d.available], True
    if route == "elastic":
        tree = scan_value_tree({field: text}, source_kind="document", object_name="qa/one")
        acc = FindingAccumulator()
        for d, loc in tree.detections:
            if d.available:
                acc.add(d, loc)
        return [(scalar(f.value), f.secret_type) for f in acc.findings()], not tree.truncated_reasons
    if route == "disk":
        with DiskBackedText() as value:
            value.append_text(json.dumps({field: text}))
            value.finish()
            found, _, complete = _scan_portioned_value(value, "$", portion)
            return [(scalar(m.value), m.detector) for m in found], complete
    if route == "stream":
        found, complete = _scan_text_chunks((text[n : n + 113] for n in range(0, len(text), 113)), "$.body", portion)
    else:
        found, _, complete = _scan_portioned_value({field: text}, "$", portion)
    return [(scalar(m.value), m.detector) for m in found], complete


@pytest.mark.parametrize("route", ["scalar", "common", "elastic", "disk", "stream"])
@pytest.mark.parametrize(
    "text,kind",
    [
        (URI, "connection_string"),
        (
            "mongodb://qa:inactive-password@db1.invalid:27017,db2.invalid:27017/app?replicaSet=rs0&authSource=admin",
            "connection_string",
        ),
        ("amqp://qa:inactive-password@mq.invalid:5672/%2Fteam?heartbeat=30", "connection_string"),
        (BASIC, "basic_auth"),
        (SAS, "signed_url"),
        (PRESIGNED, "signed_url"),
        (JDBC, "connection_string"),
        (ODBC, "connection_string"),
        (SQLSERVER, "connection_string"),
        (
            "host=db.invalid port=5432 dbname=app user=qa password='Inactive Db Password!42' sslmode=require",
            "connection_string",
        ),
        (AZURE, "connection_string"),
    ],
)
def test_complete_credential_carrier_is_one_finding(text, kind, route):
    found, complete = scan(text, route)
    assert complete
    assert found == [(text, kind)]


@pytest.mark.parametrize("route", ["common", "elastic", "disk", "stream"])
@pytest.mark.parametrize(
    "base,tail,kind",
    [
        (SAS, "&rsct=", "signed_url"),
        (PRESIGNED, "&response-content-disposition=", "signed_url"),
        (JDBC, "&ApplicationName=", "connection_string"),
    ],
)
def test_carrier_over_default_portion_preserves_tail_and_exact_value(route, base, tail, kind):
    text = base + tail + "A" * 100000
    found, complete = scan(text, route)
    assert complete
    assert found == [(text, kind)]


@pytest.mark.parametrize("route", ["scalar", "common", "elastic", "disk", "stream"])
@pytest.mark.parametrize(
    "text",
    [
        "postgres://db.invalid:5432/app",
        "https://qa.invalid/status?token_count=42",
        "Server=db.invalid;Database=app;Integrated Security=true",
        "password_length=20",
    ],
)
def test_carrier_grammar_does_not_promote_public_metadata(text, route):
    found, complete = scan(text, route)
    assert complete
    assert found == []


@pytest.mark.parametrize("field", ["body", "dsn", "connection_string"])
def test_connection_identity_does_not_depend_on_field_label(field):
    found, complete = scan(JDBC, "common", field=field)
    assert complete and found == [(JDBC, "connection_string")]


def test_two_connection_uris_with_same_password_remain_distinct():
    text = "postgres://alice:inactive-shared@one.invalid/app\npostgres://bob:inactive-shared@two.invalid/app"
    found, complete = scan(text, "common")
    assert complete
    assert sorted(v for v, _kind in found) == sorted(text.splitlines())


@pytest.mark.parametrize("route", ["scalar", "common", "elastic", "disk", "stream"])
@pytest.mark.parametrize(
    "text",
    [
        "Server=db.invalid;Database=app;User ID=qa;Password={Inactive;brace}}password!42};Encrypt=true",
        "host=db.invalid dbname=app user=qa password='Inactive \\'Db Password!42' sslmode=require",
        "Cookie: session=inactive-session-token-42; csrftoken=inactive-csrf-token-84; theme=dark",
        "Set-Cookie: sessionid=inactive-session-token-42; Path=/; Secure; HttpOnly; SameSite=Lax",
    ],
)
def test_braces_quotes_and_cookie_carriers_keep_source_spelling(route, text):
    found, complete = scan(text, route)
    assert complete
    assert found == [(text, "session_cookie" if text.startswith(("Cookie:", "Set-Cookie:")) else "connection_string")]


@pytest.mark.parametrize("route", ["common", "elastic", "disk"])
def test_registry_auth_keeps_original_encoded_pair(route):
    raw = base64.b64encode(b"qa:inactive-registry-password").decode()
    found, complete = scan(raw, route, field="auth")
    assert complete
    assert found == [(raw, "encoded_credentials")]


@pytest.mark.parametrize("route", ["common", "disk", "stream"])
def test_unfinished_brace_password_is_not_reported_as_complete(route):
    found, complete = scan("Server=db.invalid;UID=qa;PWD={Inactive;unfinished-password", route)
    assert not complete
    assert found == []


@pytest.mark.parametrize("route", ["scalar", "common", "elastic", "disk", "stream"])
def test_dsn_does_not_absorb_an_independent_next_log_line(route):
    carrier = "Server=db.invalid;UID=qa;PWD={Inactive;brace-password!42}"
    text = carrier + "\npassword=separate-log-password-84\n"
    found, complete = scan(text, route)
    assert complete
    assert sorted(found) == sorted([(carrier, "connection_string"), ("separate-log-password-84", "password")])


@pytest.mark.parametrize("route", ["scalar", "common", "elastic", "disk", "stream"])
def test_libpq_semicolon_inside_quote_is_not_a_property_separator(route):
    carrier = "host=db.invalid user=qa password='Inactive; Db password!42' sslmode=require"
    found, complete = scan(carrier, route)
    assert complete and found == [(carrier, "connection_string")]


@pytest.mark.parametrize("route", ["common", "elastic", "disk", "stream"])
def test_large_basic_and_cookie_keep_the_complete_carrier(route):
    large = "Inactive-" + "qR7b2" * 20000 + "-end"
    for carrier, kind in [
        ("Basic " + base64.b64encode(("qa:" + large).encode()).decode(), "basic_auth"),
        ("Cookie: session=" + large + "; theme=dark", "session_cookie"),
    ]:
        found, complete = scan(carrier, route)
        assert complete and found == [(carrier, kind)]


@pytest.mark.parametrize("route", ["scalar", "common", "elastic", "disk", "stream"])
@pytest.mark.parametrize("password", ["REDACTED", "****", "${PASSWORD}"])
def test_braced_dsn_placeholder_is_not_a_secret(route, password):
    found, complete = scan("Server=db.invalid;UID=qa;PWD={" + password.replace("}", "}}") + "}", route)
    assert complete and found == []


@pytest.mark.parametrize("route", ["scalar", "common", "elastic", "disk", "stream"])
def test_cookie_header_in_log_does_not_lose_name_or_absorb_next_line(route):
    cookie = "Cookie: session=inactive-session-42; theme=dark"
    found, complete = scan("request headers\n" + cookie + "\npassword=separate-password-84\n", route)
    assert complete
    assert sorted(found) == sorted([(cookie, "session_cookie"), ("separate-password-84", "password")])


@pytest.mark.parametrize("route", ["scalar", "common", "elastic", "disk", "stream"])
@pytest.mark.parametrize("suffix", ["junk", "=", ".tail", "_tail"])
@pytest.mark.parametrize("credential", [b"qa:inactive-padding-test", b"qa:inactive-padding-test!"])
def test_basic_is_not_published_before_the_full_token_boundary(route, suffix, credential):
    carrier = "Basic " + base64.b64encode(credential).decode() + suffix
    found, complete = scan(carrier, route)
    assert complete
    assert not any(kind == "basic_auth" for _value, kind in found)
