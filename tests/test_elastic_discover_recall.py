"""Regression corpus for structured credentials in Elastic/OpenSearch documents."""

from __future__ import annotations

import base64
import gzip
import json

import pytest

from redposture_core.modules.elastic.discover import DiscoverOptions, scan_value_tree


def _values(document: dict[str, str], *, options: DiscoverOptions | None = None) -> set[str]:
    result = scan_value_tree(document, source_kind="document", object_name="recall", options=options)
    return {item.value for item, _location in result.detections if item.available}


@pytest.mark.parametrize(
    ("field", "secret"),
    [
        ("x-custom-credential", "CorpusCredential!2026"),
        ("cred", "CorpusCred!2026"),
        ("creds", "CorpusCreds!2026"),
        ("apisecret", "CorpusApiSecret!2026"),
        ("passphrase", "CorpusPassphrase!2026"),
    ],
)
def test_sensitive_field_aliases_are_found(field: str, secret: str) -> None:
    assert secret in _values({field: secret})


@pytest.mark.parametrize(
    ("text", "secret"),
    [
        ("export DB_PASSWORD=CorpusEnvPass!2026", "CorpusEnvPass!2026"),
        ("db.password=CorpusPropertyPass!2026", "CorpusPropertyPass!2026"),
        ("password => 'CorpusRubyPass!2026'", "CorpusRubyPass!2026"),
        ("mysql --password=CorpusCliPass!2026", "CorpusCliPass!2026"),
        ("https://svc/?apikey=CorpusUrlToken!2026&x=1", "CorpusUrlToken!2026"),
        ("ALTER USER svc WITH PASSWORD 'CorpusSqlPass!2026'", "CorpusSqlPass!2026"),
        ('"password":"CorpusJsonPass!2026"', "CorpusJsonPass!2026"),
        ("user,password\nsvc,CorpusCsvPass!2026", "CorpusCsvPass!2026"),
        ("<password>CorpusXmlPass!2026</password>", "CorpusXmlPass!2026"),
        ('<input name="password" value="CorpusHtmlPass!2026">', "CorpusHtmlPass!2026"),
        ('<db password="CorpusAttrPass!2026"/>', "CorpusAttrPass!2026"),
        ('<div data-token="CorpusDataToken!2026"></div>', "CorpusDataToken!2026"),
    ],
)
def test_embedded_structured_secrets_are_found(text: str, secret: str) -> None:
    assert secret in _values({"log": text})


@pytest.mark.parametrize("encoding", ["base64", "base64url", "hex", "gzip_base64", "double_base64"])
def test_bounded_encoded_blobs_are_rescanned(encoding: str) -> None:
    secret = "CorpusWrappedPass!2026"
    raw = json.dumps({"password": secret}).encode()
    if encoding == "base64":
        encoded = base64.b64encode(raw).decode()
    elif encoding == "base64url":
        encoded = base64.urlsafe_b64encode(raw).decode().rstrip("=")
    elif encoding == "hex":
        encoded = raw.hex()
    elif encoding == "gzip_base64":
        encoded = base64.b64encode(gzip.compress(raw)).decode()
    else:
        encoded = base64.b64encode(base64.b64encode(raw)).decode()
    assert secret in _values({"blob": encoded})


@pytest.mark.parametrize(
    "token",
    [
        "sk-proj-ABCDEF0123456789abcdef0123456789",
        "sk-ant-api03-ABCDEF0123456789abcdef0123456789",
        "glsa_ABCDEF0123456789abcdef0123456789",
        "dop_v1_ABCDEF0123456789abcdef0123456789",
        "shpat_ABCDEF0123456789abcdef0123456789",
        "dckr_pat_ABCDEF0123456789abcdef0123456789",
        "pypi-AgEIABCDEF0123456789abcdef0123456789",
        "SG.ABCDEF0123456789.ABCDEF0123456789abcdef",
        "SK0123456789abcdef0123456789abcdef",
        "123456789:AAABCDEF0123456789abcdef0123456789",
        "https://hooks.slack.com/services/T00000000/B00000000/ABCDEF0123456789",
    ],
)
def test_provider_tokens_are_found_in_neutral_fields(token: str) -> None:
    assert token in _values({"note": f"token {token}"})


def test_neutral_encoded_basic_pair_and_public_material_are_not_findings() -> None:
    encoded_pair = base64.b64encode(b"svc:passphrase").decode()
    assert _values({"blob": encoded_pair}) == set()
    assert _values({"note": "authentication failed: invalid password"}) == set()
    assert _values({"public_key": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC"}) == set()
    assert _values({"markup": '<div notatoken="ordinary-state-value"></div>'}) == set()


def test_oversized_gzip_blob_is_not_decompressed_past_limit() -> None:
    raw = b"password=" + b"A" * 10_000
    encoded = base64.b64encode(gzip.compress(raw)).decode()
    assert _values({"blob": encoded}, options=DiscoverOptions(max_embedded_json_bytes=128)) == set()


def test_escaped_json_and_unicode_escapes_are_scanned_once() -> None:
    assert "CorpusEscaped!2026" in _values({"blob": '{\\"password\\":\\"CorpusEscaped!2026\\"}'})
    assert "CorpusUnicode!2026" in _values({"blob": "password=\\u0043orpusUnicode!2026"})
