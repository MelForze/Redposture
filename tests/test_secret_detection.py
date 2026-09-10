"""Coverage for the reusable secret-detection engine (redposture_core.secret_detection).

The module ships with regex/entropy detectors, key-name detection over nested
containers, and value masking. These tests pin both detections and intentional
non-matches across common field-name styles.
"""

from __future__ import annotations

import base64

import pytest

from redposture_core import secret_detection as sd

# --- value/format detectors ------------------------------------------------

_FORMAT_SAMPLES = [
    ("aws_access_key", "AKIAIOSFODNN7EXAMPLE"),
    ("jwt", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcDEF123"),
    ("github_token", "ghp_1234567890abcdefABCDEF1234567890xyz"),
    ("gitlab_token", "glpat-ABCDEFghij1234567890"),
    ("slack_token", "xoxb-1234567890-ABCDEFghij"),
    ("stripe_key", "sk_live_0123456789ABCDEFghijklmn"),
    ("private_key", "-----BEGIN PRIVATE KEY-----\nMIIBabc\n-----END PRIVATE KEY-----"),
    ("certificate", "-----BEGIN CERTIFICATE-----\nMIICabc\n-----END CERTIFICATE-----"),
    ("connection_string", "postgres://user:pass@host:5432/db"),
    ("bearer_token", "Authorization: Bearer abcdef012345.token_value"),
    ("password", "password = hunter2value"),
    ("webhook", "https://hooks.slack.com/services/T000/B000/XXXXXXXX"),
]


@pytest.mark.parametrize(("detector", "sample"), _FORMAT_SAMPLES, ids=[d for d, _ in _FORMAT_SAMPLES])
def test_known_secret_formats_are_detected(detector, sample):
    detectors = {match.detector for match in sd.scan_value(sample)}
    assert detector in detectors


def test_url_credentials_detected():
    detectors = {m.detector for m in sd.scan_value("amqp://guest:guest@broker:5672/")}
    assert "url_credentials" in detectors


# --- key-name detection over nested containers ------------------------------


@pytest.mark.parametrize(
    "key",
    ["password", "user_password", "api_key", "access_token", "refresh_token", "client_secret", "session_id"],
)
def test_snake_case_secret_keys_are_detected(key):
    assert sd.scan_value({key: "S3cretValue123"}), f"{key} should be flagged"


@pytest.mark.parametrize("key", ["apiKey", "clientSecret", "privateKey"])
def test_some_camelcase_keys_are_detected(key):
    assert sd.scan_value({key: "S3cretValue123"}), f"{key} should be flagged"


@pytest.mark.parametrize(
    "key",
    ["userPassword", "accessToken", "refreshToken", "authToken", "sessionId", "secretKey", "userPasswd"],
)
def test_camelcase_secret_keys_missed_is_a_bug(key):
    assert sd.scan_value({key: "S3cretValue123"}), f"{key} should be flagged"


@pytest.mark.parametrize(
    "key, detector",
    [
        ("user_password", "password"),
        ("user-password", "password"),
        ("userPassword", "password"),
        ("UserPassword", "password"),
        ("userPASSWORD", "password"),
        ("access_token", "access_token"),
        ("accessToken", "access_token"),
        ("AccessToken", "access_token"),
        ("APIKey", "api_key"),
        ("clientSecret", "client_secret"),
        ("sessionId", "session_cookie"),
        ("TLSPrivateKey", "generic_secret"),
        ("authToken", "generic_secret"),
    ],
)
def test_secret_key_styles_have_consistent_detector_types(key, detector):
    matches = sd.scan_value({key: "S3cretValue123"})
    assert [(match.detector, match.object_path) for match in matches] == [(detector, f"$.{key}")]


@pytest.mark.parametrize(
    "key",
    ["secretary", "tokenizer", "sessional", "passwordless", "monkeyBusiness", "clientSecretariat"],
)
def test_secret_words_are_not_matched_inside_ordinary_key_components(key):
    assert sd.scan_value({key: "S3cretValue123"}) == []


def test_nested_container_recursion():
    payload = {"outer": [{"inner": {"password": "topsecret1"}}]}
    matches = sd.scan_value(payload)
    assert any(m.detector == "password" and "password" in m.object_path for m in matches)


def test_embedded_json_string_is_parsed():
    matches = sd.scan_value('{"api_key": "AKIAIOSFODNN7EXAMPLE"}')
    assert {m.detector for m in matches} & {"api_key", "aws_access_key"}


# --- masking / fingerprint / decode ----------------------------------------


def test_mask_secret_redacts_key_material():
    assert sd.mask_secret("-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----") == "<private-key:redacted>"
    assert sd.mask_secret("-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----") == "<certificate:redacted>"


@pytest.mark.parametrize(("value", "expected"), [("short", "*****"), ("hunter2", "*******"), ("p@ss", "****")])
def test_mask_secret_fully_hides_short_values(value, expected):
    assert sd.mask_secret(value) == expected


def test_mask_secret_partial_reveals_long_values():
    # By design this is an audit tool: masking is a display convenience, not a
    # security boundary, so the fingerprint-style first4...last4 reveal is intended.
    assert sd.mask_secret("SuperSecretPassword123") == "Supe...d123"


def test_fingerprint_is_stable_and_distinct():
    assert sd.fingerprint("abc") == sd.fingerprint("abc")
    assert sd.fingerprint("abc") != sd.fingerprint("abd")
    assert len(sd.fingerprint("abc")) == 64


def test_decode_basic_identity_roundtrip():
    token = base64.b64encode(b"user:pass").decode()
    assert sd.decode_basic_identity(token) == "user:pass"
    assert sd.decode_basic_identity("not-base64!!") is None


def test_detector_names_are_unique_and_include_synthetic():
    names = sd.detector_names()
    assert len(names) == len(set(names))
    assert {"url_credentials", "generic_secret", "high_entropy"} <= set(names)


# --- false positives --------------------------------------------------------


@pytest.mark.parametrize(
    "benign",
    [
        "this is a normal sentence with plenty of ordinary words",
        "https://example.com/path?ref=documentation",
        "2026-09-08T12:00:00Z",
        "the quick brown fox jumps over the lazy dog",
    ],
)
def test_benign_text_is_not_flagged(benign):
    assert sd.scan_value(benign) == []


def test_scan_value_ignores_non_text_scalars():
    assert sd.scan_value(12345) == []
    assert sd.scan_value(None) == []
    assert sd.scan_value(True) == []


# --- placeholder / sentinel false positives --------------------------------

# Unambiguous non-secrets: booleans, absence markers, redaction markers and doc
# placeholders. `changeme` / `password` are deliberately excluded (they can be
# real weak defaults worth flagging).
_BENIGN_SENTINELS = [
    "true",
    "false",
    "null",
    "none",
    "N/A",
    "disabled",
    "enabled",
    "<redacted>",
    "REDACTED",
    "<value>",
    "placeholder",
]


@pytest.mark.parametrize("value", _BENIGN_SENTINELS)
def test_placeholder_values_under_secret_key_are_not_flagged(value):
    assert sd.scan_value({"password": value}) == [], f"{value!r} is not a secret"


@pytest.mark.parametrize("value", _BENIGN_SENTINELS)
def test_placeholder_values_in_secret_assignment_text_are_not_flagged(value):
    assert sd.scan_value(f"password={value}") == [], f"{value!r} is not a secret"


@pytest.mark.parametrize("value", [True, False, "****", "xxxx"])
def test_boolean_and_mask_sentinels_under_secret_key_are_not_flagged(value):
    assert sd.scan_value({"password": value}) == []


@pytest.mark.parametrize("value", ["password", "changeme", "hunter2value"])
def test_weak_default_passwords_remain_detectable(value):
    assert sd.scan_value({"password": value})
