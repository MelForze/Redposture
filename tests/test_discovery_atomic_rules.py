"""Syntax-free scalar preselection must preserve all evidence and ordering."""

import random

import pytest

from redposture_core import discovery_rules as rules
from tests.test_secret_detection_prefilter import SAMPLES


def test_atomic_preselection_matches_unfiltered_rules(monkeypatch):
    rng = random.Random(20261109)
    original = rules._syntax_free_token
    original_assignment = rules._simple_password_assignment
    samples = [*SAMPLES, "dXNlcjpwYXNzd29yZA", "p@ss", "secret-12345678", "", "null", "----"]
    samples += ["".join(rng.choices("aAzZ019_+/-", k=n)) for n in (4, 20, 64, 256) for _ in range(15)]
    samples += [s + suffix for s in SAMPLES for suffix in ("\n", "=", ":", ".", "🔑", "\x00")]
    samples += ["a" * n + "glpat-AbCdEf0123456789abcd" for n in (65510, 65536)]
    atoms = [
        "secret-01234567",
        "glpat-AbCdEf0123456789abcd",
        "AKIAIOSFODNN7EXAMPLE",
        "ASIA" + "A" * 16,
        "redacted",
        "xxxx",
        "abc",
        "A+1/b2-C_3",
    ]
    samples += [
        f"{prefix}{key}{sep}{quote}{atom}{quote}{suffix}"
        for prefix in ("", "\t--")
        for key in ("password", "PASSWD", "pwd", "passphrase")
        for sep in ("=", ":", " => ")
        for quote in ('"', "'")
        for atom in atoms
        for suffix in ("", "\r\n")
    ]
    samples += [
        'password="a.b.c"\n',
        'password="some value"\n',
        'password="ключ"\n',
        'password="value"; token=another',
        'password="one"\npassword="two"\n',
        'password="' + "a" * 65536 + '"\n',
    ]
    for path in ("", "password", "version", "registry.auth", "cookie", "client_secret", "logs.secret"):
        monkeypatch.setattr(rules, "_syntax_free_token", lambda _text: False)
        monkeypatch.setattr(rules, "_simple_password_assignment", lambda *_args: None)
        expected = [rules.analyze_value(value, path=path) for value in samples]
        monkeypatch.setattr(rules, "_syntax_free_token", original)
        monkeypatch.setattr(rules, "_simple_password_assignment", original_assignment)
        assert [rules.analyze_value(value, path=path) for value in samples] == expected


def test_atomic_provider_does_not_enter_impossible_grammars(monkeypatch):
    class Impossible:
        def finditer(self, text):
            pytest.fail(f"syntax-bearing grammar scanned atom: {text}")

    for name in (
        "_PRIVATE_KEY_RE",
        "_JWE_RE",
        "_JWT_RE",
        "_PASSWORD_HASH_RE",
        "_WEBHOOK_RE",
        "_SESSION_RE",
        "_AUTH_HEADER_RE",
        "_KEY_VALUE_RE",
        "_XML_SECRET_RE",
        "_TAG_RE",
        "_AZURE_ACCOUNT_KEY_RE",
    ):
        monkeypatch.setattr(rules, name, Impossible())
    result = rules.analyze_value("glpat-AbCdEf0123456789abcd", path="secret")
    assert len(result) == 1 and result[0].secret_type == "gitlab_token"


@pytest.mark.parametrize(
    "source",
    ['password="closed-secret-01234567"\n', "passwd='closed-secret-01234567'", 'PWD:"closed-secret-01234567"\r\n'],
)
def test_closed_password_literal_does_not_scan_impossible_grammars(monkeypatch, source):
    class Impossible:
        def finditer(self, text):
            pytest.fail("closed atomic password entered an unrelated grammar")

    for name in (
        "_PRIVATE_KEY_RE",
        "_JWE_RE",
        "_JWT_RE",
        "_PASSWORD_HASH_RE",
        "_WEBHOOK_RE",
        "_SESSION_RE",
        "_AUTH_HEADER_RE",
        "_XML_SECRET_RE",
        "_TAG_RE",
        "_AZURE_ACCOUNT_KEY_RE",
    ):
        monkeypatch.setattr(rules, name, Impossible())
    result = rules.analyze_value(source)
    assert len(result) == 1
    assert result[0].value == "closed-secret-01234567" and result[0].secret_type == "password"


@pytest.mark.parametrize(
    "source",
    [
        'password="glpat-AbCdEf0123456789abcd"',
        'password="AKIAIOSFODNN7EXAMPLE"',
        'password="https://example.invalid/?secret=value"',
        'password="some value"',
        'password="ключ"',
        'password="redacted"',
        'password="unfinished',
        'password="one"\npassword="two"',
    ],
)
def test_password_shortcut_keeps_ambiguous_and_structured_values_on_full_path(source):
    assert rules._simple_password_assignment(source, "neutral") is None


def test_password_shortcut_keeps_sensitive_outer_field_context_on_full_path():
    assert rules._simple_password_assignment('password="closed-secret-01234567"', "strong") is None
    assert rules._simple_password_assignment('password="closed-secret-01234567"', "medium") is None
