"""Syntax-free scalar preselection must preserve all evidence and ordering."""

import random

import pytest

from redposture_core import discovery_rules as rules
from tests.test_secret_detection_prefilter import SAMPLES


def test_atomic_preselection_matches_unfiltered_rules(monkeypatch):
    rng = random.Random(20261109)
    original = rules._syntax_free_token
    samples = [*SAMPLES, "dXNlcjpwYXNzd29yZA", "p@ss", "secret-12345678", "", "null", "----"]
    samples += ["".join(rng.choices("aAzZ019_+/-", k=n)) for n in (4, 20, 64, 256) for _ in range(15)]
    samples += [s + suffix for s in SAMPLES for suffix in ("\n", "=", ":", ".", "🔑", "\x00")]
    samples += ["a" * n + "glpat-AbCdEf0123456789abcd" for n in (65510, 65536)]
    for path in ("", "password", "version", "registry.auth", "cookie", "client_secret", "logs.secret"):
        monkeypatch.setattr(rules, "_syntax_free_token", lambda _text: False)
        expected = [rules.analyze_value(value, path=path) for value in samples]
        monkeypatch.setattr(rules, "_syntax_free_token", original)
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
