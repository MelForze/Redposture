"""Prefix selection must preserve every full-regex finding and its order."""

from __future__ import annotations

import random
import re

import pytest

from redposture_core import secret_detection as sd

SAMPLES = (
    "password=abcdef",
    "-----BEGIN PRIVATE KEY-----\nhello\n-----END PRIVATE KEY-----",
    "-----BEGIN CERTIFICATE-----\nhello\n-----END CERTIFICATE-----",
    "Bearer abcdef0123456789",
    "Basic dXNlcjpwYXNzd29yZA==",
    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcDEF123",
    "AKIAIOSFODNN7EXAMPLE",
    "ghp_1234567890abcdefABCDEF1234567890",
    "glpat-AbCdEf0123456789abcd",
    "xoxb-1234567890-ABCDEFghij",
    "sk_live_0123456789ABCDEFghijklmn",
    "sk-proj-AbCdEf0123456789AbCdEf0123456789",
    "glsa_AbCdEf0123456789AbCdEf012345",
    "dop_v1_" + "A" * 40,
    "shpat_" + "A" * 30,
    "dckr_pat_AbCdEf0123456789AbCdEf01234",
    "pypi-AgEI" + "a" * 30,
    "SG.abcdefgh.ABCDEFGHIJKLMNOPQRST",
    "SK0123456789abcdef0123456789abcdef",
    "12345678:AA" + "a" * 30,
    "https://hooks.slack.com/services/T000/B000/XXXXXXXX",
    "$argon2id$" + "A" * 25,
    "postgres://user:pass@host/db",
    "username=alice password=secret-value",
    "client_secret=secret-value",
    "refresh-token=secret-value",
    "access_token=secret-value",
    "api-key=secret-value",
    "sessionid=secret-value",
    "sid=secret-value",
    "auth_token=secret-value",
    "<password>secret-value</password>",
    '<input name="password" value="secret-value">',
    "WITH PASSWORD 'secret-value'",
    "без секретов",
    "neutral:value",
)


def test_short_atomic_value_only_selects_possible_regexes() -> None:
    assert [name for name, _, _ in sd._candidate_patterns("glpat-AbCdEf0123456789abcd")] == ["gitlab_token"]
    assert list(sd._candidate_patterns("ordinary text without provider markers")) == []


def test_prefilter_preserves_overlapping_formats_unicode_and_order(monkeypatch: pytest.MonkeyPatch) -> None:
    original = sd._PATTERNS
    original_words = sd._WORD_RE

    class CompleteEntropyScan:
        def fullmatch(self, text):
            return None

        def finditer(self, text):
            return original_words.finditer(text)

    enabled = set(sd.detector_names())
    random_source = random.Random(20261103)
    corpus = list(SAMPLES)
    corpus += [" ".join(SAMPLES), "|".join(SAMPLES)]
    corpus += [sample.swapcase() for sample in SAMPLES]
    corpus += [sample.replace("s", "ſ").replace("K", "K") for sample in SAMPLES]
    corpus += [" \n".join(random_source.choices(SAMPLES, k=5)) for _ in range(100)]
    corpus += [left + right for left in SAMPLES for right in SAMPLES]
    for text in corpus:
        actual = sd._scan_text(text, "$.payload", enabled)
        with monkeypatch.context() as patch:
            # A changed/custom pattern tuple takes the complete scan path.
            patch.setattr(sd, "_PATTERNS", (*original, ("custom", "high", re.compile("(?!)"))))
            patch.setattr(sd, "_WORD_RE", CompleteEntropyScan())
            expected = sd._scan_text(text, "$.payload", enabled)
        assert actual == expected, text
    found = {name for text in SAMPLES for name, _, pattern in original if pattern.search(text)}
    assert found == {name for name, _, _ in original}


def test_custom_patterns_keep_complete_scan_path(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sd, "_PATTERNS", (("custom", "high", re.compile(r"new-provider:\w+")),))
    matches = sd._scan_text("new-provider:abcdef", "$", {"custom"})
    assert [(m.detector, m.value) for m in matches] == [("custom", "new-provider:abcdef")]


@pytest.mark.parametrize("text", ["x" * 65_537, "İ-bearer-λ"])
def test_large_or_unicode_text_keeps_full_path_without_case_copy(text: str) -> None:
    class NoLower(str):
        def lower(self):
            raise AssertionError("do not copy a large value or approximate Unicode IGNORECASE")

    assert sd._candidate_patterns(NoLower(text)) is sd._PATTERNS
