"""Repeated short schema keys must avoid repeated normalization work safely."""

from __future__ import annotations

import pytest

from redposture_core import secret_detection as secrets


def clear_cache():
    cached = getattr(secrets, "_cached_normalized_secret_key", None)
    if cached is not None:
        cached.cache_clear()


def test_repeated_short_key_preserves_result_without_repeating_regex_work(monkeypatch):
    clear_cache()
    original = secrets.re.sub
    calls = []

    def counted(*args, **kwargs):
        calls.append(args[0])
        return original(*args, **kwargs)

    monkeypatch.setattr(secrets.re, "sub", counted)
    for _ in range(100):
        assert secrets._normalize_secret_key("CostProbeDatabasePassWord") == "cost_probe_database_pass_word"
    assert len(calls) == 3


@pytest.mark.parametrize(
    "key,expected",
    [
        ("databasePassword", "database_password"),
        ("HTTPAccessToken", "http_access_token"),
        ("db.password", "db_password"),
        ("db-password", "db_password"),
        ("db\tpassword", "db_password"),
        ("DB_PASSWORD", "db_password"),
        ("éPassword", "épassword"),
        ("", ""),
        ("apiKeyID", "api_key_id"),
        ("token.name", "token_name"),
    ],
)
def test_normalization_semantics_remain_exact(key, expected):
    assert secrets._normalize_secret_key(key) == expected
    assert secrets._normalize_secret_key(key) == expected


def test_only_bounded_short_plain_strings_can_be_retained():
    clear_cache()
    for index in range(5000):
        secrets._normalize_secret_key(f"boundedKey{index}")
    cache = secrets._cached_normalized_secret_key.cache_info()
    assert cache.currsize <= cache.maxsize == 4096
    before = cache.currsize
    for index in range(3):
        key = "long" + "a" * 1_000_000 + str(index) + "Password"
        assert secrets._normalize_secret_key(key).endswith("_password")
    assert secrets._cached_normalized_secret_key.cache_info().currsize == before


def test_unhashable_str_subclass_keeps_the_uncached_contract():
    class Unhashable(str):
        def __hash__(self) -> int:
            raise TypeError("custom string is unhashable")

    assert secrets._normalize_secret_key(Unhashable("dbPassword")) == "db_password"


def test_normalization_cache_boundary_is_in_characters_and_skips_long_names():
    clear_cache()
    secrets._normalize_secret_key("a" * 128)
    assert secrets._cached_normalized_secret_key.cache_info().currsize == 1
    secrets._normalize_secret_key("a" * 129)
    assert secrets._cached_normalized_secret_key.cache_info().currsize == 1
