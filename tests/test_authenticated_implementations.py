from __future__ import annotations

from copy import deepcopy

import pytest

from redposture_core.server_implementation import (
    clickhouse_implementation,
    mongodb_implementation,
    oracle_implementation,
    redis_implementation,
)

REDIS = "redis_version:7.4.11\r\nredis_mode:standalone\r\narch_bits:64\r\nos:Linux\r\ntcp_port:6379\r\n"
VALKEY = REDIS.replace("redis_mode:", "server_mode:") + "server_name:valkey\r\nvalkey_version:8.0.10\r\n"
BUILD = {
    "ok": 1.0,
    "version": "7.0.43",
    "versionArray": [7, 0, 43, 0],
    "gitVersion": "a" * 40,
    "modules": [],
    "bits": 64,
}


@pytest.mark.parametrize("valkey", [False, True])
@pytest.mark.parametrize("binary", [False, True])
def test_readonly_redis_identity_uses_specific_backend_before_compatibility(valkey, binary):
    body = VALKEY if valkey else REDIS
    result = redis_implementation(body.encode() if binary else body)
    assert result["product"] == ("Valkey" if valkey else "Redis")
    assert result["version"] == ("8.0.10" if valkey else "7.4.11")
    assert result["scope"] == "server_reported"


@pytest.mark.parametrize(
    "body",
    [
        None,
        {},
        b"NOAUTH",
        "redis_version:7.4.11",
        REDIS + "redis_version:6.0.0\r\n",
        REDIS + "keydb_version:6.3.4\r\n",
        REDIS.replace("7.4.11", "7.4.x"),
        REDIS.replace("6379", "99999"),
        REDIS.replace("arch_bits:64", "arch_bits:true"),
    ],
)
def test_redis_missing_conflicting_and_fork_evidence_stays_unattributed(body):
    assert redis_implementation(body) is None


@pytest.mark.parametrize("router", [False, True])
def test_mongodb_build_and_router_are_separate_claims(router):
    hello = {"ok": 1.0, **({"msg": "isdbgrid"} if router else {})}
    result = mongodb_implementation(hello, BUILD)
    assert result["product"] == "MongoDB" and result["version"] == "7.0.43"
    assert result["scope"] == ("proxy_router" if router else "server_reported")
    assert result.get("role") == ("mongos" if router else None)
    if router:
        limited = mongodb_implementation(hello, {"ok": 0, "code": 13})
        assert limited["role"] == "mongos" and "version" not in limited


@pytest.mark.parametrize(
    "key,value",
    [
        ("ok", 0),
        ("version", "7.0.99"),
        ("versionArray", [7, False, 43]),
        ("gitVersion", "unknown"),
        ("modules", ["other-product"]),
        ("bits", True),
        ("psmdbVersion", "7.0.43"),
    ],
)
def test_mongodb_unrelated_inconsistent_or_fork_build_is_not_exact_product(key, value):
    build = deepcopy(BUILD)
    build[key] = value
    assert mongodb_implementation({"ok": 1.0}, build) is None


@pytest.mark.parametrize("hello", [{}, None, {"ok": False, "msg": "isdbgrid"}, {"ok": 1, "msg": "example isdbgrid"}])
def test_mongodb_error_or_example_is_not_router_proof(hello):
    assert mongodb_implementation(hello, {}) is None


@pytest.mark.parametrize(
    "rows",
    [
        None,
        [],
        [["24.8.14.39"]],
        [["24.8.14.39", "other-server"]],
        [["24.8.x", "ClickHouse"]],
        [["24.8.14.39", "ClickHouse"], ["24.8.14.40", "ClickHouse"]],
    ],
)
def test_clickhouse_version_without_product_build_name_is_insufficient(rows):
    assert clickhouse_implementation(rows) is None


def test_clickhouse_version_and_build_name_are_positive():
    assert clickhouse_implementation([["24.8.14.39", "ClickHouse 24.8.14.39"]]) == {
        "product": "ClickHouse",
        "version": "24.8.14.39",
        "scope": "sql_backend",
        "evidence": "authenticated_version_and_build_name",
    }


@pytest.mark.parametrize(
    "banner",
    [
        {},
        None,
        {"version": "23.26.0.0.0"},
        {"version": "23.26.0.0.0", "banner": "Documentation for Oracle Database 26ai"},
        {"version": "bad", "banner": "Oracle Database 26ai Free Release 23.26.0.0.0"},
    ],
)
def test_oracle_listener_or_unrelated_text_cannot_replace_database_banner(banner):
    assert oracle_implementation(banner) is None


def test_oracle_marketing_release_does_not_override_authenticated_patch_version():
    result = oracle_implementation(
        {
            "version": "23.26.0.0.0",
            "banner": "Oracle Database 26ai Free Release 23.26.0.0.0 - Develop, Learn, and Run for Free",
        }
    )
    assert result["product"] == "Oracle Database" and result["version"] == "23.26.0.0.0"


def test_clickhouse_real_24_8_version_full_matches_sql_version():
    assert clickhouse_implementation([["24.8.14.39", "ClickHouse 24.8.14.39"]]) == {
        "product": "ClickHouse",
        "version": "24.8.14.39",
        "scope": "sql_backend",
        "evidence": "authenticated_version_and_build_name",
    }
    assert clickhouse_implementation([["24.8.14.39", "ClickHouse 25.1.2.3"]]) is None


def test_oracle_actual_ai_database_banner_is_supported():
    result = oracle_implementation(
        {
            "banner": "Oracle AI Database 26ai Free Release 23.26.3.0.0 - Develop, Learn, and Run for Free\nVersion 23.26.3.0.0",
            "version": "23.26.3.0.0",
        }
    )
    assert result is not None and result["product"] == "Oracle Database"
    assert result["version"] == "23.26.3.0.0"
