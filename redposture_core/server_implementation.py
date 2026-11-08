"""Strict parsers for read-only, authenticated server-reported identity.

No parser performs I/O or infers absence of a proxy. Unrecognized or conflicting
evidence returns None, keeping the existing compatible-service classification.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

_VERSION = re.compile(r"[0-9]+(?:\.[0-9]+){2,4}(?:[-+][A-Za-z0-9.-]+)?")


def redis_implementation(value: Any) -> dict[str, str] | None:
    if not isinstance(value, (str, bytes)) or len(value) > 65536:
        return None
    text = value.decode("utf-8", errors="replace") if isinstance(value, bytes) else value
    fields: dict[str, str] = {}
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        key, separator, content = line.partition(":")
        if separator:
            if key in fields:
                return None
            fields[key] = content.strip()
    valkey = "valkey_version" in fields
    if (
        fields.get("server_mode" if valkey else "redis_mode") not in {"standalone", "cluster", "sentinel"}
        or valkey
        and fields.get("server_name") != "valkey"
        or not valkey
        and fields.get("server_name", "redis") != "redis"
        or fields.get("arch_bits") not in {"32", "64"}
        or not fields.get("os")
        or not re.fullmatch(r"[0-9]{1,5}", fields.get("tcp_port", ""))
        or not 0 < int(fields["tcp_port"]) <= 65535
        or any(key in fields for key in ("keydb_version", "dragonfly_version", "redict_version"))
    ):
        return None
    key, product = ("valkey_version", "Valkey") if valkey else ("redis_version", "Redis")
    version = fields.get(key, "")
    if len(version) > 64 or _VERSION.fullmatch(version) is None:
        return None
    return {"product": product, "version": version, "scope": "server_reported", "evidence": "authenticated_info_server"}


def mongodb_implementation(hello: Any, build: Any) -> dict[str, str] | None:
    if not isinstance(hello, Mapping) or type(hello.get("ok")) not in {int, float} or hello["ok"] != 1:
        return None
    router = hello.get("msg") == "isdbgrid"
    result = (
        {"product": "MongoDB", "scope": "proxy_router", "evidence": "authenticated_hello_isdbgrid", "role": "mongos"}
        if router
        else None
    )
    if not isinstance(build, Mapping) or type(build.get("ok")) not in {int, float} or build["ok"] != 1:
        return result
    if any(key in build for key in ("psmdbVersion", "docdb_version", "documentdb_version")):
        return result
    version, array, commit, modules = (build.get(key) for key in ("version", "versionArray", "gitVersion", "modules"))
    if (
        not isinstance(version, str)
        or len(version) > 64
        or _VERSION.fullmatch(version) is None
        or not isinstance(array, list)
        or len(array) < 3
        or not all(type(number) is int for number in array[:3])
        or tuple(array[:3]) != tuple(int(x) for x in version.split("-", 1)[0].split("+", 1)[0].split(".")[:3])
        or not isinstance(commit, str)
        or re.fullmatch(r"[0-9a-f]{40,64}", commit, re.I) is None
        or type(build.get("bits")) is not int
        or build["bits"] not in {32, 64}
        or not isinstance(modules, list)
        or any(item != "enterprise" for item in modules)
    ):
        return result
    if result is not None:
        return {**result, "version": version}
    return {
        "product": "MongoDB",
        "version": version,
        "scope": "server_reported",
        "evidence": "authenticated_build_info",
    }


def clickhouse_implementation(rows: Any) -> dict[str, str] | None:
    if (
        not isinstance(rows, (list, tuple))
        or len(rows) != 1
        or not isinstance(rows[0], (list, tuple))
        or len(rows[0]) != 2
    ):
        return None
    version, name = rows[0]
    if (
        not isinstance(version, str)
        or len(version) > 64
        or _VERSION.fullmatch(version) is None
        or name != f"ClickHouse {version}"
    ):
        return None
    return {
        "product": "ClickHouse",
        "version": version,
        "scope": "sql_backend",
        "evidence": "authenticated_version_and_build_name",
    }


def oracle_implementation(banner: Any) -> dict[str, str] | None:
    if not isinstance(banner, Mapping):
        return None
    text, version = banner.get("banner"), banner.get("version")
    if (
        not isinstance(text, str)
        or len(text) > 16384
        or re.search(r"(?:^|\|)\s*Oracle (?:AI )?Database [0-9]{1,2}(?:c|g|i|ai)?\b", text) is None
        or not isinstance(version, str)
        or len(version) > 64
        or _VERSION.fullmatch(version) is None
    ):
        return None
    return {
        "product": "Oracle Database",
        "version": version,
        "scope": "sql_backend",
        "evidence": "authenticated_database_banner",
    }
