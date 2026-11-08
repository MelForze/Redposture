"""Read-only SQL product claims, separate from PostgreSQL wire compatibility.

A PostgreSQL backend banner does not prove that a proxy is absent. Unknown
implementations keep the existing compatible-endpoint classification.
"""

from __future__ import annotations

import re
from typing import Any

VERSION_QUERY = (
    "SELECT pg_catalog.version(), pg_catalog.current_setting('server_version'), "
    "pg_catalog.current_setting('server_version_num')"
)
_POSTGRES = re.compile(
    r"PostgreSQL (?P<version>\d+(?:\.\d+){1,2})(?: \([^\r\n]*\))?"
    r"(?: on [^\r\n]+)?, compiled by [^\r\n]+, (?:32|64)-bit"
)
_FORK = re.compile(r"YB-|Yugabyte|Greenplum|CockroachDB|Redshift|EnterpriseDB", re.I)


def _version_number(version: str) -> int | None:
    match = re.fullmatch(r"(\d+)\.(\d+)(?:\.(\d+))?", version)
    if match is None:
        return None
    major, minor, patch = match.groups()
    if int(major) >= 10:
        return int(major) * 10000 + int(minor) if patch is None else None
    return int(major) * 10000 + int(minor) * 100 + int(patch) if patch is not None else None


def parse_implementation(rows: list[list[Any]], *, database: str) -> dict[str, str] | None:
    if len(rows) != 1 or not isinstance(rows[0], (list, tuple)):
        return None
    row = rows[0]
    if database == "pgbouncer":
        if len(row) == 1 and isinstance(row[0], str):
            match = re.fullmatch(r"PgBouncer (\d+\.\d+(?:\.\d+)?(?:[-+][A-Za-z0-9.-]+)?)", row[0])
            if match is not None:
                return {
                    "product": "PgBouncer",
                    "version": match[1],
                    "scope": "proxy_console",
                    "evidence": "show_version",
                }
        return None
    if len(row) != 3 or not all(isinstance(value, str) for value in row):
        return None
    banner, setting, number = row
    if _FORK.search(banner) or len(banner) > 4096 or len(setting) > 256 or not re.fullmatch(r"\d{5,6}", number):
        return None
    match = _POSTGRES.fullmatch(banner)
    if match is None:
        return None
    version = match["version"]
    setting_version = re.match(r"\d+(?:\.\d+){1,2}(?=\s|$)", setting)
    if setting_version is None or setting_version[0] != version or _version_number(version) != int(number):
        return None
    return {"product": "PostgreSQL", "version": version, "scope": "sql_backend", "evidence": "sql_version_and_settings"}
