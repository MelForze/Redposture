"""MongoDB client helpers used by the MongoDB audit stage."""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from typing import Any
from urllib.parse import quote

_DEFAULT_SERVER_SELECTION_MS = 1000
_SYSTEM_DATABASES = {"admin", "config", "local"}


class MongoDependencyError(RuntimeError):
    """Raised when pymongo is unavailable at runtime."""


class MongoClientError(RuntimeError):
    """Normalized MongoDB client error."""


class MongoAuthError(MongoClientError):
    """Normalized MongoDB auth/permission error."""


class MongoNotMongoError(MongoClientError):
    """Raised when the endpoint does not look like MongoDB."""


def _load_pymongo() -> Any:
    try:
        import pymongo  # type: ignore[import-not-found]
    except ModuleNotFoundError as exc:  # pragma: no cover - exercised by stage-level fallback tests
        raise MongoDependencyError(
            "pymongo is required for mongodb module; install redposture with dependencies"
        ) from exc
    return pymongo


def _load_bson_json_util() -> Any | None:
    try:
        from bson import json_util  # type: ignore[import-not-found]
    except ModuleNotFoundError:
        return None
    return json_util


def build_mongodb_uri(
    host: str,
    port: int,
    *,
    username: str | None = None,
    password: str | None = None,
    auth_db: str | None = "admin",
) -> str:
    user = str(username or "").strip()
    secret = password
    auth_source = str(auth_db or "admin").strip() or "admin"
    host_part = f"{host}:{int(port)}"
    if user or secret is not None:
        auth = quote(user, safe="")
        if secret is not None:
            auth += f":{quote(str(secret), safe='')}"
        host_part = f"{auth}@{host_part}"
    return f"mongodb://{host_part}/?authSource={quote(auth_source, safe='')}&directConnection=true"


def normalize_mongodb_error(exc: BaseException) -> str:
    text = str(exc or "").strip()
    if not text:
        return "mongodb operation failed"
    lower = text.lower()
    if "connection refused" in lower:
        return "connection refused (service is not listening on target port)"
    if "timed out" in lower or "timeout" in lower or "serverselectiontimeouterror" in lower:
        return "connection timeout"
    if "authentication failed" in lower or "not authorized" in lower or "unauthorized" in lower:
        return "authentication failed"
    if "name or service not known" in lower or "temporary failure in name resolution" in lower:
        return "dns lookup failed"
    match = re.search(r"\[errno\s+(-?\d+)\]\s*(.*)", text, flags=re.IGNORECASE)
    if match:
        errno_num = match.group(1)
        detail = (match.group(2) or "").strip()
        if errno_num in {"61", "111"}:
            return "connection refused (service is not listening on target port)"
        if errno_num in {"60", "110"}:
            return "connection timeout"
        if errno_num in {"8", "-2"}:
            return "dns lookup failed"
        if detail:
            return detail
    return text


def is_auth_error(exc: BaseException | str | None) -> bool:
    text = str(exc or "").lower()
    return any(
        needle in text
        for needle in (
            "authentication failed",
            "not authorized",
            "unauthorized",
            "requires authentication",
            "command requires authentication",
            "auth error",
            "code 13",
            "code 18",
        )
    )


def json_safe(value: Any) -> Any:
    json_util = _load_bson_json_util()
    if json_util is not None:
        try:
            return json.loads(json_util.dumps(value, json_options=json_util.RELAXED_JSON_OPTIONS))
        except Exception:
            pass
    try:
        json.dumps(value)
        return value
    except TypeError:
        if isinstance(value, dict):
            return {str(key): json_safe(item) for key, item in value.items()}
        if isinstance(value, (list, tuple)):
            return [json_safe(item) for item in value]
        return str(value)


def _command(client: Any, database: str, command: str | dict[str, Any]) -> Any:
    db = client[database]
    return db.command(command)


def open_mongodb_client(
    host: str,
    port: int,
    *,
    username: str | None = None,
    password: str | None = None,
    auth_db: str | None = "admin",
    timeout: float = 1.0,
    mongo_client_cls: Any | None = None,
) -> Any:
    client_cls = mongo_client_cls
    if client_cls is None:
        client_cls = _load_pymongo().MongoClient
    timeout_ms = max(100, int(float(timeout) * 1000))
    uri = build_mongodb_uri(host, port, username=username, password=password, auth_db=auth_db)
    return client_cls(
        uri,
        serverSelectionTimeoutMS=timeout_ms,
        connectTimeoutMS=timeout_ms,
        socketTimeoutMS=timeout_ms,
        appname="redposture",
    )


class MongoAuditClient:
    def __init__(self, client: Any) -> None:
        self.client = client

    def close(self) -> None:
        close = getattr(self.client, "close", None)
        if callable(close):
            close()

    def hello(self) -> dict[str, Any]:
        try:
            result = _command(self.client, "admin", "hello")
        except Exception:
            result = _command(self.client, "admin", "isMaster")
        if not isinstance(result, dict):
            raise MongoNotMongoError("hello did not return a document")
        if not (
            result.get("ok") == 1 or result.get("isWritablePrimary") is not None or result.get("ismaster") is not None
        ):
            raise MongoNotMongoError("hello response is not MongoDB-like")
        safe = json_safe(dict(result))
        return safe if isinstance(safe, dict) else dict(result)

    def server_info(self) -> dict[str, Any]:
        info = self.client.server_info()
        if not isinstance(info, dict):
            return {}
        safe = json_safe(dict(info))
        return safe if isinstance(safe, dict) else dict(info)

    def list_database_names(self) -> list[str]:
        return [str(item) for item in self.client.list_database_names()]

    def list_collection_names(self, database: str) -> list[str]:
        return [str(item) for item in self.client[database].list_collection_names()]

    def list_indexes(self, database: str, collection: str) -> list[dict[str, Any]]:
        return [json_safe(item) for item in self.client[database][collection].list_indexes()]

    def run_command(self, database: str, command: dict[str, Any]) -> dict[str, Any]:
        result = _command(self.client, database, command)
        if not isinstance(result, dict):
            return {"result": json_safe(result)}
        safe = json_safe(dict(result))
        return safe if isinstance(safe, dict) else dict(result)

    def count_documents(self, database: str, collection: str) -> int | None:
        coll = self.client[database][collection]
        try:
            return int(coll.estimated_document_count())
        except Exception:
            try:
                return int(coll.count_documents({}))
            except Exception:
                return None

    def find_documents(
        self,
        database: str,
        collection: str,
        *,
        query: dict[str, Any] | None = None,
        projection: dict[str, Any] | None = None,
        limit: int | None = None,
    ) -> list[dict[str, Any]]:
        cursor = self.client[database][collection].find(query or {}, projection)
        if limit is not None:
            cursor = cursor.limit(int(limit))
        return [json_safe(item) for item in cursor]


def close_quietly(client: Any) -> None:
    try:
        close = getattr(client, "close", None)
        if callable(close):
            close()
    except Exception:
        return


def non_system_databases(names: Iterable[str]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for raw in names:
        name = str(raw or "").strip()
        if not name or name in _SYSTEM_DATABASES or name in seen:
            continue
        seen.add(name)
        result.append(name)
    return result


__all__ = [
    "MongoAuditClient",
    "MongoAuthError",
    "MongoClientError",
    "MongoDependencyError",
    "MongoNotMongoError",
    "build_mongodb_uri",
    "close_quietly",
    "is_auth_error",
    "json_safe",
    "non_system_databases",
    "normalize_mongodb_error",
    "open_mongodb_client",
]
