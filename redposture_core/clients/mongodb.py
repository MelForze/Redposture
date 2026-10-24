"""MongoDB client helpers used by the MongoDB audit stage."""

from __future__ import annotations

import json
import re
import socket
import ssl
import struct
from collections.abc import Iterable
from typing import Any
from urllib.parse import quote

_DEFAULT_SERVER_SELECTION_MS = 1000
_SYSTEM_DATABASES = {"admin", "config", "local"}


class MongoDependencyError(RuntimeError):
    """Raised when pymongo is unavailable at runtime."""


class MongoClientError(RuntimeError):
    """Normalized MongoDB client error."""


class MongoPartialReadError(MongoClientError):
    """A cursor failed after returning useful documents."""

    def __init__(self, documents: list[dict[str, Any]], cause: Exception) -> None:
        super().__init__(normalize_mongodb_error(cause))
        self.documents = documents


class MongoAuthError(MongoClientError):
    """Normalized MongoDB auth/permission error."""


class MongoNotMongoError(MongoClientError):
    """Raised when the endpoint does not look like MongoDB."""


def is_mongodb_hello_response(result: Any) -> bool:
    """Return whether *result* has a MongoDB-specific hello/isMaster shape.

    ``{"ok": 1}`` is a generic command acknowledgement and is insufficient.
    A real hello response advertises a coherent wire-version range and at
    least one topology/role field defined by MongoDB's handshake protocol.
    """

    if not isinstance(result, dict):
        return False
    ok = result.get("ok")
    if isinstance(ok, bool) or not isinstance(ok, (int, float)) or ok != 1:
        return False
    minimum = result.get("minWireVersion")
    maximum = result.get("maxWireVersion")
    if (
        not isinstance(minimum, int)
        or isinstance(minimum, bool)
        or not isinstance(maximum, int)
        or isinstance(maximum, bool)
        or minimum < 0
        or maximum < minimum
        or maximum > 10_000
    ):
        return False
    return any(
        key in result
        for key in (
            "isWritablePrimary",
            "ismaster",
            "secondary",
            "arbiterOnly",
            "setName",
            "msg",
            "topologyVersion",
        )
    )


def is_legacy_wire_error(exc: BaseException) -> bool:
    """PyMongo 4 refuses servers whose handshake advertises wire < 8."""

    message = str(exc).lower()
    return "reports wire version" in message and "requires at least" in message


def probe_legacy_mongodb_hello(
    host: str,
    port: int,
    *,
    timeout: float,
    tls: bool = False,
    tls_ca_file: str | None = None,
    tls_certificate_key_file: str | None = None,
    tls_insecure: bool = False,
) -> dict[str, Any] | None:
    """Read a bounded unauthenticated OP_QUERY isMaster reply for legacy detection.

    This is only used after PyMongo reports its unsupported wire floor. It does
    not authenticate or imply that any application data is accessible.
    """

    from bson import BSON

    document = BSON.encode({"isMaster": 1})
    body = struct.pack("<i", 0) + b"admin.$cmd\0" + struct.pack("<ii", 0, 1) + document
    request = struct.pack("<iiii", 16 + len(body), 1, 0, 2004) + body

    def read_exact(conn: socket.socket | ssl.SSLSocket, length: int) -> bytes:
        result = bytearray()
        while len(result) < length:
            part = conn.recv(length - len(result))
            if not part:
                raise ConnectionError("truncated MongoDB reply")
            result.extend(part)
        return bytes(result)

    with socket.create_connection((host, port), timeout=timeout) as raw:
        raw.settimeout(timeout)
        connection: socket.socket
        if tls:
            context = ssl.create_default_context(cafile=tls_ca_file)
            if tls_insecure:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            if tls_certificate_key_file:
                context.load_cert_chain(tls_certificate_key_file)
            connection = context.wrap_socket(raw, server_hostname=host)
        else:
            connection = raw
        with connection:
            connection.sendall(request)
            header = read_exact(connection, 16)
            length, _request_id, response_to, opcode = struct.unpack("<iiii", header)
            if not 36 <= length <= 1024 * 1024 or response_to != 1 or opcode != 1:
                return None
            payload = read_exact(connection, length - 16)
    if len(payload) < 20:
        return None
    _flags, _cursor_id, _starting_from, returned = struct.unpack("<iqii", payload[:20])
    if returned < 1 or len(payload) < 24:
        return None
    document_size = struct.unpack("<i", payload[20:24])[0]
    if not 5 <= document_size <= len(payload) - 20:
        return None
    try:
        result = BSON(payload[20 : 20 + document_size]).decode()
    except Exception:
        return None
    return result if is_mongodb_hello_response(result) else None


def _load_pymongo() -> Any:
    try:
        import pymongo
    except ModuleNotFoundError as exc:  # pragma: no cover - exercised by stage-level fallback tests
        raise MongoDependencyError(
            "pymongo is required for mongodb module; install redposture with dependencies"
        ) from exc
    return pymongo


def _load_bson_json_util() -> Any | None:
    try:
        from bson import json_util
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
    normalized_host = str(host or "").strip()
    if normalized_host.startswith("[") and normalized_host.endswith("]"):
        normalized_host = normalized_host[1:-1]
    # RFC 3986 requires an IPv6 literal in a URI authority to be bracketed.
    uri_host = f"[{normalized_host}]" if ":" in normalized_host else normalized_host
    host_part = f"{uri_host}:{int(port)}"
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
    if "authentication failed" in lower or getattr(exc, "code", None) == 18:
        return "authentication failed"
    if getattr(exc, "code", None) == 13 or "not authorized" in lower or "unauthorized" in lower:
        return "authorization denied"
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
    return (
        any(
            needle in text
            for needle in (
                "authentication failed",
                "not authorized",
                "authorization denied",
                "unauthorized",
                "requires authentication",
                "command requires authentication",
                "auth error",
            )
        )
        or re.search(r"\bcode\s+(?:13|18)\b", text) is not None
    )


def is_transient_network_error(exc: BaseException | str | None) -> bool:
    """True when the failure is a network-shaped transient (timeout, refused,
    reset, DNS blip) rather than an auth verdict from the server. Callers use
    this to avoid misclassifying network noise as 'invalid credential'."""
    text = str(exc or "").lower()
    return any(
        needle in text
        for needle in (
            "connection refused",
            "connection reset",
            "connection timeout",
            "timed out",
            "serverselectiontimeouterror",
            "dns lookup failed",
            "name or service not known",
            "temporary failure in name resolution",
            "network is unreachable",
            "no route to host",
            "topologydescription",
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
    tls: bool = False,
    tls_ca_file: str | None = None,
    tls_certificate_key_file: str | None = None,
    tls_insecure: bool = False,
    mongo_client_cls: Any | None = None,
) -> Any:
    client_cls = mongo_client_cls
    if client_cls is None:
        client_cls = _load_pymongo().MongoClient
    timeout_ms = max(100, int(float(timeout) * 1000))
    uri = build_mongodb_uri(host, port, username=username, password=password, auth_db=auth_db)
    kwargs: dict[str, Any] = {
        "serverSelectionTimeoutMS": timeout_ms,
        "connectTimeoutMS": timeout_ms,
        "socketTimeoutMS": timeout_ms,
        "appname": "redposture",
    }
    if tls or tls_ca_file or tls_certificate_key_file or tls_insecure:
        kwargs["tls"] = True
        if tls_ca_file:
            kwargs["tlsCAFile"] = tls_ca_file
        if tls_certificate_key_file:
            kwargs["tlsCertificateKeyFile"] = tls_certificate_key_file
        if tls_insecure:
            kwargs["tlsAllowInvalidCertificates"] = True
            kwargs["tlsAllowInvalidHostnames"] = True
    return client_cls(uri, **kwargs)


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
        except Exception as exc:
            try:
                from pymongo.errors import OperationFailure, ProtocolError, ServerSelectionTimeoutError
            except ImportError:
                # Embedded callers may supply a client without the optional
                # driver. Preserve their actual failure rather than masking it.
                raise exc from None

            # Only an unsupported command justifies the legacy spelling. A
            # selection/socket timeout must not receive a second full budget.
            if isinstance(exc, OperationFailure) and exc.code == 59:
                result = _command(self.client, "admin", "isMaster")
            else:
                # PyMongo wraps wire errors in ServerSelectionTimeoutError;
                # retain the actual protocol failure instead of triggering
                # the runtime's longer retry for genuine network timeouts.
                if isinstance(exc, ServerSelectionTimeoutError):
                    topology = getattr(self.client, "topology_description", None)
                    descriptions = getattr(topology, "server_descriptions", None)
                    if callable(descriptions):
                        for server in descriptions().values():
                            error = getattr(server, "error", None)
                            if isinstance(error, ProtocolError):
                                raise MongoClientError(f"mongodb protocol error: {error}") from exc
                raise
        if not isinstance(result, dict):
            raise MongoNotMongoError("hello did not return a document")
        if not is_mongodb_hello_response(result):
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
            # The exact fallback is useful for views/engines that do not
            # support estimated counts.  If it also fails, surface that error
            # so the audit can report a partial collection result instead of
            # silently turning an authorization/network failure into None.
            return int(coll.count_documents({}))

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
        documents: list[dict[str, Any]] = []
        try:
            if limit is not None:
                cursor = cursor.limit(int(limit))
            for item in cursor:
                documents.append(json_safe(item))
            return documents
        except Exception as exc:
            if documents:
                raise MongoPartialReadError(documents, exc) from exc
            raise
        finally:
            close_quietly(cursor)


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
    "is_transient_network_error",
    "MongoAuthError",
    "MongoClientError",
    "MongoDependencyError",
    "MongoNotMongoError",
    "MongoPartialReadError",
    "is_mongodb_hello_response",
    "build_mongodb_uri",
    "close_quietly",
    "is_auth_error",
    "json_safe",
    "non_system_databases",
    "normalize_mongodb_error",
    "open_mongodb_client",
]
