"""Synchronous, thread-free MongoDB SCRAM and read-only metadata transport.

Detailed data/discover/TLS routes remain on the existing SDK. A fallback may
only be requested before saslStart; credentials are never replayed after it.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import platform
import socket
import stringprep
import struct
import time
import unicodedata
from collections.abc import Iterator
from typing import Any

from .. import __version__
from .mongodb import MongoAuditClient, MongoClientError, is_mongodb_hello_response, json_safe

_MAX_MESSAGE = 48 * 1024 * 1024
# Retryable Reads specification; credentials, runCommand and getMore do not retry.
_RETRY_READ_CODES = {6, 7, 89, 91, 134, 189, 262, 9001, 10107, 11600, 11602, 13435, 13436}
_CLIENT_METADATA = {
    "application": {"name": "redposture"},
    "driver": {"name": "redposture-native-metadata", "version": __version__},
    "os": {"type": platform.system()},
}


class MongoMetadataFallback(MongoClientError):
    """Unsupported route, with no authentication conversation started."""


def _protocol(message: str) -> MongoClientError:
    return MongoClientError("mongodb protocol error: " + message)


def _saslprep(password: str) -> str:
    # RFC4013 uses Unicode3.2, not the host Python's current Unicode version.
    mapped = "".join(" " if stringprep.in_table_c12(c) else c for c in password if not stringprep.in_table_b1(c))
    prepared = unicodedata.ucd_3_2_0.normalize("NFKC", mapped)
    prohibited = (
        stringprep.in_table_a1,
        stringprep.in_table_c12,
        stringprep.in_table_c21,
        stringprep.in_table_c22,
        stringprep.in_table_c3,
        stringprep.in_table_c4,
        stringprep.in_table_c5,
        stringprep.in_table_c6,
        stringprep.in_table_c7,
        stringprep.in_table_c8,
        stringprep.in_table_c9,
    )
    if any(check(char) for char in prepared for check in prohibited):
        raise ValueError("password fails SASLprep")
    if any(stringprep.in_table_d1(char) for char in prepared) and (
        any(stringprep.in_table_d2(char) for char in prepared)
        or not stringprep.in_table_d1(prepared[0])
        or not stringprep.in_table_d1(prepared[-1])
    ):
        raise ValueError("password fails SASLprep bidirectional rules")
    return prepared


def _scram_fields(payload: Any) -> dict[bytes, bytes]:
    if not isinstance(payload, bytes) or not payload:
        raise _protocol("missing SCRAM payload")
    fields: dict[bytes, bytes] = {}
    for part in payload.split(b","):
        name, separator, value = part.partition(b"=")
        if not separator or len(name) != 1 or name in fields:
            raise _protocol("invalid SCRAM attributes")
        fields[name] = value
    if b"m" in fields:
        raise _protocol("unsupported mandatory SCRAM extension")
    return fields


def _conversation(response: dict[str, Any], expected: int | None = None) -> int:
    value = response.get("conversationId")
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < 0
        or (expected is not None and value != expected)
    ):
        raise _protocol("invalid SCRAM conversation identity")
    if type(response.get("done")) is not bool:
        raise _protocol("invalid SCRAM completion flag")
    return value


class MongoMetadataClient(MongoAuditClient):
    """One account, authDB, socket and immutable TLS/proxy context per client."""

    def __init__(self, host: str, port: int, *, username: str, password: str, auth_db: str, timeout: float):
        self.client = self  # ownership interface used by MongoAuditClient callers
        self._socket: socket.socket | None = None
        self._request_id = 0
        self._timeout = max(0.1, float(timeout))
        self._closed = False
        self._credentials = (host, port, username, password, auth_db)
        self._hello: dict[str, Any] = {}
        if not username or username != username.strip() or not password or auth_db == "$external":
            raise MongoMetadataFallback("credential form requires SDK")
        hostname = host[1:-1] if host.startswith("[") and host.endswith("]") else host
        try:
            # Uses the same socket proxy context as the other native clients.
            self._socket = socket.create_connection((hostname, int(port)), timeout=self._timeout)
            self._hello = self._command(
                "admin",
                {
                    "isMaster": 1,
                    "helloOk": True,
                    "saslSupportedMechs": auth_db + "." + username,
                    "client": _CLIENT_METADATA,
                },
            )
            if (
                not is_mongodb_hello_response(self._hello)
                or self._hello["maxWireVersion"] < 8
                or self._hello.get("arbiterOnly") is True
            ):
                raise MongoMetadataFallback("server handshake requires SDK")
            mechanisms = self._hello.get("saslSupportedMechs", [])
            if not isinstance(mechanisms, list):
                raise MongoMetadataFallback("mechanism negotiation requires SDK")
            mechanism = "SCRAM-SHA-256" if "SCRAM-SHA-256" in mechanisms else "SCRAM-SHA-1"
            self._authenticate(username, password, auth_db, mechanism)
        except BaseException:
            self.close()
            raise

    def _read(self, count: int, deadline: float) -> bytes:
        conn = self._socket
        if conn is None:
            raise MongoClientError("mongodb client is closed")
        chunks = bytearray()
        while len(chunks) < count:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("mongodb connection timeout")
            conn.settimeout(remaining)
            piece = conn.recv(count - len(chunks))
            if not piece:
                raise ConnectionError("connection closed during MongoDB reply")
            chunks.extend(piece)
        return bytes(chunks)

    def _command(self, database: str, command: dict[str, Any]) -> dict[str, Any]:
        from pymongo.errors import OperationFailure

        if self._closed:
            raise MongoClientError("mongodb client is closed")
        if self._socket is None:
            self._reconnect()
        try:
            return self._exchange(database, command)
        except (OSError, MongoClientError):
            self._discard_socket()
            raise
        except OperationFailure as exc:
            if exc.code in _RETRY_READ_CODES:
                self._discard_socket()
            raise

    def _reconnect(self) -> None:
        host, port, user, password, source = self._credentials
        fresh = type(self)(host, port, username=user, password=password, auth_db=source, timeout=self._timeout)
        self._socket, fresh._socket = fresh._socket, None
        self._request_id, self._hello = fresh._request_id, fresh._hello

    def _read_command(self, database: str, command: dict[str, Any]) -> dict[str, Any]:
        from pymongo.errors import OperationFailure

        try:
            return self._command(database, command)
        except OSError:
            self._discard_socket()
        except OperationFailure as exc:
            if exc.code not in _RETRY_READ_CODES:
                raise
            self._discard_socket()
        # Exactly one initial-enumeration retry, as in the SDK's retryReads.
        return self._command(database, command)

    def _exchange(self, database: str, command: dict[str, Any]) -> dict[str, Any]:
        from bson import BSON
        from pymongo.errors import OperationFailure

        conn = self._socket
        if conn is None:
            raise MongoClientError("mongodb client is closed")
        self._request_id = self._request_id % 2_147_483_647 + 1
        message = struct.pack("<I", 0) + b"\0" + BSON.encode({**command, "$db": database})
        packet = struct.pack("<iiii", len(message) + 16, self._request_id, 0, 2013) + message
        conn.settimeout(self._timeout)
        conn.sendall(packet)
        deadline = time.monotonic() + self._timeout
        header = self._read(16, deadline)
        length, _, response_to, opcode = struct.unpack("<iiii", header)
        if not 26 <= length <= _MAX_MESSAGE or response_to != self._request_id or opcode != 2013:
            raise _protocol("invalid OP_MSG header")
        body = self._read(length - 16, deadline)
        flags = struct.unpack("<I", body[:4])[0]
        # Like the SDK parser, reject checksum/exhaust/unknown required flags.
        # Unknown optional high bits are explicitly permitted by OP_MSG.
        if flags & 0xFFFF or body[4] != 0:
            raise _protocol("unsupported OP_MSG flags or section")
        try:
            response = BSON(body[5:]).decode()
        except Exception as exc:
            raise _protocol("invalid BSON response") from exc
        ok = response.get("ok")
        if isinstance(ok, bool) or not isinstance(ok, (int, float)) or ok not in {0, 1}:
            raise _protocol("invalid command status")
        if ok == 0:
            code = response.get("code")
            error = response.get("errmsg")
            if not isinstance(code, int) or isinstance(code, bool) or not isinstance(error, str) or not error:
                raise _protocol("invalid command error")
            raise OperationFailure(error, code=code, details=response)
        return response

    def _authenticate(self, username: str, password: str, database: str, mechanism: str) -> None:
        from bson import Binary

        if mechanism == "SCRAM-SHA-256":
            digest = "sha256"
            secret = _saslprep(password).encode("utf-8")
        else:
            digest = "sha1"
            secret = (
                hashlib.md5((username + ":mongo:" + password).encode("utf-8"), usedforsecurity=False)
                .hexdigest()
                .encode()
            )
        nonce = base64.b64encode(os.urandom(24))
        name = username.replace("=", "=3D").replace(",", "=2C").encode("utf-8")
        bare = b"n=" + name + b",r=" + nonce
        first = self._command(
            database,
            {
                "saslStart": 1,
                "mechanism": mechanism,
                "payload": Binary(b"n,," + bare),
                "autoAuthorize": 1,
                "options": {"skipEmptyExchange": True},
            },
        )
        conversation = _conversation(first)
        if first["done"]:
            raise _protocol("SCRAM completed before password proof")
        challenge = first.get("payload")
        if not isinstance(challenge, bytes):
            raise _protocol("missing SCRAM challenge")
        fields = _scram_fields(challenge)
        if not {b"r", b"s", b"i"}.issubset(fields):
            raise _protocol("incomplete SCRAM challenge")
        if not fields[b"r"].startswith(nonce) or len(fields[b"r"]) <= len(nonce):
            raise _protocol("invalid SCRAM nonce")
        if not fields[b"i"].isdigit():
            raise _protocol("invalid SCRAM iteration count")
        iterations = int(fields[b"i"])
        if iterations < 4096:
            raise _protocol("invalid SCRAM iteration count")
        try:
            salt = base64.b64decode(fields[b"s"], validate=True)
        except ValueError as exc:
            raise _protocol("invalid SCRAM salt") from exc
        if not salt:
            raise _protocol("empty SCRAM salt")
        salted = hashlib.pbkdf2_hmac(digest, secret, salt, iterations)
        client_key = hmac.digest(salted, b"Client Key", digest)
        stored_key = hashlib.new(digest, client_key).digest()
        final_bare = b"c=biws,r=" + fields[b"r"]
        auth = b",".join((bare, challenge, final_bare))
        signature = hmac.digest(stored_key, auth, digest)
        proof = bytes(a ^ b for a, b in zip(client_key, signature, strict=True))
        final = self._command(
            database,
            {
                "saslContinue": 1,
                "conversationId": conversation,
                "payload": Binary(final_bare + b",p=" + base64.b64encode(proof)),
            },
        )
        _conversation(final, conversation)
        server_key = hmac.digest(salted, b"Server Key", digest)
        expected = base64.b64encode(hmac.digest(server_key, auth, digest))
        verified = _scram_fields(final.get("payload"))
        if b"v" not in verified or b"e" in verified or not hmac.compare_digest(verified[b"v"], expected):
            raise _protocol("invalid SCRAM server signature")
        if not final["done"]:
            last = self._command(
                database,
                {
                    "saslContinue": 1,
                    "conversationId": conversation,
                    "payload": Binary(b""),
                },
            )
            _conversation(last, conversation)
            if not last["done"] or last.get("payload") != b"":
                raise _protocol("SCRAM conversation did not complete")

    def _discard_socket(self) -> None:
        conn, self._socket = self._socket, None
        if conn is not None:
            try:
                conn.close()
            except OSError:
                pass

    def close(self) -> None:
        self._closed = True
        self._discard_socket()

    def hello(self) -> dict[str, Any]:
        if self._closed:
            raise MongoClientError("mongodb client is closed")
        return dict(self._hello)

    def run_command(self, database: str, command: dict[str, Any]) -> dict[str, Any]:
        # Caller currently uses connectionStatus; do not add arbitrary data APIs.
        if not command or next(iter(command)) not in {"connectionStatus", "buildInfo", "listDatabases"}:
            raise MongoClientError("native metadata route cannot execute data operations")
        result = json_safe(self._command(database, command))
        return result if isinstance(result, dict) else {"result": result}

    def server_info(self) -> dict[str, Any]:
        return self.run_command("admin", {"buildInfo": 1})

    def list_database_names(self) -> list[str]:
        result = self._read_command("admin", {"listDatabases": 1, "nameOnly": True})
        databases = result.get("databases")
        if not isinstance(databases, list) or any(
            not isinstance(row, dict) or not isinstance(row.get("name"), str) for row in databases
        ):
            raise _protocol("invalid database catalogue")
        return [row["name"] for row in databases]

    def _collection_names(self, database: str) -> Iterator[str]:
        from ..discovery_frontier import DiscoveryFrontier

        cursor_id = 0
        seen: set[str] = set()
        seen_bytes = 0
        disk: DiscoveryFrontier | None = None
        empty_cursor: int | None = None
        try:
            result = self._read_command(
                database, {"listCollections": 1, "nameOnly": True, "cursor": {"batchSize": 128}}
            )
            batch_key = "firstBatch"
            while True:
                cursor = result.get("cursor")
                if not isinstance(cursor, dict):
                    raise _protocol("missing collection cursor")
                value = cursor.get("id")
                if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                    raise _protocol("invalid collection cursor identity")
                if cursor.get("ns") != database + ".$cmd.listCollections":
                    raise _protocol("collection cursor namespace changed")
                cursor_id = value
                batch = cursor.get(batch_key)
                if not isinstance(batch, list):
                    raise _protocol("invalid collection cursor batch")
                if not batch and cursor_id:
                    if empty_cursor == cursor_id:
                        raise _protocol("repeated empty collection page")
                    empty_cursor = cursor_id
                else:
                    empty_cursor = None
                for row in batch:
                    if not isinstance(row, dict) or not isinstance(row.get("name"), str):
                        raise _protocol("invalid collection name")
                    name = row["name"]
                    if disk is None and seen_bytes + len(name.encode("utf-8")) > 64 * 1024:
                        disk = DiscoveryFrontier()
                        for prior in seen:
                            disk.claim(prior)
                        seen.clear()
                    fresh = disk.claim(name) if disk is not None else name not in seen
                    if not fresh:
                        raise _protocol("repeated collection name or page")
                    if disk is None:
                        seen.add(name)
                        seen_bytes += len(name.encode("utf-8"))
                    yield name
                if not cursor_id:
                    break
                # getMore is not retryable: replay could silently skip a batch.
                result = self._command(
                    database, {"getMore": cursor_id, "collection": "$cmd.listCollections", "batchSize": 128}
                )
                batch_key = "nextBatch"
        finally:
            try:
                if cursor_id and not self._closed:
                    try:
                        self._command(database, {"killCursors": "$cmd.listCollections", "cursors": [cursor_id]})
                    except Exception:
                        # Disconnect is the last resort if cursor cleanup fails.
                        self._discard_socket()
            finally:
                if disk is not None:
                    disk.close()

    def list_collection_names(self, database: str) -> list[str]:
        return list(self._collection_names(database))

    def count_collection_names(self, database: str) -> int:
        # Auth needs an exact count, not a retained list of every collection.
        return sum(1 for _ in self._collection_names(database))
