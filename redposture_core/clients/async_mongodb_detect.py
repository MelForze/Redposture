"""Native, event-loop-local MongoDB detection IO (no credential/data sessions)."""

from __future__ import annotations

import asyncio
import ssl
import struct
from typing import Any

from . import mongodb as helpers
from .async_detect_stream import close_stream, require_numeric_host, reraise_fallback
from .async_http_detect import AsyncHttpFallback


class AsyncMongoDetectClient:
    def __init__(self, client: Any) -> None:
        self.client = client

    async def close(self) -> None:
        await self.client.close()

    async def hello(self) -> dict[str, Any]:
        try:
            result = await self.client["admin"].command("hello")
        except Exception as exc:
            reraise_fallback(exc)
            try:
                from pymongo.errors import OperationFailure, ProtocolError, ServerSelectionTimeoutError
            except ImportError:
                raise exc from None
            if isinstance(exc, OperationFailure) and exc.code == 59:
                result = await self.client["admin"].command("isMaster")
            else:
                if isinstance(exc, ServerSelectionTimeoutError):
                    topology = getattr(self.client, "topology_description", None)
                    descriptions = getattr(topology, "server_descriptions", None)
                    if callable(descriptions):
                        for server in descriptions().values():
                            error = getattr(server, "error", None)
                            if isinstance(error, BaseException):
                                reraise_fallback(error)
                            if isinstance(error, ProtocolError):
                                raise helpers.MongoClientError(f"mongodb protocol error: {error}") from exc
                raise
        if not isinstance(result, dict):
            raise helpers.MongoNotMongoError("hello did not return a document")
        if not helpers.is_mongodb_hello_response(result):
            raise helpers.MongoNotMongoError("hello response is not MongoDB-like")
        safe = helpers.json_safe(dict(result))
        return safe if isinstance(safe, dict) else dict(result)

    async def server_info(self) -> dict[str, Any]:
        info = await self.client.server_info()
        if not isinstance(info, dict):
            return {}
        safe = helpers.json_safe(dict(info))
        return safe if isinstance(safe, dict) else dict(info)

    async def list_database_names(self) -> list[str]:
        return [str(item) for item in await self.client.list_database_names()]

    async def list_collection_names(self, database: str) -> list[str]:
        return [str(item) for item in await self.client[database].list_collection_names()]

    async def count_documents(self, database: str, collection: str) -> int | None:
        coll = self.client[database][collection]
        try:
            return int(await coll.estimated_document_count())
        except Exception as exc:
            reraise_fallback(exc)
            return int(await coll.count_documents({}))


def open_client(
    host: str,
    port: int,
    *,
    timeout: float,
    auth_db: str,
    tls: bool = False,
    tls_ca: str | None = None,
    tls_cert_key: str | None = None,
    tls_insecure: bool = False,
) -> AsyncMongoDetectClient:
    require_numeric_host(host)
    try:
        driver = helpers._load_pymongo()
    except helpers.MongoDependencyError as exc:
        raise AsyncHttpFallback(str(exc)) from exc
    factory = getattr(driver, "AsyncMongoClient", None)
    if not callable(factory):
        raise AsyncHttpFallback("installed PyMongo has no native AsyncMongoClient")
    # Reuse the original factory's URI and timeout/TLS options; it does not
    # connect or perform IO itself. AsyncMongoClient's default lazy connection
    # avoids a second handshake or extra ping ahead of hello.
    client = helpers.open_mongodb_client(
        host,
        port,
        timeout=timeout,
        auth_db=auth_db,
        tls=tls,
        tls_ca_file=tls_ca,
        tls_certificate_key_file=tls_cert_key,
        tls_insecure=tls_insecure,
        mongo_client_cls=factory,
    )
    return AsyncMongoDetectClient(client)


async def _read(reader: asyncio.StreamReader, size: int, timeout: float) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = await asyncio.wait_for(reader.read(size - len(data)), timeout)
        if not chunk:
            raise ConnectionError("truncated MongoDB reply")
        data.extend(chunk)
    return bytes(data)


async def probe_legacy_hello(
    host: str,
    port: int,
    *,
    timeout: float,
    tls: bool = False,
    tls_ca_file: str | None = None,
    tls_certificate_key_file: str | None = None,
    tls_insecure: bool = False,
) -> dict[str, Any] | None:
    """The same bounded OP_QUERY isMaster verifier as the synchronous client."""
    require_numeric_host(host)
    from bson import BSON

    document = BSON.encode({"isMaster": 1})
    body = struct.pack("<i", 0) + b"admin.$cmd\0" + struct.pack("<ii", 0, 1) + document
    request = struct.pack("<iiii", 16 + len(body), 1, 0, 2004) + body
    context = None
    if tls:
        context = ssl.create_default_context(cafile=tls_ca_file)
        if tls_insecure:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        if tls_certificate_key_file:
            context.load_cert_chain(tls_certificate_key_file)
    writer = None
    try:
        ssl_options: dict[str, Any] = {"server_hostname": host} if context is not None else {}
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=context, **ssl_options),
            timeout,
        )
        writer.write(request)
        await asyncio.wait_for(writer.drain(), timeout)
        header = await _read(reader, 16, timeout)
        length, _request_id, response_to, opcode = struct.unpack("<iiii", header)
        if not 36 <= length <= 1024 * 1024 or response_to != 1 or opcode != 1:
            return None
        payload = await _read(reader, length - 16, timeout)
    finally:
        if writer is not None:
            await close_stream(writer)
    if len(payload) < 20:
        return None
    _flags, _cursor_id, _starting_from, returned = struct.unpack("<iqii", payload[:20])
    if returned < 1 or len(payload) < 24:
        return None
    size = struct.unpack("<i", payload[20:24])[0]
    if not 5 <= size <= len(payload) - 20:
        return None
    try:
        result = BSON(payload[20 : 20 + size]).decode()
    except Exception:
        return None
    return result if helpers.is_mongodb_hello_response(result) else None
