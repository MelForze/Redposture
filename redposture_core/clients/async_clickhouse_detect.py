"""Native ClickHouse transport with original driver codecs and session adoption.

The driver only serializes/parses bounded memory here. Its execute/connect/ping
methods never perform socket IO on the detection loop.
"""

from __future__ import annotations

import io
import socket
import ssl
from typing import Any

from .async_http_detect import AsyncHttpFallback
from .async_retained_socket import RetainedSocketIO

_PACKET_CAP = 256 * 1024
_ITEMS_CAP = 4096


class _NeedBytes(Exception):
    def __init__(self, size: int) -> None:
        self.size = size


class _MemoryReader:
    """Driver reader protocol over memory; incomplete reads request native IO."""

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.position = 0
        self.varint_run = 0

    def _take(self, size: int) -> bytes:
        end = self.position + size
        if size < 0 or end > _PACKET_CAP:
            raise AsyncHttpFallback("large ClickHouse detection packet requires legacy verification")
        if end > len(self.data):
            raise _NeedBytes(end - len(self.data))
        result = self.data[self.position : end]
        self.position = end
        return result

    def read(self, size: int) -> bytes:
        self.varint_run = 0
        return self._take(size)

    def read_one(self) -> int:
        self.varint_run += 1
        if self.varint_run > 128:
            raise AsyncHttpFallback("unbounded ClickHouse varint sequence")
        return self._take(1)[0]

    def read_strings(self, count: int, encoding: str | None = None) -> tuple[Any, ...]:
        from clickhouse_driver.varint import read_varint

        if count > _ITEMS_CAP:
            raise AsyncHttpFallback("large ClickHouse string result requires legacy verification")
        result = []
        for _ in range(count):
            data: Any = self.read(read_varint(self))
            if encoding:
                try:
                    data = data.decode(encoding)
                except UnicodeDecodeError:
                    pass
            result.append(data)
        return tuple(result)

    def read_fixed_strings(self, count: int, length: int, encoding: str | None = None) -> tuple[Any, ...]:
        if count > _ITEMS_CAP:
            raise AsyncHttpFallback("large ClickHouse fixed string result requires legacy verification")
        result = []
        for _ in range(count):
            data: Any = self.read(length)
            if encoding:
                try:
                    data = data.rstrip(b"\x00").decode(encoding)
                except UnicodeDecodeError:
                    pass
            result.append(data)
        return tuple(result)


class NativeClickHouseIO:
    def __init__(self) -> None:
        self.io = RetainedSocketIO()
        self.sessions: dict[int, tuple[Any, socket.socket, bytes]] = {}
        self.http_sessions: dict[int, Any] = {}
        self.io.check_supported()

    async def _parse(self, client: Any, sock: socket.socket, function: Any) -> Any:
        data = b""
        connection = client.connection
        while True:
            reader = _MemoryReader(data)
            connection.fin = reader
            if connection.server_info is not None:
                connection.block_in = connection.get_block_in_stream()
                from clickhouse_driver.streams.native import BlockInputStream

                connection.block_in_raw = BlockInputStream(reader, connection.context)
            try:
                value = function()
            except (AttributeError, NotImplementedError, TypeError) as exc:
                raise AsyncHttpFallback("unsupported ClickHouse driver memory codec") from exc
            except _NeedBytes as need:
                if len(data) + need.size > _PACKET_CAP:
                    raise AsyncHttpFallback("large ClickHouse detection packet") from need
                try:
                    data += await self.io.recv_exact(sock, need.size)
                except ConnectionError as exc:
                    if str(exc) == "unexpected EOF":
                        raise EOFError("Unexpected EOF while reading bytes") from exc
                    raise
                continue
            if reader.position != len(data):
                raise AsyncHttpFallback("ClickHouse codec left unread detection bytes")
            return value

    @staticmethod
    def _out(client: Any) -> io.BytesIO:
        from clickhouse_driver.streams.native import BlockOutputStream

        output = io.BytesIO()
        client.connection.fout = output
        client.connection.block_out = BlockOutputStream(output, client.connection.context)
        return output

    async def _query(self, client: Any, sock: socket.socket, query: str, prefix: bytes = b"") -> list[Any]:
        from clickhouse_driver.client import QueryInfo

        connection = client.connection
        client.make_query_settings(None)
        client.last_query = QueryInfo()
        connection.server_info.session_timezone = None
        output = self._out(client)
        output.write(prefix)
        # connected only prevents the serializer from calling sync connect().
        # No raw socket is attached until every detection packet is consumed.
        connection.connected = True
        connection.is_query_executing = True
        try:
            connection.send_query(query)
            connection.send_external_tables(None)
        finally:
            connection.connected = False
        await self.io.sendall(sock, output.getvalue())
        packets = []
        while True:
            packet = await self._parse(client, sock, client.receive_packet)
            if packet is False:
                break
            if packet is not True:
                packets.append(packet)
            if len(packets) > _ITEMS_CAP:
                raise AsyncHttpFallback("large ClickHouse detection result")
        return client.query_result_cls(iter(packets)).get_result()

    async def connect_and_probe(
        self,
        protocol: str,
        host: str,
        port: int,
        timeout: float,
        username: str,
        password: str,
        *,
        database: str = "default",
        tls_config: Any = None,
        proxy: Any = None,
    ) -> Any:
        from ..modules.clickhouse import actions

        if protocol == "http":
            return await self._connect_http(
                host, port, timeout, username, password, database=database, tls_config=tls_config, proxy=proxy
            )
        if protocol != "native":
            raise AsyncHttpFallback("unsupported ClickHouse protocol")
        if proxy is not None and str(getattr(proxy, "raw_url", proxy) or "").strip():
            raise AsyncHttpFallback("proxied ClickHouse native driver")
        client = None
        sock = None
        connecting = True
        try:
            from clickhouse_driver.client import Client as CanonicalClient

            if actions._load_clickhouse_driver_client() is not CanonicalClient:
                raise AsyncHttpFallback("ClickHouse driver factory override")
            client = actions._open_clickhouse_client(
                protocol,
                host,
                port,
                timeout,
                username,
                password,
                database,
                **actions._ch_transport_kwargs(tls_config, proxy),
            )
            from clickhouse_driver import Client, defines
            from clickhouse_driver.connection import Connection

            if type(client) is not Client or type(client.connection) is not Connection:
                raise AsyncHttpFallback("ClickHouse driver factory override")
            connection = client.connection
            if connection.compression or len(client.connections) or len(connection.hosts) != 1:
                raise AsyncHttpFallback("unsupported ClickHouse compression or failover settings")
            sock = await self.io.open((host, port), timeout)
            if connection.secure_socket:
                ssl_options = dict(connection.ssl_options)
                ssl_options["cert_reqs"] = ssl.CERT_REQUIRED if connection.verify_cert else ssl.CERT_NONE
                context = connection._create_ssl_context(ssl_options)
                sock = await self.io.wrap(context, sock, server_hostname=connection.server_hostname or host)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            connection.host, connection.port = host, port
            output = self._out(client)
            connection.send_hello()
            await self.io.sendall(sock, output.getvalue())
            session = actions._ChSession(protocol, client, username, password, database)
            try:
                await self._parse(client, sock, connection.receive_hello)
                connecting = False
                output = self._out(client)
                if connection.server_info.used_revision >= defines.DBMS_MIN_PROTOCOL_VERSION_WITH_ADDENDUM:
                    connection.send_addendum()
                await self._query(client, sock, "SELECT 1", output.getvalue())
            except AsyncHttpFallback:
                raise
            except Exception as exc:
                # execute() disconnects on query/startup errors in the sync
                # driver too, including a retained access-limited session.
                if connecting:
                    exc = self._connect_error(exc, connection, host, port)
                error = actions._classify_clickhouse_exception(exc, protocol)
                self._discard(client, sock)
                sock = None
                if error.access_limited:
                    return actions._probe_result(session, error)
                return actions._probe_result(None, error)
            self.sessions[id(client)] = (client, sock, b"")
            return actions._probe_result(session)
        except AsyncHttpFallback:
            if sock is not None:
                self._discard(client, sock)
            raise
        except Exception as exc:
            if sock is not None:
                self._discard(client, sock)
            if connecting and client is not None:
                exc = self._connect_error(exc, client.connection, host, port)
            return actions._probe_result(None, actions._classify_clickhouse_exception(exc, protocol))

    async def _connect_http(
        self,
        host: str,
        port: int,
        timeout: float,
        username: str,
        password: str,
        *,
        database: str,
        tls_config: Any,
        proxy: Any,
    ) -> Any:
        from ..modules.clickhouse import actions
        from .async_clickhouse_http_detect import NativeClickHouseHttp

        transport = NativeClickHouseHttp(self.io, host, port, timeout, username, password, database, tls_config, proxy)
        client = None
        try:
            client = await transport.initialize()
            session = actions._ChSession("http", client, username, password, database)
            try:
                await transport.query("SELECT 1")
            except AsyncHttpFallback:
                raise
            except Exception as exc:
                error = actions._classify_clickhouse_exception(exc, "http")
                if error.access_limited:
                    self.http_sessions[id(client)] = transport
                    return actions._probe_result(session, error)
                transport.close()
                client.close()
                return actions._probe_result(None, error)
            self.http_sessions[id(client)] = transport
            return actions._probe_result(session)
        except AsyncHttpFallback:
            transport.close()
            raise
        except Exception as exc:
            transport.close()
            if client is not None:
                client.close()
            return actions._probe_result(None, actions._classify_clickhouse_exception(exc, "http"))

    @staticmethod
    def _connect_error(error: Exception, connection: Any, host: str, port: int) -> Exception:
        from clickhouse_driver import errors

        if isinstance(error, OSError):
            message = connection._format_connection_error(error, host, port)
            return (
                errors.SocketTimeoutError(message) if isinstance(error, TimeoutError) else errors.NetworkError(message)
            )
        return error

    def _discard(self, client: Any, sock: socket.socket) -> None:
        self.io.sockets.pop(sock, None)
        sock.close()
        self.sessions.pop(id(client), None)
        if client is not None:
            client.disconnect()

    async def read_version(self, session: Any) -> str | None:
        if session.protocol == "http":
            transport = self.http_sessions.get(id(session.client))
            if transport is None:
                raise AsyncHttpFallback("ClickHouse HTTP session is unavailable")
            try:
                rows = await transport.query("SELECT version()", rows=True)
            except AsyncHttpFallback:
                raise
            except Exception:
                return None
            return str(rows[0][0] or "").strip() or None if rows and rows[0] else None
        entry = self.sessions.get(id(session.client))
        if entry is None:
            # An access-limited query left the original driver disconnected.
            # Preserve its reconnect semantics through explicit legacy verify.
            raise AsyncHttpFallback("ClickHouse version query needs disconnected-session reconnect")
        client, sock, _prefix = entry
        from clickhouse_driver.protocol import ClientPacketTypes, ServerPacketTypes
        from clickhouse_driver.varint import read_varint, write_varint

        output = self._out(client)
        write_varint(ClientPacketTypes.PING, output)
        await self.io.sendall(sock, output.getvalue())
        while True:
            packet_type = await self._parse(client, sock, lambda: read_varint(client.connection.fin))
            if packet_type == ServerPacketTypes.PROGRESS:
                await self._parse(client, sock, client.connection.receive_progress)
                continue
            if packet_type != ServerPacketTypes.PONG:
                raise AsyncHttpFallback("ClickHouse version ping requires driver reconnect")
            break
        try:
            rows = await self._query(client, sock, "SELECT version()")
        except AsyncHttpFallback:
            raise
        except Exception:
            raise AsyncHttpFallback("ClickHouse advisory version query requires original driver cleanup") from None
        return str(rows[0][0] or "").strip() or None if rows and rows[0] else None

    def adopt(self) -> None:
        from clickhouse_driver import defines
        from clickhouse_driver.bufferedreader import BufferedSocketReader
        from clickhouse_driver.bufferedwriter import BufferedSocketWriter
        from clickhouse_driver.streams.native import BlockInputStream

        for client, sock, _prefix in self.sessions.values():
            connection = client.connection
            connection.socket = sock
            connection.fin = BufferedSocketReader(sock, defines.BUFFER_SIZE)
            connection.fout = BufferedSocketWriter(sock, defines.BUFFER_SIZE)
            connection.block_in = connection.get_block_in_stream()
            connection.block_in_raw = BlockInputStream(connection.fin, connection.context)
            connection.block_out = connection.get_block_out_stream()
            connection.connected = True
            connection.is_query_executing = False
        for transport in self.http_sessions.values():
            transport.adopt()
        self.io.transfer()
        self.sessions.clear()
        self.http_sessions.clear()

    def close(self) -> None:
        for transport in self.http_sessions.values():
            transport.close()
        self.http_sessions.clear()
        self.io.close()
        self.sessions.clear()
