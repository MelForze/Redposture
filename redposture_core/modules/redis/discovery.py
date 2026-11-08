"""Bounded RESP reading for the synchronous discovery phase."""

from __future__ import annotations

import base64
import codecs
import hashlib
import io
import math
import sqlite3
import tempfile
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any, BinaryIO

from ...discovery_frontier import DiscoveryFrontier
from ...discovery_sources import SourceManifest
from ...discovery_spool import SpoolingRecords, SpoolingStrings
from ...discovery_values import DiskBackedText
from ...rendering import sanitize_report_payload
from ...scheduler import NestedSchedulerCancelled
from ...show_limits import dump_flag_limit, show_flag_limit
from ...storage_discovery import DiscoveryCollector


class RedisBulk:
    """One complete bulk body on disk, independent of its wire size."""

    def __init__(self, file: BinaryIO, size: int, digest: str) -> None:
        self.file = file
        self.size = size
        self.digest = digest

    def chunks(self, size: int = 65_536) -> Iterator[bytes]:
        self.file.seek(0)
        while data := self.file.read(size):
            yield data

    def text(self) -> DiskBackedText:
        value = DiskBackedText()
        decoder = codecs.getincrementaldecoder("utf-8")("strict")
        try:
            for data in self.chunks():
                value.append_text(decoder.decode(data))
            value.append_text(decoder.decode(b"", final=True))
        except UnicodeDecodeError:
            value.close()
            value = DiskBackedText()
            value.append_text("base64:")
            # Every nonfinal block must contain a whole number of base64 groups.
            for data in self.chunks(65_535):
                value.append_text(base64.b64encode(data).decode("ascii"))
        except BaseException:
            value.close()
            raise
        value.finish()
        return value

    def close(self) -> None:
        self.file.close()

    def __enter__(self) -> RedisBulk:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


class RESPArray:
    """A wire array whose children are read only when consumed."""

    def __init__(self, reader: RESPStreamReader, count: int, depth: int) -> None:
        self.reader = reader
        self.remaining = count
        self.depth = depth

    def __iter__(self) -> Iterator[tuple[str, Any]]:
        while self.remaining:
            self.remaining -= 1
            yield self.reader.read(self.depth)


class RESPStreamReader:
    def __init__(self, sock: Any, *, deadline: float, portion: int = 65_536) -> None:
        self.sock = sock
        self.deadline = deadline
        self.portion = max(1, int(portion))
        self.idle_timeout = sock.gettimeout()
        self.bytes_read = 0

    def _exact(self, size: int) -> bytes:
        data = bytearray()
        while len(data) < size:
            remaining = self.deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("discover_time")
            self.sock.settimeout(min(self.idle_timeout or remaining, remaining))
            chunk = self.sock.recv(min(self.portion, size - len(data)))
            if not chunk:
                raise ConnectionError("unexpected EOF in RESP discovery frame")
            self.bytes_read += len(chunk)
            data.extend(chunk)
        return bytes(data)

    def _line(self) -> bytes:
        data = bytearray()
        while len(data) <= 65_536:
            data.extend(self._exact(1))
            if data.endswith(b"\r\n"):
                return bytes(data[:-2])
        raise ValueError("invalid RESP header line")

    def read(self, depth: int = 0) -> tuple[str, Any]:
        if depth > 128:
            raise ValueError("invalid RESP nesting")
        prefix = self._exact(1)
        if prefix in {b"+", b"-", b":"}:
            line = self._line()
            if prefix == b":":
                return "integer", int(line)
            return ("simple" if prefix == b"+" else "error"), line
        if prefix not in {b"$", b"*"}:
            raise ValueError(f"unsupported RESP prefix: {prefix!r}")
        size = int(self._line())
        if size == -1:
            return "null", None
        if size < 0:
            raise ValueError("invalid RESP length")
        if prefix == b"*":
            return "array", RESPArray(self, size, depth + 1)
        if size <= self.portion:
            body = self._exact(size)
            if self._exact(2) != b"\r\n":
                raise ValueError("invalid RESP bulk terminator")
            return "bulk", body
        file = tempfile.TemporaryFile(mode="w+b")
        digest = hashlib.sha256()
        try:
            remaining = size
            while remaining:
                chunk = self._exact(min(self.portion, remaining))
                remaining -= len(chunk)
                file.write(chunk)
                digest.update(chunk)
            if self._exact(2) != b"\r\n":
                raise ValueError("invalid RESP bulk terminator")
            return "bulk", RedisBulk(file, size, digest.hexdigest())
        except BaseException:
            file.close()
            raise


def _text(value: bytes | RedisBulk | None) -> str | DiskBackedText:
    if isinstance(value, RedisBulk):
        return value.text()
    try:
        return (value or b"").decode("utf-8")
    except UnicodeDecodeError:
        return "base64:" + base64.b64encode(value or b"").decode("ascii")


def _append(value: DiskBackedText | None, part: str | DiskBackedText) -> None:
    if value is None:
        return
    if isinstance(part, DiskBackedText):
        for chunk in part.iter_text_chunks():
            value.append_text(chunk)
    else:
        value.append_text(part)


class _KeyQueue:
    def __init__(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="redposture-redis-keys-")
        self.directory = Path(self.temporary.name)
        self.db = sqlite3.connect(self.directory / "keys.sqlite")
        self.db.execute(
            "CREATE TABLE keys (ordinal INTEGER PRIMARY KEY, digest TEXT UNIQUE, "
            "data BLOB, file TEXT, size INTEGER, done INTEGER DEFAULT 0)"
        )

    def add(self, value: bytes | RedisBulk) -> None:
        digest = value.digest if isinstance(value, RedisBulk) else hashlib.sha256(value).hexdigest()
        if self.db.execute("SELECT 1 FROM keys WHERE digest=?", (digest,)).fetchone():
            return
        file = None
        if isinstance(value, RedisBulk):
            file = str(self.directory / digest)
            with open(file, "wb") as writer:
                for chunk in value.chunks():
                    writer.write(chunk)
        self.db.execute(
            "INSERT INTO keys(digest,data,file,size) VALUES (?,?,?,?)",
            (
                digest,
                value if isinstance(value, bytes) else None,
                file,
                len(value) if isinstance(value, bytes) else value.size,
            ),
        )

    def pop(self) -> bytes | RedisBulk | None:
        row = self.db.execute(
            "SELECT ordinal,digest,data,file,size FROM keys WHERE done=0 ORDER BY ordinal LIMIT 1"
        ).fetchone()
        if row is None:
            return None
        ordinal, digest, data, file, size = row
        self.db.execute("UPDATE keys SET done=1 WHERE ordinal=?", (ordinal,))
        return data if file is None else RedisBulk(open(file, "rb"), size, digest)

    def close(self) -> None:
        self.db.close()
        self.temporary.cleanup()


class _DiscoverySession:
    def __init__(self, ctx: Any, prior: dict[str, Any], sock: Any) -> None:
        self.ctx = ctx
        self.collector = DiscoveryCollector("redis", ctx, prior)
        self.collector.source_manifest = SourceManifest()
        for category in ("key_catalog", "key_values"):
            self.collector.source_manifest.declare("redis." + category)
        self.last_denied = False
        self.last_unsupported = False
        self.reader = RESPStreamReader(sock, deadline=self.collector.deadline)
        self.sock = sock
        self.records = SpoolingRecords()
        self.names = SpoolingStrings()
        self.keep_dump = bool(getattr(ctx.args, "dump", False)) and not bool(
            getattr(ctx.args, "_discover_implicit_dump", False)
        )
        self.keep_keys = bool(getattr(ctx.args, "show_keys", False))
        self.dump_limit = dump_flag_limit(getattr(ctx.args, "dump", False))
        self.keys_limit = show_flag_limit(getattr(ctx.args, "show_keys", False))
        self.saw_key = False
        self.query = str(getattr(ctx.args, "key", None) or getattr(ctx.args, "query_key", None) or "")
        self.error: str | None = None
        self.count = 0

    def deny(self, source: str, error: bytes) -> None:
        reason = "access_denied" if any(marker in error.upper() for marker in (b"NOPERM", b"NOAUTH")) else "read_error"
        self.last_denied |= reason == "access_denied"
        self.collector.partial(source, f"{reason}:{_text(error)}")

    def command(self, *parts: bytes | RedisBulk) -> tuple[str, Any]:
        remaining = self.collector.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("discover_time")
        self.sock.settimeout(min(self.reader.idle_timeout or remaining, remaining))
        self.sock.sendall(f"*{len(parts)}\r\n".encode("ascii"))
        for part in parts:
            size = part.size if isinstance(part, RedisBulk) else len(part)
            self.sock.sendall(f"${size}\r\n".encode("ascii"))
            if isinstance(part, RedisBulk):
                for chunk in part.chunks():
                    self.sock.sendall(chunk)
            else:
                self.sock.sendall(part)
            self.sock.sendall(b"\r\n")
        return self.reader.read()

    def scalar(self, key: str, raw: bytes | RedisBulk | None, path: str) -> str | DiskBackedText:
        try:
            value = _text(raw)
            if isinstance(raw, RedisBulk):
                raw.file.seek(0)
                self.collector._scan_retained_payload(path, raw.file, field_name=key)
            else:
                with io.BytesIO(raw or b"") as source:
                    self.collector._scan_retained_payload(path, source, field_name=key)
            return value
        finally:
            if isinstance(raw, RedisBulk):
                raw.close()

    def read_key(self, raw_key: bytes | RedisBulk) -> None:
        with self.collector.source_attempt(
            "redis.key_values", scope="selected_or_enumerated_keys_all_supported_types"
        ) as evidence:
            self.last_denied = self.last_unsupported = False
            before = self.count
            try:
                self._read_key(raw_key)
                if self.count > before:
                    evidence.accept(self.count - before)
            finally:
                evidence.status = 403 if self.last_denied else None
                evidence.unsupported = self.last_unsupported

    def _read_key(self, raw_key: bytes | RedisBulk) -> None:
        key = (
            f"key_sha256:{raw_key.digest}"
            if isinstance(raw_key, RedisBulk)
            else str(_text(raw_key)).replace("\n", "\\n")
        )
        source = f"key_value_entries.{key}"
        kind, key_type = self.command(b"TYPE", raw_key)
        if kind == "error":
            self.deny(source, key_type)
            return
        if not isinstance(key_type, bytes):
            raise ValueError("invalid Redis TYPE response")
        if key_type == b"stream":
            accessible, stream_value = self.read_stream(raw_key, key, source)
            if accessible:
                self.finish_key(key, stream_value)
            return
        commands = {
            b"string": (b"GET", raw_key),
            b"hash": (b"HGETALL", raw_key),
            b"list": (b"LRANGE", raw_key, b"0", b"-1"),
            b"set": (b"SMEMBERS", raw_key),
            b"zset": (b"ZRANGE", raw_key, b"0", b"-1", b"WITHSCORES"),
        }
        command = commands.get(key_type)
        if key_type == b"none":
            self.collector.partial(source, "key_disappeared_during_read")
            return
        if command is None:
            self.last_unsupported = True
            self.collector.partial(source, "unsupported_key_type")
            return
        kind, response = self.command(*command)
        if kind == "error":
            self.deny(source, response)
            return
        value: str | DiskBackedText
        if kind == "array" and isinstance(response, RESPArray):
            assembled = DiskBackedText() if self.keep_dump or self.query else None
            try:
                index = 0
                pair = key_type in {b"hash", b"zset"}
                iterator = iter(response)
                for child_kind, child in iterator:
                    if child_kind not in {"bulk", "simple", "null"}:
                        raise ValueError("invalid Redis collection scalar")
                    if index and assembled is not None:
                        assembled.append_text(",")
                    if pair:
                        field = (
                            self.scalar(key.rsplit("/", 1)[-1], child, f"{source}[{index}].member")
                            if key_type == b"zset"
                            else _text(child)
                        )
                        _append(assembled, field)
                        if assembled is not None:
                            assembled.append_text("=")
                        if isinstance(child, RedisBulk) and key_type != b"zset":
                            child.close()
                        next_kind, child = next(iterator, ("missing", None))
                        if next_kind not in {"bulk", "simple", "null"}:
                            raise ValueError("incomplete Redis collection pair")
                        label = field if isinstance(field, str) else f"field_sha256:{field.digest}"
                    else:
                        label = key.rsplit("/", 1)[-1]
                    if key_type == b"zset":
                        item = _text(child)
                        if isinstance(child, RedisBulk):
                            child.close()
                        if not isinstance(item, str) or len(item) > 128 or math.isnan(float(item)):
                            raise ValueError("invalid Redis sorted-set score")
                    else:
                        item = self.scalar(label, child, source if pair else f"{source}[{index}]")
                    _append(assembled, item)
                    index += 1
                if assembled is not None:
                    assembled.finish()
                value = assembled if assembled is not None else ""
            except BaseException:
                if assembled is not None:
                    assembled.close()
                raise
        elif kind in {"bulk", "simple", "null"}:
            value = self.scalar(key.rsplit("/", 1)[-1], response, source)
        else:
            raise ValueError("invalid Redis value response")
        self.finish_key(key, value)

    def finish_key(self, key: str, value: str | DiskBackedText) -> None:
        self.collector.mark_accessible_source()
        self.count += 1
        if self.query or (self.keep_dump and (self.dump_limit is None or len(self.records) < self.dump_limit)):
            self.records.append({"key": key, "value": value, "error": None}, sort_key=key)
        if self.keep_keys and (self.keys_limit is None or len(self.names) < self.keys_limit):
            self.names.append(key)

    def read_stream(self, raw_key: bytes | RedisBulk, key: str, source: str) -> tuple[bool, str | DiskBackedText]:
        assembled = DiskBackedText() if self.keep_dump or self.query else None
        cursor = b"-"
        previous: tuple[int, int] | None = None
        try:
            while self.collector.allowed():
                kind, response = self.command(b"XRANGE", raw_key, cursor, b"+", b"COUNT", b"128")
                if kind == "error":
                    self.deny(source, response)
                    if assembled is not None:
                        assembled.close()
                    return False, ""
                if kind != "array" or not isinstance(response, RESPArray):
                    raise ValueError("invalid Redis XRANGE response")
                count = 0
                for entry_kind, entry in response:
                    if entry_kind != "array" or not isinstance(entry, RESPArray):
                        raise ValueError("invalid Redis stream entry")
                    fields = iter(entry)
                    id_kind, raw_id = next(fields, ("missing", None))
                    if id_kind != "bulk" or not isinstance(raw_id, bytes):
                        raise ValueError("invalid Redis stream ID")
                    parts = raw_id.split(b"-")
                    if len(parts) != 2 or any(not part.isdigit() or len(part) > 20 for part in parts):
                        raise ValueError("invalid Redis stream ID")
                    identifier = (int(parts[0]), int(parts[1]))
                    maximum = (1 << 64) - 1
                    if any(part > maximum for part in identifier) or previous is not None and identifier <= previous:
                        raise ValueError("Redis stream pagination stalled")
                    previous = identifier
                    values_kind, values = next(fields, ("missing", None))
                    if values_kind != "array" or not isinstance(values, RESPArray):
                        raise ValueError("invalid Redis stream fields")
                    if assembled is not None:
                        if count or cursor != b"-":
                            assembled.append_text(";")
                        assembled.append_text(raw_id.decode("ascii") + ":")
                    pairs = iter(values)
                    field_count = 0
                    for field_kind, raw_field in pairs:
                        if field_kind not in {"bulk", "simple"}:
                            raise ValueError("invalid Redis stream field")
                        field = _text(raw_field)
                        if isinstance(raw_field, RedisBulk):
                            raw_field.close()
                        value_kind, raw_value = next(pairs, ("missing", None))
                        if value_kind not in {"bulk", "simple", "null"}:
                            raise ValueError("incomplete Redis stream field pair")
                        label = field if isinstance(field, str) else f"field_sha256:{field.digest}"
                        value = self.scalar(label, raw_value, f"{source}.{raw_id.decode('ascii')}")
                        if field_count and assembled is not None:
                            assembled.append_text(",")
                        _append(assembled, field)
                        _append(assembled, "=")
                        _append(assembled, value)
                        field_count += 1
                    if next(fields, None) is not None:
                        raise ValueError("extra Redis stream entry fields")
                    count += 1
                if not count or previous == (maximum, maximum):
                    if assembled is not None:
                        assembled.finish()
                    return True, assembled if assembled is not None else ""
                assert previous is not None
                milliseconds, sequence = previous
                cursor = (f"{milliseconds}-{sequence + 1}" if sequence < maximum else f"{milliseconds + 1}-0").encode(
                    "ascii"
                )
            if assembled is not None:
                assembled.close()
            return False, ""
        except BaseException:
            if assembled is not None:
                assembled.close()
            raise

    def scan(self) -> None:
        if self.query:
            self.read_key(self.query.encode("utf-8"))
            return
        queue = _KeyQueue()
        cursors = DiscoveryFrontier()
        cursor = b"0"
        catalog_complete = False
        try:
            while self.collector.allowed():
                if not cursors.claim(cursor.decode("ascii")):
                    self.collector.partial("keys", "repeated_scan_cursor")
                    assert self.collector.source_manifest is not None
                    self.collector.source_manifest.finish("redis.key_catalog", complete=False)
                    break
                with self.collector.source_attempt(
                    "redis.key_catalog", scope="validated_SCAN_pages", content=False
                ) as evidence:
                    kind, root = self.command(b"SCAN", cursor, b"COUNT", b"500")
                    if kind == "error":
                        self.deny("keys", root)
                        evidence.status = 403 if self.last_denied else None
                        break
                    if kind != "array" or not isinstance(root, RESPArray) or root.remaining != 2:
                        raise ValueError("invalid Redis SCAN response")
                    parts = iter(root)
                    kind, next_cursor = next(parts)
                    if kind != "bulk" or not isinstance(next_cursor, bytes) or not next_cursor.isdigit():
                        raise ValueError("invalid Redis SCAN cursor")
                    kind, keys = next(parts)
                    if kind != "array" or not isinstance(keys, RESPArray):
                        raise ValueError("invalid Redis SCAN keys")
                    for kind, key in keys:
                        if kind != "bulk" or not isinstance(key, (bytes, RedisBulk)):
                            raise ValueError("invalid Redis key")
                        self.saw_key = True
                        try:
                            queue.add(key)
                        finally:
                            if isinstance(key, RedisBulk):
                                key.close()
                    evidence.accept()
                    catalog_complete = next_cursor == b"0"
                while (raw_key := queue.pop()) is not None:
                    try:
                        self.read_key(raw_key)
                    finally:
                        if isinstance(raw_key, RedisBulk):
                            raw_key.close()
                if not self.saw_key:
                    self.collector.mark_accessible_source()
                cursor = next_cursor
                if cursor == b"0":
                    break
        finally:
            if not catalog_complete:
                assert self.collector.source_manifest is not None
                self.collector.source_manifest.finish("redis.key_catalog", complete=False)
            queue.close()
            cursors.close()


def discover_redis(ctx: Any, prior: dict[str, Any], sock: Any) -> dict[str, Any]:
    session = _DiscoverySession(ctx, prior, sock)
    try:
        session.scan()
    except (NestedSchedulerCancelled, KeyboardInterrupt):
        sock.close()  # Cancellation may interrupt a RESP header or bulk body.
        raise
    except (OSError, ValueError, ConnectionError) as exc:
        session.error = str(exc) or type(exc).__name__
        session.collector.partial("redis", session.error)
        sock.close()  # A partially consumed frame cannot be reused.
    session.records.finish()
    session.names.finish()
    session.collector.bytes_read = session.reader.bytes_read
    result: dict[str, Any] = {
        "content_discovery": session.collector.result(),
        "key_value_entries": session.records if session.keep_dump else None,
        "key_values": None,
        "keys": session.names if session.keep_keys else None,
        "dump_error": session.error,
        "query_key_entry": session.records[0] if session.query and session.records else None,
        "query_key_value": None,
    }
    output_format = getattr(ctx.args, "output_format", getattr(ctx.args, "format", "txt"))
    if output_format == "txt" and (session.keep_dump or session.keep_keys or session.query):
        result["_stream_lines_file"] = _raw_output_file(session)
        result["_redis_streamed_details"] = True
    return result


def _raw_output_file(session: _DiscoverySession) -> str:
    prefix = f"{'REDIS':<8}\t{session.ctx.host}\t{session.ctx.port}\t"
    writer = tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", prefix="redposture-redis-output-", delete=False)
    try:
        if session.query:
            heading = f"Dump Key {sanitize_report_payload(session.query)}"
        else:
            heading = "Keys Enumeration" if session.keep_keys else "Dump Keys"
        writer.write(f"{prefix} [*] {heading}\n")
        if session.keep_dump or session.query:
            for entry in session.records:
                key = sanitize_report_payload(str(entry["key"]))
                if session.keep_keys:
                    writer.write(f"{prefix} {key}\n")
                writer.write(f"{prefix} {key}:")
                value = entry["value"]
                chunks = value.iter_text_chunks() if isinstance(value, DiskBackedText) else (str(value),)
                for chunk in chunks:
                    writer.write(chunk.translate(_RAW_CONTROL_ESCAPES))
                writer.write("\n")
        else:
            for key in session.names:
                writer.write(f"{prefix} {sanitize_report_payload(key)}\n")
        writer.close()
        return writer.name
    except BaseException:
        writer.close()
        Path(writer.name).unlink(missing_ok=True)
        raise


_RAW_CONTROL_ESCAPES = {
    code: {9: r"\t", 10: r"\n", 13: r"\r"}.get(code, f"\\x{code:02x}") for code in (*range(32), *range(127, 160))
}
