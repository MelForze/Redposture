"""Bounded, forward-only TAR discovery, including extension metadata.

The intentionally small API is ``open_tar_stream(fileobj, check=...)``. Iterate
TarInfo records and extract the *current* regular member before advancing. Input
ownership stays with the caller. Large names/metadata are DiskBackedText values;
PAX mappings and sparse extents live on temporary disk, not in a member catalog.

Header parsing delegates to CPython TarInfo._frombuf(dircheck=...), whose header,
checksum, old-GNU sparse fields and dircheck contracts were source-audited against
installed CPython 3.12, 3.13 and 3.14. We do not call TarFile's eager _proc_pax,
_proc_gnulong, _FileInFile or member caching. This is a discovery reader, not a
random-access TarFile replacement: name lookup, filesystem extraction and link
resolution are deliberately outside its API, as with forward-only extraction.
"""

from __future__ import annotations

import bz2
import codecs
import gzip
import hashlib
import io
import lzma
import sqlite3
import sys
import tarfile
import tempfile
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from importlib import import_module
from pathlib import Path
from typing import IO, Any, Protocol, cast

from .discovery_values import DiskBackedText

_CHUNK = 65536
_BLOCK = tarfile.BLOCKSIZE
_Text = str | DiskBackedText
# CPython extension-header internals are intentionally outside public stubs.
_TAR: Any = tarfile


class TarStreamMember(Protocol):
    """TarInfo's discovery surface, including its disk-backed field variants."""

    name: _Text
    linkname: _Text
    size: int
    uid: int
    gid: int
    mode: int
    mtime: int | float
    uname: _Text
    gname: _Text
    chksum: int
    devmajor: int
    devminor: int
    offset: int
    offset_data: int
    type: bytes
    sparse: Sequence[tuple[int, int]] | None
    pax_headers: Mapping[_Text, _Text]
    _sparse_structs: tuple[list[tuple[int, int]], bool, int]

    def isreg(self) -> bool: ...
    def isfile(self) -> bool: ...
    def isdir(self) -> bool: ...
    def islnk(self) -> bool: ...
    def issym(self) -> bool: ...


def _chunks(value: _Text) -> Iterator[str]:
    if isinstance(value, str):
        for start in range(0, len(value), _CHUNK):
            yield value[start : start + _CHUNK]
    else:
        yield from value.iter_text_chunks()


def _equal(left: _Text, right: _Text) -> bool:
    # All spool text readers use the same character chunk size.
    from itertools import zip_longest

    return all(a == b for a, b in zip_longest(_chunks(left), _chunks(right)))


def _integer(value: _Text, check: Callable[[], Any] | None = None) -> int:
    """Use Python's numeric guard, retaining the full original scalar on disk."""
    if check is not None:
        check()
    if isinstance(value, str):
        return int(value)
    limit = sys.get_int_max_str_digits()
    result, sign, state, digits, count, underscore = 0, 1, 0, False, 0, False
    for chunk in _chunks(value):
        if check is not None:
            check()
        for char in chunk:
            if state == 0 and char.isspace():
                continue
            if state == 0 and char in "+-":
                sign, state = (-1 if char == "-" else 1), 1
                continue
            if char.isdecimal() and state != 2:
                count += 1
                if limit and count > limit:
                    raise ValueError("PAX integer exceeds Python's integer conversion guard")
                result, state, digits, underscore = result * 10 + int(char), 1, True, False
            elif char == "_" and digits and not underscore and state == 1:
                underscore = True
            elif char.isspace() and digits and not underscore:
                state = 2
            else:
                raise ValueError("invalid integer in TAR metadata")
    if not digits or underscore:
        raise ValueError("invalid integer in TAR metadata")
    return sign * result


class _Cursor:
    """Normalize delayed SQLite read failures as well as execute failures."""

    def __init__(self, cursor) -> None:
        self.cursor = cursor

    def __iter__(self):
        return self

    def __next__(self):
        try:
            return next(self.cursor)
        except sqlite3.Error as exc:
            raise OSError("TAR metadata storage failed") from exc

    def fetchone(self):
        try:
            return self.cursor.fetchone()
        except sqlite3.Error as exc:
            raise OSError("TAR metadata storage failed") from exc


class _Spool:
    def __init__(self, check: Callable[[], Any]) -> None:
        self.check = check
        self.closed = False
        self.temporary: tempfile.TemporaryDirectory[str] | None = None
        self.file: io.BufferedRandom | None = None
        self.db: sqlite3.Connection | None = None
        try:
            self.temporary = tempfile.TemporaryDirectory(prefix="redposture-tar-")
            self.path = Path(self.temporary.name) / "metadata.bin"
            self.file = self.path.open("w+b")
            self.db = sqlite3.connect(Path(self.temporary.name) / "metadata.sqlite3", isolation_level=None)
            self.execute("PRAGMA journal_mode=OFF")
            self.execute("PRAGMA synchronous=OFF")
            self.execute("PRAGMA cache_size=-512")
            self.execute("PRAGMA temp_store=FILE")
            self.execute(
                "CREATE TABLE pax(scope INTEGER,digest TEXT,kstart INTEGER,klen INTEGER,"
                "vstart INTEGER,vlen INTEGER,PRIMARY KEY(scope,digest,kstart)) WITHOUT ROWID"
            )
            self.execute(
                "CREATE TABLE actions(id INTEGER PRIMARY KEY,kind BLOB,scope INTEGER,start INTEGER,"
                "length INTEGER,offset TEXT)"
            )
            self.execute(
                "CREATE TABLE raw(id INTEGER PRIMARY KEY,kstart INTEGER,klen INTEGER,vstart INTEGER,vlen INTEGER)"
            )
            self.execute(
                "CREATE TABLE extents(scope INTEGER,idx INTEGER,offset TEXT,length TEXT,"
                "PRIMARY KEY(scope,idx)) WITHOUT ROWID"
            )
            self.scope = 0
            self.end = 0
        except BaseException as exc:
            self.close()
            if isinstance(exc, sqlite3.Error):
                raise OSError("TAR metadata storage failed") from exc
            raise

    @property
    def _active_file(self) -> io.BufferedRandom:
        assert self.file is not None
        return self.file

    def execute(self, sql, parameters=()):
        try:
            assert self.db is not None
            return _Cursor(self.db.execute(sql, parameters))
        except sqlite3.Error as exc:
            raise OSError("TAR metadata storage failed") from exc

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        # Cleanup is best-effort across every independently owned resource.
        # The original I/O/deadline failure must never be replaced by cleanup.
        for resource in (self.db, self.file):
            if resource is not None:
                try:
                    resource.close()
                except (sqlite3.Error, OSError):
                    pass
        if self.temporary is not None:
            try:
                self.temporary.cleanup()
            except OSError:
                pass

    def __del__(self) -> None:
        self.close()

    def append(self, value: bytes) -> int:
        self.check()
        start = self.end
        self._active_file.seek(start)
        self._active_file.write(value)
        self.end += len(value)
        return start

    def read(self, start: int, length: int) -> bytes:
        self.check()
        self._active_file.seek(start)
        return self._active_file.read(length)

    def bytes(self, start: int, length: int) -> Iterator[bytes]:
        while length:
            chunk = self.read(start, min(length, _CHUNK))
            if not chunk:
                raise OSError("incomplete TAR metadata spool")
            yield chunk
            start, length = start + len(chunk), length - len(chunk)

    def decode(self, start: int, length: int, encoding: str, fallback: str, errors: str) -> tuple[int, int]:
        """Decode with stdlib's strict-first/fallback policy in bounded passes."""
        output_start = self.end
        for codec, policy in ((encoding, "strict"), (fallback, errors)):
            decoder = codecs.getincrementaldecoder(codec)(policy)
            try:
                for chunk in self.bytes(start, length):
                    self.append(decoder.decode(chunk).encode("utf-8", "surrogatepass"))
                self.append(decoder.decode(b"", final=True).encode("utf-8", "surrogatepass"))
                return output_start, self.end - output_start
            except UnicodeDecodeError:
                self._active_file.seek(output_start)
                self._active_file.truncate()
                self.end = output_start
                if policy != "strict" or (codec == fallback and errors == "strict"):
                    raise
        raise AssertionError("unreachable decoder fallback")

    def text(self, start: int, length: int) -> _Text:
        if length <= _CHUNK:
            return self.read(start, length).decode("utf-8", "surrogatepass")
        return _SpoolText(self, start, length)

    def new_scope(self) -> int:
        self.scope += 1
        return self.scope


class _SpoolText(DiskBackedText):
    """A retained name owns its spool independently of the archive context."""

    def __init__(self, spool: _Spool, start: int, length: int) -> None:
        self._spool: _Spool | None = spool
        self._start, self.byte_length = start, length
        self._finished, self._closed = True, False
        self._materialized: DiskBackedText | None = None
        self._all_x = self._all_star = self._all_dash = self._uniform = False
        self._uniform_char, self._has_nonspace = None, True

    def iter_text_chunks(self, *, max_chars: int = _CHUNK) -> Iterator[str]:
        self._readable()
        if max_chars <= 0:
            raise ValueError("max_chars must be positive")
        assert self._spool is not None
        decoder = codecs.getincrementaldecoder("utf-8")("surrogatepass")
        pending = ""
        for chunk in self._spool.bytes(self._start, self.byte_length):
            pending += decoder.decode(chunk)
            while len(pending) >= max_chars:
                yield pending[:max_chars]
                pending = pending[max_chars:]
        pending += decoder.decode(b"", final=True)
        if pending:
            yield pending

    @property
    def digest(self) -> str:
        self._readable()
        digest = hashlib.sha256()
        for chunk in self.iter_text_chunks():
            digest.update(chunk.encode("utf-8", "surrogatepass"))
        return digest.hexdigest()

    @property
    def path(self) -> Path:  # type: ignore[override]
        self._readable()
        if self._materialized is None:
            value = DiskBackedText()
            try:
                for chunk in self.iter_text_chunks():
                    value.append_text(chunk)
                value.finish()
                self._materialized = value
            except BaseException:
                value.close()
                raise
        return self._materialized.path

    def close(self) -> None:
        self._closed = True
        self._spool = None
        if self._materialized is not None:
            self._materialized.close()
            self._materialized = None


def _rstrip(value: _Text, *, once: bool = False) -> _Text:
    if isinstance(value, str):
        return value.removesuffix("/") if once else value.rstrip("/")
    assert isinstance(value, _SpoolText) and value._spool is not None
    length = value.byte_length
    while length:
        chunk = value._spool.read(value._start + max(0, length - _CHUNK), min(length, _CHUNK))
        removed = min(1, len(chunk) - len(chunk.rstrip(b"/"))) if once else len(chunk) - len(chunk.rstrip(b"/"))
        length -= removed
        if once or removed < len(chunk):
            break
    return value._spool.text(value._start, length)


class _PaxMap(Mapping):
    def __init__(self, spool: _Spool, scope: int | None = None) -> None:
        self.spool = spool
        self.scope = spool.new_scope() if scope is None else scope
        self._owns_scope = scope is None

    def __del__(self) -> None:
        if getattr(self, "_owns_scope", False) and not self.spool.closed:
            try:
                self.spool.execute("DELETE FROM pax WHERE scope=?", (self.scope,))
            except OSError:
                pass

    def copy(self) -> _PaxMap:
        result = _PaxMap(self.spool)
        self.spool.check()
        self.spool.execute(
            "INSERT INTO pax SELECT ?,digest,kstart,klen,vstart,vlen FROM pax WHERE scope=?", (result.scope, self.scope)
        )
        return result

    def _digest(self, key: _Text) -> str:
        digest = hashlib.sha256()
        for chunk in _chunks(key):
            self.spool.check()
            digest.update(chunk.encode("utf-8", "surrogatepass"))
        return digest.hexdigest()

    def _row(self, key: _Text):
        digest = self._digest(key)
        for row in self.spool.execute(
            "SELECT kstart,klen,vstart,vlen FROM pax WHERE scope=? AND digest=?", (self.scope, digest)
        ):
            if _equal(self.spool.text(row[0], row[1]), key):
                return digest, row
        raise KeyError(key)

    def __getitem__(self, key: _Text) -> _Text:
        _, row = self._row(key)
        return self.spool.text(row[2], row[3])

    def __iter__(self):
        for start, length in self.spool.execute("SELECT kstart,klen FROM pax WHERE scope=?", (self.scope,)):
            self.spool.check()
            yield self.spool.text(start, length)

    def __len__(self) -> int:
        return self.spool.execute("SELECT count(*) FROM pax WHERE scope=?", (self.scope,)).fetchone()[0]

    def items(self):
        for row in self.spool.execute(
            "SELECT kstart,klen,vstart,vlen FROM pax WHERE scope=? ORDER BY kstart", (self.scope,)
        ):
            self.spool.check()
            yield self.spool.text(row[0], row[1]), self.spool.text(row[2], row[3])

    def put(self, key: tuple[int, int], value: tuple[int, int]) -> None:
        key_text = self.spool.text(*key)
        try:
            digest, old = self._row(key_text)
        except KeyError:
            digest = self._digest(key_text)
        else:
            self.spool.execute("DELETE FROM pax WHERE scope=? AND digest=? AND kstart=?", (self.scope, digest, old[0]))
        self.spool.execute("INSERT INTO pax VALUES (?,?,?,?,?,?)", (self.scope, digest, *key, *value))


class _Sparse(Sequence[tuple[int, int]]):
    def __init__(self, spool: _Spool) -> None:
        self.spool, self.scope, self._count = spool, spool.new_scope(), 0

    def __del__(self) -> None:
        if hasattr(self, "scope") and not self.spool.closed:
            try:
                self.spool.execute("DELETE FROM extents WHERE scope=?", (self.scope,))
            except OSError:
                pass

    def append(self, offset: int, length: int) -> None:
        if offset < 0 or length < 0:
            raise _TAR.InvalidHeaderError("invalid sparse offset")
        self.spool.check()
        self.spool.execute("INSERT INTO extents VALUES (?,?,?,?)", (self.scope, self._count, str(offset), str(length)))
        self._count += 1

    def __len__(self):
        return self._count

    def __getitem__(self, index):
        if not isinstance(index, int):
            raise TypeError("sparse extent indices must be integers")
        if index < 0:
            index += self._count
        row = self.spool.execute(
            "SELECT offset,length FROM extents WHERE scope=? AND idx=?", (self.scope, index)
        ).fetchone()
        if row is None:
            raise IndexError(index)
        return int(row[0]), int(row[1])

    def __iter__(self):
        for offset, length in self.spool.execute(
            "SELECT offset,length FROM extents WHERE scope=? ORDER BY idx", (self.scope,)
        ):
            self.spool.check()
            yield int(offset), int(length)


class _Prefix(io.RawIOBase):
    def __init__(self, source, prefix: bytes, check):
        super().__init__()
        self.source, self.prefix, self.check = source, prefix, check

    def read(self, size: int = -1) -> bytes:
        self.check()
        if size < 0:
            raise ValueError("TAR input reads must have a size")
        if self.prefix:
            result, self.prefix = self.prefix[:size], self.prefix[size:]
            return result
        return self.source.read(min(size, _CHUNK))

    def readable(self):
        return True

    def seekable(self):
        return False


class _MemberReader(io.RawIOBase):
    def __init__(self, archive: StreamingTarArchive, member: TarStreamMember) -> None:
        super().__init__()
        self.archive, self.member, self.position = archive, member, 0
        self.extents = iter(member.sparse if member.sparse is not None else ((0, member.size),))
        self.extent = next(self.extents, None)

    def readable(self):
        return True

    def seekable(self):
        return False

    def tell(self):
        return self.position

    def read(self, size: int = -1) -> bytes:
        if self.closed:
            raise ValueError("read of closed TAR member")
        if self.archive._current is not self.member:
            raise tarfile.StreamError("member is no longer current")
        remaining = self.member.size - self.position
        size = remaining if size is None or size < 0 else min(size, remaining)
        parts = []
        while size > 0:
            self.archive.check()
            while self.extent is not None and self.position >= sum(self.extent):
                self.extent = next(self.extents, None)
            if self.extent is None or self.position < self.extent[0]:
                stop = self.member.size if self.extent is None else self.extent[0]
                amount = min(size, stop - self.position, _CHUNK)
                piece = b"\0" * amount
            else:
                amount = min(size, sum(self.extent) - self.position, _CHUNK)
                piece = self.archive._read_exact(amount)
            parts.append(piece)
            self.position += amount
            size -= amount
        return b"".join(parts)

    def readinto(self, buffer):
        chunk = self.read(len(buffer))
        buffer[: len(chunk)] = chunk
        return len(chunk)


class StreamingTarArchive:
    def __init__(
        self,
        stream,
        *,
        check: Callable[[], Any] | None = None,
        compression: str = "auto",
        encoding: str = tarfile.ENCODING,
        errors: str = "surrogateescape",
    ) -> None:
        self.check = check or (lambda: None)
        self.encoding, self.errors = encoding, errors
        self._spool: _Spool | None = None
        self.pax_headers: _PaxMap | None = None
        self._decoder: io.BufferedIOBase | None = None
        self._reader: _MemberReader | None = None
        self._current: TarStreamMember | None = None
        self._closed = False
        self._compression_errors: tuple[type[Exception], ...] = (lzma.LZMAError,)
        try:
            self._spool = _Spool(self.check)
            self.pax_headers = _PaxMap(self._spool)
            self._source, self._decoder = stream, None
            self._current = None
            self._reader = None
            self._position = self._next_header = 0
            self._done = self._closed = False
            prefix = bytearray()
            while len(prefix) < 6:
                self.check()
                chunk = stream.read(6 - len(prefix))
                if not chunk:
                    break
                prefix.extend(chunk)
            replay = _Prefix(stream, bytes(prefix), self.check)
            if compression == "auto":
                if prefix.startswith(b"\x1f\x8b"):
                    compression = "gz"
                elif prefix.startswith(b"BZh"):
                    compression = "bz2"
                elif prefix.startswith((b"\xfd7zXZ", b"\x5d\x00\x00\x80")):
                    compression = "xz"
                elif prefix.startswith(b"\x28\xb5\x2f\xfd"):
                    compression = "zst"
                else:
                    compression = "none"
            if compression == "gz":
                self._decoder = gzip.GzipFile(fileobj=replay, mode="rb")
            elif compression == "bz2":
                self._decoder = bz2.BZ2File(replay, mode="rb")
            elif compression == "xz":
                self._decoder = lzma.LZMAFile(cast(IO[bytes], replay), mode="rb")
            elif compression in ("zst", "zstd"):
                try:
                    zstd = import_module("compression.zstd")
                except ImportError:
                    raise tarfile.CompressionError("compression.zstd module is not available") from None
                self._decoder = zstd.ZstdFile(replay, mode="rb")
                self._compression_errors += (zstd.ZstdError,)
            elif compression != "none":
                raise ValueError("unsupported TAR compression")
            self._stream = self._decoder if self._decoder is not None else replay
        except BaseException:
            spool = self._spool
            try:
                self.close()
            finally:
                if spool is not None:
                    spool.close()
            raise

    @property
    def _active_spool(self) -> _Spool:
        assert self._spool is not None
        return self._spool

    def _read(self, size: int) -> bytes:
        self.check()
        try:
            value = self._stream.read(min(size, _CHUNK))
        except self._compression_errors as exc:
            raise tarfile.ReadError("invalid compressed TAR data") from exc
        self._position += len(value)
        self.check()
        return value

    def _read_exact(self, size: int) -> bytes:
        parts, remaining = [], size
        while remaining:
            piece = self._read(remaining)
            if not piece:
                raise tarfile.ReadError("unexpected end of data")
            parts.append(piece)
            remaining -= len(piece)
        return b"".join(parts)

    def _skip(self, size: int) -> None:
        if size < 0:
            raise tarfile.ReadError("invalid backwards TAR data offset")
        while size:
            piece = self._read(min(size, _CHUNK))
            if not piece:
                raise tarfile.ReadError("unexpected end of data")
            size -= len(piece)

    def _header(self, *, extension: bool) -> TarStreamMember | None:
        start = self._position
        parts, count = [], 0
        while count < _BLOCK:
            piece = self._read(_BLOCK - count)
            if not piece:
                break
            parts.append(piece)
            count += len(piece)
        block = b"".join(parts)
        if not block and start and not extension:
            return None
        try:
            member = cast(
                TarStreamMember, _TAR.TarInfo._frombuf(block, self.encoding, self.errors, dircheck=not extension)
            )
        except _TAR.EOFHeaderError:
            if extension:
                raise tarfile.ReadError("missing header after TAR extension") from None
            return None
        except tarfile.HeaderError as exc:
            raise tarfile.ReadError(str(exc)) from None
        member.offset = start
        return member

    def _raw_payload(self, member: TarStreamMember) -> tuple[int, int]:
        spool = self._active_spool
        start = spool.end
        remaining = member.size
        if remaining < 0:
            raise tarfile.ReadError("negative TAR extension size")
        while remaining:
            piece = self._read_exact(min(remaining, _CHUNK))
            spool.append(piece)
            remaining -= len(piece)
        self._skip((-member.size) % _BLOCK)
        return start, member.size

    def _gnu(self, member: TarStreamMember) -> tuple[int, int]:
        spool = self._active_spool
        start, length = self._raw_payload(member)
        used = 0
        for chunk in spool.bytes(start, length):
            index = chunk.find(b"\0")
            if index >= 0:
                used += index
                break
            used += len(chunk)
        return spool.decode(start, used, self.encoding, self.encoding, self.errors)

    def _pax(self, member: TarStreamMember, mapping: _PaxMap) -> _Sparse | None:
        spool = self._active_spool
        start, size = self._raw_payload(member)
        end, position = start + size, start
        spool.execute("DELETE FROM raw")
        charset = None
        offsets, lengths = _Sparse(spool), _Sparse(spool)
        # Records are framed on disk first: hdrcharset may occur after a name.
        while position < end:
            self.check()
            first = spool.read(position, 1)
            if first == b"\0":
                break
            cursor, length, digits = position, 0, 0
            while cursor < end:
                char = spool.read(cursor, 1)
                cursor += 1
                if char == b" ":
                    break
                if not b"0" <= char <= b"9":
                    raise tarfile.ReadError("invalid PAX length")
                length, digits = length * 10 + char[0] - 48, digits + 1
                if length > end - position:
                    raise tarfile.ReadError("invalid PAX length")
            else:
                raise tarfile.ReadError("invalid PAX length")
            if not digits or length < 5 or length > end - position:
                raise tarfile.ReadError("invalid PAX record")
            record_end, key_start, equals = position + length, cursor, None
            while cursor < record_end - 1:
                chunk = spool.read(cursor, min(_CHUNK, record_end - 1 - cursor))
                index = chunk.find(b"=")
                if index >= 0:
                    equals = cursor + index
                    break
                cursor += len(chunk)
            if equals is None or equals == key_start or spool.read(record_end - 1, 1) != b"\n":
                raise tarfile.ReadError("invalid PAX record framing")
            key_len, value_start, value_len = equals - key_start, equals + 1, record_end - equals - 2
            spool.execute(
                "INSERT INTO raw(kstart,klen,vstart,vlen) VALUES (?,?,?,?)",
                (key_start, key_len, value_start, value_len),
            )
            # Fixed-width key checks never materialize arbitrary unknown keys.
            raw_key = spool.read(key_start, key_len) if key_len <= 64 else b""
            if raw_key == b"hdrcharset" and charset is None:
                charset = self.encoding if value_len == 6 and spool.read(value_start, 6) == b"BINARY" else "utf-8"
            if raw_key in (b"GNU.sparse.offset", b"GNU.sparse.numbytes"):
                decoded = spool.decode(value_start, value_len, "utf-8", "utf-8", self.errors)
                try:
                    number = _integer(spool.text(*decoded), self.check)
                except ValueError as exc:
                    raise tarfile.ReadError("invalid sparse number") from exc
                (offsets if raw_key.endswith(b"offset") else lengths).append(number, 0)
            position = record_end
        charset = charset or "utf-8"
        for ks, kl, vs, vl in spool.execute("SELECT kstart,klen,vstart,vlen FROM raw ORDER BY id"):
            self.check()
            decoded_key = spool.decode(ks, kl, "utf-8", "utf-8", self.errors)
            key_text = spool.text(*decoded_key)
            is_name = isinstance(key_text, str) and key_text in tarfile.PAX_NAME_FIELDS
            value = spool.decode(
                vs, vl, charset if is_name else "utf-8", self.encoding if is_name else "utf-8", self.errors
            )
            mapping.put(decoded_key, value)
        spool.execute("DELETE FROM raw")
        if "GNU.sparse.size" in mapping and "GNU.sparse.map" not in mapping:
            sparse = _Sparse(spool)
            for (offset, _), (length, _) in zip(offsets, lengths, strict=False):
                sparse.append(offset, length)
            return sparse
        return None

    def _apply(self, member: TarStreamMember, headers: _PaxMap) -> None:
        for key, value in headers.items():
            if not isinstance(key, str):
                continue  # Unknown, arbitrarily long keywords remain in pax_headers.
            if key == "GNU.sparse.name":
                member.name = value
            elif key in ("GNU.sparse.size", "GNU.sparse.realsize"):
                member.size = _integer(value, self.check)
            elif key in tarfile.PAX_FIELDS:
                if key in tarfile.PAX_NUMBER_FIELDS:
                    try:
                        if tarfile.PAX_NUMBER_FIELDS[key] is int:
                            value = _integer(value, self.check)
                        else:
                            value = _float(value)
                    except ValueError:
                        value = 0
                if key == "path":
                    value = _rstrip(value)
                setattr(member, key, value)
        member.pax_headers = headers

    def _old_sparse(self, member: TarStreamMember) -> None:
        spool = self._active_spool
        structs, extended, original_size = member._sparse_structs
        del member._sparse_structs
        sparse = _Sparse(spool)
        for offset, length in structs:
            sparse.append(offset, length)
        while extended:
            block = self._read_exact(_BLOCK)
            for position in range(0, 21 * 24, 24):
                try:
                    offset, length = (
                        _TAR.nti(block[position : position + 12]),
                        _TAR.nti(block[position + 12 : position + 24]),
                    )
                except ValueError:
                    break
                if offset and length:
                    sparse.append(offset, length)
            extended = bool(block[504])
        member.sparse, member.size = sparse, original_size

    def _sparse_map(self, value: _Text) -> _Sparse:
        spool = self._active_spool
        sparse, number, offset, have = _Sparse(spool), 0, None, False
        digits, limit = 0, sys.get_int_max_str_digits()
        for chunk in _chunks(value):
            self.check()
            for char in chunk:
                if char == ",":
                    if not have:
                        raise tarfile.ReadError("invalid sparse map")
                    if offset is None:
                        offset = number
                    else:
                        sparse.append(offset, number)
                        offset = None
                    number, have, digits = 0, False, 0
                elif "0" <= char <= "9":
                    digits += 1
                    if limit and digits > limit:
                        raise tarfile.ReadError("sparse number exceeds Python integer conversion guard")
                    number, have = number * 10 + ord(char) - 48, True
                else:
                    raise tarfile.ReadError("invalid sparse map")
        if have and offset is not None:
            sparse.append(offset, number)
        elif have or offset is not None:
            raise tarfile.ReadError("invalid sparse map")
        return sparse

    def _sparse_10(self, member: TarStreamMember) -> None:
        spool = self._active_spool
        # Newline-delimited numbers fill whole 512-byte blocks before data.
        block, position = b"", _BLOCK

        def number():
            nonlocal block, position
            result, digits, limit = 0, 0, sys.get_int_max_str_digits()
            while True:
                if position == _BLOCK:
                    block, position = self._read_exact(_BLOCK), 0
                char, position = block[position], position + 1
                if char == 10 and digits:
                    return result
                if not 48 <= char <= 57:
                    raise tarfile.ReadError("invalid sparse 1.0 map")
                digits += 1
                if limit and digits > limit:
                    raise tarfile.ReadError("sparse number exceeds Python integer conversion guard")
                result = result * 10 + char - 48

        count = number()
        sparse = _Sparse(spool)
        for _ in range(count):
            sparse.append(number(), number())
        member.sparse = sparse
        member.offset_data = self._position

    def __iter__(self):
        return self

    def __next__(self) -> TarStreamMember:
        if self._closed or self._done:
            raise StopIteration
        self.check()
        self._skip(self._next_header - self._position)
        self._current, self._reader = None, None
        spool = self._active_spool
        assert self.pax_headers is not None
        spool.execute("DELETE FROM actions")
        extension = False
        while True:
            member = self._header(extension=extension)
            if member is None:
                self._done = True
                if self._decoder is not None:
                    while self._read(_CHUNK):
                        pass  # Validate compressed CRC/trailer beyond TAR padding.
                raise StopIteration
            if member.type not in (
                tarfile.GNUTYPE_LONGNAME,
                tarfile.GNUTYPE_LONGLINK,
                tarfile.XHDTYPE,
                tarfile.XGLTYPE,
                tarfile.SOLARIS_XHDTYPE,
            ):
                break
            extension = True
            if member.type in (tarfile.GNUTYPE_LONGNAME, tarfile.GNUTYPE_LONGLINK):
                start, length = self._gnu(member)
                spool.execute(
                    "INSERT INTO actions(kind,start,length,offset) VALUES (?,?,?,?)",
                    (member.type, start, length, str(member.offset)),
                )
            else:
                headers = self.pax_headers if member.type == tarfile.XGLTYPE else self.pax_headers.copy()
                sparse = self._pax(member, headers)
                # Actions own scopes through their SQL rows; no Python prefix stack.
                headers._owns_scope = False
                spool.execute(
                    "INSERT INTO actions(kind,scope,start,length,offset) VALUES (?,?,?,?,?)",
                    (
                        member.type,
                        headers.scope,
                        sparse.scope if sparse is not None else None,
                        len(sparse) if sparse is not None else None,
                        str(member.offset),
                    ),
                )
                if sparse is not None:
                    sparse.scope = -1  # Transfer extent-row ownership to this action.
        stored_size = member.size
        if stored_size < 0:
            raise tarfile.ReadError("negative TAR member size")
        if member.type == tarfile.GNUTYPE_SPARSE:
            self._old_sparse(member)
        member.offset_data = self._position
        data_header = member.offset_data
        self._next_header = member.offset_data
        if member.isreg() or member.type not in tarfile.SUPPORTED_TYPES:
            self._next_header += ((stored_size + _BLOCK - 1) // _BLOCK) * _BLOCK
        if member.type != tarfile.GNUTYPE_SPARSE:
            self._apply(member, self.pax_headers.copy())
        if member.isdir():
            member.name = _rstrip(member.name)
        for kind, scope, start, length, offset in spool.execute(
            "SELECT kind,scope,start,length,offset FROM actions ORDER BY id DESC"
        ):
            self.check()
            if kind in (tarfile.GNUTYPE_LONGNAME, tarfile.GNUTYPE_LONGLINK):
                value = spool.text(start, length)
                if kind == tarfile.GNUTYPE_LONGNAME:
                    member.name = _rstrip(value, once=True) if member.isdir() else value
                else:
                    member.linkname = value
            else:
                headers = _PaxMap(spool, scope)
                if "GNU.sparse.map" in headers:
                    member.sparse = self._sparse_map(headers["GNU.sparse.map"])
                elif "GNU.sparse.size" in headers:
                    sparse = _Sparse(spool)
                    if start is not None:
                        spool.execute(
                            "INSERT INTO extents SELECT ?,idx,offset,length FROM extents WHERE scope=?",
                            (sparse.scope, start),
                        )
                        sparse._count = length
                        spool.execute("DELETE FROM extents WHERE scope=?", (start,))
                    member.sparse = sparse
                elif headers.get("GNU.sparse.major") == "1" and headers.get("GNU.sparse.minor") == "0":
                    self._sparse_10(member)
                if kind in (tarfile.XHDTYPE, tarfile.SOLARIS_XHDTYPE):
                    self._apply(member, headers.copy())
                    if "size" in headers:
                        # PAX size is the stored payload size; sparse realsize
                        # is the logical size and must not move the next header.
                        try:
                            physical_size = _integer(headers["size"], self.check)
                        except ValueError:
                            physical_size = 0
                        if physical_size < 0:
                            raise tarfile.ReadError("negative TAR member size")
                        self._next_header = data_header
                        if member.isreg() or member.type not in tarfile.SUPPORTED_TYPES:
                            self._next_header += ((physical_size + _BLOCK - 1) // _BLOCK) * _BLOCK
                    spool.execute("DELETE FROM pax WHERE scope=?", (scope,))
            if kind != tarfile.XGLTYPE:
                member.offset = int(offset)
        spool.execute("DELETE FROM actions")
        if member.size < 0:
            raise tarfile.ReadError("negative TAR member size")
        self._current = member
        return member

    def extractfile(self, member: TarStreamMember):
        self.check()
        if member is not self._current:
            raise tarfile.StreamError("only the current TAR member can be extracted")
        if member.islnk() or member.issym():
            raise tarfile.StreamError("cannot extract links from a forward TAR stream")
        if not member.isreg() and member.type in tarfile.SUPPORTED_TYPES:
            return None
        if self._reader is not None:
            raise tarfile.StreamError("current TAR member already opened")
        self._reader = _MemberReader(self, member)
        return self._reader

    def close(self):
        if self._closed:
            return
        self._closed = True
        try:
            if self._reader is not None:
                self._reader.close()
            if self._decoder is not None:
                self._decoder.close()
        finally:
            self._current = self._reader = None
            self.pax_headers = None
            if self._spool is not None:
                self._spool.check = lambda: None
            self._spool = None

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        self.close()


def _float(value: _Text) -> float:
    if isinstance(value, str):
        return float(value)
    # Every finite binary64 midpoint has fewer than 1100 significant decimal
    # digits. A retained prefix plus a sticky digit therefore preserves float()
    # rounding while decimal timestamps of any length stay bounded in memory.
    sign, significant, exponent, fraction = "", "", 0, False
    explicit, exponent_sign, exponent_value = 0, 1, 0
    started = trailing = saw_digit = sticky = False
    special = ""
    for chunk in _chunks(value):
        for char in chunk:
            if char.isspace() and not started:
                continue
            if char.isspace():
                trailing = True
                continue
            if trailing:
                raise ValueError("invalid PAX number")
            if not started and char in "+-":
                sign, started = char, True
                continue
            started = True
            if special or (not saw_digit and not fraction and char.lower() in "in"):
                special += char.lower()
                if len(special) > 8:
                    raise ValueError("invalid PAX number")
            elif explicit:
                if char in "+-" and explicit == 1:
                    exponent_sign, explicit = (-1 if char == "-" else 1), 2
                elif "0" <= char <= "9":
                    exponent_value = min(1000000, exponent_value * 10 + ord(char) - 48)
                    explicit = 3
                else:
                    raise ValueError("invalid PAX exponent")
            elif char == "." and not fraction:
                fraction = True
            elif char in "eE" and saw_digit:
                explicit = 1
            elif "0" <= char <= "9":
                saw_digit = True
                if len(significant) < 1100:
                    if significant or char != "0":
                        significant += char
                    if fraction:
                        exponent -= 1
                else:
                    sticky |= char != "0"
                    if not fraction:
                        exponent += 1
            else:
                raise ValueError("invalid PAX number")
    if special:
        return float(sign + special)
    if not saw_digit or explicit in (1, 2):
        raise ValueError("invalid PAX number")
    exponent += exponent_sign * exponent_value
    if sticky:
        significant += "1"
        exponent -= 1
    if not significant:
        significant = "0"
    return float(sign + significant + "e" + str(exponent))


@contextmanager
def open_tar_stream(
    stream,
    *,
    check: Callable[[], Any] | None = None,
    compression: str = "auto",
    encoding: str = tarfile.ENCODING,
    errors: str = "surrogateescape",
) -> Iterator[StreamingTarArchive]:
    archive = StreamingTarArchive(stream, check=check, compression=compression, encoding=encoding, errors=errors)
    try:
        yield archive
    finally:
        archive.close()
