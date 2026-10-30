"""Read-only ZIP extraction with a disk-backed central directory.

``BoundedZipFile(stream, check_deadline=callback)`` is a context manager.
Iterate ``infolist()`` and pass each ordinary ``zipfile.ZipInfo`` to ``open``.
The directory, duplicate-name index, and local-header overlap boundaries live
in a temporary SQLite database.  Python retains one directory entry at a time;
each entry's name, extra field, and comment have ZIP's 16-bit length bounds.
There are no limits on member count or archive/member size.

This read-only adapter supports the installed CPython 3.12--3.14 zipfile
implementations.  It replaces only their eager ``_RealGetContents`` catalog,
using their EOCD/ZIP64 decoder, ZipInfo extra-field decoder, and extraction
implementation.  The two extra-field signatures and pre/post ZIP64 EOCD
location correction are handled below.  CRC, encryption, compression, local
header validation, and path sanitization remain stdlib behavior.

``infolist`` returns a real lazy Sequence, and ``NameToInfo`` a real Mapping;
neither pretends to be an empty builtin container.  Explicit eager operations
such as ``read()`` without a size, ``namelist()``, ``list(infolist())``, and
``dict(NameToInfo)`` retain their normal eager semantics.  Use bounded member
reads for streaming discovery.  Retained ZipInfo objects and already-open
members remain usable after archive close; the catalog views do not.

The callback runs before/after physical reads and decompression, on directory
entries (including directories), and while indexing overlap boundaries.  It
may raise, or return exactly False to raise ZipDeadlineExceeded.  It cannot
interrupt a blocking OS read or an individual stdlib decompression call.
"""

from __future__ import annotations

import io
import json
import operator
import sqlite3
import struct
import tempfile
import zipfile
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import closing, contextmanager
from pathlib import Path
from typing import Any, SupportsIndex, overload

# The adapter intentionally follows installed CPython internals, which are
# absent from the public zipfile typing stubs.
_ZIP: Any = zipfile


class ZipDeadlineExceeded(TimeoutError):
    """The discovery callback reported that its deadline was exhausted."""


def _check(callback: Callable[[], object] | None) -> None:
    if callback is not None and callback() is False:
        raise ZipDeadlineExceeded("ZIP discovery deadline exceeded")


@contextmanager
def _catalog_io() -> Iterator[None]:
    """Keep temporary database failures in the discovery spool contract."""
    try:
        yield
    except sqlite3.Error as exc:
        raise OSError("ZIP directory storage failed") from exc


class _DeadlineSeekable:
    """Coalesce short reads and preserve the original stream's ownership."""

    def __init__(self, source: Any, callback: Callable[[], object] | None):
        self._source = source
        self._callback = callback
        self.deadline_error: BaseException | None = None

    def _checkpoint(self) -> None:
        try:
            _check(self._callback)
        except BaseException as exc:
            # _EndRecData intentionally catches OSError from its first seek;
            # do not let that convert a discovery timeout into BadZipFile.
            self.deadline_error = exc
            raise

    def read(self, size: int = -1) -> bytes:
        self._checkpoint()
        if size is None or size < 0:
            # zipfile's directory decoder and bounded member reads never use
            # this path; retain ordinary file semantics for explicit callers.
            result = self._source.read(size)
        else:
            result = self._source.read(size)
            if result and len(result) < size:
                pieces = bytearray(result)
                while len(pieces) < size:
                    self._checkpoint()
                    piece = self._source.read(size - len(pieces))
                    self._checkpoint()
                    if not piece:
                        break
                    pieces.extend(piece)
                result = bytes(pieces)
        self._checkpoint()
        return result

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        self._checkpoint()
        result = self._source.seek(offset, whence)
        self._checkpoint()
        return result

    def tell(self) -> int:
        return self._source.tell()

    def close(self) -> None:
        self._source.close()

    def __getattr__(self, name: str) -> Any:
        return getattr(self._source, name)


class _DeadlineMember:
    """Wrap public ZipExtFile reads, including decompressor-buffered reads."""

    def __init__(self, source: Any, callback: Callable[[], object] | None):
        self._source = source
        self._callback = callback

    def _call(self, name: str, *args: Any, **kwargs: Any) -> Any:
        _check(self._callback)
        result = getattr(self._source, name)(*args, **kwargs)
        _check(self._callback)
        return result

    def read(self, size: int = -1) -> bytes:
        return self._call("read", size)

    def read1(self, size: int = -1) -> bytes:
        return self._call("read1", size)

    def readline(self, size: int = -1) -> bytes:
        return self._call("readline", size)

    def readinto(self, buffer: Any) -> int:
        return self._call("readinto", buffer)

    def readinto1(self, buffer: Any) -> int:
        return self._call("readinto1", buffer)

    def readlines(self, hint: int = -1) -> list[bytes]:
        result = []
        total = 0
        for line in self:
            result.append(line)
            total += len(line)
            if hint > 0 and total >= hint:
                break
        return result

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        return self._call("seek", offset, whence)

    def peek(self, size: int = 0) -> bytes:
        return self._call("peek", size)

    def close(self) -> None:
        self._source.close()

    def __enter__(self) -> _DeadlineMember:
        return self

    def __exit__(self, *_exc: Any) -> None:
        self.close()

    def __iter__(self) -> _DeadlineMember:
        return self

    def __next__(self) -> bytes:
        line = self.readline()
        if not line:
            raise StopIteration
        return line

    def __getattr__(self, name: str) -> Any:
        return getattr(self._source, name)


def _compare_offsets(left: str, right: str) -> int:
    """Preserve ZIP64 unsigned offsets without SQLite's signed-int ceiling."""
    first, second = int(left), int(right)
    return (first > second) - (first < second)


_INFO_FIELDS = (
    "orig_filename",
    "filename",
    "date_time",
    "compress_type",
    "create_system",
    "create_version",
    "extract_version",
    "reserved",
    "flag_bits",
    "volume",
    "internal_attr",
    "external_attr",
    "header_offset",
    "CRC",
    "compress_size",
    "file_size",
    "_raw_time",
)
_INFO_COLUMNS = "metadata, extra, comment, end_offset"


class _ZipCatalog:
    def __init__(self, callback: Callable[[], object] | None):
        self.callback = callback
        self.count = 0
        self.name_count = 0
        self._db: sqlite3.Connection | None = None
        self._temporary = tempfile.TemporaryDirectory(prefix="redposture-zip-")
        try:
            self._db = sqlite3.connect(Path(self._temporary.name) / "directory.sqlite3")
            self._db.create_collation("zip_offset", _compare_offsets)
            # Every catalog is disposable; cache and sorting must stay bounded
            # even when a directory or its duplicate-name index is enormous.
            self._db.execute("PRAGMA cache_size=-512")
            self._db.execute("PRAGMA temp_store=FILE")
            self._db.execute("PRAGMA mmap_size=0")
            self._db.execute("PRAGMA journal_mode=OFF")
            self._db.execute("PRAGMA synchronous=OFF")
            self._db.execute(
                "CREATE TABLE entries (ordinal INTEGER PRIMARY KEY, header_offset TEXT COLLATE zip_offset NOT NULL, "
                "end_offset TEXT, metadata TEXT NOT NULL, extra BLOB NOT NULL, comment BLOB NOT NULL)"
            )
            self._db.execute("CREATE INDEX entry_offsets ON entries(header_offset COLLATE zip_offset, ordinal)")
            self._db.execute(
                "CREATE TABLE names (name BLOB PRIMARY KEY, ordinal INTEGER NOT NULL, first_ordinal INTEGER NOT NULL)"
            )
            self._db.execute("CREATE INDEX name_order ON names(first_ordinal)")
        except BaseException:
            try:
                self.close()
            except (OSError, sqlite3.Error):
                pass  # Preserve the initialization failure after cleanup.
            raise

    @property
    def db(self) -> sqlite3.Connection:
        if self._db is None:
            raise ValueError("ZIP directory catalog is closed")
        return self._db

    def add(self, info: zipfile.ZipInfo) -> None:
        _check(self.callback)
        metadata = json.dumps({field: getattr(info, field) for field in _INFO_FIELDS}, ensure_ascii=True)
        self.db.execute(
            "INSERT INTO entries(ordinal, header_offset, metadata, extra, comment) VALUES (?, ?, ?, ?, ?)",
            (self.count, str(info.header_offset), metadata, info.extra, info.comment),
        )
        key = info.filename.encode("utf-8", "surrogatepass")
        inserted = self.db.execute(
            "INSERT OR IGNORE INTO names(name, ordinal, first_ordinal) VALUES (?, ?, ?)",
            (key, self.count, self.count),
        ).rowcount
        if inserted:
            self.name_count += 1
        else:
            self.db.execute("UPDATE names SET ordinal=? WHERE name=?", (self.count, key))
        self.count += 1

    def finish(self, start_dir: int) -> None:
        # This matches reversed(sorted(filelist, key=header_offset)), including
        # its stable ordering for several entries sharing one local header.
        end_offset = start_dir
        with closing(
            self.db.execute(
                "SELECT ordinal, header_offset FROM entries ORDER BY header_offset COLLATE zip_offset DESC, ordinal DESC"
            )
        ) as cursor:
            for ordinal, offset in cursor:
                _check(self.callback)
                self.db.execute("UPDATE entries SET end_offset=? WHERE ordinal=?", (str(end_offset), ordinal))
                end_offset = int(offset)
        self.db.commit()
        _check(self.callback)

    def restore(self, row: Any) -> zipfile.ZipInfo:
        _check(self.callback)
        metadata, extra, comment, end_offset = row
        values = json.loads(metadata)
        info = _ZIP.ZipInfo(values["orig_filename"])
        values["date_time"] = tuple(values["date_time"])
        for name, value in values.items():
            setattr(info, name, value)
        info.extra = extra
        info.comment = comment
        info._end_offset = int(end_offset)
        return info

    def at(self, ordinal: int) -> zipfile.ZipInfo:
        _check(self.callback)
        with _catalog_io():
            row = self.db.execute(f"SELECT {_INFO_COLUMNS} FROM entries WHERE ordinal=?", (ordinal,)).fetchone()
        if row is None:
            raise IndexError("ZIP directory index out of range")
        return self.restore(row)

    def by_name(self, name: str) -> zipfile.ZipInfo:
        _check(self.callback)
        if not isinstance(name, str):
            raise KeyError(name)
        with _catalog_io():
            row = self.db.execute(
                f"SELECT {_INFO_COLUMNS} FROM entries WHERE ordinal=(SELECT ordinal FROM names WHERE name=?)",
                (name.encode("utf-8", "surrogatepass"),),
            ).fetchone()
        if row is None:
            raise KeyError(name)
        return self.restore(row)

    def iter_infos(self, ordinals: range) -> Iterator[zipfile.ZipInfo]:
        _check(self.callback)
        if not ordinals:
            return
        if abs(ordinals.step) != 1:
            for ordinal in ordinals:
                yield self.at(ordinal)
            return
        low, high = sorted((ordinals[0], ordinals[-1]))
        direction = "ASC" if ordinals.step > 0 else "DESC"
        with _catalog_io():
            with closing(
                self.db.execute(
                    f"SELECT {_INFO_COLUMNS} FROM entries WHERE ordinal BETWEEN ? AND ? ORDER BY ordinal {direction}",
                    (low, high),
                )
            ) as cursor:
                for row in cursor:
                    yield self.restore(row)

    def iter_names(self) -> Iterator[str]:
        _check(self.callback)
        with _catalog_io():
            with closing(self.db.execute("SELECT name FROM names ORDER BY first_ordinal")) as cursor:
                for (name,) in cursor:
                    _check(self.callback)
                    yield name.decode("utf-8", "surrogatepass")

    def close(self) -> None:
        db, self._db = self._db, None
        failure: OSError | sqlite3.Error | None = None
        try:
            if db is not None:
                db.close()
        except (OSError, sqlite3.Error) as exc:
            failure = exc
        try:
            self._temporary.cleanup()
        except OSError as exc:
            if failure is None:
                failure = exc
        if failure is not None:
            with _catalog_io():
                raise failure


class _ZipInfoSequence(Sequence[zipfile.ZipInfo]):
    def __init__(self, catalog: _ZipCatalog, ordinals: range | None = None):
        self._catalog = catalog
        self._ordinals = range(catalog.count) if ordinals is None else ordinals

    def __len__(self) -> int:
        return len(self._ordinals)

    @overload
    def __getitem__(self, index: SupportsIndex) -> zipfile.ZipInfo: ...

    @overload
    def __getitem__(self, index: slice) -> _ZipInfoSequence: ...

    def __getitem__(self, index: SupportsIndex | slice) -> zipfile.ZipInfo | _ZipInfoSequence:
        ordinal = self._ordinals[index if isinstance(index, slice) else operator.index(index)]
        if isinstance(ordinal, range):
            return _ZipInfoSequence(self._catalog, ordinal)
        return self._catalog.at(ordinal)

    def __iter__(self) -> Iterator[zipfile.ZipInfo]:
        return self._catalog.iter_infos(self._ordinals)


class _ZipNameMapping(Mapping[str, zipfile.ZipInfo]):
    def __init__(self, catalog: _ZipCatalog):
        self._catalog = catalog

    def __getitem__(self, name: str) -> zipfile.ZipInfo:
        return self._catalog.by_name(name)

    def __iter__(self) -> Iterator[str]:
        return self._catalog.iter_names()

    def __len__(self) -> int:
        _check(self._catalog.callback)
        return self._catalog.name_count


class BoundedZipFile(zipfile.ZipFile):
    """Read-only ZipFile whose directory cardinality consumes disk, not RAM."""

    def __init__(
        self,
        file: Any,
        *,
        check_deadline: Callable[[], object] | None = None,
        metadata_encoding: str | None = None,
    ):
        self._catalog: _ZipCatalog | None = None
        self._check_deadline = check_deadline
        try:
            _check(check_deadline)
            with _catalog_io():
                super().__init__(file, mode="r", metadata_encoding=metadata_encoding)
        except BaseException:
            try:
                self.close()
            except (OSError, sqlite3.Error):
                pass  # Preserve import/deadline failures after cleanup.
            raise

    def _RealGetContents(self) -> None:
        owner: Any = self
        owner.fp = _DeadlineSeekable(owner.fp, self._check_deadline)
        fp = owner.fp
        try:
            endrec = _ZIP._EndRecData(fp)
        except OSError as exc:
            if fp.deadline_error is not None:
                raise fp.deadline_error from exc
            raise zipfile.BadZipFile("File is not a zip file") from exc
        if fp.deadline_error is not None:
            raise fp.deadline_error
        if not endrec:
            raise zipfile.BadZipFile("File is not a zip file")
        size_cd = endrec[_ZIP._ECD_SIZE]
        offset_cd = endrec[_ZIP._ECD_OFFSET]
        self._comment = endrec[_ZIP._ECD_COMMENT]
        concat = endrec[_ZIP._ECD_LOCATION] - size_cd - offset_cd
        # Recent CPython security updates move _ECD_LOCATION back to the
        # ZIP64 EOCD.  Older 3.12--3.14 builds leave it at the classic EOCD.
        # Detect the actual installed decoder, rather than a patch version.
        if (
            endrec[_ZIP._ECD_SIGNATURE] == _ZIP.stringEndArchive64
            and "_ECD_LOCATION" not in _ZIP._EndRecData64.__code__.co_names
        ):
            concat -= _ZIP.sizeEndCentDir64 + _ZIP.sizeEndCentDir64Locator
        self.start_dir = offset_cd + concat
        if self.start_dir < 0:
            raise zipfile.BadZipFile("Bad offset for central directory")
        fp.seek(self.start_dir)
        self._catalog = catalog = _ZipCatalog(self._check_deadline)
        total = 0

        def read_field(size: int) -> bytes:
            nonlocal total
            if size > size_cd - total:
                raise zipfile.BadZipFile("Truncated central directory")
            value = fp.read(size)
            if len(value) != size:
                raise zipfile.BadZipFile("Truncated central directory")
            total += size
            return value

        while total < size_cd:
            _check(self._check_deadline)
            entry = struct.unpack(_ZIP.structCentralDir, read_field(_ZIP.sizeCentralDir))
            if entry[_ZIP._CD_SIGNATURE] != _ZIP.stringCentralDir:
                raise zipfile.BadZipFile("Bad magic number for central directory")
            raw_name = read_field(entry[_ZIP._CD_FILENAME_LENGTH])
            encoding = "utf-8" if entry[_ZIP._CD_FLAG_BITS] & 0x800 else owner.metadata_encoding or "cp437"
            info: Any = zipfile.ZipInfo(raw_name.decode(encoding))
            info.extra = read_field(entry[_ZIP._CD_EXTRA_FIELD_LENGTH])
            info.comment = read_field(entry[_ZIP._CD_COMMENT_LENGTH])
            info.header_offset = entry[_ZIP._CD_LOCAL_HEADER_OFFSET]
            (
                info.create_version,
                info.create_system,
                info.extract_version,
                info.reserved,
                info.flag_bits,
                info.compress_type,
                dos_time,
                dos_date,
                info.CRC,
                info.compress_size,
                info.file_size,
            ) = entry[1:12]
            if info.extract_version > _ZIP.MAX_EXTRACT_VERSION:
                raise NotImplementedError("zip file version %.1f" % (info.extract_version / 10))
            info.volume, info.internal_attr, info.external_attr = entry[15:18]
            info._raw_time = dos_time
            info.date_time = (
                (dos_date >> 9) + 1980,
                (dos_date >> 5) & 0xF,
                dos_date & 0x1F,
                dos_time >> 11,
                (dos_time >> 5) & 0x3F,
                (dos_time & 0x1F) * 2,
            )
            if _ZIP.ZipInfo._decodeExtra.__code__.co_argcount == 1:
                info._decodeExtra()
            else:
                info._decodeExtra(_ZIP.crc32(raw_name))
            info.header_offset += concat
            catalog.add(info)
        catalog.finish(self.start_dir)
        owner.filelist = _ZipInfoSequence(catalog)
        owner.NameToInfo = _ZipNameMapping(catalog)

    def open(self, name: Any, mode: str = "r", pwd: bytes | None = None, *, force_zip64: bool = False) -> Any:
        if mode != "r":
            raise ValueError("BoundedZipFile only supports reading")
        _check(self._check_deadline)
        source = super().open(name, mode="r", pwd=pwd, force_zip64=force_zip64)
        try:
            _check(self._check_deadline)
            return _DeadlineMember(source, self._check_deadline)
        except BaseException:
            source.close()
            raise

    def close(self) -> None:
        with _catalog_io():
            try:
                super().close()
            finally:
                catalog, self._catalog = self._catalog, None
                if catalog is not None:
                    catalog.close()
