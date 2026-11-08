"""Exact discovery values retained on temporary disk until output finishes."""

from __future__ import annotations

import codecs
import hashlib
import json
import sqlite3
import tempfile
from collections.abc import Iterator, Mapping
from pathlib import Path

from .discovery_containers import DiskContainer


class DiskBackedText:
    """Incrementally write one UTF-8 scalar and read it only after completion."""

    def __init__(self, *, directory: str | Path | None = None) -> None:
        self._temporary = tempfile.TemporaryDirectory(prefix="redposture-discover-value-", dir=directory)
        self.path = Path(self._temporary.name) / "value.txt"
        self._writer = self.path.open("wb")
        self._hash = hashlib.sha256()
        self.byte_length = 0
        self._finished = False
        self._closed = False
        self._all_x = True
        self._all_star = True
        self._all_dash = True
        self._has_nonspace = False
        self._uniform_char: str | None = None
        self._uniform = True

    @property
    def digest(self) -> str:
        return self._hash.hexdigest()

    @property
    def obvious_placeholder(self) -> bool:
        self._readable()
        if self.byte_length >= 4 and (self._all_x or self._all_star or self._all_dash or not self._has_nonspace):
            return True
        if self.byte_length <= 128:
            # Exact short API sentinels have the same meaning on disk and in
            # ordinary strings. Never search a prefix of a large real value.
            from .secret_fields import _is_secret_sentinel

            return _is_secret_sentinel("".join(self.iter_text_chunks(max_chars=128)))
        return False

    @property
    def uniform(self) -> bool:
        """Whether the entire completed value repeats one character."""
        self._readable()
        return bool(self.byte_length) and self._uniform

    def append_text(self, text: str) -> None:
        if self._finished or self._closed:
            raise RuntimeError("disk value is finished")
        if text and self._uniform:
            if self._uniform_char is None:
                self._uniform_char = text[0]
            self._uniform = text.count(self._uniform_char) == len(text)
        encoded = text.encode("utf-8")
        self._writer.write(encoded)
        self._hash.update(encoded)
        self.byte_length += len(encoded)
        self._all_x &= all(char in "xX" for char in text)
        self._all_star &= all(char == "*" for char in text)
        self._all_dash &= all(char == "-" for char in text)
        self._has_nonspace |= any(not char.isspace() for char in text)

    def finish(self) -> None:
        if self._finished or self._closed:
            raise RuntimeError("disk value is finished")
        self._writer.close()
        self._finished = True

    def _readable(self) -> None:
        if self._closed:
            raise RuntimeError("disk value is closed")
        if not self._finished:
            raise RuntimeError("disk value is incomplete")

    def iter_text_chunks(self, *, max_chars: int = 65_536) -> Iterator[str]:
        self._readable()
        if max_chars <= 0:
            raise ValueError("max_chars must be positive")
        with self.path.open("r", encoding="utf-8", newline="") as reader:
            while chunk := reader.read(max_chars):
                yield chunk

    def iter_json_chunks(self, *, max_chars: int = 65_536) -> Iterator[str]:
        self._readable()
        yield '"'
        for chunk in self.iter_text_chunks(max_chars=max_chars):
            yield json.dumps(chunk, ensure_ascii=False)[1:-1]
        yield '"'

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._writer.close()
        self._temporary.cleanup()

    def __del__(self) -> None:
        if not getattr(self, "_closed", True):
            self.close()

    def __enter__(self) -> DiskBackedText:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


class InlineDiskText(DiskBackedText):
    """Completed small scalar with the disk-text API and lazy file adoption.

    Spool payloads keep the text in SQLite. Reading one record creates this
    short-lived view, without keeping the original temporary file alive.
    """

    def __init__(self, text: str) -> None:
        self._text = text
        self._materialized: DiskBackedText | None = None
        self._hash = hashlib.sha256(text.encode("utf-8"))
        self.byte_length = len(text.encode("utf-8"))
        self._finished, self._closed = True, False
        self._all_x = all(char in "xX" for char in text)
        self._all_star = all(char == "*" for char in text)
        self._all_dash = all(char == "-" for char in text)
        self._has_nonspace = any(not char.isspace() for char in text)
        self._uniform_char = text[0] if text else None
        self._uniform = not text or text.count(text[0]) == len(text)

    def iter_text_chunks(self, *, max_chars: int = 65_536) -> Iterator[str]:
        self._readable()
        if max_chars <= 0:
            raise ValueError("max_chars must be positive")
        for offset in range(0, len(self._text), max_chars):
            yield self._text[offset : offset + max_chars]

    @property
    def path(self) -> Path:  # type: ignore[override]
        self._readable()
        if self._materialized is None:
            value = DiskBackedText()
            try:
                value.append_text(self._text)
                value.finish()
                self._materialized = value
            except BaseException:
                value.close()
                raise
        return self._materialized.path

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self._materialized is not None:
            self._materialized.close()
            self._materialized = None
        self._text = ""


class EncodedSecretText(DiskBackedText):
    """Lossless percent spelling for password bytes that cannot be UTF-8 text.

    Storage digest describes the spelling; secret_digest describes decoded
    bytes. Keeping these identities separate prevents arena corruption and
    merging a binary password with a literal percent-prefixed password.
    """

    def __init__(self, source: str | DiskBackedText, secret_digest: str) -> None:
        self.source = InlineDiskText(source) if isinstance(source, str) else source
        self.secret_digest = secret_digest
        self.byte_length = self.source.byte_length
        self._finished, self._closed = True, False

    @property
    def digest(self) -> str:
        return self.source.digest

    @property
    def obvious_placeholder(self) -> bool:
        return self.source.obvious_placeholder

    @property
    def uniform(self) -> bool:
        return self.source.uniform

    @property
    def path(self) -> Path:  # type: ignore[override]
        self._readable()
        return self.source.path

    def iter_text_chunks(self, *, max_chars: int = 65_536) -> Iterator[str]:
        self._readable()
        yield from self.source.iter_text_chunks(max_chars=max_chars)

    def iter_json_chunks(self, *, max_chars: int = 65_536) -> Iterator[str]:
        self._readable()
        yield '{"encoding":"percent","data":'
        yield from self.source.iter_json_chunks(max_chars=max_chars)
        yield "}"

    def close(self) -> None:
        # The original scalar can also be retained by its parser/spool owner.
        # Release our reference normally rather than closing another owner.
        self._closed = True


class CredentialObject(DiskBackedText):
    """An already validated credential object encoded on disk, never a JSON string.

    The typed digest separates an object from a literal string with identical
    JSON spelling. The spool retains this type when adopting the payload.
    """

    def __init__(self, source: DiskBackedText) -> None:
        self.source = source
        self.byte_length = source.byte_length
        self._finished, self._closed = True, False

    @classmethod
    def from_fields(cls, fields: Mapping[str, object]) -> CredentialObject:
        source = DiskBackedText()
        try:
            for chunk in iter_json_chunks(dict(sorted(fields.items()))):
                source.append_text(chunk)
            source.finish()
            return cls(source)
        except BaseException:
            source.close()
            raise

    @property
    def digest(self) -> str:
        return self.source.digest

    @property
    def secret_digest(self) -> str:
        return hashlib.sha256(("credential-object:" + self.digest).encode()).hexdigest()

    @property
    def obvious_placeholder(self) -> bool:
        return False

    @property
    def uniform(self) -> bool:
        return False

    @property
    def path(self) -> Path:  # type: ignore[override]
        self._readable()
        return self.source.path

    def iter_text_chunks(self, *, max_chars: int = 65_536) -> Iterator[str]:
        self._readable()
        yield from self.source.iter_text_chunks(max_chars=max_chars)

    def iter_json_chunks(self, *, max_chars: int = 65_536) -> Iterator[str]:
        yield from self.iter_text_chunks(max_chars=max_chars)

    def close(self) -> None:
        self._closed = True


class DiskTextArena:
    """One payload file and disk index for all large scalars in a spool."""

    def __init__(self) -> None:
        self._temporary = tempfile.TemporaryDirectory(prefix="redposture-text-arena-")
        self._path = Path(self._temporary.name) / "values.bin"
        self._path.touch()
        self._db = sqlite3.connect(
            Path(self._temporary.name) / "index.sqlite3", isolation_level=None, check_same_thread=False
        )
        self._db.execute("PRAGMA journal_mode=MEMORY")
        self._db.execute("PRAGMA synchronous=OFF")
        self._db.execute("PRAGMA cache_size=-1024")
        self._db.execute(
            "CREATE TABLE texts (digest TEXT NOT NULL, byte_length INTEGER NOT NULL, start INTEGER NOT NULL, "
            "placeholder INTEGER NOT NULL, uniform INTEGER NOT NULL, PRIMARY KEY (digest, byte_length)) WITHOUT ROWID"
        )
        self._size = 0

    def __del__(self) -> None:
        db = getattr(self, "_db", None)
        if db is not None:
            db.close()
        temporary = getattr(self, "_temporary", None)
        if temporary is not None:
            temporary.cleanup()

    def stage(self) -> _ArenaWrite:
        return _ArenaWrite(self)

    def _import_text(self, value: DiskBackedText) -> tuple[int, int, str, bool, bool]:
        value._readable()
        digest, length = value.digest, value.byte_length
        existing = self._db.execute(
            "SELECT start,placeholder,uniform FROM texts WHERE digest=? AND byte_length=?", (digest, length)
        ).fetchone()
        if existing is not None:
            return existing[0], length, digest, bool(existing[1]), bool(existing[2])
        start = self._size
        try:
            with self._path.open("r+b") as stream:
                stream.seek(start)
                for chunk in value.iter_text_chunks():
                    stream.write(chunk.encode("utf-8"))
                if stream.tell() - start != length:
                    raise OSError("discovery text arena received an incomplete scalar")
            placeholder, uniform = value.obvious_placeholder, value.uniform
            self._db.execute(
                "INSERT INTO texts(digest,byte_length,start,placeholder,uniform) VALUES (?,?,?,?,?)",
                (digest, length, start, int(placeholder), int(uniform)),
            )
        except BaseException:
            with self._path.open("r+b") as stream:
                stream.truncate(start)
            raise
        self._size = start + length
        return start, length, digest, placeholder, uniform

    def _rollback(self, start: int) -> None:
        if start == self._size:
            return
        self._db.execute("DELETE FROM texts WHERE start>=?", (start,))
        with self._path.open("r+b") as stream:
            stream.truncate(start)
        self._size = start

    def restore(self, locator: tuple[int, int, str, bool, bool], *, content_key: bool = False) -> ArenaDiskText:
        cls = ArenaDiskKeyText if content_key else ArenaDiskText
        return cls(self, locator)


class _ArenaWrite:
    """A record's staged arena tail; failed or duplicate records release it."""

    def __init__(self, arena: DiskTextArena) -> None:
        self.arena = arena
        self._start = arena._size
        self._finished = False

    def add(self, value: DiskBackedText) -> tuple[int, int, str, bool, bool]:
        return self.arena._import_text(value)

    def commit(self) -> DiskTextArena:
        self._finished = True
        return self.arena

    def rollback(self) -> None:
        if not self._finished:
            self.arena._rollback(self._start)
            self._finished = True

    def __del__(self) -> None:
        if not getattr(self, "_finished", True):
            try:
                self.rollback()
            except (OSError, sqlite3.Error):
                # No committed record refers to this tail. Cleanup of its
                # disposable arena still runs when the last reader releases it.
                pass


class ArenaDiskText(DiskBackedText):
    """An immutable UTF-8 range that independently owns its shared arena."""

    def __init__(self, arena: DiskTextArena, locator: tuple[int, int, str, bool, bool]) -> None:
        self._arena: DiskTextArena | None = arena
        self._start, self.byte_length, self._digest, self._placeholder, self._uniform = locator
        self._finished, self._closed = True, False
        self._materialized: DiskBackedText | None = None

    @property
    def digest(self) -> str:
        return self._digest

    @property
    def obvious_placeholder(self) -> bool:
        self._readable()
        return self._placeholder

    def iter_text_chunks(self, *, max_chars: int = 65_536) -> Iterator[str]:
        self._readable()
        if max_chars <= 0:
            raise ValueError("max_chars must be positive")
        arena = self._arena
        if arena is None:
            raise RuntimeError("disk value is closed")
        decoder = codecs.getincrementaldecoder("utf-8")("strict")
        with arena._path.open("rb") as stream:
            stream.seek(self._start)
            remaining = self.byte_length
            while remaining:
                portion = stream.read(min(65_536, remaining))
                if not portion:
                    raise OSError("discovery text arena scalar was truncated")
                remaining -= len(portion)
                text = decoder.decode(portion, final=remaining == 0)
                for offset in range(0, len(text), max_chars):
                    yield text[offset : offset + max_chars]

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
        if self._closed:
            return
        self._closed = True
        self._arena = None
        if self._materialized is not None:
            self._materialized.close()
            self._materialized = None


class ArenaDiskKeyText(ArenaDiskText):
    """Preserve content identity when a parser key moves into an arena."""

    def __hash__(self) -> int:
        return hash((self.byte_length, self.digest))

    def __eq__(self, other: object) -> bool:
        from .json_stream import DiskJSONKey

        if not isinstance(other, (ArenaDiskKeyText, DiskJSONKey)):
            return NotImplemented
        return self.byte_length == other.byte_length and self.digest == other.digest


def iter_json_chunks(value: object, *, max_chars: int = 65_536) -> Iterator[str]:
    """Encode nested JSON while retaining disk-backed scalars outside RAM."""
    if max_chars <= 0:
        raise ValueError("max_chars must be positive")
    if isinstance(value, DiskBackedText):
        yield from value.iter_json_chunks(max_chars=max_chars)
    elif isinstance(value, str):
        yield '"'
        for offset in range(0, len(value), max_chars):
            yield json.dumps(value[offset : offset + max_chars], ensure_ascii=False)[1:-1]
        yield '"'
    elif isinstance(value, Mapping):
        yield "{"
        for index, (key, item) in enumerate(value.items()):
            if index:
                yield ","
            yield from iter_json_chunks(key if isinstance(key, DiskBackedText) else str(key), max_chars=max_chars)
            yield ":"
            yield from iter_json_chunks(item, max_chars=max_chars)
        yield "}"
    elif isinstance(value, (list, tuple)):
        yield "["
        for index, item in enumerate(value):
            if index:
                yield ","
            yield from iter_json_chunks(item, max_chars=max_chars)
        yield "]"
    else:
        yield from json.JSONEncoder(ensure_ascii=False).iterencode(value)


def contains_disk_backed(value: object) -> bool:
    """Return whether a JSON-like payload contains a disk-backed scalar."""
    if isinstance(value, (DiskBackedText, DiskContainer)):
        return True
    if isinstance(value, Mapping):
        return any(contains_disk_backed(key) or contains_disk_backed(item) for key, item in value.items())
    if isinstance(value, (list, tuple)):
        return any(contains_disk_backed(item) for item in value)
    return False
