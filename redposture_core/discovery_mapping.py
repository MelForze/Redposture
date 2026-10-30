"""Bounded, reference-owned object and array catalogs for discovery JSON.

All nodes share one SQLite catalog and the spool codec's text arena.  A view
owns its store, rather than its parent or parser: retaining any child after the
document closes therefore keeps exactly the resources that child needs alive.
"""

from __future__ import annotations

import hashlib
import json
import operator
import sqlite3
import tempfile
import uuid
from collections.abc import Callable, ItemsView, Iterator, Mapping, ValuesView
from itertools import zip_longest
from pathlib import Path
from typing import Any

from .discovery_containers import DiskContainer, DiskMapping
from .discovery_spool import SpoolingValues, _DiskValueReferences
from .discovery_values import ArenaDiskKeyText, DiskBackedText, iter_json_chunks
from .json_stream import DiskJSONKey


def _text_chunks(value: str | DiskBackedText) -> Iterator[str]:
    if isinstance(value, DiskBackedText):
        yield from value.iter_text_chunks(max_chars=4096)
    else:
        for offset in range(0, len(value), 4096):
            yield value[offset : offset + 4096]


def _same_key(left: str | DiskBackedText, right: str | DiskBackedText, check: Callable[[], None] | None = None) -> bool:
    # Disk arena reads may split at a UTF-8 byte boundary. Compare a character
    # stream, without assuming matching chunk boundaries or materializing keys.
    if isinstance(left, str) and isinstance(right, str):
        return left == right

    def characters(value: str | DiskBackedText) -> Iterator[str]:
        for chunk in _text_chunks(value):
            if check is not None:
                check()
            yield from chunk

    left_chars = characters(left)
    right_chars = characters(right)
    missing = object()
    return all(a == b for a, b in zip_longest(left_chars, right_chars, fillvalue=missing))


class _CheckedText(DiskBackedText):
    """Give the shared arena codec a deadline-aware streaming source."""

    def __init__(self, value: DiskBackedText, check: Callable[[], None]) -> None:
        self._value, self._check = value, check
        self.byte_length = value.byte_length

    def _readable(self) -> None:
        self._value._readable()

    @property
    def digest(self) -> str:
        return self._value.digest

    @property
    def obvious_placeholder(self) -> bool:
        return self._value.obvious_placeholder

    @property
    def uniform(self) -> bool:
        return self._value.uniform

    def iter_text_chunks(self, *, max_chars: int = 65_536) -> Iterator[str]:
        for chunk in self._value.iter_text_chunks(max_chars=max_chars):
            self._check()
            yield chunk

    def close(self) -> None:
        pass


class _CheckedKey(_CheckedText, DiskJSONKey):
    pass


class DiskObjectStore(_DiskValueReferences):
    """Disposable shared tree storage; no per-node Python ownership index."""

    def __init__(self, *, check: Callable[[], None] | None = None) -> None:
        self.reference_id = uuid.uuid4().hex
        self._check_callback = check
        self._temporary = tempfile.TemporaryDirectory(prefix="redposture-objects-")
        self._db = sqlite3.connect(
            Path(self._temporary.name) / "objects.sqlite3", check_same_thread=False, isolation_level=None
        )
        self._db.execute("PRAGMA journal_mode=MEMORY")
        self._db.execute("PRAGMA synchronous=OFF")
        self._db.execute("PRAGMA cache_size=-1024")
        self._db.execute(
            "CREATE TABLE containers (id INTEGER PRIMARY KEY, kind TEXT NOT NULL, "
            "count INTEGER NOT NULL DEFAULT 0, bytes INTEGER NOT NULL DEFAULT 2)"
        )
        self._db.execute(
            "CREATE TABLE entries (parent INTEGER NOT NULL, ordinal INTEGER NOT NULL, "
            "digest TEXT, key_length INTEGER, key_payload TEXT, value_payload TEXT NOT NULL, "
            "key_bytes INTEGER NOT NULL, value_bytes INTEGER NOT NULL, PRIMARY KEY(parent,ordinal)) WITHOUT ROWID"
        )
        self._db.execute("CREATE INDEX entry_keys ON entries(parent,digest,key_length)")
        self._disk_refs = {}
        self._spool_refs = {}
        # Recovery adds at most one open child per parser depth. These local
        # IDs do not retain views/owners or require a successful disk write.
        self._partials: dict[int, tuple[Any, str, Any]] = {}

    def __del__(self) -> None:
        db = getattr(self, "_db", None)
        if db is not None:
            db.close()
        temporary = getattr(self, "_temporary", None)
        if temporary is not None:
            temporary.cleanup()

    def check(self) -> None:
        if self._check_callback is not None:
            self._check_callback()

    def detach(self) -> None:
        """Readers outlive the request deadline and its parser callbacks."""
        self._check_callback = None

    def _new(self, kind: str) -> Any:
        self.check()
        try:
            cursor = self._db.execute("INSERT INTO containers(kind) VALUES (?)", (kind,))
        except sqlite3.Error as exc:
            raise OSError(f"discovery object storage failure: {exc}") from exc
        return self.restore((kind, cursor.lastrowid))

    def mapping(self) -> DiskObjectMapping:
        return self._new("object")

    def sequence(self) -> DiskObjectValues:
        return self._new("array")

    def restore(self, locator: Any) -> Any:
        kind, identifier = locator
        return DiskObjectMapping(self, identifier) if kind == "object" else DiskObjectValues(self, identifier)

    def attach_partial(self, parent: Any, key: Any, child: Any) -> None:
        if isinstance(child, (DiskObjectMapping, DiskObjectValues)) and child.reference_owner is self:
            kind, identifier = child.reference_locator
            self._partials[parent._identifier] = (key, kind, identifier)
        else:
            # A validated scalar whose storage failed still belongs to the
            # completed prefix. This is only the interrupted scalar, not an
            # object-cardinality-sized cache; disk scalars keep their own file.
            self._partials[parent._identifier] = (key, "scalar", child)

    def _partial(self, identifier: int) -> tuple[Any, Any] | None:
        partial = self._partials.get(identifier)
        if partial is None:
            return None
        key, kind, child = partial
        return key, child if kind == "scalar" else self.restore((kind, child))

    def _encode(self, value: Any, pending: dict[str, Any]) -> str:
        if isinstance(value, (DiskObjectMapping, DiskObjectValues)) and value.reference_owner is self:
            encoded = ["local", value.reference_locator]
        else:
            if isinstance(value, DiskBackedText):
                cls = _CheckedKey if isinstance(value, (DiskJSONKey, ArenaDiskKeyText)) else _CheckedText
                value = cls(value, self.check)
            encoded = ["value", self._encode_disk_refs(value, pending)]
        return json.dumps(encoded, ensure_ascii=False)

    def _decode(self, payload: str) -> Any:
        kind, value = json.loads(payload)
        return self.restore(value) if kind == "local" else self._decode_disk_refs(value)

    def _key_identity(self, key: Any) -> tuple[str, int]:
        if isinstance(key, DiskBackedText):
            key._readable()
            return key.digest, key.byte_length
        if not isinstance(key, str):
            raise TypeError("discovery object keys must be text")
        digest = hashlib.sha256()
        length = 0
        for chunk in _text_chunks(key):
            self.check()
            encoded = chunk.encode("utf-8")
            digest.update(encoded)
            length += len(encoded)
        return digest.hexdigest(), length

    def _find(self, identifier: int, key: Any) -> Any:
        digest, length = self._key_identity(key)
        for row in self._db.execute(
            "SELECT ordinal,key_payload,value_payload,value_bytes FROM entries "
            "WHERE parent=? AND digest=? AND key_length=? ORDER BY ordinal",
            (identifier, digest, length),
        ):
            self.check()
            if _same_key(self._decode(row[1]), key, self.check):
                return row
        return None

    def _size(self, value: Any) -> int:
        if isinstance(value, DiskContainer):
            return value.byte_length
        size = 0
        for chunk in iter_json_chunks(value, max_chars=4096):
            self.check()
            size += len(chunk.encode("utf-8"))
        return size

    def import_value(self, value: Any, *, scalar: Callable[[Any], Any] | None = None) -> Any:
        """Import a native JSON tree one member at a time, never dumping it."""
        self.check()
        if isinstance(value, (DiskObjectMapping, DiskObjectValues)):
            if value.reference_owner is self:
                return value
            # Another document's views must be adopted memberwise. Keeping its
            # owner here would retain one SQLite connection per source row.
        elif isinstance(value, (DiskContainer, SpoolingValues, DiskBackedText)):
            return value
        if isinstance(value, Mapping):
            result = self.mapping()
            for key, item in value.items():
                self.check()
                result[key if isinstance(key, (str, DiskBackedText)) else str(key)] = self.import_value(
                    item, scalar=scalar
                )
            return result
        if isinstance(value, (list, tuple)):
            sequence = self.sequence()
            for item in value:
                sequence.append(self.import_value(item, scalar=scalar))
            return sequence
        if isinstance(value, str) and len(value) > 65536:
            text = DiskBackedText()
            try:
                for offset in range(0, len(value), 4096):
                    self.check()
                    text.append_text(value[offset : offset + 4096])
                text.finish()
                return text
            except BaseException:
                text.close()
                raise
        return scalar(value) if scalar is not None else value

    def put(self, identifier: int, key: Any, value: Any, *, array: bool = False) -> None:
        self.check()
        pending: dict[str, Any] = {}
        writing = False
        try:
            # Native callers may insert a nested tree directly. Parser-created
            # child views take the constant-sized local-reference path instead.
            value = self.import_value(value)
            old = None if array else self._find(identifier, key)
            value_size = self._size(value)
            value_payload = self._encode(value, pending)
            if old is not None:
                self._db.execute("SAVEPOINT object_entry")
                writing = True
                self._db.execute(
                    "UPDATE entries SET value_payload=?,value_bytes=? WHERE parent=? AND ordinal=?",
                    (value_payload, value_size, identifier, old[0]),
                )
                self._db.execute("UPDATE containers SET bytes=bytes+? WHERE id=?", (value_size - old[3], identifier))
            else:
                count = self._db.execute("SELECT count FROM containers WHERE id=?", (identifier,)).fetchone()[0]
                if array:
                    digest, length, key_payload, key_size = None, None, None, 0
                else:
                    digest, length = self._key_identity(key)
                    key_size = self._size(key)
                    # Keys use the same arena, including native keys which did
                    # not pass through JSONScalarStream's long-key writer.
                    stored_key = key
                    if isinstance(key, str) and length > 4096:
                        stored_key = DiskJSONKey()
                        for chunk in _text_chunks(key):
                            self.check()
                            stored_key.append_text(chunk)
                        stored_key.finish()
                    key_payload = self._encode(stored_key, pending)
                self.check()
                self._db.execute("SAVEPOINT object_entry")
                writing = True
                self._db.execute(
                    "INSERT INTO entries VALUES (?,?,?,?,?,?,?,?)",
                    (identifier, count, digest, length, key_payload, value_payload, key_size, value_size),
                )
                added = value_size + bool(count) + (key_size + 1 if not array else 0)
                self._db.execute("UPDATE containers SET count=count+1,bytes=bytes+? WHERE id=?", (added, identifier))
            self._db.execute("RELEASE object_entry")
            writing = False
        except sqlite3.Error as exc:
            if writing:
                self._rollback_entry()
            self._abort_refs(pending)
            raise OSError(f"discovery object storage failure: {exc}") from exc
        except BaseException:
            if writing:
                self._rollback_entry()
            self._abort_refs(pending)
            raise
        self._commit_refs(pending)

    def _rollback_entry(self) -> None:
        try:
            self._db.execute("ROLLBACK TO object_entry")
            self._db.execute("RELEASE object_entry")
        except sqlite3.Error:
            # SQLITE_FULL can already have rolled back the statement/transaction.
            pass


class _ObjectView:
    _kind: str

    def __init__(self, owner: DiskObjectStore, identifier: int) -> None:
        self._owner = owner
        self._identifier = identifier

    @property
    def reference_owner(self) -> DiskObjectStore:
        return self._owner

    @property
    def reference_locator(self) -> tuple[str, int]:
        return self._kind, self._identifier

    @property
    def byte_length(self) -> int:
        size = self._owner._db.execute("SELECT bytes FROM containers WHERE id=?", (self._identifier,)).fetchone()[0]
        partial = self._owner._partial(self._identifier)
        if partial is not None:
            key, child = partial
            if self._kind == "object":
                old = self._owner._find(self._identifier, key)
                child_size = self._owner._size(child)
                size += (
                    child_size - old[3]
                    if old is not None
                    else (self._owner._size(key) + 1 + child_size + bool(self._count()))
                )
            else:
                size += self._owner._size(child) + bool(self._count())
        return size

    def _count(self) -> int:
        return self._owner._db.execute("SELECT count FROM containers WHERE id=?", (self._identifier,)).fetchone()[0]

    def __len__(self) -> int:
        count = self._count()
        partial = self._owner._partial(self._identifier)
        if partial is not None and (self._kind == "array" or self._owner._find(self._identifier, partial[0]) is None):
            count += 1
        return count


class DiskObjectMapping(_ObjectView, DiskMapping):
    """Insertion-ordered Mapping with dictionary duplicate-key semantics."""

    _kind = "object"

    def __getitem__(self, key: Any) -> Any:
        if not isinstance(key, (str, DiskBackedText)):
            raise KeyError(key)
        partial = self._owner._partial(self._identifier)
        if partial is not None and _same_key(partial[0], key):
            return partial[1]
        row = self._owner._find(self._identifier, key)
        if row is None:
            raise KeyError(key)
        return self._owner._decode(row[2])

    def __setitem__(self, key: Any, value: Any) -> None:
        self._owner.put(self._identifier, key, value)

    def __iter__(self) -> Iterator[Any]:
        for key, _value in self.items():
            yield key

    def _iter_items(self) -> Iterator[tuple[Any, Any]]:
        partial = self._owner._partial(self._identifier)
        replaced = False
        for key, value in self._owner._db.execute(
            "SELECT key_payload,value_payload FROM entries WHERE parent=? ORDER BY ordinal", (self._identifier,)
        ):
            decoded_key = self._owner._decode(key)
            if partial is not None and _same_key(decoded_key, partial[0]):
                replaced = True
                yield decoded_key, partial[1]
            else:
                yield decoded_key, self._owner._decode(value)
        if partial is not None and not replaced:
            yield partial

    def items(self) -> ItemsView[Any, Any]:
        return _ObjectItems(self)

    def values(self) -> ValuesView[Any]:
        return ValuesView(self)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Mapping):
            return NotImplemented
        if len(self) != len(other):
            return False
        try:
            return all(self[key] == value for key, value in other.items())
        except (KeyError, TypeError):
            return False

    def __repr__(self) -> str:
        return f"DiskObjectMapping(count={len(self)})"


class _ObjectItems(ItemsView[Any, Any]):
    def __init__(self, value: DiskObjectMapping) -> None:
        super().__init__(value)
        self._view = value

    def __iter__(self) -> Iterator[tuple[Any, Any]]:
        return self._view._iter_items()


class DiskObjectValues(_ObjectView, SpoolingValues, DiskContainer):
    """SpoolingValues-compatible array view sharing the object tree store."""

    _kind = "array"

    def append(self, value: Any) -> None:
        self._owner.put(self._identifier, None, value, array=True)

    def finish(self) -> None:
        pass

    def __iter__(self) -> Iterator[Any]:
        for (payload,) in self._owner._db.execute(
            "SELECT value_payload FROM entries WHERE parent=? ORDER BY ordinal", (self._identifier,)
        ):
            yield self._owner._decode(payload)
        partial = self._owner._partial(self._identifier)
        if partial is not None:
            yield partial[1]

    def __getitem__(self, index: Any) -> Any:
        if isinstance(index, slice):
            return [self[position] for position in range(*index.indices(len(self)))]
        position = operator.index(index)
        if position < 0:
            position += len(self)
        if position < 0 or position >= len(self):
            raise IndexError(position)
        partial = self._owner._partial(self._identifier)
        if partial is not None and position == self._count():
            return partial[1]
        row = self._owner._db.execute(
            "SELECT value_payload FROM entries WHERE parent=? AND ordinal=?", (self._identifier, position)
        ).fetchone()
        return self._owner._decode(row[0])

    def __reversed__(self) -> Iterator[Any]:
        partial = self._owner._partial(self._identifier)
        if partial is not None:
            yield partial[1]
        for (payload,) in self._owner._db.execute(
            "SELECT value_payload FROM entries WHERE parent=? ORDER BY ordinal DESC", (self._identifier,)
        ):
            yield self._owner._decode(payload)

    def __repr__(self) -> str:
        return f"DiskObjectValues(count={len(self)})"
