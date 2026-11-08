"""Disk-backed list of full discovery findings.

The list interface preserves the existing result and JSON schema while its
elements and deduplication index live in a temporary SQLite database.
"""

from __future__ import annotations

import json
import operator
import sqlite3
import tempfile
from collections.abc import Generator, Iterable, Iterator, Mapping
from contextlib import closing
from itertools import islice, zip_longest
from pathlib import Path
from typing import Any, SupportsIndex, overload

from .discovery_containers import DiskContainer
from .discovery_paths import DiskBackedPath
from .discovery_values import (
    ArenaDiskKeyText,
    CredentialObject,
    DiskBackedText,
    DiskTextArena,
    EncodedSecretText,
    InlineDiskText,
    _ArenaWrite,
)

_DISK_VALUE_REF = "\x00redposture_disk_value"
_SPOOL_VALUE_REF = "\x00redposture_spool_value"
_CONTAINER_VALUE_REF = "\x00redposture_container_value"
_MAPPING_VALUE_REF = "\x00redposture_mapping_value"
_PATH_VALUE_REF = "\x00redposture_path_value"
_INLINE_VALUE_REF = "\x00redposture_inline_value"
_ARENA_VALUE_REF = "\x00redposture_arena_value"
_ENCODED_VALUE_REF = "\x00redposture_encoded_value"
_CREDENTIAL_OBJECT_REF = "\x00redposture_credential_object"
_ARENA_OWNER_KEY = "text-arena"
_OBJECT_OWNER_KEY = "object-store"
_REFERENCE_MARKERS = (
    _DISK_VALUE_REF,
    _SPOOL_VALUE_REF,
    _CONTAINER_VALUE_REF,
    _MAPPING_VALUE_REF,
    _PATH_VALUE_REF,
    _INLINE_VALUE_REF,
    _ARENA_VALUE_REF,
    _ENCODED_VALUE_REF,
    _CREDENTIAL_OBJECT_REF,
)
_INLINE_TEXT_MAX_BYTES = 1024
_PLAIN_SCALAR_TYPES = (str, int, float, bool, type(None))


def _plain_scalar_record(value: Mapping[str, Any]) -> bool:
    """Allow small flat records to skip recursive disk-reference encoding."""
    return type(value) is dict and all(
        type(key) is str and key not in _REFERENCE_MARKERS and type(item) in _PLAIN_SCALAR_TYPES
        for key, item in value.items()
    )


def _slice_values(values: Any, index: slice) -> list[Any]:
    start, stop, step = index.indices(len(values))
    if not range(start, stop, step):
        return []
    if step > 0:
        return list(islice(values, start, stop, step))
    return list(islice(reversed(values), len(values) - 1 - start, len(values) - 1 - stop, -step))


# Bound retained payload as well as finding count. A small number of large
# values must not bypass the disk spool; len(str) avoids allocating an encoded
# copy merely to decide whether to spill.
FINDING_SPOOL_MAX_CHARS = 262_144


class _DiskValueReferences:
    _disk_refs: dict[str, DiskBackedText]
    _spool_refs: dict[str, Any]

    def _load_record(self, payload: str) -> Any:
        value = json.loads(payload)
        # Our encoder always escapes NUL, including in ensure_ascii=False
        # payloads. Without this prefix there cannot be a reference marker at
        # any depth; ordinary JSON needs no recursive reference restoration.
        return self._decode_disk_refs(value) if "\\u0000redposture_" in payload else value

    def _encode_disk_refs(self, value: Any, pending: dict[str, Any]) -> Any:
        if isinstance(value, CredentialObject):
            return {_CREDENTIAL_OBJECT_REF: self._encode_disk_refs(value.source, pending)}
        if isinstance(value, EncodedSecretText):
            return {_ENCODED_VALUE_REF: [value.secret_digest, self._encode_disk_refs(value.source, pending)]}
        if isinstance(value, DiskBackedPath):
            return {
                _PATH_VALUE_REF: [
                    [self._encode_disk_refs(part, pending), skip_chars, skip_bytes]
                    for part, skip_chars, skip_bytes in value.spool_components()
                ]
            }
        if isinstance(value, DiskContainer):
            owner = value.reference_owner
            # Independent JSON documents cannot each keep an open catalog in
            # a long-lived result spool. Consolidate their subtrees on disk;
            # inside that shared owner children continue to use local IDs.
            from .discovery_mapping import DiskObjectStore

            if isinstance(owner, DiskObjectStore) and not isinstance(self, DiskObjectStore):
                destination = pending.get(_OBJECT_OWNER_KEY) or self._spool_refs.get(_OBJECT_OWNER_KEY)
                if destination is None:
                    destination = DiskObjectStore()
                adopted = destination.import_value(value)
                pending[_OBJECT_OWNER_KEY] = destination
                return {_CONTAINER_VALUE_REF: [_OBJECT_OWNER_KEY, adopted.reference_locator]}
            key = "container:" + owner.reference_id
            pending[key] = owner
            return {_CONTAINER_VALUE_REF: [key, value.reference_locator]}
        if isinstance(value, (SpoolingValues, SpoolingRecords, SpoolingStrings, SpoolingFindings)):
            key = "spool:" + str(id(value))
            pending[key] = value
            return {_SPOOL_VALUE_REF: key}
        if isinstance(value, DiskBackedText):
            value._readable()
            if value.byte_length <= _INLINE_TEXT_MAX_BYTES:
                return {_INLINE_VALUE_REF: "".join(value.iter_text_chunks())}
            stage = pending.get(_ARENA_OWNER_KEY)
            if stage is None:
                arena = self._spool_refs.get(_ARENA_OWNER_KEY)
                stage = (arena if arena is not None else DiskTextArena()).stage()
                pending[_ARENA_OWNER_KEY] = stage
            from .json_stream import DiskJSONKey

            return {
                _ARENA_VALUE_REF: [
                    _ARENA_OWNER_KEY,
                    stage.add(value),
                    isinstance(value, (DiskJSONKey, ArenaDiskKeyText)),
                ]
            }
        if isinstance(value, Mapping):
            if any(marker in value for marker in _REFERENCE_MARKERS) or any(
                isinstance(key, DiskBackedText) for key in value
            ):
                return {
                    _MAPPING_VALUE_REF: [
                        [self._encode_disk_refs(key, pending), self._encode_disk_refs(item, pending)]
                        for key, item in value.items()
                    ]
                }
            return {key: self._encode_disk_refs(item, pending) for key, item in value.items()}
        if isinstance(value, (list, tuple)):
            return [self._encode_disk_refs(item, pending) for item in value]
        return value

    def _decode_disk_refs(self, value: Any) -> Any:
        if type(value) in _PLAIN_SCALAR_TYPES or _plain_scalar_record(value):
            return value
        if isinstance(value, dict):
            if len(value) == 1 and _CREDENTIAL_OBJECT_REF in value:
                return CredentialObject(self._decode_disk_refs(value[_CREDENTIAL_OBJECT_REF]))
            if len(value) == 1 and _ENCODED_VALUE_REF in value:
                digest, source = value[_ENCODED_VALUE_REF]
                return EncodedSecretText(self._decode_disk_refs(source), digest)
            if len(value) == 1 and _MAPPING_VALUE_REF in value:
                return {
                    self._decode_disk_refs(key): self._decode_disk_refs(item) for key, item in value[_MAPPING_VALUE_REF]
                }
            if len(value) == 1 and _PATH_VALUE_REF in value:
                return DiskBackedPath.from_spool_components(
                    (self._decode_disk_refs(part), skip_chars, skip_bytes)
                    for part, skip_chars, skip_bytes in value[_PATH_VALUE_REF]
                )
            if len(value) == 1 and _INLINE_VALUE_REF in value:
                return InlineDiskText(value[_INLINE_VALUE_REF])
            if len(value) == 1 and _ARENA_VALUE_REF in value:
                key, locator, content_key = value[_ARENA_VALUE_REF]
                return self._spool_refs[key].restore(locator, content_key=content_key)
            if len(value) == 1 and _CONTAINER_VALUE_REF in value:
                key, locator = value[_CONTAINER_VALUE_REF]
                owner = self._spool_refs.get(key)
                if owner is not None:
                    return owner.restore(locator)
            if len(value) == 1 and _SPOOL_VALUE_REF in value:
                referenced_spool = self._spool_refs.get(value[_SPOOL_VALUE_REF])
                if referenced_spool is not None:
                    return referenced_spool
            if len(value) == 1 and _DISK_VALUE_REF in value:
                referenced = self._disk_refs.get(value[_DISK_VALUE_REF])
                if referenced is not None:
                    return referenced
            return {key: self._decode_disk_refs(item) for key, item in value.items()}
        if isinstance(value, list):
            return [self._decode_disk_refs(item) for item in value]
        return value

    def _commit_refs(self, pending: dict[str, Any]) -> None:
        for key, value in pending.items():
            if isinstance(value, _ArenaWrite):
                self._spool_refs[key] = value.commit()
            elif isinstance(value, DiskBackedText):
                self._disk_refs[key] = value
            else:
                self._spool_refs[key] = value

    def _abort_refs(self, pending: dict[str, Any]) -> None:
        for value in pending.values():
            if isinstance(value, _ArenaWrite):
                value.rollback()


class SpoolingFindings(_DiskValueReferences, list[dict[str, Any]]):
    """Read-only list view after construction, backed by a temporary database."""

    def __init__(self) -> None:
        super().__init__()
        self._temporary = tempfile.TemporaryDirectory(prefix="redposture-findings-")
        self._path = Path(self._temporary.name) / "findings.sqlite3"
        # Discovery is collected in a worker and rendered by the result thread.
        # Ownership has moved by then, so the connection must allow finish().
        self._db: sqlite3.Connection | None = sqlite3.connect(self._path, check_same_thread=False, isolation_level=None)
        self._db.execute("PRAGMA journal_mode=MEMORY")
        self._db.execute("PRAGMA synchronous=OFF")
        self._db.execute(
            "CREATE TABLE findings (ordinal INTEGER PRIMARY KEY, detector TEXT NOT NULL, "
            "fingerprint TEXT NOT NULL, payload TEXT NOT NULL, emitted INTEGER NOT NULL, "
            "UNIQUE(detector, fingerprint))"
        )
        self._count = 0
        self._disk_refs = {}
        self._spool_refs = {}

    def __del__(self) -> None:
        db = getattr(self, "_db", None)
        if db is not None:
            db.close()
        temporary = getattr(self, "_temporary", None)
        if temporary is not None:
            temporary.cleanup()

    def add(
        self,
        finding: Mapping[str, Any],
        *,
        emitted: bool = False,
        merge_emission: bool = False,
        identity: tuple[str, str] | None = None,
    ) -> bool:
        db = self._db
        if db is None:
            raise RuntimeError("finding spool is finalized")
        detector, fingerprint = (
            identity
            if identity is not None
            else (str(finding.get("type") or ""), str(finding.get("fingerprint") or ""))
        )
        pending: dict[str, Any] = {}
        try:
            record = dict(finding)
            encoded = record if _plain_scalar_record(record) else self._encode_disk_refs(record, pending)
            serialized = json.dumps(encoded, ensure_ascii=False)
            cursor = db.execute(
                "INSERT OR IGNORE INTO findings(detector, fingerprint, payload, emitted) VALUES (?, ?, ?, ?)",
                (detector, fingerprint, serialized, int(emitted)),
            )
        except sqlite3.Error as exc:
            self._abort_refs(pending)
            raise OSError(f"discovery finding storage failure: {exc}") from exc
        except BaseException:
            self._abort_refs(pending)
            raise
        if cursor.rowcount:
            self._count += 1
            self._commit_refs(pending)
            return True
        self._abort_refs(pending)
        if emitted and merge_emission:
            db.execute(
                "UPDATE findings SET emitted=1 WHERE detector=? AND fingerprint=?",
                (detector, fingerprint),
            )
        return False

    def finish(self) -> None:
        if self._db is not None:
            self._db.commit()
            self._db.close()
            self._db = None

    def redact_keys(self, *keys: str) -> None:
        """Remove raw-only fields in bounded batches before structured output."""
        self.finish()
        last_ordinal = 0
        with closing(sqlite3.connect(self._path)) as db:
            while rows := db.execute(
                "SELECT ordinal, payload FROM findings WHERE ordinal > ? ORDER BY ordinal LIMIT 256",
                (last_ordinal,),
            ).fetchall():
                changes = []
                for ordinal, payload in rows:
                    finding = json.loads(payload)
                    for key in keys:
                        finding.pop(key, None)
                    changes.append((json.dumps(finding, ensure_ascii=False), ordinal))
                db.executemany("UPDATE findings SET payload=? WHERE ordinal=?", changes)
                last_ordinal = rows[-1][0]
            db.commit()

    def mark_emitted(self, detector: str, fingerprint: str) -> None:
        db = self._db
        if db is None:
            raise RuntimeError("finding spool is finalized")
        db.execute(
            "UPDATE findings SET emitted=1 WHERE detector=? AND fingerprint=?",
            (detector, fingerprint),
        )

    def _rows(self, *, only_unemitted: bool = False, reverse: bool = False) -> Iterator[dict[str, Any]]:
        self.finish()
        with closing(sqlite3.connect(self._path)) as db:
            query = "SELECT payload FROM findings"
            if only_unemitted:
                query += " WHERE emitted=0"
            query += " ORDER BY ordinal DESC" if reverse else " ORDER BY ordinal"
            for (payload,) in db.execute(query):
                value = self._load_record(payload)
                if isinstance(value, dict):
                    yield value

    def iter_unemitted(self) -> Iterator[dict[str, Any]]:
        return self._rows(only_unemitted=True)

    def iter_with_emission(self) -> Iterator[tuple[dict[str, Any], bool]]:
        self.finish()
        with closing(sqlite3.connect(self._path)) as db:
            for payload, emitted in db.execute("SELECT payload, emitted FROM findings ORDER BY ordinal"):
                value = self._load_record(payload)
                if isinstance(value, dict):
                    yield value, bool(emitted)

    def emitted_fingerprints(self) -> SpoolingFingerprints:
        return SpoolingFingerprints(self)

    def __iter__(self) -> Iterator[dict[str, Any]]:
        return self._rows()

    def __reversed__(self) -> Iterator[dict[str, Any]]:
        return self._rows(reverse=True)

    def __len__(self) -> int:
        return self._count

    def __repr__(self) -> str:
        return f"SpoolingFindings(count={self._count})"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, (list, tuple)):
            return NotImplemented
        missing = object()
        return all(left == right for left, right in zip_longest(self, other, fillvalue=missing))

    def __ne__(self, other: object) -> bool:
        result = self.__eq__(other)
        return NotImplemented if result is NotImplemented else not result

    def __contains__(self, value: object) -> bool:
        return any(item == value for item in self)

    def copy(self) -> list[dict[str, Any]]:
        return list(self)

    @overload
    def __getitem__(self, index: SupportsIndex, /) -> dict[str, Any]: ...

    @overload
    def __getitem__(self, index: slice, /) -> list[dict[str, Any]]: ...

    def __getitem__(self, index: SupportsIndex | slice, /) -> dict[str, Any] | list[dict[str, Any]]:
        if isinstance(index, slice):
            return _slice_values(self, index)
        index = operator.index(index)
        if index < 0:
            index += self._count
        if index < 0 or index >= self._count:
            raise IndexError(index)
        self.finish()
        with closing(sqlite3.connect(self._path)) as db:
            row = db.execute("SELECT payload FROM findings ORDER BY ordinal LIMIT 1 OFFSET ?", (index,)).fetchone()
        if row is None:
            raise IndexError(index)
        return self._load_record(row[0])


class SpoolingFingerprints(list[str]):
    """List-compatible view of emitted fingerprint IDs in the same spool."""

    def __init__(self, findings: SpoolingFindings) -> None:
        super().__init__()
        self._findings = findings

    def __iter__(self) -> Iterator[str]:
        self._findings.finish()
        with closing(sqlite3.connect(self._findings._path)) as db:
            for (fingerprint,) in db.execute("SELECT fingerprint FROM findings WHERE emitted=1 ORDER BY fingerprint"):
                yield fingerprint

    def __len__(self) -> int:
        self._findings.finish()
        with closing(sqlite3.connect(self._findings._path)) as db:
            row = db.execute("SELECT COUNT(*) FROM findings WHERE emitted=1").fetchone()
        return int(row[0]) if row is not None else 0

    def __reversed__(self) -> Iterator[str]:
        self._findings.finish()
        with closing(sqlite3.connect(self._findings._path)) as db:
            for (fingerprint,) in db.execute(
                "SELECT fingerprint FROM findings WHERE emitted=1 ORDER BY fingerprint DESC"
            ):
                yield fingerprint

    def __repr__(self) -> str:
        return f"SpoolingFingerprints(count={len(self)})"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, (list, tuple)):
            return NotImplemented
        missing = object()
        return all(left == right for left, right in zip_longest(self, other, fillvalue=missing))

    def __ne__(self, other: object) -> bool:
        result = self.__eq__(other)
        return NotImplemented if result is NotImplemented else not result

    def __contains__(self, value: object) -> bool:
        return any(item == value for item in self)

    def copy(self) -> list[str]:
        return list(self)

    @overload
    def __getitem__(self, index: SupportsIndex, /) -> str: ...

    @overload
    def __getitem__(self, index: slice, /) -> list[str]: ...

    def __getitem__(self, index: SupportsIndex | slice, /) -> str | list[str]:
        if isinstance(index, slice):
            return _slice_values(self, index)
        position = operator.index(index)
        if position < 0:
            position += len(self)
        if position < 0 or position >= len(self):
            raise IndexError(position)
        self._findings.finish()
        with closing(sqlite3.connect(self._findings._path)) as db:
            row = db.execute(
                "SELECT fingerprint FROM findings WHERE emitted=1 ORDER BY fingerprint LIMIT 1 OFFSET ?",
                (position,),
            ).fetchone()
        if row is None:
            raise IndexError(position)
        return str(row[0])


class SpoolingStrings(list[str]):
    """List-compatible disk-backed sequence for large discovery name catalogs."""

    def __init__(self, values: Iterable[str] = ()) -> None:
        super().__init__()
        self._temporary = tempfile.TemporaryDirectory(prefix="redposture-names-")
        self._path = Path(self._temporary.name) / "names.sqlite3"
        self._db: sqlite3.Connection | None = sqlite3.connect(self._path, check_same_thread=False, isolation_level=None)
        self._db.execute("PRAGMA journal_mode=MEMORY")
        self._db.execute("PRAGMA synchronous=OFF")
        self._db.execute("CREATE TABLE names (ordinal INTEGER PRIMARY KEY, value TEXT NOT NULL)")
        self._count = 0
        self.extend(values)

    def __del__(self) -> None:
        db = getattr(self, "_db", None)
        if db is not None:
            db.close()
        temporary = getattr(self, "_temporary", None)
        if temporary is not None:
            temporary.cleanup()

    def append(self, value: str) -> None:
        db = self._db
        if db is None:
            raise RuntimeError("name spool is finalized")
        try:
            db.execute("INSERT INTO names(value) VALUES (?)", (value,))
        except sqlite3.Error as exc:
            raise OSError(f"discovery name storage failure: {exc}") from exc
        self._count += 1

    def extend(self, values: Iterable[str]) -> None:
        for value in values:
            self.append(value)

    def finish(self) -> None:
        if self._db is not None:
            self._db.commit()
            self._db.close()
            self._db = None

    def __iter__(self) -> Iterator[str]:
        self.finish()
        with closing(sqlite3.connect(self._path)) as db:
            for (value,) in db.execute("SELECT value FROM names ORDER BY ordinal"):
                yield str(value)

    def __len__(self) -> int:
        return self._count

    def __reversed__(self) -> Iterator[str]:
        self.finish()
        with closing(sqlite3.connect(self._path)) as db:
            for (value,) in db.execute("SELECT value FROM names ORDER BY ordinal DESC"):
                yield str(value)

    def __repr__(self) -> str:
        return f"SpoolingStrings(count={self._count})"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, (list, tuple)):
            return NotImplemented
        missing = object()
        return all(left == right for left, right in zip_longest(self, other, fillvalue=missing))

    def __ne__(self, other: object) -> bool:
        result = self.__eq__(other)
        return NotImplemented if result is NotImplemented else not result

    def __contains__(self, value: object) -> bool:
        return any(item == value for item in self)

    def copy(self) -> list[str]:
        return list(self)

    @overload
    def __getitem__(self, index: SupportsIndex, /) -> str: ...

    @overload
    def __getitem__(self, index: slice, /) -> list[str]: ...

    def __getitem__(self, index: SupportsIndex | slice, /) -> str | list[str]:
        if isinstance(index, slice):
            return _slice_values(self, index)
        position = operator.index(index)
        if position < 0:
            position += self._count
        if position < 0 or position >= self._count:
            raise IndexError(position)
        self.finish()
        with closing(sqlite3.connect(self._path)) as db:
            row = db.execute("SELECT value FROM names ORDER BY ordinal LIMIT 1 OFFSET ?", (position,)).fetchone()
        if row is None:
            raise IndexError(position)
        return str(row[0])


JSONRecord = Mapping[str, Any]


class SpoolingRecords(_DiskValueReferences, list[Any]):
    """Ordered, disk-backed list of discovery source records."""

    def __init__(self) -> None:
        super().__init__()
        self._temporary = tempfile.TemporaryDirectory(prefix="redposture-records-")
        self._path = Path(self._temporary.name) / "records.sqlite3"
        # This store is disposable, not a durable checkpoint. Autocommit
        # prevents SQLITE_FULL rolling back earlier accepted records; MEMORY
        # journaling retains statement rollback without per-row fsync/files.
        self._db: sqlite3.Connection | None = sqlite3.connect(self._path, check_same_thread=False, isolation_level=None)
        self._db.execute("PRAGMA journal_mode=MEMORY")
        self._db.execute("PRAGMA synchronous=OFF")
        self._db.execute(
            "CREATE TABLE records (ordinal INTEGER PRIMARY KEY, sort_key TEXT NOT NULL, payload TEXT NOT NULL)"
        )
        self._count = 0
        self._disk_refs = {}
        self._spool_refs = {}

    @classmethod
    def _from_encoded_records(cls, payloads: Iterable[str], source: _DiskValueReferences) -> SpoolingRecords:
        """Snapshot already encoded records, retaining their reference owners.

        Only internal stores using the same disk-reference codec can supply
        these payloads. Copying their JSON bytes avoids reconstructing every
        nested finding merely to move it between two disposable databases.
        """
        records = cls()
        if _OBJECT_OWNER_KEY in source._spool_refs:
            # Mutable imported object trees need the ordinary codec's deep
            # adoption into a separate owner. Text arenas and nested source
            # spools retain the same ownership semantics on the fast path.
            for payload in payloads:
                records.append(source._decode_disk_refs(json.loads(payload)))
            return records
        db = records._db
        assert db is not None
        try:
            db.executemany("INSERT INTO records(sort_key,payload) VALUES ('',?)", ((payload,) for payload in payloads))
        except sqlite3.Error as exc:
            raise OSError(f"discovery record storage failure: {exc}") from exc
        records._count = db.total_changes
        records._disk_refs.update(source._disk_refs)
        records._spool_refs.update(source._spool_refs)
        return records

    def __del__(self) -> None:
        db = getattr(self, "_db", None)
        if db is not None:
            db.close()
        temporary = getattr(self, "_temporary", None)
        if temporary is not None:
            temporary.cleanup()

    def append(self, value: JSONRecord, *, sort_key: str = "") -> None:
        db = self._db
        if db is None:
            raise RuntimeError("record spool is finalized")
        pending: dict[str, Any] = {}
        try:
            encoded = value if _plain_scalar_record(value) else self._encode_disk_refs(value, pending)
            payload = json.dumps(encoded, ensure_ascii=False)
            db.execute("INSERT INTO records(sort_key, payload) VALUES (?, ?)", (sort_key, payload))
        except sqlite3.Error as exc:
            self._abort_refs(pending)
            raise OSError(f"discovery record storage failure: {exc}") from exc
        except BaseException:
            self._abort_refs(pending)
            raise
        self._commit_refs(pending)
        self._count += 1

    def finish(self) -> None:
        if self._db is not None:
            self._db.commit()
            self._db.close()
            self._db = None

    def iter_appended(self, after: int, *, reverse: bool = False) -> Generator[JSONRecord, None, None]:
        """Read a current append-order window without closing the producer."""
        direction = "DESC" if reverse else "ASC"
        query = f"SELECT payload FROM records WHERE ordinal>? ORDER BY ordinal {direction}"
        db = self._db
        if db is not None:
            for (payload,) in db.execute(query, (after,)):
                yield self._load_record(payload)
        else:
            with closing(sqlite3.connect(self._path)) as reader:
                for (payload,) in reader.execute(query, (after,)):
                    yield self._load_record(payload)

    def __iter__(self) -> Iterator[JSONRecord]:
        self.finish()
        with closing(sqlite3.connect(self._path)) as db:
            for (payload,) in db.execute("SELECT payload FROM records ORDER BY sort_key, ordinal"):
                value = self._load_record(payload)
                if isinstance(value, Mapping):
                    yield value

    def __len__(self) -> int:
        return self._count

    def iter_reversed(self) -> Iterator[JSONRecord]:
        self.finish()
        with closing(sqlite3.connect(self._path)) as db:
            for (payload,) in db.execute("SELECT payload FROM records ORDER BY sort_key DESC, ordinal DESC"):
                yield self._load_record(payload)

    def __reversed__(self) -> Iterator[JSONRecord]:
        return self.iter_reversed()

    def __repr__(self) -> str:
        return f"SpoolingRecords(count={self._count})"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, (list, tuple)):
            return NotImplemented
        missing = object()
        return all(left == right for left, right in zip_longest(self, other, fillvalue=missing))

    def __ne__(self, other: object) -> bool:
        result = self.__eq__(other)
        return NotImplemented if result is NotImplemented else not result

    @overload
    def __getitem__(self, index: SupportsIndex, /) -> JSONRecord: ...

    @overload
    def __getitem__(self, index: slice, /) -> list[JSONRecord]: ...

    def __getitem__(self, index: SupportsIndex | slice, /) -> JSONRecord | list[JSONRecord]:
        if isinstance(index, slice):
            return _slice_values(self, index)
        position = operator.index(index)
        if position < 0:
            position += self._count
        if position < 0 or position >= self._count:
            raise IndexError(position)
        query = "SELECT payload FROM records ORDER BY sort_key, ordinal LIMIT 1 OFFSET ?"
        if self._db is not None:
            row = self._db.execute(query, (position,)).fetchone()
        else:
            with closing(sqlite3.connect(self._path)) as db:
                row = db.execute(query, (position,)).fetchone()
        if row is None:
            raise IndexError(position)
        value = self._load_record(row[0])
        if not isinstance(value, Mapping):
            raise ValueError("record spool contains a non-object")
        return value


class SpoolingValues(list[Any]):
    """List-shaped scalar/row values, sharing the source-record disk store."""

    def __init__(self) -> None:
        super().__init__()
        self._records = SpoolingRecords()

    def append(self, value: Any) -> None:
        self._records.append({"value": value})

    def extend(self, values: Iterable[Any]) -> None:
        for value in values:
            self.append(value)

    def finish(self) -> None:
        self._records.finish()

    def __iter__(self) -> Iterator[Any]:
        for record in self._records:
            yield record["value"]

    def __len__(self) -> int:
        return len(self._records)

    def __repr__(self) -> str:
        return f"SpoolingValues(count={len(self)})"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, (list, tuple)):
            return NotImplemented
        missing = object()
        return all(left == right for left, right in zip_longest(self, other, fillvalue=missing))

    def __ne__(self, other: object) -> bool:
        result = self.__eq__(other)
        return NotImplemented if result is NotImplemented else not result

    def __getitem__(self, index: Any) -> Any:
        if isinstance(index, slice):
            return [record["value"] for record in self._records[index]]
        return self._records[index]["value"]


def contains_spooled(value: Any) -> bool:
    """Detect lazy containers without traversing or finalizing their contents."""
    if isinstance(value, (SpoolingFindings, SpoolingRecords, SpoolingStrings, SpoolingValues, DiskContainer)):
        return True
    if isinstance(value, Mapping):
        return any(contains_spooled(item) for item in value.values())
    if isinstance(value, (list, tuple)):
        return any(contains_spooled(item) for item in value)
    return False
