"""Disposable, live disk-backed containers for catalog and checkpoint metadata."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import tempfile
from collections.abc import Mapping
from functools import lru_cache
from itertools import zip_longest
from pathlib import Path
from typing import Any

from ....discovery_containers import DiskMapping, DiskSequence
from ....discovery_json import DiskJSONDocument
from ....discovery_spool import _DiskValueReferences
from ....discovery_values import DiskBackedText

_SCALAR_TYPES = (str, int, float, bool, type(None))


@lru_cache(maxsize=512, typed=True)
def _cached_scalar_json(value):
    return json.dumps(value, ensure_ascii=False)


def _scalar_json(value):
    # Cache immutable, small metadata only: never retain a large value or an
    # owned disk view, nor conflate False/0/0.0 in the serializer's cache.
    if (
        (type(value) is str and len(value) <= 256)
        or value is None
        or type(value) is bool
        or (type(value) is int and value.bit_length() <= 128)
    ):
        return _cached_scalar_json(value)
    return json.dumps(value, ensure_ascii=False)


@lru_cache(maxsize=512)
def _cached_scalar_value(payload):
    return json.loads(payload)


@lru_cache(maxsize=512)
def _cached_key_identity(text):
    encoded = text.encode("utf-8")
    return f"{len(encoded)}:{hashlib.sha256(encoded).hexdigest()}"


class CatalogTree(_DiskValueReferences):
    def __init__(self):
        self._temporary = tempfile.TemporaryDirectory(prefix="redposture-clickhouse-catalog-")
        self._db = sqlite3.connect(
            Path(self._temporary.name) / "catalog.sqlite3", isolation_level=None, check_same_thread=False
        )
        self._db.execute("PRAGMA journal_mode=MEMORY")
        self._db.execute("PRAGMA synchronous=OFF")
        self._db.execute("PRAGMA cache_size=-1024")
        self._db.execute("CREATE TABLE nodes(id INTEGER PRIMARY KEY, kind TEXT, length INTEGER DEFAULT 0)")
        self._db.execute(
            "CREATE TABLE entries(parent INTEGER, key TEXT, ordinal INTEGER, kind TEXT, payload TEXT, key_payload TEXT, "
            "PRIMARY KEY(parent,key))"
        )
        self._db.execute("CREATE INDEX entries_order ON entries(parent,ordinal)")
        self._disk_refs = {}
        self._spool_refs = {}
        self._foreign = {}
        self.reference_id = f"clickhouse-catalog:{id(self)}"

    def __del__(self):
        db = getattr(self, "_db", None)
        if db is not None:
            db.close()
        temporary = getattr(self, "_temporary", None)
        if temporary is not None:
            temporary.cleanup()

    def mapping(self, values=None):
        node = self._db.execute("INSERT INTO nodes(kind) VALUES ('map')").lastrowid
        result = CatalogMapping(self, node)
        if (
            type(values) is dict
            and values
            and all(
                isinstance(key, str)
                and len(key) <= 4096
                and (
                    value is None
                    or type(value) in (bool, int, float)
                    or isinstance(value, str)
                    and len(value) <= 65_536
                )
                for key, value in values.items()
            )
        ):
            # Inventory/coverage records start empty and have unique string
            # keys. Batch their scalar fields: per-field put() would repeat
            # indexed lookups, ordinal allocation and a transaction for every
            # field of every table. Large/referenced/nested values still use
            # the arena-aware path below.
            self._db.execute("SAVEPOINT catalog_mapping")
            try:
                self._db.executemany(
                    "INSERT INTO entries VALUES (?,?,?,?,?,?)",
                    (
                        (
                            node,
                            self.key_identity(key),
                            ordinal,
                            "scalar",
                            _scalar_json(value),
                            _scalar_json(key),
                        )
                        for ordinal, (key, value) in enumerate(values.items())
                    ),
                )
                self._db.execute("UPDATE nodes SET length=? WHERE id=?", (len(values), node))
                self._db.execute("RELEASE catalog_mapping")
            except BaseException as exc:
                self._db.execute("ROLLBACK TO catalog_mapping")
                self._db.execute("RELEASE catalog_mapping")
                if isinstance(exc, sqlite3.Error):
                    raise OSError(f"ClickHouse catalog storage failure: {exc}") from exc
                raise
        elif values is not None:
            result.update(values)
        return result

    def sequence(self, values=()):
        node = self._db.execute("INSERT INTO nodes(kind) VALUES ('list')").lastrowid
        result = CatalogSequence(self, node)
        result.extend(values)
        return result

    def restore(self, locator):
        kind, node = locator
        return CatalogMapping(self, node) if kind == "map" else CatalogSequence(self, node)

    def _encode(self, value, pending: dict[str, Any]):
        if type(value) in _SCALAR_TYPES and (type(value) is not str or len(value) <= 65_536):
            return "scalar", _scalar_json(value)
        if isinstance(value, (CatalogMapping, CatalogSequence)) and value._owner is self:
            return value._kind, str(value._node)
        if isinstance(value, (CatalogMapping, CatalogSequence)):
            key = str(id(value._owner))
            self._foreign[key] = value._owner
            return "foreign_node", json.dumps([key, value._kind, value._node])
        # Keep external owned views as one live reference rather than repeatedly
        # snapshotting findings or catalog lists on every checkpoint update.
        if isinstance(value, (DiskMapping, DiskSequence)) or (
            isinstance(value, Mapping) and not isinstance(value, dict)
        ):
            key = str(id(value))
            self._foreign[key] = value
            return "foreign", key
        if isinstance(value, Mapping):
            nested = self.mapping(value)
            return "map", str(nested._node)
        if isinstance(value, (list, tuple)):
            nested = self.sequence(value)
            return "list", str(nested._node)
        if isinstance(value, str) and len(value) > 65_536:
            # Adopt long caller-owned strings into the same shared text arena
            # as imported JSON scalars, without retaining a private str copy.
            with DiskBackedText() as source:
                for offset in range(0, len(value), 65_536):
                    source.append_text(value[offset : offset + 65_536])
                source.finish()
                encoded = self._encode_disk_refs(source, pending)
        else:
            encoded = self._encode_disk_refs(value, pending)
        return "scalar", json.dumps(encoded, ensure_ascii=False)

    def _decode(self, kind, payload):
        if kind in {"map", "list"}:
            return self.restore((kind, int(payload)))
        if kind == "foreign_node":
            key, node_kind, node = json.loads(payload)
            return self._foreign[key].restore((node_kind, node))
        if kind == "foreign":
            return self._foreign[payload]
        return self._decode_scalar(payload)

    def _decode_scalar(self, payload):
        if len(payload) <= 256 and payload[:1] in (
            '"',
            "-",
            "0",
            "1",
            "2",
            "3",
            "4",
            "5",
            "6",
            "7",
            "8",
            "9",
            "t",
            "f",
            "n",
            "I",
            "N",
        ):
            return _cached_scalar_value(payload)
        return self._decode_disk_refs(json.loads(payload))

    @staticmethod
    def key_identity(key):
        if isinstance(key, DiskBackedText):
            return f"{key.byte_length}:{key.digest}"
        text = key if isinstance(key, str) else str(key)
        if type(text) is str and len(text) <= 256:
            return _cached_key_identity(text)
        digest = hashlib.sha256()
        length = 0
        for offset in range(0, len(text), 65_536):
            portion = text[offset : offset + 65_536].encode("utf-8")
            digest.update(portion)
            length += len(portion)
        return f"{length}:{digest.hexdigest()}"

    def _encode_key(self, key, pending):
        if isinstance(key, DiskBackedText):
            encoded = (
                self._encode_disk_refs(key, pending) if key.byte_length > 4096 else "".join(key.iter_text_chunks())
            )
        else:
            text = key if isinstance(key, str) else str(key)
            if len(text) > 4096:
                from ....json_stream import DiskJSONKey

                with DiskJSONKey() as source:
                    for offset in range(0, len(text), 65_536):
                        source.append_text(text[offset : offset + 65_536])
                    source.finish()
                    encoded = self._encode_disk_refs(source, pending)
            else:
                encoded = text
        return _scalar_json(encoded)

    def decode_key(self, payload):
        return self._decode_scalar(payload)

    def put(self, parent, key, value):
        pending: dict[str, Any] = {}
        active_savepoint = False
        try:
            # Nested values commit their own records first. Only then stage
            # this record's key alongside its scalar value in the same arena.
            kind, payload = self._encode(value, pending)
            identity = self.key_identity(key)
            key_payload = self._encode_key(key, pending)
            row = self._db.execute(
                "SELECT ordinal FROM entries WHERE parent=? AND key=?", (parent, identity)
            ).fetchone()
            ordinal = (
                row[0]
                if row
                else self._db.execute(
                    "SELECT COALESCE(MAX(ordinal), -1) + 1 FROM entries WHERE parent=?", (parent,)
                ).fetchone()[0]
            )
            self._db.execute("SAVEPOINT catalog_entry")
            active_savepoint = True
            self._db.execute(
                "INSERT INTO entries VALUES (?,?,?,?,?,?) ON CONFLICT(parent,key) DO UPDATE SET "
                "kind=excluded.kind,payload=excluded.payload,key_payload=excluded.key_payload",
                (parent, identity, ordinal, kind, payload, key_payload),
            )
            if row is None:
                self._db.execute("UPDATE nodes SET length=length+1 WHERE id=?", (parent,))
            self._db.execute("RELEASE catalog_entry")
            active_savepoint = False
            self._commit_refs(pending)
        except BaseException as exc:
            if active_savepoint:
                self._db.execute("ROLLBACK TO catalog_entry")
                self._db.execute("RELEASE catalog_entry")
            self._abort_refs(pending)
            if isinstance(exc, sqlite3.Error):
                raise OSError(f"ClickHouse catalog storage failure: {exc}") from exc
            raise


class _CatalogView:
    _kind: str

    def __init__(self, owner, node):
        self._owner, self._node = owner, node

    @property
    def reference_owner(self):
        return self._owner

    @property
    def reference_locator(self):
        return self._kind, self._node

    @property
    def byte_length(self):
        return 0

    def __len__(self):
        return self._owner._db.execute("SELECT length FROM nodes WHERE id=?", (self._node,)).fetchone()[0]

    def _get(self, key):
        row = self._owner._db.execute(
            "SELECT kind,payload FROM entries WHERE parent=? AND key=?", (self._node, self._owner.key_identity(key))
        ).fetchone()
        if row is None:
            raise KeyError(key)
        return self._owner._decode(*row)

    def _values(self):
        for kind, payload in self._owner._db.execute(
            "SELECT kind,payload FROM entries WHERE parent=? ORDER BY ordinal", (self._node,)
        ):
            yield self._owner._decode(kind, payload)


class CatalogMapping(_CatalogView, DiskMapping, dict):
    _kind = "map"

    def __getitem__(self, key):
        return self._get(key)

    def __setitem__(self, key, value):
        self._owner.put(self._node, key, value)

    def __delitem__(self, key):
        cursor = self._owner._db.execute(
            "DELETE FROM entries WHERE parent=? AND key=?", (self._node, self._owner.key_identity(key))
        )
        if not cursor.rowcount:
            raise KeyError(key)
        self._owner._db.execute("UPDATE nodes SET length=length-1 WHERE id=?", (self._node,))

    def __iter__(self):
        for (key,) in self._owner._db.execute(
            "SELECT key_payload FROM entries WHERE parent=? ORDER BY ordinal", (self._node,)
        ):
            yield self._owner.decode_key(key)

    def __contains__(self, key):
        return (
            self._owner._db.execute(
                "SELECT 1 FROM entries WHERE parent=? AND key=?", (self._node, self._owner.key_identity(key))
            ).fetchone()
            is not None
        )

    def pop(self, key, *default):
        if len(default) > 1:
            raise TypeError("pop expected at most 2 arguments")
        try:
            value = self[key]
        except KeyError:
            if default:
                return default[0]
            raise
        del self[key]
        return value

    def clear(self):
        self._owner._db.execute("DELETE FROM entries WHERE parent=?", (self._node,))
        self._owner._db.execute("UPDATE nodes SET length=0 WHERE id=?", (self._node,))

    def copy(self):
        return dict(self.items())

    def get(self, key, default=None):
        try:
            return self[key]
        except KeyError:
            return default

    def setdefault(self, key, default=None):
        if key not in self:
            self[key] = default
        return self[key]

    def update(self, values: Any = (), /, **kwargs: Any) -> None:
        for key, value in values.items() if hasattr(values, "items") else values:
            self[key] = value
        for key, value in kwargs.items():
            self[key] = value

    def keys(self):
        return Mapping.keys(self)

    def items(self):
        for key, kind, payload in self._owner._db.execute(
            "SELECT key_payload,kind,payload FROM entries WHERE parent=? ORDER BY ordinal", (self._node,)
        ):
            yield self._owner.decode_key(key), self._owner._decode(kind, payload)

    def values(self):
        return self._values()

    def __eq__(self, other):
        return (
            isinstance(other, Mapping)
            and len(self) == len(other)
            and all(key in self and self[key] == value for key, value in other.items())
        )

    def __ne__(self, other):
        return not self == other


class CatalogSequence(_CatalogView, DiskSequence):
    _kind = "list"

    def __iter__(self):
        return self._values()

    def __getitem__(self, index):
        if isinstance(index, slice):
            from itertools import islice

            start, stop, step = index.indices(len(self))
            if step > 0:
                return list(islice(self, start, stop, step))
            return [self[i] for i in range(start, stop, step)]
        if index < 0:
            index += len(self)
        if not 0 <= index < len(self):
            raise IndexError(index)
        return self._get(index)

    def __setitem__(self, index, value):
        if index < 0:
            index += len(self)
        if not 0 <= index < len(self):
            raise IndexError(index)
        self._owner.put(self._node, index, value)

    def append(self, value):
        self._owner.put(self._node, len(self), value)

    def extend(self, values):
        for value in values:
            self.append(value)

    def sort_errors(self, *, key):
        db = self._owner._db
        db.execute("CREATE TEMP TABLE ordering(a TEXT, b TEXT, c TEXT, d INTEGER, kind TEXT, payload TEXT)")
        try:
            for kind, payload in db.execute(
                "SELECT kind,payload FROM entries WHERE parent=? ORDER BY ordinal", (self._node,)
            ):
                value = key(self._owner._decode(kind, payload))
                db.execute("INSERT INTO ordering VALUES (?,?,?,?,?,?)", (*value, kind, payload))
            db.execute("DELETE FROM entries WHERE parent=?", (self._node,))
            for ordinal, (kind, payload) in enumerate(db.execute("SELECT kind,payload FROM ordering ORDER BY a,b,c,d")):
                db.execute(
                    "INSERT INTO entries VALUES (?,?,?,?,?,?)",
                    (self._node, self._owner.key_identity(ordinal), ordinal, kind, payload, json.dumps(str(ordinal))),
                )
        finally:
            db.execute("DROP TABLE ordering")

    def __contains__(self, value):
        return any(item == value for item in self)

    def __eq__(self, other):
        if not isinstance(other, (list, tuple)):
            return False
        missing = object()
        return all(a == b for a, b in zip_longest(self, other, fillvalue=missing))

    def __ne__(self, other):
        return not self == other


class CatalogDocument(DiskJSONDocument):
    """Import JSON object keys and arrays directly into disposable indexed state."""

    def __init__(self):
        self.tree = CatalogTree()
        super().__init__()

    def _start(self, path, kind):
        self._containers[path] = self.tree.mapping() if kind == "object" else self.tree.sequence()


class ColumnSequence(list):
    def __init__(self, payload):
        self.payload = payload

    def __len__(self):
        return len(self.payload)

    def __iter__(self):
        from .models import ColumnInventory

        for value in self.payload:
            yield ColumnInventory(**dict(value.items()))

    def __getitem__(self, index):
        from .models import ColumnInventory

        if isinstance(index, slice):
            return [ColumnInventory(**dict(value.items())) for value in self.payload[index]]
        return ColumnInventory(**dict(self.payload[index].items()))

    def __setitem__(self, index, value):
        self.payload[index] = value.to_dict()

    def append(self, value):
        self.payload.append(value.to_dict())


class InventoryCatalog(list):
    def __init__(self):
        self.tree = CatalogTree()
        self.records = self.tree.sequence()
        self._lookup = self.tree.mapping()
        self.tree._db.execute("CREATE TABLE catalog_order(ordinal INTEGER PRIMARY KEY, database TEXT, name TEXT)")

    def __len__(self):
        return len(self.records)

    def __iter__(self):
        for record in self.records:
            yield self._table(record)

    def __getitem__(self, index):
        if isinstance(index, slice):
            return [self._table(value) for value in self.records[index]]
        return self._table(self.records[index])

    def _table(self, record):
        from .models import TableInventory

        # Only the fixed-size metadata record is detached. Its children stay
        # live disk views, so catalog width and data values are not copied.
        fields = dict(record.items())
        return TableInventory(
            database=fields["database"],
            name=fields["table"],
            engine=fields["engine"],
            partition_key=fields["partition_key"],
            sorting_key=fields["sorting_key"],
            primary_key=fields["primary_key"],
            total_rows=fields["total_rows"],
            total_bytes=fields["total_bytes"],
            columns=ColumnSequence(fields["columns"]),
            partitions=fields["partitions"],
            inventory_errors=fields["inventory_errors"],
            _catalog_record=record,
        )

    @staticmethod
    def _key(database, name):
        return json.dumps([database, name], ensure_ascii=False)

    def append(self, table):
        key = self._key(table.database, table.name)
        ordinal = self._lookup.get(key)
        if ordinal is None:
            ordinal = len(self.records)
            self._lookup[key] = ordinal
            self.records.append(table.to_dict())
            self.tree._db.execute("INSERT INTO catalog_order VALUES (?,?,?)", (ordinal, table.database, table.name))
        else:
            self.records[ordinal] = table.to_dict()

    def get(self, key):
        ordinal = self._lookup.get(self._key(*key))
        return None if ordinal is None else self[ordinal]

    def sorted_tables(self):
        for (ordinal,) in self.tree._db.execute("SELECT ordinal FROM catalog_order ORDER BY database,name"):
            yield self[ordinal]

    def values(self):
        return iter(self)
