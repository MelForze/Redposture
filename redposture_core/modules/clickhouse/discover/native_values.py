"""One temporary tree store for native columns and all their nested values."""

from __future__ import annotations

import hashlib
import json
import math
import operator
import os
import pickle
import sqlite3
import tempfile
import time
import uuid
import weakref
from collections.abc import Iterator
from itertools import zip_longest
from pathlib import Path
from typing import Any

from ....discovery_containers import DiskMapping, DiskSequence
from ....discovery_values import DiskBackedText


class _TextView(DiskBackedText):
    def __init__(self, owner: NativeValues, node: int, meta: dict[str, Any]) -> None:
        self._owner = weakref.ref(owner)
        self.node = node
        self._temporary = tempfile.TemporaryDirectory(prefix="redposture-native-text-")
        self.path = Path(self._temporary.name) / "value.txt"
        try:
            os.link(owner.directory / meta["file"], self.path)
        except BaseException:
            self._temporary.cleanup()
            raise
        self.byte_length = meta["byte_length"]
        self._digest = meta["digest"]
        self._all_x, self._all_star, self._all_dash = meta["all_x"], meta["all_star"], meta["all_dash"]
        self._has_nonspace = meta["has_nonspace"]
        self._uniform, self._uniform_char = meta["uniform"], meta["uniform_char"]
        self._finished, self._closed = True, False

    @property
    def digest(self) -> str:
        return self._digest

    @property
    def owner(self) -> NativeValues | None:
        return self._owner()

    def close(self) -> None:
        self._closed = True
        self._temporary.cleanup()


class NativeValues:
    """Store nested nodes/edges without an in-memory index of every object."""

    def __init__(self, deadline: float | None = None) -> None:
        self.deadline = deadline
        self.reference_id = uuid.uuid4().hex
        self._temporary = tempfile.TemporaryDirectory(prefix="redposture-native-values-")
        self.directory = Path(self._temporary.name)
        self.db = sqlite3.connect(self.directory / "tree.sqlite3", isolation_level=None, check_same_thread=False)
        self.db.executescript("""
            PRAGMA journal_mode=MEMORY;
            PRAGMA synchronous=OFF;
            CREATE TABLE nodes(id INTEGER PRIMARY KEY, kind TEXT NOT NULL, payload BLOB,
                               value_bytes INTEGER NOT NULL, n_items INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE edges(parent INTEGER NOT NULL, ordinal INTEGER NOT NULL, child INTEGER NOT NULL,
                               key_node INTEGER, key_hash TEXT, PRIMARY KEY(parent,ordinal));
            CREATE UNIQUE INDEX map_keys ON edges(parent,key_hash) WHERE key_hash IS NOT NULL;
            CREATE TRIGGER edge_insert AFTER INSERT ON edges BEGIN
              UPDATE nodes SET n_items=n_items+1,
                value_bytes=value_bytes+(SELECT value_bytes FROM nodes WHERE id=NEW.child)
                +COALESCE((SELECT value_bytes FROM nodes WHERE id=NEW.key_node),0) WHERE id=NEW.parent;
            END;
            CREATE TRIGGER edge_update AFTER UPDATE OF child ON edges BEGIN
              UPDATE nodes SET value_bytes=value_bytes+(SELECT value_bytes FROM nodes WHERE id=NEW.child)
                -(SELECT value_bytes FROM nodes WHERE id=OLD.child) WHERE id=NEW.parent;
            END;
        """)

    def __del__(self) -> None:
        db = getattr(self, "db", None)
        if db is not None:
            db.close()
        temporary = getattr(self, "_temporary", None)
        if temporary is not None:
            temporary.cleanup()

    def execute(self, query: str, args: tuple[Any, ...] = ()) -> sqlite3.Cursor:
        try:
            return self.db.execute(query, args)
        except sqlite3.Error as exc:
            raise OSError(f"native value storage failure: {exc}") from exc

    def scalar(self, value: Any) -> int:
        if isinstance(value, (_Sequence, _Map, _TextView)) and value.owner is self:
            return value.node
        if isinstance(value, dict):
            mapping = self.mapping()
            for key, child in value.items():
                self.put(mapping.node, self.scalar(key), self.scalar(child))
            return mapping.node
        if isinstance(value, (list, tuple)):
            sequence = self.sequence(tuple_value=isinstance(value, tuple))
            for child in value:
                sequence.append(child)
            return sequence.node
        if isinstance(value, DiskBackedText):
            filename = uuid.uuid4().hex + ".txt"
            meta = {
                "file": filename,
                "byte_length": value.byte_length,
                "digest": value.digest,
                "all_x": value._all_x,
                "all_star": value._all_star,
                "all_dash": value._all_dash,
                "has_nonspace": value._has_nonspace,
                "uniform": value._uniform,
                "uniform_char": value._uniform_char,
            }
            node = int(
                self.execute(
                    "INSERT INTO nodes(kind,payload,value_bytes) VALUES(?,?,?)",
                    ("text", json.dumps(meta), value.byte_length),
                ).lastrowid
                or 0
            )
            os.replace(value.path, self.directory / filename)
            value.close()
            return node
        size = 0 if value is None else len(value if isinstance(value, bytes) else str(value).encode("utf-8"))
        return int(
            self.execute(
                "INSERT INTO nodes(kind,payload,value_bytes) VALUES(?,?,?)",
                ("scalar", pickle.dumps(value, protocol=5), size),
            ).lastrowid
            or 0
        )

    def sequence(self, *, tuple_value: bool = False) -> _Sequence:
        node = int(
            self.execute(
                "INSERT INTO nodes(kind,value_bytes) VALUES(?,0)", ("tuple" if tuple_value else "list",)
            ).lastrowid
            or 0
        )
        return _Sequence(self, node, tuple_value=tuple_value)

    def mapping(self) -> _Map:
        node = int(self.execute("INSERT INTO nodes(kind,value_bytes) VALUES('map',0)").lastrowid or 0)
        return _Map(self, node)

    def view(self, node: int) -> Any:
        row = self.execute("SELECT kind,payload FROM nodes WHERE id=?", (node,)).fetchone()
        if row is None:
            raise ValueError("native value node is missing")
        kind, payload = row
        if kind in ("list", "tuple"):
            return _Sequence(self, node, tuple_value=kind == "tuple")
        if kind == "map":
            return _Map(self, node)
        if kind == "text":
            return _TextView(self, node, json.loads(payload))
        return pickle.loads(payload)

    def stats(self, node: int) -> tuple[int, int]:
        count, size = self.execute("SELECT n_items,value_bytes FROM nodes WHERE id=?", (node,)).fetchone()
        return count, size

    def restore(self, locator: Any) -> Any:
        if len(locator) == 3 and locator[0] == "row":
            return NativeRow(self, tuple(locator[1]), locator[2])
        if len(locator) == 3 and locator[0] == "rows":
            return NativeRows(self, tuple(locator[1]), range(*locator[2]))
        node, selection = locator
        value = self.view(node)
        if selection is not None:
            if not isinstance(value, _Sequence):
                raise ValueError("native mapping cannot have a sequence slice")
            return _Sequence(self, node, range(*selection), tuple_value=value.tuple_value)
        return value

    def append(self, parent: int, child: int) -> None:
        self.execute(
            "INSERT INTO edges(parent,ordinal,child) SELECT ?,n_items,? FROM nodes WHERE id=?", (parent, child, parent)
        )

    def key_hash(self, key: Any) -> str:
        if identity := getattr(key, "_native_key_identity", None):
            return str(identity)
        if isinstance(key, _Map):
            digest = hashlib.sha256()
            for key_node, child in key.owner.execute(
                "SELECT key_node,child FROM edges WHERE parent=? ORDER BY ordinal", (key.node,)
            ):
                self._check_deadline()
                digest.update(self.key_hash(key.owner.view(key_node)).encode("ascii") + b"\0")
                digest.update(self.key_hash(key.owner.view(child)).encode("ascii") + b"\0")
            return "m:" + digest.hexdigest()
        if isinstance(key, (_Sequence, list, tuple)):
            tuple_value = key.tuple_value if isinstance(key, _Sequence) else isinstance(key, tuple)
            digest = hashlib.sha256()
            for child in key:
                self._check_deadline()
                digest.update(self.key_hash(child).encode("ascii") + b"\0")
            return ("t:" if tuple_value else "l:") + digest.hexdigest()
        if isinstance(key, str):
            return "s:" + hashlib.sha256(key.encode("utf-8")).hexdigest()
        if isinstance(key, DiskBackedText):
            return "s:" + key.digest
        if isinstance(key, float):
            if math.isnan(key):
                return "nan:" + uuid.uuid4().hex
            if key == 0:
                return "f:zero"
        return "p:" + hashlib.sha256(pickle.dumps(key, protocol=5)).hexdigest()

    def display_key(self, node: int) -> Any:
        key = self.view(node)
        if isinstance(key, _Map) or isinstance(key, _Sequence) and (key.byte_length > 65_536 or len(key) > 4096):
            from .native_keys import rendered_native_key

            self._check_deadline()
            return rendered_native_key(key, self.key_hash(key), self.deadline)
        if isinstance(key, _Sequence):
            values = (self.display_key(child) for child in key.iter_nodes())
            return tuple(values) if key.tuple_value else list(values)
        return key

    def _check_deadline(self) -> None:
        if self.deadline is not None and time.monotonic() >= self.deadline:
            raise TimeoutError("discover_time")

    def put(self, parent: int, key_node: int, child: int, *, preserve_entries: bool = False) -> None:
        key = self.view(key_node)
        digest = self.key_hash(key)
        # Ordinary Python mappings keep dict semantics. ClickHouse wire Maps
        # can contain repeated keys: scan every value, while keyed lookup still
        # returns the last entry just as it does in the SDK.
        old = self.execute("SELECT ordinal FROM edges WHERE parent=? AND key_hash=?", (parent, digest)).fetchone()
        if old is not None and preserve_entries:
            self.execute("UPDATE edges SET key_hash=NULL WHERE parent=? AND ordinal=?", (parent, old[0]))
        if old is not None and not preserve_entries:
            self.execute("UPDATE edges SET child=? WHERE parent=? AND ordinal=?", (child, parent, old[0]))
        else:
            self.execute(
                "INSERT INTO edges(parent,ordinal,child,key_node,key_hash) "
                "SELECT ?,n_items,?,?,? FROM nodes WHERE id=?",
                (parent, child, key_node, digest, parent),
            )


class _Sequence(DiskSequence):
    def __init__(
        self, owner: NativeValues, node: int, selected: range | None = None, *, tuple_value: bool = False
    ) -> None:
        super().__init__()
        self.owner, self.node, self.selected = owner, node, selected
        self.tuple_value = tuple_value

    @property
    def byte_length(self) -> int:
        return self.owner.stats(self.node)[1]

    @property
    def reference_owner(self) -> NativeValues:
        return self.owner

    @property
    def reference_locator(self) -> Any:
        selected = self.selected
        return [self.node, None if selected is None else [selected.start, selected.stop, selected.step]]

    def __len__(self) -> int:
        return len(self.selected) if self.selected is not None else self.owner.stats(self.node)[0]

    def append(self, value: Any) -> None:
        self.append_node(self.owner.scalar(value))

    def append_node(self, child: int) -> None:
        if self.selected is not None:
            raise ValueError("native sequence slice is read-only")
        self.owner.append(self.node, child)

    def node_at(self, index: int) -> int:
        position = operator.index(index)
        if position < 0:
            position += len(self)
        if not 0 <= position < len(self):
            raise IndexError(index)
        if self.selected is not None:
            position = self.selected[position]
        row = self.owner.execute(
            "SELECT child FROM edges WHERE parent=? AND ordinal=?", (self.node, position)
        ).fetchone()
        if row is None:
            raise IndexError(index)
        return row[0]

    def __getitem__(self, index: Any) -> Any:
        if isinstance(index, slice):
            selected = (self.selected if self.selected is not None else range(len(self)))[index]
            return _Sequence(self.owner, self.node, selected, tuple_value=self.tuple_value)
        return self.owner.view(self.node_at(index))

    def iter_nodes(self) -> Iterator[int]:
        if self.selected is not None:
            for index in self.selected:
                row = self.owner.execute(
                    "SELECT child FROM edges WHERE parent=? AND ordinal=?", (self.node, index)
                ).fetchone()
                if row is None:
                    raise IndexError(index)
                yield row[0]
        else:
            for (node,) in self.owner.execute("SELECT child FROM edges WHERE parent=? ORDER BY ordinal", (self.node,)):
                yield node

    def __iter__(self) -> Iterator[Any]:
        return (self.owner.view(node) for node in self.iter_nodes())

    def __repr__(self) -> str:
        return f"NativeSequence(count={len(self)})"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, (list, tuple)):
            return NotImplemented
        missing = object()
        return all(a == b for a, b in zip_longest(self, other, fillvalue=missing))

    def __ne__(self, other: object) -> bool:
        result = self.__eq__(other)
        return NotImplemented if result is NotImplemented else not result


class _Map(DiskMapping):
    def __init__(self, owner: NativeValues, node: int) -> None:
        self.owner, self.node = owner, node

    @property
    def byte_length(self) -> int:
        return self.owner.stats(self.node)[1]

    @property
    def reference_owner(self) -> NativeValues:
        return self.owner

    @property
    def reference_locator(self) -> Any:
        return [self.node, None]

    def __len__(self) -> int:
        return self.owner.stats(self.node)[0]

    def __iter__(self) -> Iterator[Any]:
        for (key,) in self.owner.execute("SELECT key_node FROM edges WHERE parent=? ORDER BY ordinal", (self.node,)):
            yield self.owner.display_key(key)

    def __getitem__(self, key: Any) -> Any:
        row = self.owner.execute(
            "SELECT child FROM edges WHERE parent=? AND key_hash=?", (self.node, self.owner.key_hash(key))
        ).fetchone()
        if row is None:
            raise KeyError(key)
        return self.owner.view(row[0])

    def items(self) -> Iterator[tuple[Any, Any]]:  # type: ignore[override]
        for key, value in self.owner.execute(
            "SELECT key_node,child FROM edges WHERE parent=? ORDER BY ordinal", (self.node,)
        ):
            decoded_key = self.owner.display_key(key)
            yield decoded_key, self.owner.view(value)

    def __repr__(self) -> str:
        return f"NativeMapping(count={len(self)})"


class NativeRow(DiskSequence):
    """A columnar row view; never decode every cell just to queue a row."""

    def __init__(self, owner: NativeValues, columns: tuple[int, ...], index: int) -> None:
        super().__init__()
        self.owner, self.columns, self.row_index = owner, columns, index

    @property
    def reference_owner(self) -> NativeValues:
        return self.owner

    @property
    def reference_locator(self) -> Any:
        return ["row", self.columns, self.row_index]

    @property
    def byte_length(self) -> int:
        total = 0
        for column in self.columns:
            row = self.owner.execute(
                "SELECT n.value_bytes FROM edges e JOIN nodes n ON n.id=e.child WHERE e.parent=? AND e.ordinal=?",
                (column, self.row_index),
            ).fetchone()
            if row is None:
                raise ValueError("native row cell is missing")
            total += row[0]
        return total

    def __len__(self) -> int:
        return len(self.columns)

    def __getitem__(self, index: Any) -> Any:
        if isinstance(index, slice):
            return NativeRow(self.owner, self.columns[index], self.row_index)
        column = self.columns[index]
        node = self.owner.execute(
            "SELECT child FROM edges WHERE parent=? AND ordinal=?", (column, self.row_index)
        ).fetchone()
        if node is None:
            raise IndexError(index)
        return self.owner.view(node[0])

    def __iter__(self) -> Iterator[Any]:
        return (self[index] for index in range(len(self)))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, (list, tuple)):
            return NotImplemented
        missing = object()
        return all(a == b for a, b in zip_longest(self, other, fillvalue=missing))

    def __ne__(self, other: object) -> bool:
        result = self.__eq__(other)
        return NotImplemented if result is NotImplemented else not result

    def __repr__(self) -> str:
        return f"NativeRow(columns={len(self)})"


class NativeRows(DiskSequence):
    """Lazy ownership transfer of already decoded rows, including on timeout."""

    def __init__(self, owner: NativeValues, columns: tuple[int, ...], selected: range) -> None:
        super().__init__()
        self.owner, self.columns, self.selected = owner, columns, selected

    @property
    def reference_owner(self) -> NativeValues:
        return self.owner

    @property
    def reference_locator(self) -> Any:
        return ["rows", self.columns, [self.selected.start, self.selected.stop, self.selected.step]]

    @property
    def byte_length(self) -> int:
        if self.selected.step != 1:
            return sum(NativeRow(self.owner, self.columns, index).byte_length for index in self.selected)
        total = 0
        for column in self.columns:
            if (
                self.selected.start == 0
                and self.selected.step == 1
                and self.selected.stop == self.owner.stats(column)[0]
            ):
                total += self.owner.stats(column)[1]
            elif self.selected.step == 1:
                row = self.owner.execute(
                    "SELECT COALESCE(SUM(n.value_bytes),0) FROM edges e "
                    "JOIN nodes n ON n.id=e.child WHERE e.parent=? AND e.ordinal>=? AND e.ordinal<?",
                    (column, self.selected.start, self.selected.stop),
                ).fetchone()
                total += row[0]
        return total

    def __len__(self) -> int:
        return len(self.selected)

    def __getitem__(self, index: Any) -> Any:
        if isinstance(index, slice):
            return NativeRows(self.owner, self.columns, self.selected[index])
        return NativeRow(self.owner, self.columns, self.selected[index])

    def __iter__(self) -> Iterator[Any]:
        return (NativeRow(self.owner, self.columns, index) for index in self.selected)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, (list, tuple)):
            return NotImplemented
        missing = object()
        return all(a == b for a, b in zip_longest(self, other, fillvalue=missing))

    def __ne__(self, other: object) -> bool:
        result = self.__eq__(other)
        return NotImplemented if result is NotImplemented else not result

    def __repr__(self) -> str:
        return f"NativeRows(count={len(self)})"
