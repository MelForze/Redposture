"""Incremental JSON materialization with disk-backed strings and catalogs."""

from __future__ import annotations

import time
from collections.abc import Mapping
from typing import Any, Protocol

from .discovery_mapping import DiskObjectStore
from .discovery_spool import SpoolingValues
from .discovery_values import DiskBackedText
from .json_stream import JSONPath, JSONScalarStream


class _ObjectWriter(Protocol):
    """Construction-time mutation supported by the document's object views."""

    def __setitem__(self, key: Any, value: Any) -> None: ...


class DiskJSONDocument:
    """Keep object cardinality, nested catalogs and long values outside RAM."""

    def __init__(self, *, deadline: float | None = None) -> None:
        self.value: Any = None
        self._containers: dict[JSONPath, Any] = {}
        self._parts: list[str] = []
        self._length = 0
        self._disk: DiskBackedText | None = None
        self._store: DiskObjectStore | None = None
        self.parser = JSONScalarStream(
            self._string,
            on_primitive=lambda item: self._put(*item),
            on_container=self._start,
            on_container_end=self._end,
            deadline=deadline,
        )

    def _check_deadline(self) -> None:
        if self.parser.deadline is not None and time.monotonic() >= self.parser.deadline:
            raise TimeoutError("discover_time")

    def _put(self, path: JSONPath, value: Any) -> None:
        if not path:
            self.value = value
        else:
            parent = self._containers[path[:-1]]
            writer: _ObjectWriter = parent
            try:
                if isinstance(parent, Mapping):
                    writer[path[-1]] = value
                else:
                    parent.append(value)
            except (OSError, TimeoutError):
                store = self._store
                if store is not None and getattr(parent, "reference_owner", None) is self._store:
                    store.attach_partial(parent, path[-1], value)
                raise

    def _start(self, path: JSONPath, kind: str) -> None:
        if self._store is None:
            self._store = DiskObjectStore(check=self._check_deadline)
        self._containers[path] = self._store.mapping() if kind == "object" else self._store.sequence()

    def _end(self, path: JSONPath, _kind: str) -> None:
        value = self._containers[path]
        if isinstance(value, SpoolingValues):
            value.finish()
        self._put(path, value)
        self._containers.pop(path)

    def _string(self, path: JSONPath, text: str, final: bool) -> None:
        self._length += len(text)
        if self._disk is None and self._length > 65536:
            self._disk = DiskBackedText()
            for part in self._parts:
                self._disk.append_text(part)
            self._parts.clear()
        if self._disk is not None:
            self._disk.append_text(text)
        else:
            self._parts.append(text)
        if final:
            if self._disk is not None:
                self._disk.finish()
                value: Any = self._disk
                self._disk = None
            else:
                value = "".join(self._parts)
            self._put(path, value)
            self._parts.clear()
            self._length = 0
            self._disk = None

    def feed(self, chunk: bytes) -> None:
        self.parser.feed(chunk)

    def finish(self) -> Any:
        self.parser.finish()
        if self._store is not None:
            self._store.detach()
        return self.value

    def close(self) -> None:
        """Release parser cycles and unfinished values after ownership transfers."""
        if self._disk is not None:
            self._disk.close()
            self._disk = None
        self._parts.clear()
        self._containers.clear()
        self.value = None
        if self._store is not None:
            self._store.detach()
            self._store = None
        self.parser.on_string = lambda *_args: None
        self.parser.on_primitive = None
        self.parser.on_container = None
        self.parser.on_container_end = None
        self.parser.close()
        self.parser.string_parts.clear()
        self.parser.stack.clear()

    def partial_value(self, *, completed_arrays_only: bool = False) -> Any:
        """Recover closed scalars/children after input fails, never a string prefix.

        The caller must mark the result incomplete and stop feeding this reader.
        Active containers can contain completed children; an open string is not
        attached until its JSON closing quote has been validated.
        With completed_arrays_only, open array items are excluded, while open
        object envelopes can still expose their already completed child rows.
        """
        store = self._store
        if store is not None:
            store.detach()
        if self.value is not None:
            return self.value
        for path in sorted(self._containers, key=len, reverse=True):
            if path:
                parent = self._containers[path[:-1]]
                child = self._containers[path]
                if completed_arrays_only and isinstance(parent, list):
                    continue
                if store is not None and getattr(parent, "reference_owner", None) is self._store:
                    store.attach_partial(parent, path[-1], child)
                else:
                    self._put(path, child)
        self.value = self._containers.get(())
        return self.value

    def is_open_container(self, path: JSONPath) -> bool:
        return path in self._containers

    def root_field_seen(self, field: str) -> bool:
        """Confirm a required field without materializing or flushing the document."""
        root = self.value if isinstance(self.value, Mapping) else self._containers.get(())
        return (field,) in self._containers or (isinstance(root, Mapping) and field in root)

    def completed_array(self) -> SpoolingValues | None:
        """Recover closed root-array items after input has stopped with an error.

        An unfinished child is attached to its parent only on its closing token,
        so the root spool contains no prefix of the interrupted item. The caller
        still owns reporting the failed transport or invalid document as partial.
        """
        if self.parser.root_kind != "array":
            return None
        if self._store is not None:
            self._store.detach()
        value = self.value if isinstance(self.value, SpoolingValues) else self._containers.get(())
        if not isinstance(value, SpoolingValues):
            return None
        value.finish()
        return value
