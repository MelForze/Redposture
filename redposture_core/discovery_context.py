"""Product-neutral semantic field/value bindings with physical source paths."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from .discovery_keys import disk_key_hint
from .discovery_rules import _disk_field_hint, classify_field, normalize_field_name
from .discovery_values import DiskBackedText

LABEL_ORDER = ("field", "target_field", "name", "key", "kind", "type")
CONTEXT_KEYS = frozenset((*LABEL_ORDER, "value"))


@dataclass(frozen=True)
class FieldBinding:
    key: Any
    field_name: str
    value: Any


def context_key(key: Any, deadline: float | None = None) -> str | None:
    if isinstance(key, DiskBackedText):
        name = _disk_field_hint(key, deadline, normalized_name=True)
        return name if name in CONTEXT_KEYS else None
    if not isinstance(key, str):
        return None
    # Every metadata role begins with one of these ASCII letters after
    # normalization. A necessary-start gate avoids normalizing wide catalogs.
    first = re.search(r"[A-Za-z0-9]", key)
    if first is None or first.group().lower() not in "fntkv":
        return None
    name = normalize_field_name(key)
    return name if name in CONTEXT_KEYS else None


def field_binding(value: Mapping[Any, Any], *, deadline: float | None = None) -> FieldBinding | None:
    entries = {name: (key, child) for key, child in value.items() if (name := context_key(key, deadline)) is not None}
    actual_value = entries.get("value")
    if actual_value is None or isinstance(actual_value[1], (Mapping, list, tuple)):
        return None
    label = next((entries[name][1] for name in LABEL_ORDER if name in entries), None)
    if isinstance(label, DiskBackedText):
        label = disk_key_hint(label, deadline)
    if not isinstance(label, str) or classify_field(label) not in {"strong", "medium", "excluded"}:
        return None
    return FieldBinding(actual_value[0], label, actual_value[1])


@dataclass
class _ObjectContext:
    label_rank: int = len(LABEL_ORDER)
    label: Any = None
    pending: tuple[tuple[Any, ...], Any] | None = None
    credentials: dict[str, tuple[tuple[Any, ...], Any]] = field(default_factory=dict)
    ambiguous: set[str] = field(default_factory=set)


class JSONFieldContext:
    """Bind a completed value at object end, never retaining whole objects.

    At most one label/value pair is retained per open object (parser depth is
    bounded). Large scalars already own a disk lease. Ordinary fields are
    emitted immediately; deferred contextual values preserve physical paths.
    """

    def __init__(self, emit, partial, *, deadline: float | None = None) -> None:
        self.emit = emit
        self.partial = partial
        self.deadline = deadline
        self.frames: dict[tuple[Any, ...], _ObjectContext] = {}

    def container(self, path, kind: str) -> None:
        parent = self.frames.get(path[:-1]) if path else None
        name = context_key(path[-1], self.deadline) if path else None
        from .discovery_groups import credential_field

        credential_name = credential_field(path[-1]) if path else None
        if parent is not None and credential_name in parent.credentials:
            previous_path, previous = parent.credentials.pop(credential_name)
            if previous_path == path:
                self.partial("duplicate_credential_field")
            self.emit(previous_path, previous, None)
            parent.ambiguous.add(credential_name)
        if parent is not None and name in LABEL_ORDER:
            rank = LABEL_ORDER.index(name)
            if rank <= parent.label_rank:
                parent.label_rank, parent.label = rank, None
        if parent is not None and name == "value" and parent.pending is not None:
            self.partial("duplicate_semantic_value")
            previous_path, previous = parent.pending
            self.emit(previous_path, previous, None)
            parent.pending = None
        if kind == "object":
            self.frames[path] = _ObjectContext()

    def value(self, path, value: Any) -> None:
        frame = self.frames.get(path[:-1]) if path else None
        name = context_key(path[-1], self.deadline) if path else None
        from .discovery_groups import credential_field

        credential_name = credential_field(path[-1]) if path else None
        if frame is not None and credential_name is not None:
            if credential_name in frame.credentials:
                previous_path, previous = frame.credentials.pop(credential_name)
                if previous_path == path:
                    self.partial("duplicate_credential_field")
                self.emit(previous_path, previous, None)
                frame.ambiguous.add(credential_name)
            if credential_name in frame.ambiguous:
                self.emit(path, value, None)
            else:
                frame.credentials[credential_name] = (path, value)
            return
        if frame is not None and name == "value":
            if frame.pending is not None:
                # Duplicate JSON members have no unique semantic binding.
                # Retain completed explicit content and report the ambiguity.
                self.partial("duplicate_semantic_value")
                previous_path, previous = frame.pending
                self.emit(previous_path, previous, None)
            frame.pending = (path, value)
            return
        if frame is not None and name in LABEL_ORDER:
            rank = LABEL_ORDER.index(name)
            if rank <= frame.label_rank:
                frame.label_rank, frame.label = rank, value
        self.emit(path, value, None)

    def _flush(self, frame: _ObjectContext, *, grouped: bool = False) -> None:
        from .discovery_groups import credential_groups

        candidates = {parts[-1]: value for parts, value in frame.credentials.values()}
        consumed: set[str] = set()
        if grouped:
            for group in credential_groups(candidates, deadline=self.deadline):
                consumed.update(group.fields)
                parent = next(iter(frame.credentials.values()))[0][:-1]
                self.emit(parent, group.fields, None)
        for parts, value in frame.credentials.values():
            if parts[-1] not in consumed:
                self.emit(parts, value, None)
        frame.credentials.clear()
        if frame.pending is None:
            return
        path, value = frame.pending
        binding = field_binding({"name": frame.label, "value": value}, deadline=self.deadline)
        self.emit(path, value, binding.field_name if binding is not None else None)
        frame.pending = None

    def end(self, path, kind: str) -> None:
        if kind == "object":
            frame = self.frames.pop(path)
            self._flush(frame, grouped=True)

    def close(self, *, flush: bool = True) -> None:
        try:
            while self.frames:
                _path, frame = self.frames.popitem()
                if flush:
                    self._flush(frame)
        finally:
            self.frames.clear()
