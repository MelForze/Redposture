"""Atomic, target-aware checkpoint storage for resumable discovery."""

from __future__ import annotations

import json
import os
import tempfile
import threading
from pathlib import Path
from typing import Any

_LOCKS_GUARD = threading.Lock()
_LOCKS: dict[str, threading.RLock] = {}


def _path_lock(path: Path) -> threading.RLock:
    key = str(path.resolve())
    with _LOCKS_GUARD:
        return _LOCKS.setdefault(key, threading.RLock())


class CheckpointStore:
    schema_version = 1

    def __init__(self, path: Path, target_key: str, *, resume: bool) -> None:
        self.path = path
        self.target_key = target_key
        self._lock = _path_lock(path)
        with self._lock:
            document = self._read_document()
            targets = document.setdefault("targets", {})
            if not resume or target_key not in targets:
                targets[target_key] = {"status": "running", "chunks": {}, "findings": {}, "coverage": {}}
                self._write_document(document)

    def _read_document(self) -> dict[str, Any]:
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {"schema_version": self.schema_version, "targets": {}}
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            raise ValueError(f"invalid checkpoint {self.path}: {exc}") from exc
        if not isinstance(raw, dict) or raw.get("schema_version") != self.schema_version:
            raise ValueError(f"unsupported checkpoint schema in {self.path}")
        if not isinstance(raw.get("targets"), dict):
            raise ValueError(f"invalid checkpoint targets in {self.path}")
        return raw

    def _write_document(self, document: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, temp_name = tempfile.mkstemp(prefix=f".{self.path.name}.", dir=str(self.path.parent))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump(document, stream, ensure_ascii=False, sort_keys=True, indent=2)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temp_name, self.path)
        except BaseException:
            try:
                os.unlink(temp_name)
            except OSError:
                pass
            raise

    def target_state(self) -> dict[str, Any]:
        with self._lock:
            document = self._read_document()
            return dict(document["targets"].get(self.target_key) or {})

    def is_complete(self, chunk_id: str) -> bool:
        state = self.target_state()
        chunk = (state.get("chunks") or {}).get(chunk_id)
        return isinstance(chunk, dict) and chunk.get("status") == "complete"

    def update(self, *, chunk_id: str | None = None, chunk: dict[str, Any] | None = None, **values: Any) -> None:
        with self._lock:
            document = self._read_document()
            target = document["targets"].setdefault(
                self.target_key, {"status": "running", "chunks": {}, "findings": {}, "coverage": {}}
            )
            target.update(values)
            if chunk_id is not None and chunk is not None:
                target.setdefault("chunks", {})[chunk_id] = chunk
            self._write_document(document)


class InMemoryCheckpointStore:
    """Non-persistent checkpoint used when no ``--checkpoint`` path is given.

    Exposes the same surface as :class:`CheckpointStore` (``target_state``,
    ``is_complete``, ``update``) but keeps all state in memory, so a discovery
    run never touches the filesystem unless the operator opts in with a path.
    """

    schema_version = CheckpointStore.schema_version

    def __init__(self, target_key: str, *, resume: bool = False) -> None:
        self.path: Path | None = None
        self.target_key = target_key
        self._document: dict[str, Any] = {
            "schema_version": self.schema_version,
            "targets": {target_key: {"status": "running", "chunks": {}, "findings": {}, "coverage": {}}},
        }

    def target_state(self) -> dict[str, Any]:
        return dict(self._document["targets"].get(self.target_key) or {})

    def is_complete(self, chunk_id: str) -> bool:
        chunk = (self.target_state().get("chunks") or {}).get(chunk_id)
        return isinstance(chunk, dict) and chunk.get("status") == "complete"

    def update(self, *, chunk_id: str | None = None, chunk: dict[str, Any] | None = None, **values: Any) -> None:
        target = self._document["targets"].setdefault(
            self.target_key, {"status": "running", "chunks": {}, "findings": {}, "coverage": {}}
        )
        target.update(values)
        if chunk_id is not None and chunk is not None:
            target.setdefault("chunks", {})[chunk_id] = chunk


__all__ = ["CheckpointStore", "InMemoryCheckpointStore"]
