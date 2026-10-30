"""Atomic, target-aware checkpoint storage for resumable discovery."""

from __future__ import annotations

import json
import os
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

from ....discovery_values import iter_json_chunks
from .catalog import CatalogDocument, CatalogTree

_LOCKS_GUARD = threading.Lock()
_LOCKS: dict[str, threading.RLock] = {}


def _path_lock(path: Path) -> threading.RLock:
    key = str(path.resolve())
    with _LOCKS_GUARD:
        return _LOCKS.setdefault(key, threading.RLock())


class CheckpointStore:
    schema_version = 1

    def __init__(self, path: Path, target_key: str, *, resume: bool, deadline: float | None = None) -> None:
        self.path = path
        self.target_key = target_key
        self._lock = _path_lock(path)
        self._document: dict[str, Any] | None = None
        self._stamp = None
        self._import_deadline = deadline
        with self._lock:
            try:
                document = self._current_document()
                targets = document.setdefault("targets", {})
                if not resume or target_key not in targets:
                    targets[target_key] = {"status": "running", "chunks": {}, "findings": {}, "coverage": {}}
                    self._write_document(document)
            finally:
                self._import_deadline = None

    def _file_stamp(self):
        try:
            stat = self.path.stat()
            return stat.st_ino, stat.st_size, stat.st_mtime_ns
        except FileNotFoundError:
            return None

    def _current_document(self):
        if self._document is None or self._stamp != self._file_stamp():
            self._document = self._read_document()
            self._stamp = self._file_stamp()
        return self._document

    def _check_import_deadline(self):
        if self._import_deadline is not None and time.monotonic() >= self._import_deadline:
            raise TimeoutError("discover_time")

    def _read_document(self) -> dict[str, Any]:
        self._check_import_deadline()
        try:
            parser = CatalogDocument()
            try:
                with self.path.open("rb") as stream:
                    while True:
                        self._check_import_deadline()
                        portion = stream.read(65_536)
                        if not portion:
                            break
                        parser.feed(portion)
                        self._check_import_deadline()
                raw = parser.finish()
                self._check_import_deadline()
            finally:
                parser.close()
        except FileNotFoundError:
            return CatalogTree().mapping({"schema_version": self.schema_version, "targets": {}})
        except TimeoutError:
            raise
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            raise ValueError(f"invalid checkpoint {self.path}: {exc}") from exc
        if not isinstance(raw, dict) or raw.get("schema_version") != self.schema_version:
            raise ValueError(f"unsupported checkpoint schema in {self.path}")
        if not isinstance(raw.get("targets"), dict):
            raise ValueError(f"invalid checkpoint targets in {self.path}")
        for key, state in raw["targets"].items():
            self._check_import_deadline()
            if state is None:
                # Older checkpoints could contain a null target; preserve the
                # existing empty-state behavior for this harmless case.
                continue
            if not isinstance(key, str) or not isinstance(state, dict):
                raise ValueError(f"invalid checkpoint target in {self.path}")
            if any(
                field in state and not isinstance(state[field], dict) for field in ("chunks", "findings", "coverage")
            ):
                raise ValueError(f"invalid checkpoint target in {self.path}")
        return raw

    def _write_document(self, document: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, temp_name = tempfile.mkstemp(prefix=f".{self.path.name}.", dir=str(self.path.parent))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                for portion in iter_json_chunks(document):
                    stream.write(portion)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temp_name, self.path)
            self._document = document
            self._stamp = self._file_stamp()
        except BaseException:
            self._document = None
            self._stamp = None
            try:
                os.unlink(temp_name)
            except OSError:
                pass
            raise

    def target_state(self) -> dict[str, Any]:
        with self._lock:
            document = self._current_document()
            return dict(document["targets"].get(self.target_key) or {})

    def is_complete(self, chunk_id: str) -> bool:
        state = self.target_state()
        chunk = (state.get("chunks") or {}).get(chunk_id)
        return isinstance(chunk, dict) and chunk.get("status") == "complete"

    def update(self, *, chunk_id: str | None = None, chunk: dict[str, Any] | None = None, **values: Any) -> None:
        with self._lock:
            document = self._current_document()
            target = document["targets"].get(self.target_key)
            if target is None:
                target = {"status": "running", "chunks": {}, "findings": {}, "coverage": {}}
                document["targets"][self.target_key] = target
                target = document["targets"][self.target_key]
            target.update(values)
            if chunk_id is not None and chunk is not None:
                target.setdefault("chunks", {})[chunk_id] = chunk
            self._write_document(document)


class InMemoryCheckpointStore:
    """Ephemeral checkpoint with disposable disk-backed chunk history."""

    schema_version = CheckpointStore.schema_version

    def __init__(self, target_key: str, *, resume: bool = False) -> None:
        self.path: Path | None = None
        self.target_key = target_key
        self._tree = CatalogTree()
        self._document: dict[str, Any] = {
            "schema_version": self.schema_version,
            "targets": {
                target_key: {"status": "running", "chunks": self._tree.mapping(), "findings": {}, "coverage": {}}
            },
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
