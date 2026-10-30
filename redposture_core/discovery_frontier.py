"""Disk-backed traversal frontier for large per-target discovery trees."""

from __future__ import annotations

import sqlite3
import tempfile
from pathlib import Path
from types import TracebackType


class DiscoveryFrontier:
    """Keep queued and visited paths out of process RSS; delete them on exit."""

    def __init__(self) -> None:
        self._temporary = tempfile.TemporaryDirectory(prefix="redposture-discover-")
        self.location = Path(self._temporary.name) / "frontier.sqlite"
        try:
            self._database = sqlite3.connect(self.location, isolation_level=None)
            self._database.execute("PRAGMA journal_mode=MEMORY")
            self._database.execute("PRAGMA synchronous=OFF")
            self._database.execute("CREATE TABLE known (path TEXT PRIMARY KEY)")
            self._database.execute("CREATE TABLE queue (id INTEGER PRIMARY KEY, path TEXT NOT NULL)")
        except Exception:
            self._temporary.cleanup()
            raise
        self._closed = False

    def claim(self, path: str) -> bool:
        """Return true once per path, including paths not placed in the queue."""
        try:
            cursor = self._database.execute("INSERT OR IGNORE INTO known(path) VALUES (?)", (path,))
        except sqlite3.Error as exc:
            raise OSError(f"discovery frontier storage failure: {exc}") from exc
        return cursor.rowcount == 1

    def contains(self, path: str) -> bool:
        return self._database.execute("SELECT 1 FROM known WHERE path=?", (path,)).fetchone() is not None

    def enqueue(self, path: str) -> bool:
        # Claim and queue together: a failed enqueue must remain retryable.
        self._database.execute("BEGIN")
        try:
            added = self.claim(path)
            if added:
                self._database.execute("INSERT INTO queue(path) VALUES (?)", (path,))
            self._database.commit()
        except (sqlite3.Error, OSError) as exc:
            self._database.rollback()
            raise OSError(f"discovery frontier storage failure: {exc}") from exc
        return added

    def pop(self) -> str | None:
        row = self._database.execute("SELECT id, path FROM queue ORDER BY id LIMIT 1").fetchone()
        if row is None:
            return None
        self._database.execute("DELETE FROM queue WHERE id = ?", (row[0],))
        return str(row[1])

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            self._database.close()
            self._temporary.cleanup()

    def __enter__(self) -> DiscoveryFrontier:
        return self

    def __exit__(
        self,
        _exception_type: type[BaseException] | None,
        _exception: BaseException | None,
        _traceback: TracebackType | None,
    ) -> None:
        self.close()
