"""Disk-backed keyed findings between ClickHouse discovery chunks."""

from __future__ import annotations

import json
import sqlite3
import tempfile
from collections.abc import Iterator, Mapping, MutableMapping
from pathlib import Path
from typing import Any

from ....discovery_spool import SpoolingRecords, _DiskValueReferences
from ....discovery_values import DiskBackedText


class FindingStore(_DiskValueReferences, MutableMapping[str, dict[str, Any]]):
    """Read/modify/write findings without retaining the complete result in RAM."""

    def __init__(self, values: Mapping[str, Any] | None = None) -> None:
        self._temporary = tempfile.TemporaryDirectory(prefix="redposture-clickhouse-findings-")
        self._path = Path(self._temporary.name) / "findings.sqlite3"
        self._db = sqlite3.connect(self._path, isolation_level=None)
        self._db.execute("PRAGMA journal_mode=MEMORY")
        self._db.execute("PRAGMA synchronous=OFF")
        self._db.execute(
            "CREATE TABLE findings (ordinal INTEGER PRIMARY KEY, identity TEXT UNIQUE NOT NULL, "
            "sort_type TEXT NOT NULL, fingerprint TEXT NOT NULL, occurrences INTEGER NOT NULL, payload TEXT NOT NULL)"
        )
        self._disk_refs = {}
        self._spool_refs = {}
        self.update(values or {})

    def __del__(self) -> None:
        db = getattr(self, "_db", None)
        if db is not None:
            db.close()
        temporary = getattr(self, "_temporary", None)
        if temporary is not None:
            temporary.cleanup()

    def __getitem__(self, key: str) -> dict[str, Any]:
        row = self._db.execute("SELECT payload FROM findings WHERE identity=?", (key,)).fetchone()
        if row is None:
            raise KeyError(key)
        return self._decode_disk_refs(json.loads(row[0]))

    def __setitem__(self, key: str, value: dict[str, Any]) -> None:
        pending: dict[str, DiskBackedText] = {}
        encoded = self._encode_disk_refs(value, pending)
        try:
            self._db.execute(
                "INSERT INTO findings(identity,sort_type,fingerprint,occurrences,payload) VALUES (?,?,?,?,?) "
                "ON CONFLICT(identity) DO UPDATE SET occurrences=excluded.occurrences,payload=excluded.payload",
                (
                    key,
                    str(value.get("type") or ""),
                    str(value.get("fingerprint") or ""),
                    int(value.get("occurrences") or 0),
                    json.dumps(encoded),
                ),
            )
        except sqlite3.Error as exc:
            raise OSError(f"ClickHouse finding storage failure: {exc}") from exc
        self._commit_refs(pending)

    def __delitem__(self, key: str) -> None:
        cursor = self._db.execute("DELETE FROM findings WHERE identity=?", (key,))
        if not cursor.rowcount:
            raise KeyError(key)

    def __iter__(self) -> Iterator[str]:
        for (key,) in self._db.execute("SELECT identity FROM findings ORDER BY ordinal"):
            yield key

    def __len__(self) -> int:
        return self._db.execute("SELECT COUNT(*) FROM findings").fetchone()[0]

    def occurrence_count(self) -> int:
        """Aggregate a scalar without reading and decoding all secret values."""
        return self._db.execute("SELECT COALESCE(SUM(occurrences),0) FROM findings").fetchone()[0]

    def created_after(self, ordinal: int) -> SpoolingRecords:
        """Copy this chunk's new final records, without a growing key snapshot."""
        rows = self._db.execute("SELECT payload FROM findings WHERE ordinal>? ORDER BY ordinal", (ordinal,))
        return SpoolingRecords._from_encoded_records((payload for (payload,) in rows), self)

    def sorted_values(self) -> SpoolingRecords:
        rows = self._db.execute("SELECT payload FROM findings ORDER BY sort_type,fingerprint")
        return SpoolingRecords._from_encoded_records((payload for (payload,) in rows), self)
