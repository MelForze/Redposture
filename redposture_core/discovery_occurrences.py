"""Disk-backed finding identities and every unique source location.

Location rows never grow a finding's JSON payload. Views keep the shared store
alive through final output, with one database/text arena per registry rather
than one open file or a Python list per occurrence.
"""

from __future__ import annotations

import hashlib
import json
import operator
import sqlite3
import threading
import uuid
from collections.abc import Callable, Iterator, Mapping
from contextlib import closing, contextmanager
from itertools import zip_longest
from typing import Any

from .discovery_containers import DiskSequence
from .discovery_spool import SpoolingFindings, _slice_values
from .discovery_values import iter_json_chunks


class OccurrenceLocations(DiskSequence):
    """Ordered read-only locations, independent of the number of occurrences."""

    def __init__(self, owner: OccurrenceRegistry, ordinal: int, count: int, size: int) -> None:
        self._owner = owner
        self._ordinal = ordinal
        self._count = count
        self._size = size

    @property
    def reference_owner(self) -> OccurrenceRegistry:
        return self._owner

    @property
    def reference_locator(self) -> tuple[int, int, int]:
        return self._ordinal, self._count, self._size

    @property
    def byte_length(self) -> int:
        return self._size

    def __len__(self) -> int:
        return self._count

    def __iter__(self) -> Iterator[Any]:
        with closing(sqlite3.connect(self._owner._path)) as db:
            for (payload,) in db.execute(
                "SELECT payload FROM occurrences WHERE finding=? ORDER BY ordinal LIMIT ?", (self._ordinal, self._count)
            ):
                yield self._owner._load_record(payload)

    def __getitem__(self, index: Any) -> Any:
        if isinstance(index, slice):
            return _slice_values(self, index)
        position = operator.index(index)
        if position < 0:
            position += len(self)
        if not 0 <= position < len(self):
            raise IndexError(index)
        with closing(sqlite3.connect(self._owner._path)) as db:
            row = db.execute(
                "SELECT payload FROM occurrences WHERE finding=? ORDER BY ordinal LIMIT 1 OFFSET ?",
                (self._ordinal, position),
            ).fetchone()
        if row is None:
            raise IndexError(index)
        return self._owner._load_record(row[0])

    def __repr__(self) -> str:
        return f"OccurrenceLocations(count={self._count})"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, (list, tuple)):
            return NotImplemented
        missing = object()
        return all(a == b for a, b in zip_longest(self, other, fillvalue=missing))

    def __ne__(self, other: object) -> bool:
        result = self.__eq__(other)
        return NotImplemented if result is NotImplemented else not result

    def __contains__(self, value: object) -> bool:
        return any(location == value for location in self)

    def __reversed__(self) -> Iterator[Any]:
        with closing(sqlite3.connect(self._owner._path)) as db:
            for (payload,) in db.execute(
                "SELECT payload FROM (SELECT ordinal,payload FROM occurrences WHERE finding=? ORDER BY ordinal LIMIT ?) ORDER BY ordinal DESC",
                (self._ordinal, self._count),
            ):
                yield self._owner._load_record(payload)


class OccurrenceRegistry(SpoolingFindings):
    """One finding payload per identity, any number of unique locations.

    ``add`` returns whether the value was first seen, suitable for one early
    live finding. Every accepted location remains visible in the final result.
    An explicit identity lets the unified engine deduplicate by value while
    legacy adapters retain their existing detector/fingerprint contract.
    """

    def __init__(self, *, check: Callable[[], None] | None = None, source_order: bool = False) -> None:
        super().__init__()
        self.reference_id = uuid.uuid4().hex
        self._lock = threading.RLock()
        self._check = check
        self._source_order = source_order
        assert self._db is not None
        self._db.execute("PRAGMA cache_size=-1024")
        self._db.execute("PRAGMA temp_store=FILE")
        self._db.execute("ALTER TABLE findings ADD COLUMN occurrence_count INTEGER NOT NULL DEFAULT 0")
        self._db.execute("ALTER TABLE findings ADD COLUMN locations_bytes INTEGER NOT NULL DEFAULT 2")
        self._db.execute("ALTER TABLE findings ADD COLUMN sort_key TEXT NOT NULL DEFAULT ''")
        self._db.execute(
            "CREATE TABLE occurrences (ordinal INTEGER PRIMARY KEY, finding INTEGER NOT NULL, "
            "digest TEXT NOT NULL, payload TEXT NOT NULL, UNIQUE(finding,digest))"
        )

    def restore(self, locator: Any) -> OccurrenceLocations:
        return OccurrenceLocations(self, *locator)

    def finish(self) -> None:
        with self._lock:
            super().finish()
            # Output keeps this owner alive, not the request context/deadline.
            self._check = None

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        """Group adapter metadata and locations into one rollback boundary."""
        with self._lock:
            if self._db is None:
                raise RuntimeError("finding registry is finalized")
            try:
                with self._event(self._db):
                    yield self._db
            except sqlite3.Error as exc:
                raise OSError(f"discovery occurrence storage failure: {exc}") from exc

    def set_payload(self, identity: tuple[str, str], finding: Mapping[str, Any]) -> int:
        """Update adapter metadata without copying its growing location catalog.

        Adapters publishing a new finding must append its verified location in
        the same transaction. Metadata-only entries remain usable by legacy
        keyed stores, but are not evidence of a completed source inspection.
        """
        if not all(identity):
            raise ValueError("finding identity requires a detector and fingerprint")
        payload = {key: value for key, value in finding.items() if key not in {"locations", "occurrence_count"}}
        with self.transaction() as db:
            row = db.execute("SELECT ordinal FROM findings WHERE detector=? AND fingerprint=?", identity).fetchone()
            if row is None:
                super().add(payload, identity=identity)
                row = db.execute("SELECT ordinal FROM findings WHERE detector=? AND fingerprint=?", identity).fetchone()
            else:
                pending: dict[str, Any] = {}
                try:
                    encoded = json.dumps(self._encode_disk_refs(payload, pending), ensure_ascii=False)
                    db.execute("UPDATE findings SET payload=? WHERE ordinal=?", (encoded, row[0]))
                except BaseException:
                    self._abort_refs(pending)
                    raise
                self._commit_refs(pending)
            assert row is not None
            return int(row[0])

    def bounded_inline_view(self, *, max_bytes: int = 65_536, max_findings: int = 4096) -> list[dict[str, Any]]:
        """Keep small output contracts while retaining large results on disk.

        The registry always records occurrences on disk. A completed small
        result may be projected inline for existing JSON/callback consumers;
        neither a large value nor a large occurrence list is materialized.
        """
        if len(self) >= max(1, max_findings):
            return self
        chunks = iter_json_chunks(self, max_chars=4096)
        prefix: list[str] = []
        size = 0
        try:
            for chunk in chunks:
                size += len(chunk.encode("utf-8"))
                if size > max_bytes:
                    return self
                prefix.append(chunk)
        finally:
            close = getattr(chunks, "close", None)
            if close is not None:
                close()
        # Size measurement must not turn retained disk values into a second,
        # materialized representation or change their ownership contract.
        return [{**finding, "locations": list(finding["locations"])} for finding in self]

    @contextmanager
    def _event(self, db: sqlite3.Connection) -> Iterator[None]:
        count = self._count
        db.execute("SAVEPOINT finding_event")
        try:
            yield
            db.execute("RELEASE finding_event")
        except BaseException:
            try:
                db.execute("ROLLBACK TO finding_event")
                db.execute("RELEASE finding_event")
            finally:
                self._count = count
            raise

    def _location_identity(self, location: Mapping[str, Any]) -> tuple[str, int]:
        digest = hashlib.sha256()
        size = 0
        # Locators have scalar keys; canonical key order makes replay/page
        # repeats idempotent without converting large values into strings.
        for chunk in iter_json_chunks({key: location[key] for key in sorted(location)}, max_chars=4096):
            if self._check is not None:
                self._check()
            encoded = chunk.encode("utf-8")
            digest.update(encoded)
            size += len(encoded)
        return digest.hexdigest(), size

    def add(
        self,
        finding: Mapping[str, Any],
        *,
        location: Mapping[str, Any] | None = None,
        emitted: bool = False,
        merge_emission: bool = False,
        identity: tuple[str, str] | None = None,
        order_key: str | None = None,
    ) -> bool:
        key = identity or (str(finding.get("type") or ""), str(finding.get("fingerprint") or ""))
        if not all(key):
            raise ValueError("finding identity requires a detector and fingerprint")
        place = (
            dict(location)
            if location is not None
            else {name: finding[name] for name in ("source", "object_path") if name in finding}
        )
        if not place:
            raise ValueError("finding requires a source location")
        digest, size = self._location_identity(place)
        with self._lock:
            db = self._db
            if db is None:
                raise RuntimeError("finding registry is finalized")
            try:
                with self._event(db):
                    existing = db.execute(
                        "SELECT ordinal FROM findings WHERE detector=? AND fingerprint=?", key
                    ).fetchone()
                    created = existing is None
                    if created:
                        payload = {k: v for k, v in finding.items() if k not in {"locations", "occurrence_count"}}
                        super().add(payload, emitted=emitted, identity=key)
                        existing = db.execute(
                            "SELECT ordinal FROM findings WHERE detector=? AND fingerprint=?", key
                        ).fetchone()
                    elif emitted and merge_emission:
                        db.execute("UPDATE findings SET emitted=1 WHERE ordinal=?", (existing[0],))
                    assert existing is not None
                    ordinal = existing[0]
                    if order_key is not None:
                        db.execute(
                            "UPDATE findings SET sort_key=CASE WHEN sort_key='' OR sort_key>? THEN ? ELSE sort_key END WHERE ordinal=?",
                            (order_key, order_key, ordinal),
                        )
                    if db.execute(
                        "SELECT 1 FROM occurrences WHERE finding=? AND digest=?", (ordinal, digest)
                    ).fetchone():
                        return created
                    pending: dict[str, Any] = {}
                    try:
                        serialized = json.dumps(self._encode_disk_refs(place, pending), ensure_ascii=False)
                        db.execute(
                            "INSERT INTO occurrences(finding,digest,payload) VALUES (?,?,?)",
                            (ordinal, digest, serialized),
                        )
                        db.execute(
                            "UPDATE findings SET occurrence_count=occurrence_count+1, "
                            "locations_bytes=locations_bytes+?+CASE WHEN occurrence_count>0 THEN 1 ELSE 0 END "
                            "WHERE ordinal=?",
                            (size, ordinal),
                        )
                    except BaseException:
                        self._abort_refs(pending)
                        raise
                    self._commit_refs(pending)
                    return created
            except sqlite3.Error as exc:
                raise OSError(f"discovery occurrence storage failure: {exc}") from exc

    def _finding(self, row: Any) -> dict[str, Any]:
        ordinal, payload, count, size = row
        result = self._load_record(payload)
        result["occurrence_count"] = count
        result["locations"] = OccurrenceLocations(self, ordinal, count, size)
        return result

    def lookup(self, identity: tuple[str, str]) -> dict[str, Any] | None:
        """Read a current snapshot without finalizing an active producer."""
        with self._lock:
            if self._db is not None:
                row = self._db.execute(
                    "SELECT ordinal,payload,occurrence_count,locations_bytes FROM findings WHERE detector=? AND fingerprint=?",
                    identity,
                ).fetchone()
            else:
                with closing(sqlite3.connect(self._path)) as db:
                    row = db.execute(
                        "SELECT ordinal,payload,occurrence_count,locations_bytes FROM findings WHERE detector=? AND fingerprint=?",
                        identity,
                    ).fetchone()
            return self._finding(row) if row is not None else None

    def _rows(self, *, only_unemitted: bool = False, reverse: bool = False) -> Iterator[dict[str, Any]]:
        self.finish()
        query = "SELECT ordinal,payload,occurrence_count,locations_bytes FROM findings"
        if only_unemitted:
            query += " WHERE emitted=0"
        query += " ORDER BY " + self._order(reverse=reverse)
        with closing(sqlite3.connect(self._path)) as db:
            for row in db.execute(query):
                yield self._finding(row)

    def iter_with_emission(self) -> Iterator[tuple[dict[str, Any], bool]]:
        self.finish()
        with closing(sqlite3.connect(self._path)) as db:
            for row in db.execute(
                "SELECT ordinal,payload,occurrence_count,locations_bytes,emitted FROM findings ORDER BY "
                + self._order()
            ):
                yield self._finding(row[:4]), bool(row[4])

    def _order(self, *, reverse: bool = False) -> str:
        direction = " DESC" if reverse else ""
        return (f"sort_key{direction}," if self._source_order else "") + f"ordinal{direction}"

    def __getitem__(self, index: Any) -> Any:
        if isinstance(index, slice):
            return _slice_values(self, index)
        position = operator.index(index)
        if position < 0:
            position += len(self)
        if not 0 <= position < len(self):
            raise IndexError(index)
        self.finish()
        with closing(sqlite3.connect(self._path)) as db:
            row = db.execute(
                "SELECT ordinal,payload,occurrence_count,locations_bytes FROM findings ORDER BY "
                + self._order()
                + " LIMIT 1 OFFSET ?",
                (position,),
            ).fetchone()
        if row is None:
            raise IndexError(index)
        return self._finding(row)
