"""ClickHouse keyed projection over the common disk occurrence registry."""

from __future__ import annotations

import json
from collections.abc import Iterator, Mapping, MutableMapping
from typing import Any

from ....discovery_occurrences import OccurrenceLocations, OccurrenceRegistry
from ....discovery_spool import SpoolingRecords, _DiskValueReferences


class FindingStore(_DiskValueReferences, MutableMapping[str, dict[str, Any]]):
    """One registry for values, metadata and arbitrarily many unique locations."""

    def __init__(self, values: Mapping[str, Any] | None = None) -> None:
        self._registry = OccurrenceRegistry()
        assert self._registry._db is not None
        self._db = self._registry._db
        self._db.execute("ALTER TABLE findings ADD COLUMN sort_type TEXT NOT NULL DEFAULT ''")
        self._db.execute("ALTER TABLE findings ADD COLUMN sort_fp TEXT NOT NULL DEFAULT ''")
        self._db.execute("ALTER TABLE findings ADD COLUMN legacy_missing INTEGER NOT NULL DEFAULT 0")
        self._disk_refs = {}
        self._spool_refs = {}
        self.update(values or {})

    def __del__(self) -> None:
        registry = getattr(self, "_registry", None)
        if registry is not None:
            registry.finish()

    @staticmethod
    def _project(row: dict[str, Any]) -> dict[str, Any]:
        count = row.pop("occurrence_count")
        row["occurrences"] = count
        row["location_count"] = count
        return row

    def __getitem__(self, key: str) -> dict[str, Any]:
        row = self._registry.lookup(("finding", key))
        if row is None:
            raise KeyError(key)
        return self._project(row)

    def __setitem__(self, key: str, value: dict[str, Any]) -> None:
        locations = value.get("locations") or []
        same_owner = isinstance(locations, OccurrenceLocations) and locations.reference_owner is self._registry
        with self._registry.transaction() as db:
            ordinal = self._registry.set_payload(("finding", key), value)
            if not same_owner:
                db.execute("DELETE FROM occurrences WHERE finding=?", (ordinal,))
                db.execute("UPDATE findings SET occurrence_count=0, locations_bytes=2 WHERE ordinal=?", (ordinal,))
                for place in locations:
                    self._registry.add(value, location=place, identity=("finding", key))
                declared = max(int(value.get("occurrences") or 0), int(value.get("location_count") or 0))
                missing = max(0, declared - len(locations), int(value.get("locations_complete") is False))
                db.execute("UPDATE findings SET legacy_missing=? WHERE ordinal=?", (missing, ordinal))
            db.execute(
                "UPDATE findings SET sort_type=?,sort_fp=? WHERE ordinal=?",
                (str(value.get("type") or ""), str(value.get("fingerprint") or ""), ordinal),
            )

    def record_location(self, key: str, finding: dict[str, Any], location: Mapping[str, Any]) -> None:
        with self._registry.transaction():
            # Preserve virtual __setitem__ for adapter fault-injection/contracts.
            self[key] = finding
            self._registry.add(finding, location=location, identity=("finding", key))

    def import_finding(self, key: str, finding: dict[str, Any]) -> None:
        """Merge legacy type-keyed checkpoint entries sharing the same value."""
        current = self.get(key)
        if current is None:
            self[key] = finding
            return
        incoming = finding.get("locations") or []
        with self._registry.transaction() as db:
            self[key] = {**finding, "locations": current["locations"]}
            for location in incoming:
                self._registry.add(finding, location=location, identity=("finding", key))
            missing = max(
                0, int(finding.get("occurrences") or 0) - len(incoming), int(finding.get("locations_complete") is False)
            )
            if missing:
                db.execute(
                    "UPDATE findings SET legacy_missing=MAX(legacy_missing,?) WHERE fingerprint=? AND detector='finding'",
                    (missing, key),
                )

    def __delitem__(self, key: str) -> None:
        with self._registry.transaction() as db:
            row = db.execute(
                "SELECT ordinal FROM findings WHERE detector='finding' AND fingerprint=?", (key,)
            ).fetchone()
            if row is None:
                raise KeyError(key)
            db.execute("DELETE FROM occurrences WHERE finding=?", row)
            db.execute("DELETE FROM findings WHERE ordinal=?", row)
            self._registry._count -= 1

    def __iter__(self) -> Iterator[str]:
        for (key,) in self._db.execute("SELECT fingerprint FROM findings ORDER BY ordinal"):
            yield key

    def __len__(self) -> int:
        return len(self._registry)

    def occurrence_count(self) -> int:
        return int(self._db.execute("SELECT COALESCE(SUM(occurrence_count),0) FROM findings").fetchone()[0])

    def has_incomplete_locations(self) -> bool:
        return self._db.execute("SELECT 1 FROM findings WHERE legacy_missing>0 LIMIT 1").fetchone() is not None

    def _records(self, query: str, parameters: tuple[Any, ...] = ()) -> SpoolingRecords:
        def payloads() -> Iterator[str]:
            for ordinal, payload, count, size, missing in self._db.execute(query, parameters):
                encoded = json.loads(payload)
                pending: dict[str, Any] = {}
                locations = OccurrenceLocations(self._registry, ordinal, count, size)
                encoded["locations"] = self._encode_disk_refs(locations, pending)
                encoded["occurrences"] = encoded["location_count"] = count
                if missing:
                    encoded["locations_complete"] = False
                self._commit_refs(pending)
                yield json.dumps(encoded, ensure_ascii=False)

        self._disk_refs.update(self._registry._disk_refs)
        self._spool_refs.update(self._registry._spool_refs)
        result = SpoolingRecords._from_encoded_records(payloads(), self)
        return result

    def created_after(self, ordinal: int) -> SpoolingRecords:
        return self._records(
            "SELECT ordinal,payload,occurrence_count,locations_bytes,legacy_missing FROM findings WHERE ordinal>? ORDER BY ordinal",
            (ordinal,),
        )

    def sorted_values(self) -> SpoolingRecords:
        return self._records(
            "SELECT ordinal,payload,occurrence_count,locations_bytes,legacy_missing FROM findings ORDER BY sort_type,sort_fp"
        )
