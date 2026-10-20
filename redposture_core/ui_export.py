"""Durable, append-only storage for explicitly requested full UI reads."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import time
from contextlib import closing
from pathlib import Path
from typing import Any


class UIExport:
    """Keep page results on disk so a long UI read can resume without duplicates."""

    def __init__(
        self,
        directory: str,
        target: str,
        product: str,
        *,
        resume: bool | None,
        scope: dict[str, Any] | None = None,
    ) -> None:
        root = Path(directory).expanduser()
        root.mkdir(parents=True, exist_ok=True)
        identity = json.dumps(
            {"target": target, "product": product, "scope": scope or {}},
            sort_keys=True,
            separators=(",", ":"),
        )
        digest = hashlib.sha256(identity.encode()).hexdigest()[:16]
        stem = f"{product}-{digest}"
        self.database = root / f"{stem}.sqlite3"
        self.output = root / f"{stem}.jsonl"
        if resume is None:
            candidates = sorted(
                ([self.database] if self.database.exists() else []) + list(root.glob(f"{stem}-*.sqlite3")),
                key=lambda path: path.stat().st_mtime_ns,
                reverse=True,
            )
            if candidates:
                candidate = candidates[0]
                with closing(sqlite3.connect(candidate)) as previous_connection:
                    row = previous_connection.execute("SELECT value FROM meta WHERE key='complete'").fetchone()
                if row is None or row[0] != "True":
                    self.database = candidate
                    self.output = candidate.with_suffix(".jsonl")
                    resume = True
            if resume is None and candidates:
                stem += f"-{time.time_ns()}"
                self.database = root / f"{stem}.sqlite3"
                self.output = root / f"{stem}.jsonl"
        if self.database.exists() and resume is False:
            raise FileExistsError(f"UI export already exists: {self.database}")
        if not self.database.exists() and resume:
            raise FileNotFoundError(f"UI export checkpoint not found: {self.database}")
        self.connection = sqlite3.connect(self.database)
        os.chmod(self.database, 0o600)
        self.connection.execute("CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        self.connection.execute(
            "CREATE TABLE IF NOT EXISTS records ("
            "sequence INTEGER PRIMARY KEY AUTOINCREMENT, key TEXT UNIQUE NOT NULL, payload TEXT NOT NULL)"
        )
        previous = self.connection.execute("SELECT value FROM meta WHERE key='identity'").fetchone()
        if previous is not None and previous[0] != identity:
            self.connection.close()
            raise ValueError("UI export checkpoint belongs to another target or product")
        self.connection.execute("INSERT OR IGNORE INTO meta(key,value) VALUES ('identity',?)", (identity,))
        self.connection.commit()
        self.target = target
        self.product = product
        self.new_count = 0

    def has(self, key: str) -> bool:
        return self.connection.execute("SELECT 1 FROM records WHERE key=?", (key,)).fetchone() is not None

    def get_meta(self, key: str) -> Any:
        row = self.connection.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return json.loads(row[0]) if row is not None else None

    def set_meta(self, key: str, value: Any) -> None:
        self.connection.execute(
            "INSERT OR REPLACE INTO meta(key,value) VALUES (?,?)",
            (key, json.dumps(value, ensure_ascii=False, separators=(",", ":"))),
        )
        self.connection.commit()

    def add(self, key: str, collection: str, value: Any) -> bool:
        item = {"target": self.target, "ui_product": self.product, "collection": collection, "value": value}
        cursor = self.connection.execute(
            "INSERT OR IGNORE INTO records(key,payload) VALUES (?,?)",
            (key, json.dumps(item, ensure_ascii=False, separators=(",", ":"), default=str)),
        )
        if not cursor.rowcount:
            return False
        self.new_count += 1
        self.connection.commit()
        return True

    @property
    def count(self) -> int:
        row = self.connection.execute("SELECT count(*) FROM records").fetchone()
        return int(row[0]) if row is not None else 0

    def finish(self, *, complete: bool, reason: str | None = None) -> dict[str, Any]:
        temporary = self.output.with_suffix(".jsonl.tmp")
        descriptor = os.open(temporary, os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            os.fchmod(stream.fileno(), 0o600)
            for (payload,) in self.connection.execute("SELECT payload FROM records ORDER BY sequence"):
                stream.write(payload + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, self.output)
        self.connection.execute("INSERT OR REPLACE INTO meta(key,value) VALUES ('complete',?)", (str(complete),))
        self.connection.commit()
        return {
            "count": self.count,
            "items": [str(self.output)],
            "path": str(self.output),
            "checkpoint": str(self.database),
            "partial": not complete,
            "reason": reason,
        }

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> UIExport:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()
