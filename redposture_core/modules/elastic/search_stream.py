"""Bounded decoding of an oversized, single-hit Elastic search response."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, BinaryIO

from ...discovery_paths import Text
from ...discovery_values import DiskBackedText
from ...json_stream import JSONPath, JSONScalarStream

Path = JSONPath
_SOURCE_PATH: Path = ("hits", "hits", 0, "_source")
_METADATA_PATHS: frozenset[Path] = frozenset(
    {
        ("pit_id",),
        ("id",),
        ("_scroll_id",),
        ("timed_out",),
        ("_shards", "failed"),
        ("hits", "total"),
        ("hits", "total", "value"),
        ("hits", "total", "relation"),
        ("hits", "hits", 0, "_index"),
        ("hits", "hits", 0, "_id"),
    }
)


class SearchStreamError(ValueError):
    """The streamed response cannot be verified as one complete search page."""


class StreamedSearchPage:
    """Reparse a disk-spooled response without retaining a large source field."""

    def __init__(self, file: BinaryIO, *, inline_limit: int = 256 * 1024, incomplete: bool = False) -> None:
        self.file = file
        self.inline_limit = max(1, inline_limit)
        self.incomplete = incomplete
        self.large_paths: set[Path] = set()
        self.resolved_paths: set[Path] = set()
        self.source_bytes = 0
        self.deadline: float | None = None

    def _walk(
        self,
        on_string: Callable[[Path, str, bool], None],
        *,
        on_primitive: Callable[[tuple[Path, Any]], None] | None = None,
        on_container: Callable[[Path, str], None] | None = None,
    ) -> None:
        self.file.seek(0)
        parser = JSONScalarStream(
            on_string, on_primitive=on_primitive, on_container=on_container, deadline=self.deadline
        )
        while chunk := self.file.read(64 * 1024):
            parser.feed(chunk)
        if not self.incomplete:
            parser.finish()
        if parser.root_kind != "object":
            raise SearchStreamError("search response is not an object")

    def summary(self) -> dict[str, Any]:
        metadata: dict[Path, Any] = {}
        fragments: dict[Path, list[str]] = {}
        hit_count = 0
        saw_hits_array = False
        saw_source = False
        saw_extra_fields = False

        def on_container(path: Path, kind: str) -> None:
            nonlocal hit_count, saw_hits_array, saw_source, saw_extra_fields
            if path == ("hits", "hits"):
                saw_hits_array = kind == "array"
            elif len(path) == 3 and path[:2] == ("hits", "hits") and isinstance(path[2], int):
                if kind != "object":
                    raise SearchStreamError("search hit is not an object")
                hit_count += 1
                if hit_count > 1:
                    raise SearchStreamError("streamed search page contains more than one hit")
            elif path == _SOURCE_PATH:
                saw_source = kind in {"object", "array"}
            elif path in {("hits", "hits", 0, "fields"), ("hits", "hits", 0, "stored_fields")}:
                saw_extra_fields = True

        def relevant(path: Path) -> bool:
            return path in _METADATA_PATHS or (path[:5] == ("hits", "hits", 0, "sort", 0))

        def on_string(path: Path, fragment: str, final: bool) -> None:
            if not relevant(path):
                return
            parts = fragments.setdefault(path, [])
            parts.append(fragment)
            if sum(map(len, parts)) > 8192:
                raise SearchStreamError("search metadata exceeds bounded portion")
            if final:
                metadata[path] = "".join(parts)
                fragments.pop(path, None)

        def on_primitive(item: tuple[Path, Any]) -> None:
            path, value = item
            if relevant(path):
                metadata[path] = value

        self._walk(on_string, on_primitive=on_primitive, on_container=on_container)
        if not saw_hits_array or hit_count > 1 or (hit_count == 1 and not saw_source):
            raise SearchStreamError("search page lacks readable hits")
        hits: list[dict[str, Any]] = []
        if hit_count:
            hit: dict[str, Any] = {"_source": {}}
            for name in ("_index", "_id"):
                value = metadata.get(("hits", "hits", 0, name))
                if isinstance(value, str):
                    hit[name] = value
            sort = metadata.get(("hits", "hits", 0, "sort", 0))
            if sort is not None:
                hit["sort"] = [sort]
            if saw_extra_fields:
                hit["_stream_extra_fields"] = True
            hits.append(hit)
        total_value = metadata.get(("hits", "total", "value"), metadata.get(("hits", "total"), 1))
        relation = metadata.get(("hits", "total", "relation"), "eq")
        result: dict[str, Any] = {"hits": {"total": {"value": total_value, "relation": relation}, "hits": hits}}
        for name in ("pit_id", "id", "_scroll_id", "timed_out"):
            value = metadata.get((name,))
            if value is not None:
                result[name] = value
        shard_failures = metadata.get(("_shards", "failed"))
        if shard_failures is not None:
            result["_shards"] = {"failed": shard_failures}
        return result

    @staticmethod
    def _put(root: dict[Text, Any] | list[Any], path: Path, value: Any) -> None:
        current: dict[Text, Any] | list[Any] = root
        for part in path[:-1]:
            current = current[part]  # type: ignore[index]
        last = path[-1]
        if isinstance(current, list) and isinstance(last, int):
            while len(current) <= last:
                current.append(None)
            current[last] = value
        elif isinstance(current, dict) and isinstance(last, (str, DiskBackedText)):
            current[last] = value
        else:
            raise SearchStreamError("invalid source container path")

    def compact_source(self) -> dict[Text, Any] | list[Any]:
        root: dict[Text, Any] | list[Any] = {}
        active_path: Path | None = None
        parts: list[str] = []
        size = 0
        nodes = 0

        def on_container(path: Path, kind: str) -> None:
            nonlocal root, nodes
            if path[: len(_SOURCE_PATH)] != _SOURCE_PATH:
                return
            nodes += 1
            if nodes > 100_000:
                raise SearchStreamError("source has too many containers")
            relative = path[len(_SOURCE_PATH) :]
            value: dict[Text, Any] | list[Any] = {} if kind == "object" else []
            if not relative:
                root = value
            else:
                self._put(root, relative, value)

        def on_string(path: Path, fragment: str, final: bool) -> None:
            nonlocal active_path, parts, size, nodes
            if path[: len(_SOURCE_PATH)] != _SOURCE_PATH:
                return
            if active_path != path:
                active_path, parts, size = path, [], 0
            encoded_size = len(fragment.encode("utf-8"))
            self.source_bytes += encoded_size
            size += encoded_size
            if path not in self.large_paths:
                if size > self.inline_limit:
                    self.large_paths.add(path)
                    parts.clear()
                else:
                    parts.append(fragment)
            if final:
                nodes += 1
                if nodes > 100_000:
                    raise SearchStreamError("source has too many fields")
                relative = path[len(_SOURCE_PATH) :]
                if not relative:
                    raise SearchStreamError("scalar root source is unsupported")
                self._put(root, relative, "" if path in self.large_paths else "".join(parts))
                active_path, parts, size = None, [], 0

        def on_primitive(item: tuple[Path, Any]) -> None:
            nonlocal nodes
            path, value = item
            if path[: len(_SOURCE_PATH)] != _SOURCE_PATH:
                return
            nodes += 1
            if nodes > 100_000:
                raise SearchStreamError("source has too many fields")
            relative = path[len(_SOURCE_PATH) :]
            if not relative:
                raise SearchStreamError("scalar root source is unsupported")
            self._put(root, relative, value)

        self._walk(on_string, on_primitive=on_primitive, on_container=on_container)
        return root

    def scan_large_fields(
        self,
        on_segment: Callable[[Path, str], None],
        *,
        on_scalar: Callable[[Path, DiskBackedText], bool] | None = None,
    ) -> bool:
        """Emit delimiter-complete scalar pieces; report undecidable strings."""
        current_path: Path | None = None
        pending = ""
        skipping = False
        problem_paths: set[Path] = set()
        current_disk: DiskBackedText | None = None
        self.resolved_paths.clear()
        window = min(self.inline_limit, 256 * 1024)
        delimiters = " \t\r\n,;\"'"

        def on_string(path: Path, fragment: str, final: bool) -> None:
            nonlocal current_path, pending, skipping, current_disk
            if path not in self.large_paths:
                return
            if current_path != path:
                current_path, pending, skipping = path, "", False
                if on_scalar is not None:
                    current_disk = DiskBackedText()
            if current_disk is not None:
                current_disk.append_text(fragment)
                if final:
                    current_disk.finish()
                    if on_scalar is not None and on_scalar(path, current_disk):
                        self.resolved_paths.add(path)
                    else:
                        problem_paths.add(path)
                        current_disk.close()
                    current_disk = None
                    pending, current_path, skipping = "", None, False
                # A delimiter within a quoted value or a JWT payload is not
                # a completed secret. The scalar owner validates the whole
                # value and streams only its own completed candidates.
                return
            if any(marker in fragment for marker in ("-----BEGIN", "-----END", "{", "[")):
                problem_paths.add(path)
            for piece in fragment.splitlines(keepends=True):
                if skipping:
                    boundary = next((i for i, char in enumerate(piece) if char in delimiters), None)
                    if boundary is None:
                        continue
                    piece = piece[boundary + 1 :]
                    skipping = False
                pending += piece
                while len(pending.encode("utf-8")) > window:
                    prefix = pending[:window]
                    cut = max(prefix.rfind(char) for char in delimiters)
                    if cut < 0:
                        problem_paths.add(path)
                        pending = pending[len(prefix) :]
                        skipping = True
                        continue
                    on_segment(path, pending[: cut + 1])
                    pending = pending[cut + 1 :]
            if final:
                if pending and not skipping:
                    on_segment(path, pending)
                if current_disk is not None:
                    current_disk.finish()
                    if on_scalar is not None and on_scalar(path, current_disk):
                        self.resolved_paths.add(path)
                    else:
                        current_disk.close()
                    current_disk = None
                pending, current_path, skipping = "", None, False

        try:
            self._walk(on_string)
        finally:
            if current_disk is not None:
                current_disk.close()
        return not (problem_paths - self.resolved_paths)

    def close(self) -> None:
        self.file.close()
