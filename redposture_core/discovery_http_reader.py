"""Read-only, disk-backed JSON for source adapters with a shared deadline."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from tempfile import SpooledTemporaryFile
from typing import Any

from .discovery_json import DiskJSONDocument
from .json_stream import JSONPath
from .storage_discovery import DiscoveryCollector, JSONChunkScan


def read_json(
    collector: DiscoveryCollector,
    pool: Any,
    url: str,
    source: str,
    *,
    source_class: str,
    headers: Mapping[str, str],
    timeout: float,
    root: str = "object",
    scan: bool = True,
    project: Callable[[Any], Any] | None = None,
    required_fields: tuple[str, ...] = (),
    exclude: Callable[[JSONPath], bool] | None = None,
) -> Any:
    """Return disk-backed catalogs; scan only authorized, closed JSON values.

    No response-size quota or eager response.json() is used. An interrupted
    response can retain closed fields, but can never claim a complete source.
    Callers must not materialize returned catalogs with list()/dict().
    """
    if not collector.allowed():
        return None
    document = DiskJSONDocument(deadline=collector.deadline)
    stream_scan = scan and (project is None or exclude is not None)
    scanner: JSONChunkScan | None = None
    # Hold a prefix only until the expected root/schema is confirmed. Replay
    # it into the shared scanner, so early fields are never lost or trusted
    # from an unrelated HTTP-200 error document. Large prefixes spill to disk.
    prefix = SpooledTemporaryFile(max_size=65_536)
    status: int | None = None

    class StopRead(Exception):
        pass

    reason: str | None = None

    def on_response(code: int, response_headers: Mapping[str, str]) -> None:
        nonlocal status, reason
        status = code
        if code != 200:
            reason = "access_denied" if code in {401, 403} else f"HTTP {code}"
            raise StopRead
        media = next((str(v).lower() for k, v in response_headers.items() if k.lower() == "content-type"), "")
        if media and "json" not in media:
            reason = "unexpected_content_type"
            raise StopRead

    def on_chunk(chunk: bytes) -> None:
        nonlocal reason, scanner
        if not collector.charge(len(chunk)):
            reason = "discover_time"
            raise StopRead
        if stream_scan and scanner is None:
            prefix.write(chunk)
        try:
            document.feed(chunk)
        except (ValueError, UnicodeError):
            reason = "invalid_json"
        except TimeoutError:
            reason = "discover_time"
        except OSError:
            reason = "storage_failure"
        if stream_scan and reason not in {"storage_failure", "discover_time"}:
            if scanner is None:
                if document.parser.root_kind == root and all(
                    document.root_field_seen(name) for name in required_fields
                ):
                    scanner = collector.json_chunk_scanner(source, exclude=exclude)
                    prefix.seek(0)
                    while part := prefix.read(65_536):
                        if not scanner.feed(part):
                            reason = reason or "invalid_json"
                            break
                    prefix.close()
            elif not scanner.feed(chunk):
                reason = reason or "invalid_json"
        if reason:
            raise StopRead

    try:
        with collector.source_attempt(source_class, scope=source) as evidence:
            try:
                response = pool.request_stream(
                    "GET",
                    url,
                    headers=dict(headers),
                    timeout=timeout,
                    deadline=collector.deadline,
                    chunk_size=65_536,
                    on_response=on_response,
                    on_chunk=on_chunk,
                    allow_cross_origin_redirects=False,
                )
                evidence.status = status
                reason = reason or response.error or (f"HTTP {response.status}" if response.status != 200 else None)
                if response.truncated:
                    reason = reason or "truncated_response"
                if reason:
                    raise StopRead
                value = document.finish()
                valid = (
                    isinstance(value, Mapping)
                    if root == "object"
                    else isinstance(value, Sequence) and not isinstance(value, (str, bytes))
                )
                if not valid:
                    reason = "invalid_json_root"
                    raise StopRead
                if required_fields and (
                    not isinstance(value, Mapping) or any(name not in value for name in required_fields)
                ):
                    reason = "required_json_field_missing"
                    raise StopRead
                if scan:
                    if stream_scan:
                        if scanner is None or not scanner.finish():
                            reason = "invalid_json"
                            raise StopRead
                    else:
                        collector.add(source, project(value) if project else value, charge=False)
                evidence.accept()
                return value
            except (StopRead, ValueError, UnicodeError, OSError, TimeoutError) as exc:
                evidence.status = status
                collector.partial(
                    source,
                    reason
                    or (
                        "discover_time"
                        if isinstance(exc, TimeoutError)
                        else "invalid_json"
                        if isinstance(exc, (ValueError, UnicodeError))
                        else "read_failed"
                    ),
                )
                if scanner is not None:
                    # An interrupted source is distinct from cancellation:
                    # flush closed credential fields, never an unfinished
                    # group/value. Respect an exhausted target deadline.
                    scanner.abort(
                        TimeoutError("discover_time")
                        if reason == "discover_time" or not collector.allowed()
                        else OSError("source interrupted")
                    )
                if (
                    scan
                    and not stream_scan
                    and status == 200
                    and reason not in {"invalid_json_root", "required_json_field_missing", "unexpected_content_type"}
                ):
                    completed = document.partial_value()
                    if completed is not None:
                        collector.add(source, project(completed) if project else completed, charge=False)
                return None
    finally:
        if scanner is not None:
            scanner.close()
        prefix.close()
        document.close()
