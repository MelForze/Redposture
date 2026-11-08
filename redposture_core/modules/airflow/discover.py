"""Read-only secret discovery in Airflow DAG sources, configuration and logs."""

from __future__ import annotations

import ast
import base64
import codecs
import json
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote, urlencode

from ...clients.airflow_api import AirflowClient
from ...data_discovery import _scan_portioned_value
from ...discovery_occurrences import OccurrenceRegistry
from ...discovery_options import DEFAULT_DISCOVER_MAX_BYTES, DEFAULT_DISCOVER_TIME, UNLIMITED_DISCOVER_BYTES
from ...discovery_paths import concat_discovery_text
from ...discovery_sources import SourceManifest, SourceRead
from ...discovery_spool import SpoolingStrings
from ...discovery_text import DiscoveryTextStream
from ...discovery_values import DiskBackedText, iter_json_chunks
from ...json_stream import JSONPath, JSONScalarStream, SingleStringFieldStream
from ...scheduler import NestedSchedulerCancelled
from ...secret_detection import fingerprint

AIRFLOW_FINDING_SPOOL_THRESHOLD = 4096


@dataclass(frozen=True)
class DiscoverConfig:
    max_dags: int | None = None
    max_runs: int | None = None
    max_tasks: int | None = None
    max_logs: int | None = None
    max_log_bytes: int | None = None
    max_bytes: int = UNLIMITED_DISCOVER_BYTES
    max_seconds: float | None = DEFAULT_DISCOVER_TIME
    max_findings: int | None = None
    include_dag_sources: bool = False
    include_variables: bool = False
    include_connections: bool = False


@dataclass(frozen=True)
class _Collection:
    items: tuple[dict[str, Any], ...]
    complete: bool
    error: str | None = None
    total: int | None = None


@dataclass
class _NetworkBudget:
    remaining: int


def _request_timeout(deadline: float | None) -> float | None:
    return max(0.001, deadline - time.monotonic()) if deadline is not None else None


def _component(value: str) -> str:
    return quote(value, safe="")


class _StreamedCollectionJSON:
    """Rebuild one oversized API page while spooling long string scalars."""

    def __init__(self) -> None:
        self.value: Any = None
        self._parts: list[str] = []
        self._active_path: JSONPath | None = None
        self._disk: DiskBackedText | None = None
        self._owned: list[DiskBackedText] = []
        self.parser = JSONScalarStream(
            self._string,
            on_primitive=self._primitive,
            on_container=self._container,
        )

    def _set(self, path: JSONPath, value: Any) -> None:
        if not path:
            self.value = value
            return
        parent = self.value
        for component in path[:-1]:
            parent = parent[component]
        final = path[-1]
        if isinstance(parent, list) and isinstance(final, int):
            if final != len(parent):
                raise ValueError("out-of-order JSON array")
            parent.append(value)
        elif isinstance(parent, dict) and isinstance(final, (str, DiskBackedText)):
            parent[final] = value
        else:
            raise ValueError("invalid JSON collection path")

    def _container(self, path: JSONPath, kind: str) -> None:
        self._set(path, {} if kind == "object" else [])

    def _primitive(self, entry: tuple[JSONPath, Any]) -> None:
        self._set(*entry)

    def _string(self, path: JSONPath, fragment: str, final: bool) -> None:
        if self._active_path is None:
            self._active_path = path
        if self._active_path != path:
            raise ValueError("overlapping JSON scalars")
        if self._disk is None and sum(map(len, self._parts)) + len(fragment) > 64 * 1024:
            self._disk = DiskBackedText()
            self._owned.append(self._disk)
            for part in self._parts:
                self._disk.append_text(part)
            self._parts.clear()
        if self._disk is None:
            self._parts.append(fragment)
        else:
            self._disk.append_text(fragment)
        if final:
            if self._disk is None:
                value: str | DiskBackedText = "".join(self._parts)
            else:
                self._disk.finish()
                value = self._disk
            self._set(path, value)
            self._disk = None
            self._parts.clear()
            self._active_path = None

    def close(self) -> None:
        for value in self._owned:
            value.close()


def _collection(
    client: AirflowClient,
    path: str,
    key: str,
    limit: int | None,
    deadline: float | None,
    *,
    order_by: str | None = None,
    start_offset: int = 0,
    cancelled: Callable[[], bool] | None = None,
    network_budget: _NetworkBudget | None = None,
) -> _Collection:
    items: list[dict[str, Any]] = []
    seen_pages: set[tuple[str, str, int]] = set()
    selected_order = order_by
    latest_total: int | None = None
    page_size_ceiling = 100
    while limit is None or len(items) < limit:
        if cancelled is not None and cancelled():
            raise NestedSchedulerCancelled("Airflow discovery cancelled")
        if deadline is not None and time.monotonic() >= deadline:
            return _Collection(tuple(items), False, "discover_time")
        page_size = min(page_size_ceiling, limit - len(items)) if limit is not None else page_size_ceiling
        query_args: dict[str, int | str] = {"limit": page_size, "offset": start_offset + len(items)}
        if selected_order is not None:
            query_args["order_by"] = selected_order
        query = urlencode(query_args)
        cap = min(2 * 1024 * 1024, network_budget.remaining) if network_budget is not None else None
        request_kwargs: dict[str, Any] = {}
        if cap is not None:
            request_kwargs["response_size_cap"] = cap
        if network_budget is not None and deadline is not None:
            request_kwargs["timeout"] = _request_timeout(deadline)
        response = client.get(
            f"{path}?{query}",
            **request_kwargs,
        )
        if response.http_status != 200:
            if response.transport_error:
                return _Collection(tuple(items), False, "transport_error")
            if response.http_status in {400, 422} and selected_order is not None and not items:
                selected_order = None
                continue
            return _Collection(tuple(items), False, f"http_{response.http_status}")
        streamed_payload: Any = None
        if network_budget is not None:
            assert cap is not None
            budget_limited = cap == network_budget.remaining
            if len(response.body) > cap or response.truncated:
                if budget_limited:
                    return _Collection(tuple(items), False, "max_bytes")
                if page_size > 1:
                    page_size_ceiling = max(1, page_size // 2)
                    continue
                decoded = _StreamedCollectionJSON()
                try:

                    def on_chunk(chunk: bytes, stream: _StreamedCollectionJSON = decoded) -> None:
                        if cancelled is not None and cancelled():
                            raise NestedSchedulerCancelled("Airflow discovery cancelled")
                        if deadline is not None and time.monotonic() >= deadline:
                            raise TimeoutError("discover_time")
                        stream.parser.feed(chunk)

                    streamed = client.get_stream(
                        f"{path}?{query}",
                        on_chunk=on_chunk,
                        timeout=_request_timeout(deadline),
                        deadline=deadline,
                    )
                    if streamed.http_status != 200 or streamed.transport_error or streamed.truncated:
                        decoded.close()
                        if streamed.http_status not in {0, 200}:
                            reason = f"http_{streamed.http_status}"
                        elif deadline is not None and time.monotonic() >= deadline:
                            reason = "discover_time"
                        elif streamed.truncated:
                            reason = "response_truncated"
                        else:
                            reason = "transport_error"
                        return _Collection(tuple(items), False, reason)
                    decoded.parser.finish()
                    streamed_payload = decoded.value
                except NestedSchedulerCancelled:
                    decoded.close()
                    raise
                except (ValueError, UnicodeError, TimeoutError):
                    decoded.close()
                    return _Collection(tuple(items), False, "invalid_collection")
            if budget_limited and response.transport_error and "exceeds limit" in response.transport_error:
                return _Collection(tuple(items), False, "max_bytes")
            if response.transport_error and "exceeds limit" in response.transport_error and page_size > 1:
                page_size_ceiling = max(1, page_size // 2)
                continue
        if response.transport_error:
            return _Collection(tuple(items), False, "transport_error")
        if response.truncated and streamed_payload is None:
            return _Collection(tuple(items), False, "response_truncated")
        payload = streamed_payload if streamed_payload is not None else response.json()
        if not isinstance(payload, dict):
            return _Collection(tuple(items), False, "invalid_collection")
        page = payload.get(key)
        if not isinstance(page, list) or any(not isinstance(item, dict) for item in page):
            return _Collection(tuple(items), False, "invalid_collection")
        raw_total = payload.get("total_entries")
        total: int | None = (
            raw_total if isinstance(raw_total, int) and not isinstance(raw_total, bool) and raw_total >= 0 else None
        )
        latest_total = total
        if not page:
            stalled = total is not None and start_offset + len(items) < total
            return _Collection(
                tuple(items),
                not stalled,
                "pagination_stalled" if stalled else None,
                total,
            )
        signature = (repr(page[0])[:256], repr(page[-1])[:256], len(page))
        if signature in seen_pages:
            return _Collection(tuple(items), False, "pagination_stalled", total)
        seen_pages.add(signature)
        items.extend(page[:page_size])
        if total is not None and start_offset + len(items) >= total:
            return _Collection(tuple(items), True, total=total)
        if total is None and len(page) < page_size:
            return _Collection(tuple(items), True, total=total)
    return _Collection(tuple(items), False, total=latest_total)


def _log_content(response_body: bytes, payload: Any) -> tuple[str, str | None]:
    if not isinstance(payload, dict) or "content" not in payload:
        return response_body.decode("utf-8", errors="replace"), None
    content = payload["content"]
    if isinstance(content, str):
        text = content
    elif isinstance(content, list):
        text = "\n".join(str(item.get("event") or "") if isinstance(item, dict) else str(item) for item in content)
    else:
        text = ""
    # Airflow 2.x can serialize multi-host task logs as the repr of
    # ``[(hostname, content), ...]``. Unwrap that transport envelope so host
    # names and the generated local-file preamble are not scanned as secrets.
    unwrapped = False
    if text.startswith("[("):
        try:
            wrapped = ast.literal_eval(text)
        except (SyntaxError, ValueError):
            wrapped = None
        if isinstance(wrapped, list) and all(
            isinstance(item, tuple) and len(item) == 2 and isinstance(item[1], str) for item in wrapped
        ):
            text = "\n".join(item[1] for item in wrapped)
            unwrapped = True
    if unwrapped:
        text = "\n".join(
            line
            for line in text.splitlines()
            if line.strip() != "*** Found local files:" and not line.strip().startswith("***   * ")
        )
    token = payload.get("continuation_token")
    return text, str(token) if isinstance(token, str) and token else None


def _continuation_at_end(token: str) -> bool:
    """Recognize Airflow's signed continuation payload without trusting it."""
    try:
        encoded = token.split(".", 1)[0]
        encoded += "=" * (-len(encoded) % 4)
        payload = json.loads(base64.urlsafe_b64decode(encoded).decode("utf-8"))
    except (ValueError, TypeError, UnicodeDecodeError, json.JSONDecodeError):
        return False
    return isinstance(payload, dict) and payload.get("end_of_log") is True


class _WrappedLogStream:
    """Decode Airflow 2.x ``[(host, log), ...]`` repr without retaining a log."""

    _ESCAPES = {
        "a": "\a",
        "b": "\b",
        "f": "\f",
        "n": "\n",
        "r": "\r",
        "t": "\t",
        "v": "\v",
        "\\": "\\",
        "'": "'",
        '"': '"',
    }

    def __init__(self, emit: Callable[[str], None]) -> None:
        self.emit = emit
        self.state = "open"
        self.quote = ""
        self.escape = ""
        self.digits = ""
        self.expected_digits = 0
        self.line: list[str] = []
        self.line_passthrough = False
        self.line_skip = False
        self.output: list[str] = []
        self.has_pair = False

    def _flush_output(self) -> None:
        if self.output:
            self.emit("".join(self.output))
            self.output.clear()

    def _queue(self, value: str) -> None:
        self.output.append(value)
        if len(self.output) >= 8192:
            self._flush_output()

    def _flush_line(self) -> None:
        line = "".join(self.line)
        if line.strip() != "*** Found local files:" and not line.strip().startswith("***   * "):
            self._queue(line)
        self.line.clear()
        self.line_passthrough = False
        self.line_skip = False

    def _content_char(self, char: str) -> None:
        if self.line_skip:
            if char == "\n":
                self.line_skip = False
            return
        if self.line_passthrough:
            self._queue(char)
            if char == "\n":
                self.line_passthrough = False
            return
        self.line.append(char)
        if len(self.line) == 8 and "".join(self.line) == "***   * ":
            self.line.clear()
            self.line_skip = True
            return
        if char == "\n":
            self._flush_line()
        elif len(self.line) >= 128:
            self._queue("".join(self.line))
            self.line.clear()
            self.line_passthrough = True

    def _decoded_char(self, char: str) -> None:
        if self.state == "content":
            self._content_char(char)

    def _string_char(self, char: str) -> None:
        if self.escape == "start":
            self.escape = ""
            if char in self._ESCAPES:
                self._decoded_char(self._ESCAPES[char])
            elif char in "xuU":
                self.escape = "hex"
                self.expected_digits = {"x": 2, "u": 4, "U": 8}[char]
                self.digits = ""
            elif char in "01234567":
                self.escape = "octal"
                self.digits = char
            else:
                raise ValueError("unsupported Python string escape")
            return
        if self.escape == "hex":
            if char not in "0123456789abcdefABCDEF":
                raise ValueError("invalid Python hex escape")
            self.digits += char
            if len(self.digits) == self.expected_digits:
                self._decoded_char(chr(int(self.digits, 16)))
                self.escape = ""
            return
        if self.escape == "octal":
            if char in "01234567" and len(self.digits) < 3:
                self.digits += char
                if len(self.digits) == 3:
                    self._decoded_char(chr(int(self.digits, 8)))
                    self.escape = ""
                return
            self._decoded_char(chr(int(self.digits, 8)))
            self.escape = ""
            self._string_char(char)
            return
        if char == "\\":
            self.escape = "start"
        elif char == self.quote:
            if self.state == "content":
                self._flush_line()
                self._queue("\n")
                self.has_pair = True
                self.state = "content_end"
            else:
                self.state = "host_end"
        else:
            self._decoded_char(char)

    def feed(self, fragment: str) -> None:
        for char in fragment:
            if self.state in {"host", "content"}:
                self._string_char(char)
                continue
            if char.isspace():
                continue
            if self.state == "open" and char == "[":
                self.state = "item_or_end"
            elif self.state == "item_or_end" and char == "(":
                self.state = "host_start"
            elif self.state == "item_or_end" and char == "]":
                self.state = "done"
            elif self.state in {"host_start", "content_start"} and char in "\"'":
                self.quote = char
                self.state = "host" if self.state == "host_start" else "content"
            elif self.state == "host_end" and char == ",":
                self.state = "content_start"
            elif self.state == "content_end" and char == ")":
                self.state = "next"
            elif self.state == "next" and char == ",":
                self.state = "item_or_end"
            elif self.state == "next" and char == "]":
                self.state = "done"
            else:
                raise ValueError("invalid Airflow multi-host log wrapper")

    def finish(self) -> bool:
        if self.escape == "octal":
            self._decoded_char(chr(int(self.digits, 8)))
            self.escape = ""
        if self.state != "done" or not self.has_pair:
            return False
        self._flush_output()
        return True


def _read_log(
    client: AirflowClient,
    path: str,
    *,
    max_log_bytes: int | None,
    max_total_bytes: int,
    deadline: float | None,
    cancelled: Callable[[], bool] | None = None,
    network_budget: _NetworkBudget | None = None,
    on_chunk: Callable[[str], bool] | None = None,
) -> tuple[str, int, str | None]:
    def stream_large_page(page_path: str) -> tuple[int, str | None, str | None]:
        """Retry one truncated page as a validated, incremental response."""
        assert on_chunk is not None
        received = 0
        continuation_parts: list[str] = []
        has_content = False
        unsupported_content = False
        wrapped_content = False
        content_started = False
        wrapped_parser: _WrappedLogStream | None = None
        stream_error: str | None = None
        media_type = ""
        text_decoder = codecs.getincrementaldecoder("utf-8")("replace")

        def emit_part(part: str) -> None:
            nonlocal received, stream_error
            if not part:
                return
            encoded_size = len(part.encode("utf-8", errors="replace"))
            received += encoded_size
            if max_log_bytes is not None and received > max_log_bytes:
                stream_error = "max_log_bytes"
                raise StopIteration
            if not on_chunk(part):
                stream_error = "max_findings"
                raise StopIteration

        def on_string(path: JSONPath, fragment: str, final: bool) -> None:
            nonlocal has_content, unsupported_content, wrapped_content, content_started, wrapped_parser
            if path == ("continuation_token",):
                if sum(map(len, continuation_parts)) + len(fragment) <= 8192:
                    continuation_parts.append(fragment)
                else:
                    unsupported_content = True
                return
            if (
                path == ("content",)
                or (len(path) == 3 and path[0] == "content" and isinstance(path[1], int) and path[2] == "event")
                or (len(path) == 2 and path[0] == "content" and isinstance(path[1], int))
            ):
                has_content = True
                if not content_started:
                    content_started = True
                    wrapped_content = fragment.startswith("[(")
                    if wrapped_content:
                        wrapped_parser = _WrappedLogStream(emit_part)
                if wrapped_content:
                    if not unsupported_content and wrapped_parser is not None:
                        try:
                            wrapped_parser.feed(fragment)
                            if final and not wrapped_parser.finish():
                                unsupported_content = True
                        except ValueError:
                            unsupported_content = True
                    if final:
                        content_started = False
                        wrapped_parser = None
                    return
                emit_part(fragment + ("\n" if final and len(path) == 3 else ""))
                if final:
                    content_started = False
                return
            if path and path[0] == "content":
                unsupported_content = True

        json_decoder = JSONScalarStream(on_string)

        def on_response(_status: int, headers: Any) -> None:
            nonlocal media_type, stream_error
            if _status != 200:
                stream_error = f"http_{_status}"
                raise StopIteration
            media_type = next(
                (str(value).lower() for key, value in headers.items() if str(key).lower() == "content-type"),
                "",
            )

        def on_wire_chunk(chunk: bytes) -> None:
            nonlocal stream_error
            if cancelled is not None and cancelled():
                stream_error = "cancelled"
                raise StopIteration("cancelled")
            if deadline is not None and time.monotonic() >= deadline:
                stream_error = "discover_time"
                raise TimeoutError("discover_time")
            try:
                if "json" in media_type:
                    json_decoder.feed(chunk)
                else:
                    emit_part(text_decoder.decode(chunk))
            except (UnicodeDecodeError, ValueError):
                stream_error = "invalid_log_response"
                raise

        try:
            streamed = client.get_stream(
                page_path,
                on_chunk=on_wire_chunk,
                on_response=on_response,
                extra_headers={"Accept": "application/json"},
                chunk_size=64 * 1024,
                timeout=_request_timeout(deadline),
                deadline=deadline,
            )
            if stream_error:
                return received, None, stream_error
            if streamed.http_status != 200:
                return received, None, f"http_{streamed.http_status}"
            if streamed.transport_error or streamed.truncated:
                return received, None, "transport_error"
            if "json" in media_type:
                json_decoder.finish()
                if not has_content or unsupported_content:
                    return received, None, "unsupported_log_content"
            else:
                emit_part(text_decoder.decode(b"", final=True))
        except StopIteration as exc:
            return received, None, stream_error or ("cancelled" if str(exc) == "cancelled" else "transport_error")
        except TimeoutError:
            return received, None, "discover_time"
        except (UnicodeDecodeError, ValueError):
            return received, None, "invalid_log_response"
        continuation = "".join(continuation_parts)
        return received, continuation or None, None

    parts: list[str] = []
    used = 0
    token: str | None = None
    seen_tokens: set[str] = set()
    while True:
        if cancelled is not None and cancelled():
            raise NestedSchedulerCancelled("Airflow discovery cancelled")
        if deadline is not None and time.monotonic() >= deadline:
            return "".join(parts), used, "discover_time"
        remaining = max_log_bytes
        if remaining is not None and remaining <= 0:
            return "".join(parts), used, "max_log_bytes"
        query = f"&token={quote(token, safe='')}" if token is not None else ""
        separator = "&" if "?" in path else "?"
        page_path = f"{path}{separator}full_content=false{query}"
        cap = min(2 * 1024 * 1024, remaining + 64 * 1024) if remaining is not None else 2 * 1024 * 1024
        if network_budget is not None:
            cap = min(cap, network_budget.remaining)
        request_kwargs: dict[str, Any] = {}
        if network_budget is not None and deadline is not None:
            request_kwargs["timeout"] = _request_timeout(deadline)
        response = client.get(
            page_path,
            extra_headers={"Accept": "application/json"},
            response_size_cap=cap,
            **request_kwargs,
        )
        can_stream = (
            response.truncated
            and on_chunk is not None
            and hasattr(client, "get_stream")
            and (not response.transport_error or "exceeds limit" in response.transport_error.lower())
        )
        if network_budget is not None:
            budget_limited = cap == network_budget.remaining
            if (len(response.body) > cap or (response.truncated and budget_limited)) and not can_stream:
                return "".join(parts), used, "max_bytes" if budget_limited else "response_truncated"
            if (
                budget_limited
                and response.transport_error
                and "exceeds limit" in response.transport_error
                and not can_stream
            ):
                return "".join(parts), used, "max_bytes"
        if response.transport_error and not can_stream:
            return "".join(parts), used, "transport_error"
        if response.http_status != 200:
            return "".join(parts), used, f"http_{response.http_status}"
        text, next_token = _log_content(response.body, response.json())
        encoded = text.encode("utf-8", errors="replace")
        if can_stream:
            streamed_used, next_token, stream_error = stream_large_page(page_path)
            used += streamed_used
            if stream_error:
                return "".join(parts), used, stream_error
            if next_token is None or _continuation_at_end(next_token):
                return "".join(parts), used, None
            if next_token in seen_tokens:
                return "".join(parts), used, "continuation_loop"
            seen_tokens.add(next_token)
            token = next_token
            continue
        accepted = encoded[:remaining] if remaining is not None else encoded
        accepted_text = accepted.decode("utf-8", errors="replace")
        if on_chunk is None:
            parts.append(accepted_text)
        elif not response.truncated:
            safe_text = accepted_text
            if remaining is not None and len(encoded) > remaining:
                boundary = max(safe_text.rfind(char) for char in " \t\r\n,;\"'")
                safe_text = safe_text[: boundary + 1] if boundary >= 0 else ""
            if safe_text and not on_chunk(safe_text):
                used += len(accepted)
                return "", used, "max_findings"
        used += len(accepted)
        if response.truncated:
            return "".join(parts), used, "response_truncated"
        if remaining is not None and len(encoded) > remaining:
            return "".join(parts), used, "max_log_bytes" if used >= remaining else "max_bytes"
        if next_token is None:
            return "".join(parts), used, None
        if _continuation_at_end(next_token):
            return "".join(parts), used, None
        if next_token in seen_tokens:
            return "".join(parts), used, "continuation_loop"
        seen_tokens.add(next_token)
        token = next_token


def list_variable_keys(client: AirflowClient, generation: str, *, limit: int | None = None) -> dict[str, Any]:
    """Return Variable names only; values are never copied into this result."""
    prefix = "/api/v2" if generation == "v2" else "/api/v1"
    result = _collection(client, f"{prefix}/variables", "variables", limit, None)
    keys = [
        str(item["key"]) for item in result.items if isinstance(item.get("key"), str) and str(item.get("key") or "")
    ]
    total = result.total if result.total is not None else len(keys)
    return {
        "keys": keys,
        "count": len(keys),
        "total": total,
        "truncated": total > len(keys),
        "error": result.error,
    }


def list_connections(client: AirflowClient, generation: str, *, limit: int | None = None) -> dict[str, Any]:
    """Return the complete read-only Connection objects exposed by Airflow."""

    prefix = "/api/v2" if generation == "v2" else "/api/v1"
    result = _collection(client, f"{prefix}/connections", "connections", limit, None)
    connections = [dict(item) for item in result.items]
    total = result.total if result.total is not None else len(connections)
    return {
        "connections": connections,
        "count": len(connections),
        "total": total,
        "truncated": total > len(connections),
        "error": result.error,
    }


def list_dag_ids(client: AirflowClient, generation: str, *, limit: int | None = None) -> dict[str, Any]:
    """List DAG IDs through the API without treating an incomplete page as empty."""
    prefix = "/api/v2" if generation == "v2" else "/api/v1"
    result = _collection(client, f"{prefix}/dags", "dags", limit, None)
    dag_ids = [str(item["dag_id"]) for item in result.items if isinstance(item.get("dag_id"), str)]
    return {
        "dags": dag_ids,
        "count": len(dag_ids),
        "total": result.total if result.total is not None else len(dag_ids),
        "truncated": not result.complete,
        "error": result.error,
    }


def list_dag_sources(
    client: AirflowClient,
    generation: str,
    *,
    source_ids: list[str] | None = None,
    max_items: int = 10_000,
    max_seconds: float = DEFAULT_DISCOVER_TIME,
    cancelled: Callable[[], bool] | None = None,
) -> dict[str, Any]:
    """List API source handles without downloading code.

    Airflow 2 uses signed file tokens shared by DAGs in the same file. Airflow 3
    authorizes source reads per DAG, so its handles must not be merged by path.
    """
    prefix = "/api/v2" if generation == "v2" else "/api/v1"
    deadline = time.monotonic() + max_seconds
    collection = _collection(client, f"{prefix}/dags", "dags", max_items, deadline, cancelled=cancelled)
    reasons: list[str] = []
    by_id: dict[str, dict[str, Any]] = {}
    seen_dags: set[tuple[str, str]] = set()
    if not collection.complete:
        reasons.append(f"dag_sources_list:{collection.error or 'item_limit'}")
    for dag in collection.items:
        if cancelled is not None and cancelled():
            raise NestedSchedulerCancelled("Airflow source inventory cancelled")
        if time.monotonic() >= deadline:
            reasons.append("max_time")
            break
        dag_id = dag.get("dag_id")
        if not isinstance(dag_id, str) or not dag_id:
            reasons.append("dag_sources:missing_dag_id")
            continue
        data = dict(dag)
        source_id = dag_id if generation == "v2" else dag.get("file_token")
        if generation != "v2" and (not isinstance(source_id, str) or not source_id):
            # Some 2.x list responses omit file_token; details expose the same
            # signed handle without requesting the source body.
            detail = client.get(f"{prefix}/dags/{_component(dag_id)}/details")
            if detail.http_status == 404 and not detail.transport_error:
                detail = client.get(f"{prefix}/dags/{_component(dag_id)}")
            payload = (
                detail.json()
                if detail.http_status == 200 and not detail.truncated and not detail.transport_error
                else None
            )
            if isinstance(payload, dict):
                data.update(payload)
                source_id = payload.get("file_token")
        if not isinstance(source_id, str) or not source_id:
            reasons.append(f"dag_source:{dag_id}:missing_file_token")
            continue
        if source_id not in by_id:
            by_id[source_id] = {
                "source_id": source_id,
                "file_token": source_id if generation != "v2" else None,
                "fileloc": data.get("fileloc") or data.get("relative_fileloc"),
                "dag_ids": [],
            }
        if (source_id, dag_id) not in seen_dags:
            seen_dags.add((source_id, dag_id))
            by_id[source_id]["dag_ids"].append(dag_id)
    if source_ids:
        for source_id in dict.fromkeys(source_ids):
            if source_id not in by_id:
                reasons.append(f"source_not_listed:{source_id}")
        sources = [by_id[source_id] for source_id in dict.fromkeys(source_ids) if source_id in by_id]
    else:
        sources = list(by_id.values())
    return {
        "status": "partial" if reasons else "complete",
        "sources": sources,
        "count": len(sources),
        "partial_reasons": list(dict.fromkeys(reasons)),
    }


def _read_dag_source(
    client: AirflowClient, prefix: str, source_id: str, max_bytes: int
) -> tuple[str | None, str | None]:
    response = client.get(
        f"{prefix}/dagSources/{_component(source_id)}",
        extra_headers={"Accept": "application/json"},
        response_size_cap=max_bytes,
    )
    if response.transport_error:
        return None, "transport_error"
    if response.http_status != 200:
        return None, f"http_{response.http_status}"
    if response.truncated:
        return None, "response_truncated"
    data = response.json()
    if isinstance(data, dict) and isinstance(data.get("content"), str):
        return data["content"], None
    content_type = next((value.lower() for key, value in response.headers.items() if key.lower() == "content-type"), "")
    if "text/plain" in content_type:
        return response.body.decode("utf-8", "replace"), None
    return None, "invalid_source"


def dump_airflow(
    client: AirflowClient,
    generation: str,
    *,
    dags: list[str] | None = None,
    keys: list[str] | None = None,
    connections: list[str] | None = None,
    sources: list[str] | None = None,
    all_sources: bool = False,
    source_inventory: dict[str, Any] | None = None,
    max_bytes: int = DEFAULT_DISCOVER_MAX_BYTES,
    max_seconds: float = DEFAULT_DISCOVER_TIME,
    max_items: int = 10_000,
    cancelled: Callable[[], bool] | None = None,
) -> dict[str, Any]:
    """Read the selected API objects, or all three collections when unfiltered.

    The API's own authorization and masking determine which fields are present.
    A failed object read, incomplete listing, or exhausted budget is explicit.
    """
    prefix = "/api/v2" if generation == "v2" else "/api/v1"
    deadline = time.monotonic() + max_seconds
    selected = any((dags, keys, connections, sources, all_sources))
    requested: dict[str, list[tuple[str, dict[str, Any] | None]]] = {}
    reasons: list[str] = []
    records: list[dict[str, Any]] = []
    bytes_used = 0

    def add_reason(reason: str) -> None:
        if reason not in reasons:
            reasons.append(reason)

    for kind, names, endpoint, item_key, id_key in (
        ("dag", dags, "dags", "dags", "dag_id"),
        ("variable", keys, "variables", "variables", "key"),
        ("connection", connections, "connections", "connections", "connection_id"),
    ):
        if selected and not names:
            continue
        if names:
            requested[kind] = [(name, None) for name in dict.fromkeys(names)]
            continue
        collection = _collection(
            client,
            f"{prefix}/{endpoint}",
            item_key,
            max_items,
            deadline,
            cancelled=cancelled,
        )
        requested[kind] = [(str(item[id_key]), item) for item in collection.items if isinstance(item.get(id_key), str)]
        if not collection.complete:
            add_reason(f"{kind}_list:{collection.error or 'item_limit'}")

    if sources:
        requested["dag_source"] = [(name, None) for name in dict.fromkeys(sources)]
    elif all_sources:
        inventory = (
            source_inventory
            if source_inventory is not None
            else list_dag_sources(
                client,
                generation,
                max_items=max_items,
                max_seconds=max(0.0, deadline - time.monotonic()),
                cancelled=cancelled,
            )
        )
        requested["dag_source"] = [(item["source_id"], item) for item in inventory.get("sources", [])]
        for reason in inventory.get("partial_reasons", []):
            add_reason(reason)

    for kind, entries in requested.items():
        for object_id, listed in entries:
            if cancelled is not None and cancelled():
                raise NestedSchedulerCancelled("Airflow dump cancelled")
            if len(records) >= max_items or bytes_used >= max_bytes or time.monotonic() >= deadline:
                add_reason(
                    "item_limit"
                    if len(records) >= max_items
                    else "max_bytes"
                    if bytes_used >= max_bytes
                    else "max_time"
                )
                break
            if kind == "dag_source":
                content, error = _read_dag_source(client, prefix, object_id, max_bytes - bytes_used)
                if error is not None:
                    add_reason(f"dag_source:{object_id}:{error}")
                    continue
                source_record: dict[str, Any] = {"kind": kind, "id": object_id, "source": content}
                if listed is not None:
                    source_record.update({key: listed.get(key) for key in ("file_token", "fileloc", "dag_ids")})
                encoded_size = len(json.dumps(source_record, ensure_ascii=False).encode("utf-8"))
                if bytes_used + encoded_size > max_bytes:
                    add_reason("max_bytes")
                    break
                records.append(source_record)
                bytes_used += encoded_size
                continue
            endpoint = "dags" if kind == "dag" else "variables" if kind == "variable" else "connections"
            path = f"{prefix}/{endpoint}/{_component(object_id)}"
            response = client.get(path, response_size_cap=min(2 * 1024 * 1024, max_bytes - bytes_used))
            if response.transport_error or response.http_status != 200 or response.truncated:
                add_reason(
                    f"{kind}:{object_id}:{'transport_error' if response.transport_error else 'response_truncated' if response.truncated else f'http_{response.http_status}'}"
                )
                continue
            data = response.json()
            if not isinstance(data, dict):
                add_reason(f"{kind}:{object_id}:invalid_object")
                continue
            record: dict[str, Any] = {"kind": kind, "id": object_id, "data": data}
            if kind == "variable" and "value" not in data:
                add_reason(f"variable:{object_id}:value_unavailable")
            if kind == "dag":
                source_id = (
                    object_id if generation == "v2" else data.get("file_token") or (listed or {}).get("file_token")
                )
                if generation == "v1" and (not isinstance(source_id, str) or not source_id):
                    details = client.get(f"{path}/details")
                    detail_data = details.json() if details.http_status == 200 and not details.truncated else None
                    if isinstance(detail_data, dict):
                        source_id = detail_data.get("file_token")
                        record["details"] = detail_data
                if not isinstance(source_id, str) or not source_id:
                    add_reason(f"dag:{object_id}:source_unavailable")
                else:
                    source = client.get(
                        f"{prefix}/dagSources/{_component(source_id)}",
                        extra_headers={"Accept": "application/json"},
                        response_size_cap=min(2 * 1024 * 1024, max_bytes - bytes_used),
                    )
                    if source.transport_error or source.http_status != 200 or source.truncated:
                        add_reason(f"dag:{object_id}:source_unavailable")
                    else:
                        source_json = source.json()
                        if isinstance(source_json, dict) and isinstance(source_json.get("content"), str):
                            record["source"] = source_json["content"]
                        elif "text/plain" in next(
                            (value.lower() for key, value in source.headers.items() if key.lower() == "content-type"),
                            "",
                        ):
                            record["source"] = source.body.decode("utf-8", "replace")
                        else:
                            add_reason(f"dag:{object_id}:invalid_source")
            encoded_size = len(json.dumps(record, ensure_ascii=False, default=str).encode("utf-8"))
            if bytes_used + encoded_size > max_bytes:
                add_reason("max_bytes")
                break
            records.append(record)
            bytes_used += encoded_size
        if "item_limit" in reasons or "max_bytes" in reasons or "max_time" in reasons:
            break
    return {
        "status": "partial" if reasons else "complete",
        "count": len(records),
        "records": records,
        "bytes_read": bytes_used,
        "partial_reasons": reasons,
    }


def discover_task_logs(
    client: AirflowClient,
    generation: str,
    config: DiscoverConfig,
    on_finding: Callable[[dict[str, Any]], bool | None] | None = None,
    cancelled: Callable[[], bool] | None = None,
    started_at: float | None = None,
) -> dict[str, Any]:
    """Read DAG task logs in stable order and retain only secret findings."""
    started = time.monotonic() if started_at is None else started_at
    deadline = started + config.max_seconds if config.max_seconds is not None else None
    prefix = "/api/v2" if generation == "v2" else "/api/v1"
    reasons: list[str] = []
    errors: list[dict[str, str]] = []
    findings: list[dict[str, Any]] = []
    registry: OccurrenceRegistry | None = None
    dags_scanned = runs_scanned = tasks_seen = logs_scanned = bytes_scanned = 0
    dag_sources_scanned = variables_scanned = connections_scanned = 0
    dag_source_bytes_scanned = variable_bytes_scanned = connection_bytes_scanned = log_bytes_scanned = 0
    variable_keys: list[str] = []
    variables_error: str | None = None
    network_budget = _NetworkBudget(config.max_bytes)
    manifest = SourceManifest()
    for kind in (
        "variable_collection",
        "connection_collection",
        "dag_catalog",
        "run_catalog",
        "task_catalog",
        "dag_sources",
        "task_logs",
    ):
        manifest.declare("airflow." + kind)
    partial_events = 0

    @contextmanager
    def source_attempt(kind: str, *, catalog: bool = False) -> Iterator[SourceRead]:
        source = "airflow." + kind
        manifest.request(source, scope="selected_collection_pages" if catalog else "selected_complete_content_reads")
        evidence, finished = SourceRead(), False
        before = partial_events
        try:
            with manifest.guard(source):
                yield evidence
                finished = True
        finally:
            manifest.read(source, evidence.count)
            manifest.finish(
                source,
                complete=finished and evidence.complete and (catalog or before == partial_events),
                denied=evidence.status in {401, 403},
            )

    def partial(reason: str, path: str | None = None) -> None:
        nonlocal partial_events
        partial_events += 1
        if reason not in reasons:
            reasons.append(reason)
        if path is not None:
            errors.append({"path": path, "reason": reason})

    def add_matches(value: Any, *, source_kind: str, place: str, context: dict[str, Any] | None = None) -> bool:
        """Append and stream stable, de-duplicated findings. Return False at the finding limit."""
        nonlocal findings, registry
        matches, _scanned_bytes, covered = _scan_portioned_value(value, "$", config.max_bytes, _deadline=deadline)
        if not covered:
            partial(
                "discover_time"
                if deadline is not None and time.monotonic() >= deadline
                else "unscannable_continuous_field"
            )
        for match in matches:
            if cancelled is not None and cancelled():
                raise NestedSchedulerCancelled("Airflow discovery cancelled")
            # A vendor-specific detector and the generic api-key detector can
            # identify the exact same value. Likewise, the entropy fallback can
            # encompass an already classified assignment. Keep the specific
            # finding so live output contains one useful line per secret/place.
            if (
                match.detector == "high_entropy"
                and isinstance(match.value, str)
                and any(
                    other.detector != "high_entropy" and isinstance(other.value, str) and other.value in match.value
                    for other in matches
                )
            ):
                continue
            location = concat_discovery_text(place, match.object_path)
            key = ("value", fingerprint(match.value))
            finding: dict[str, Any] = {
                "type": match.detector,
                "confidence": match.confidence,
                "value": match.value,
                "fingerprint": key[1],
                "detectors": list(match.rule_ids),
                "source_kind": source_kind,
                "place": location,
                "object_path": match.object_path,
            }
            if context:
                finding.update(context)
            if registry is None:
                registry = OccurrenceRegistry()
                findings = registry
            if not registry.add(
                finding,
                identity=key,
                location={
                    "source_kind": source_kind,
                    "object": place,
                    "place": location,
                    "object_path": match.object_path,
                    **(context or {}),
                },
            ):
                continue
            if on_finding is not None:
                emitted = on_finding(registry.lookup(key) or dict(finding))
                was_emitted = emitted is True or (emitted is None and not isinstance(match.value, DiskBackedText))
                if was_emitted:
                    registry.mark_emitted(*key)
            if config.max_findings is not None and len(findings) >= config.max_findings:
                partial("max_findings")
                return False
        return True

    def consume_value(value: Any) -> tuple[Any, int, bool]:
        """Account for inspected source data without a cumulative target cap."""
        nonlocal bytes_scanned
        used = sum(len(chunk.encode("utf-8", errors="replace")) for chunk in iter_json_chunks(value))
        bytes_scanned += used
        return value, used, True

    def stream_dag_source(path: str, dag_id: str) -> tuple[int, bool]:
        with source_attempt("dag_sources") as evidence:
            return read_dag_source(path, dag_id, evidence)

    def read_dag_source(path: str, dag_id: str, evidence: SourceRead) -> tuple[int, bool]:
        """Scan plain text or the API JSON envelope as one bounded HTTP stream."""
        received = 0
        json_mode = False
        stop_reason: str | None = None
        response_status: int | None = None
        decoder = codecs.getincrementaldecoder("utf-8")("strict")
        context = {"dag_id": dag_id}

        class StopSourceStream(Exception):
            pass

        def publish(value: Any) -> None:
            nonlocal stop_reason
            if not add_matches(value, source_kind="dag_source", place=f"dag_source:{dag_id}", context=context):
                stop_reason = "max_findings"
                raise StopSourceStream

        scanner = DiscoveryTextStream(
            publish, lambda reason: partial(f"dag_sources:{reason}", path), portion=config.max_bytes
        )

        def scan_text(value: str, *, final: bool = False) -> None:
            if value:
                scanner.feed(value)
            if final and not scanner.finished:
                scanner.finish()

        def on_response(_status: int, headers: Any) -> None:
            nonlocal json_mode, response_status
            response_status = _status
            evidence.status = _status
            json_mode = "json" in next(
                (str(value).lower() for key, value in headers.items() if str(key).lower() == "content-type"),
                "",
            )

        json_decoder = SingleStringFieldStream("content", scan_text, on_complete=lambda: scan_text("", final=True))

        def on_chunk(chunk: bytes) -> None:
            nonlocal received, stop_reason
            if response_status != 200:
                return
            if cancelled is not None and cancelled():
                scanner.close()
                raise NestedSchedulerCancelled("Airflow discovery cancelled")
            if deadline is not None and time.monotonic() >= deadline:
                stop_reason = "discover_time"
                raise StopSourceStream
            received += len(chunk)
            try:
                if json_mode:
                    json_decoder.feed(chunk)
                else:
                    scan_text(decoder.decode(chunk))
            except (UnicodeDecodeError, ValueError):
                stop_reason = "dag_sources:invalid_source"
                raise StopSourceStream from None

        try:
            response = client.get_stream(
                path,
                on_chunk=on_chunk,
                on_response=on_response,
                extra_headers={"Accept": "text/plain, application/json"},
                chunk_size=max(1, min(config.max_bytes, 64 * 1024)),
                timeout=_request_timeout(deadline),
                deadline=deadline,
            )
        except (NestedSchedulerCancelled, KeyboardInterrupt):
            scanner.close()
            raise
        evidence.status = response.http_status
        if stop_reason:
            scanner.close()
            partial(stop_reason, path)
            return received, stop_reason in {"cancelled", "discover_time", "max_findings"}
        if response.transport_error or response.truncated:
            scanner.close()
            partial("dag_sources:transport_error", path)
            return received, False
        if response.http_status != 200:
            scanner.close()
            partial(f"dag_sources:http_{response.http_status}", path)
            return received, False
        try:
            if json_mode:
                json_decoder.finish()
            else:
                scan_text(decoder.decode(b"", final=True))
            scan_text("", final=True)
        except (UnicodeDecodeError, ValueError):
            scanner.close()
            partial("dag_sources:invalid_source", path)
        except StopSourceStream:
            partial("max_findings", path)
        scanner.close()
        evidence.accept()
        return received, False

    stopped = False

    def iter_collection(
        path: str,
        key: str,
        limit: int | None,
        *,
        error_prefix: str,
        max_reason: str,
        order_by: str | None = None,
    ):
        kinds = {
            "variables": "variable_collection",
            "connections": "connection_collection",
            "dags": "dag_catalog",
            "dag_runs": "run_catalog",
            "task_instances": "task_catalog",
        }
        with source_attempt(kinds[key], catalog=True) as evidence:
            yield from read_collection(
                path, key, limit, error_prefix=error_prefix, max_reason=max_reason, order_by=order_by, evidence=evidence
            )

    def read_collection(
        path: str,
        key: str,
        limit: int | None,
        *,
        error_prefix: str,
        max_reason: str,
        order_by: str | None,
        evidence: SourceRead,
    ):
        nonlocal stopped
        offset = 0
        seen_pages: set[tuple[str, str, int]] = set()
        while True:
            if cancelled is not None and cancelled():
                raise NestedSchedulerCancelled("Airflow discovery cancelled")
            page_limit = min(100, limit - offset) if limit is not None else 100
            if page_limit <= 0:
                partial(max_reason)
                return
            page = _collection(
                client,
                path,
                key,
                page_limit,
                deadline,
                order_by=order_by,
                start_offset=offset,
                cancelled=cancelled,
                network_budget=network_budget,
            )
            if page.items:
                signature = (repr(page.items[0])[:256], repr(page.items[-1])[:256], len(page.items))
                if signature in seen_pages:
                    partial(f"{error_prefix}:pagination_stalled", path)
                    return
                seen_pages.add(signature)
            if not page.error:
                evidence.count += 1
            elif page.error in {"http_401", "http_403"}:
                evidence.status = int(page.error[5:])
            for item in page.items:
                if cancelled is not None and cancelled():
                    raise NestedSchedulerCancelled("Airflow discovery cancelled")
                yield item
            offset += len(page.items)
            if page.error:
                partial(f"{error_prefix}:{page.error}", path)
                if page.error == "max_bytes":
                    partial("max_bytes")
                    stopped = True
                return
            if page.complete:
                evidence.complete = True
                return
            if not page.items:
                partial(f"{error_prefix}:pagination_stalled", path)
                return

    # Variables and Connections are global configuration surfaces. Inspect them
    # before potentially large task-log walks so a busy deployment cannot starve
    # the small, high-value collections of their shared time/byte budget.
    if config.include_variables:
        variables_path = f"{prefix}/variables"
        for variable in iter_collection(
            variables_path,
            "variables",
            None,
            error_prefix="variables",
            max_reason="max_variables",
        ):
            if deadline is not None and time.monotonic() >= deadline:
                partial("discover_time")
                stopped = True
                break
            key_value = variable.get("key")
            key_name = str(key_value) if isinstance(key_value, str) and key_value else "?"
            if key_name != "?":
                if (
                    not isinstance(variable_keys, SpoolingStrings)
                    and len(variable_keys) >= AIRFLOW_FINDING_SPOOL_THRESHOLD
                ):
                    variable_keys = SpoolingStrings(variable_keys)
                variable_keys.append(key_name)
            scanned, used, complete = consume_value(variable)
            variables_scanned += 1
            variable_bytes_scanned += used
            scan_target: Any = scanned
            if complete and key_name != "?" and "value" in variable:
                # Airflow's collection schema uses the generic field name
                # ``value``. Re-key it with the Variable name so semantic
                # detectors can classify names such as ``db_password``.
                scan_target = {key_name: variable.get("value")}
            if not add_matches(scan_target, source_kind="variable", place=f"variable:{key_name}"):
                stopped = True
                break
            if not complete:
                stopped = True
                break
        variables_error = next(
            (reason.split(":", 1)[1] for reason in reasons if reason.startswith("variables:")),
            None,
        )

    if config.include_connections and not stopped:
        connections_path = f"{prefix}/connections"
        for connection in iter_collection(
            connections_path,
            "connections",
            None,
            error_prefix="connections",
            max_reason="max_connections",
        ):
            if deadline is not None and time.monotonic() >= deadline:
                partial("discover_time")
                stopped = True
                break
            connection_id = connection.get("connection_id") or connection.get("conn_id") or "?"
            scanned, used, complete = consume_value(connection)
            connections_scanned += 1
            connection_bytes_scanned += used
            if not add_matches(
                scanned,
                source_kind="connection",
                place=f"connection:{connection_id}",
            ):
                stopped = True
                break
            if not complete:
                stopped = True
                break

    dag_items = (
        ()
        if stopped
        else iter_collection(f"{prefix}/dags", "dags", config.max_dags, error_prefix="dags", max_reason="max_dags")
    )
    for dag in dag_items:
        if cancelled is not None and cancelled():
            raise NestedSchedulerCancelled("Airflow discovery cancelled")
        if stopped:
            break
        dag_id = dag.get("dag_id")
        if not isinstance(dag_id, str) or not dag_id:
            continue
        if deadline is not None and time.monotonic() >= deadline:
            partial("discover_time")
            break
        dags_scanned += 1

        if config.include_dag_sources:
            source_id = dag_id if generation == "v2" else dag.get("file_token")
            if not isinstance(source_id, str) or not source_id:
                partial("dag_sources:missing_file_token", f"{prefix}/dags/{_component(dag_id)}")
            else:
                source_path = f"{prefix}/dagSources/{_component(source_id)}"
                if callable(getattr(client, "get_stream", None)):
                    used, stop_all = stream_dag_source(source_path, dag_id)
                    dag_sources_scanned += 1
                    dag_source_bytes_scanned += used
                    bytes_scanned += used
                    if stop_all:
                        stopped = True
                        break
                    continue_source = True
                else:
                    continue_source = False
                if not continue_source:
                    # Airflow 2.x exposes DAG source as ``text/plain`` and returns
                    # HTTP 406 when the shared HTTP client advertises JSON only.
                    # Airflow 3.x may return the JSON ``{"content": ...}`` shape;
                    # accepting both representations keeps the read-only probe
                    # compatible with both API generations.
                    with source_attempt("dag_sources") as evidence:
                        source_cap = min(config.max_bytes, 2 * 1024 * 1024)
                        source_request_kwargs: dict[str, Any] = {}
                        if deadline is not None:
                            source_request_kwargs["timeout"] = _request_timeout(deadline)
                        source_response = client.get(
                            source_path,
                            extra_headers={"Accept": "text/plain, application/json"},
                            response_size_cap=source_cap,
                            **source_request_kwargs,
                        )
                        evidence.status = source_response.http_status
                        budget_limited = source_cap == network_budget.remaining
                        if len(source_response.body) > source_cap or (source_response.truncated and budget_limited):
                            partial("max_bytes" if budget_limited else "dag_sources:response_truncated", source_path)
                            stopped = True
                            break
                        if (
                            budget_limited
                            and source_response.transport_error
                            and "exceeds limit" in source_response.transport_error
                        ):
                            partial("max_bytes", source_path)
                            stopped = True
                            break
                        if source_response.transport_error:
                            partial("dag_sources:transport_error", source_path)
                        elif source_response.http_status != 200:
                            partial(f"dag_sources:http_{source_response.http_status}", source_path)
                        else:
                            payload = source_response.json()
                            source_value: Any = (
                                payload.get("content")
                                if isinstance(payload, dict) and isinstance(payload.get("content"), str)
                                else source_response.body.decode("utf-8", errors="replace")
                            )
                            scanned, used, complete = consume_value(source_value)
                            dag_sources_scanned += 1
                            dag_source_bytes_scanned += used
                            if source_response.truncated:
                                partial("dag_sources:response_truncated", source_path)
                            if not add_matches(
                                scanned,
                                source_kind="dag_source",
                                place=f"dag_source:{dag_id}",
                                context={"dag_id": dag_id},
                            ):
                                stopped = True
                                break
                            if not complete:
                                stopped = True
                                break
                        if (
                            source_response.http_status == 200
                            and not source_response.truncated
                            and not source_response.transport_error
                        ):
                            evidence.accept()
        runs_path = f"{prefix}/dags/{_component(dag_id)}/dagRuns"
        runs = iter_collection(
            runs_path,
            "dag_runs",
            config.max_runs,
            error_prefix="dag_runs",
            max_reason="max_runs",
            order_by="-start_date" if generation == "v2" else "-execution_date",
        )
        for run in runs:
            run_id = run.get("dag_run_id")
            if not isinstance(run_id, str) or not run_id:
                continue
            runs_scanned += 1
            tasks_path = f"{runs_path}/{_component(run_id)}/taskInstances"
            remaining_tasks = config.max_tasks - tasks_seen if config.max_tasks is not None else None
            if remaining_tasks is not None and remaining_tasks <= 0:
                partial("max_tasks")
                stopped = True
                break
            tasks = iter_collection(
                tasks_path,
                "task_instances",
                remaining_tasks,
                error_prefix="task_instances",
                max_reason="max_tasks",
            )
            for task in tasks:
                task_id = task.get("task_id")
                if not isinstance(task_id, str) or not task_id:
                    continue
                tasks_seen += 1
                try_number = task.get("try_number")
                if not isinstance(try_number, int) or isinstance(try_number, bool) or try_number < 1:
                    continue
                map_index = task.get("map_index", -1)
                if not isinstance(map_index, int) or isinstance(map_index, bool):
                    map_index = -1
                for attempt in range(1, try_number + 1):
                    if cancelled is not None and cancelled():
                        raise NestedSchedulerCancelled("Airflow discovery cancelled")
                    if deadline is not None and time.monotonic() >= deadline:
                        partial("discover_time")
                        stopped = True
                        break
                    if config.max_logs is not None and logs_scanned >= config.max_logs:
                        partial("max_logs")
                        stopped = True
                        break
                    if config.max_findings is not None and len(findings) >= config.max_findings:
                        partial("max_findings")
                        stopped = True
                        break
                    log_path = f"{tasks_path}/{_component(task_id)}/logs/{attempt}"
                    if map_index >= 0:
                        log_path += f"?map_index={map_index}"
                    log_place = f"log:{dag_id}/{run_id}/{task_id}/try:{attempt}/map:{map_index}"
                    log_context = {
                        "dag_id": dag_id,
                        "dag_run_id": run_id,
                        "task_id": task_id,
                        "try_number": attempt,
                        "map_index": map_index,
                    }

                    class StopLogScan(Exception):
                        pass

                    def publish_log(
                        value: Any, *, log_place: str = log_place, log_context: dict[str, Any] = log_context
                    ) -> None:
                        if not add_matches(value, source_kind="task_log", place=log_place, context=log_context):
                            raise StopLogScan

                    def log_partial(reason: str, *, log_path: str = log_path) -> None:
                        partial(f"logs:{reason}", log_path)

                    log_scanner = DiscoveryTextStream(publish_log, log_partial, portion=config.max_bytes)

                    def emit_log_chunk(part: str, *, log_scanner: DiscoveryTextStream = log_scanner) -> bool:
                        try:
                            log_scanner.feed(part)
                        except StopLogScan:
                            return False
                        return True

                    with source_attempt("task_logs") as evidence:
                        _text, used, error = _read_log(
                            client,
                            log_path,
                            max_log_bytes=config.max_log_bytes,
                            max_total_bytes=config.max_bytes,
                            deadline=deadline,
                            cancelled=cancelled,
                            network_budget=network_budget,
                            on_chunk=emit_log_chunk,
                        )
                        logs_scanned += 1
                        bytes_scanned += used
                        log_bytes_scanned += used
                        if error:
                            log_scanner.close()
                            partial(f"logs:{error}", log_path)
                        else:
                            try:
                                log_scanner.finish()
                            except StopLogScan:
                                stopped = True
                            finally:
                                log_scanner.close()
                        if error is None:
                            evidence.accept()
                        elif error in {"http_401", "http_403"}:
                            evidence.status = int(error[5:])
                    if stopped:
                        break
                if stopped:
                    break
            if stopped:
                break
        if stopped:
            break

    if registry is not None:
        registry.finish()
        findings = registry.bounded_inline_view(max_findings=AIRFLOW_FINDING_SPOOL_THRESHOLD)
    if isinstance(variable_keys, SpoolingStrings):
        variable_keys.finish()
    return {
        "status": "partial" if reasons else "complete",
        "sources": manifest.result(),
        "api_generation": generation,
        "dags_scanned": dags_scanned,
        "runs_scanned": runs_scanned,
        "task_instances_seen": tasks_seen,
        "logs_scanned": logs_scanned,
        "dag_sources_scanned": dag_sources_scanned,
        "variables_scanned": variables_scanned,
        "connections_scanned": connections_scanned,
        "bytes_scanned": bytes_scanned,
        "log_bytes_scanned": log_bytes_scanned,
        "dag_source_bytes_scanned": dag_source_bytes_scanned,
        "variable_bytes_scanned": variable_bytes_scanned,
        "connection_bytes_scanned": connection_bytes_scanned,
        "variable_keys": variable_keys,
        "variables_error": variables_error,
        "finding_count": len(findings),
        "findings": findings,
        "emitted_fingerprints": (
            registry.emitted_fingerprints() if findings is registry else list(registry.emitted_fingerprints())
        )
        if registry is not None
        else [],
        "partial_reasons": reasons,
        "errors": errors,
        "elapsed_ms": int((time.monotonic() - started) * 1000),
    }


__all__ = ["DiscoverConfig", "discover_task_logs", "list_connections", "list_variable_keys"]
