"""Bounded Kafka UI event-stream decoding for discovery."""

from __future__ import annotations

import tempfile
import time
from collections.abc import Callable, Mapping
from typing import Any

from ...discovery_json import DiskJSONDocument
from ...discovery_spool import SpoolingRecords
from ...discovery_values import DiskBackedText


def read_events(
    pool: Any,
    url: str,
    *,
    cookie: str,
    deadline: float,
    limit: int,
    on_message: Callable[[dict[str, Any]], None] | None = None,
) -> tuple[Any, list[dict[str, Any]], bool, str | None, str | None]:
    messages = SpoolingRecords()
    done = False
    cursor = None
    error: str | None = None
    line = tempfile.TemporaryFile()
    content_type = ""

    def headers(status: int, values: Any) -> None:
        nonlocal content_type
        content_type = next((str(v).lower() for k, v in values.items() if k.lower() == "content-type"), "")
        if status == 200 and "text/event-stream" not in content_type:
            raise ValueError("Kafka UI message API did not return an event stream")

    def completed_line() -> None:
        nonlocal done, cursor
        line.seek(0)
        prefix = line.read(5)
        if prefix != b"data:" or done:
            line.seek(0)
            line.truncate()
            return
        decoder = DiskJSONDocument(deadline=deadline)
        try:
            while chunk := line.read(65536):
                if time.monotonic() >= deadline:
                    raise TimeoutError("discover_time")
                decoder.feed(chunk)
            event = decoder.finish()
        finally:
            decoder.close()
        if not isinstance(event, Mapping):
            raise ValueError("invalid Kafka UI message event")
        kind = event.get("type")
        if kind == "DONE":
            done = True
            data = event.get("cursor")
            if isinstance(data, Mapping) and isinstance(data.get("id"), str):
                cursor = data["id"] or None
        elif kind == "ERROR":
            raise ValueError("Kafka UI message stream reported an error")
        elif kind == "MESSAGE":
            message = event.get("message")
            if not isinstance(message, Mapping):
                raise ValueError("invalid Kafka UI message payload")
            value = message.get("value", message.get("content"))
            if not isinstance(value, (str, DiskBackedText)) and value is not None:
                raise ValueError("invalid Kafka UI message value")
            if not all(
                isinstance(message.get(key), int) and not isinstance(message[key], bool) and message[key] >= 0
                for key in ("partition", "offset")
            ):
                raise ValueError("invalid Kafka UI message position")
            if len(messages) >= limit:
                raise ValueError("Kafka UI returned more messages than requested")
            message = {key: message.get(key) for key in ("partition", "offset", "timestamp", "key", "headers")} | {
                "value": value
            }
            messages.append(message)
            if on_message is not None:
                on_message(message)
        line.seek(0)
        line.truncate()

    def receive(chunk: bytes) -> None:
        if time.monotonic() >= deadline:
            raise TimeoutError("discover_time")
        for part in chunk.splitlines(keepends=True):
            line.write(part)
            if part.endswith(b"\n"):
                completed_line()

    try:
        response = pool.request_stream(
            "GET",
            url,
            on_chunk=receive,
            on_response=headers,
            headers={
                "Accept": "text/event-stream",
                "Accept-Encoding": "identity",
                **({"Cookie": cookie} if cookie else {}),
            },
            deadline=deadline,
            timeout=max(0.001, deadline - time.monotonic()),
            chunk_size=65536,
            allow_cross_origin_redirects=False,
            preserve_authorization_on_cross_origin=False,
        )
        error = response.error
        if response.status != 200:
            error = error or f"HTTP {response.status} from Kafka UI message API"
        if not error and not done:
            error = "Kafka UI message stream ended without completion"
    except (OSError, ValueError, RuntimeError) as exc:
        from ...clients.http_api import HttpResponse

        response = HttpResponse(200, b"", {"Content-Type": content_type}, error=str(exc))
        error = str(exc)
    finally:
        line.close()
    return response, messages, done and not error, error, cursor
