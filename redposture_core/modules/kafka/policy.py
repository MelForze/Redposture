"""Policy helpers for the kafka audit module."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from ...clients.kafka import KAFKA_MAX_WRITE_VALUE_BYTES
from ...stage_runtime import validate_basic_module_args


def validate_args(args: Any, console: Any) -> int | None:
    common_rc = validate_basic_module_args(args, console, module="kafka", pure_http=False)
    if common_rc is not None:
        return common_rc
    max_messages = getattr(args, "max_messages", None)
    if max_messages is not None and int(max_messages) <= 0:
        console.error("--max-messages must be > 0")
        return 2
    if bool(getattr(args, "tls_cert", None)) != bool(getattr(args, "tls_key", None)):
        console.error("--tls-cert and --tls-key must be provided together")
        return 2
    if bool(getattr(args, "plaintext", False)) and any(
        (
            bool(getattr(args, "tls_ca", None)),
            bool(getattr(args, "tls_cert", None)),
            bool(getattr(args, "tls_server_name", None)),
        )
    ):
        console.error("--plaintext cannot be combined with TLS options")
        return 2
    write_message = getattr(args, "write_message", None)
    write_file = getattr(args, "write_file", None)
    writing = write_message is not None or write_file is not None
    if writing and not str(getattr(args, "topic", "") or "").strip():
        console.error("--write-message/--write-file requires --topic NAME")
        return 2
    if writing and not re.fullmatch(r"[A-Za-z0-9._-]{1,249}", str(args.topic)):
        console.error("--topic for message writes must be a Kafka topic name of at most 249 characters")
        return 2
    if writing and bool(getattr(args, "probe_write", False)):
        console.error("--write-message/--write-file cannot be combined with --probe-write")
        return 2
    if getattr(args, "write_key", None) is not None and not writing:
        console.error("--write-key requires --write-message or --write-file")
        return 2
    if writing:
        try:
            if write_message is not None:
                payload = write_message.encode("utf-8")
            else:
                path = Path(str(write_file))
                if not path.is_file() or path.stat().st_size > KAFKA_MAX_WRITE_VALUE_BYTES:
                    console.error("--write-file must be a regular file of at most 1 MiB")
                    return 2
                with path.open("rb") as stream:
                    payload = stream.read(KAFKA_MAX_WRITE_VALUE_BYTES + 1)
            key = getattr(args, "write_key", None)
            key_bytes = key.encode("utf-8") if key is not None else None
        except (OSError, UnicodeError) as exc:
            console.error(f"cannot read --write-file/--write-message: {exc}")
            return 2
        if len(payload) > KAFKA_MAX_WRITE_VALUE_BYTES or (key_bytes is not None and len(key_bytes) > 65536):
            console.error("Kafka write payload or key exceeds its size limit")
            return 2
        args._kafka_write_payload = payload
        args._kafka_write_key = key_bytes
    return None


__all__ = ["validate_args"]
