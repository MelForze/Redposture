"""Kafka broker audit stage."""

from __future__ import annotations

import argparse
import json
import os
import time
from collections.abc import Callable
from typing import Any

from .clients import kafka as _kafka_client
from .clients.kafka import (
    KAFKA_AUTH_ERROR_CODES,
    _authenticate_and_fetch_metadata,
    _build_credential_runs,
    _build_metadata_request_body,
    _build_request_header,
    _clip,
    _encode_kafka_bytes,
    _encode_kafka_nullable_string,
    _encode_kafka_string,
    _fetch_metadata,
    _friendly_error_from_exception,
    _friendly_error_text,
    _is_connection_refused_fail_record,
    _is_connection_timeout_error,
    _is_probable_auth_error,
    _is_sasl_probe_candidate,
    _is_suppressed_fail_record,
    _kafka_error_name,
    _KafkaReader,
    _parse_apiversions_response,
    _parse_fetch_response,
    _parse_list_offsets_response,
    _parse_metadata_response,
    _probe_apiversions,
    _read_dump_topics,
    _read_topic_messages,
    _recv_exact,
    _recv_kafka_frame,
    _retry_delay,
    _sasl_authenticate_plain,
    _sasl_handshake_plain,
    _send_kafka_request,
    open_kafka_socket,
)
from .console import Console
from .logger import AttemptLogger
from .rendering import CountColorRule, render_colored_marker_line
from .stage_runtime import (
    LineOutputSink,
    StageTelemetryBuilder,
    TwoPassAuditRunner,
    merge_stage_records,
    progress_total_from_groups,
    should_use_global_progress,
    start_audit_progress,
    start_command_progress,
)
from .utils import (
    collect_scan_ports,
    collect_scan_targets,
    filter_open_tcp_hosts_for_credential_file,
    parse_username_password_credential_file,
    utc_now_iso,
)

__all__ = [
    "_KafkaReader",
    "_authenticate_and_fetch_metadata",
    "_build_credential_runs",
    "_build_metadata_request_body",
    "_build_request_header",
    "_clip",
    "_encode_kafka_bytes",
    "_encode_kafka_nullable_string",
    "_encode_kafka_string",
    "_fetch_metadata",
    "_friendly_error_from_exception",
    "_friendly_error_text",
    "_is_connection_refused_fail_record",
    "_is_connection_timeout_error",
    "_is_probable_auth_error",
    "_is_sasl_probe_candidate",
    "_is_suppressed_fail_record",
    "_kafka_error_name",
    "_parse_apiversions_response",
    "_parse_fetch_response",
    "_parse_list_offsets_response",
    "_parse_metadata_response",
    "_probe_apiversions",
    "_read_dump_topics",
    "_read_topic_messages",
    "_recv_exact",
    "_recv_kafka_frame",
    "_sasl_authenticate_plain",
    "_sasl_handshake_plain",
    "_send_kafka_request",
    "_retry_delay",
]

KAFKA_CLIENT_ID = "redposture"
KAFKA_API_VERSIONS = 18
KAFKA_METADATA = 3
KAFKA_FETCH = 1
KAFKA_LIST_OFFSETS = 2
KAFKA_SASL_HANDSHAKE = 17
KAFKA_SASL_AUTHENTICATE = 36
_CONNECTION_REFUSED_PREFIX = "connection refused"
_CONNECTION_TIMEOUT_PREFIX = "connection timeout"
_STAGE_DETECT_PROTOCOL = "detect_protocol"
_STAGE_AUTH_INFERENCE = "auth_inference_credentials"
_STAGE_ACCESS_CAPABILITIES = "access_capabilities"
_STAGE_DATA = "data"
_KAFKA_DEEP_STATUSES = {"open_no_auth", "valid_credentials", "invalid_credentials_anonymous"}

_CLIENT_AUTHENTICATE_AND_FETCH_METADATA = _authenticate_and_fetch_metadata
_CLIENT_READ_DUMP_TOPICS = _read_dump_topics
_CLIENT_READ_TOPIC_MESSAGES = _read_topic_messages
_CLIENT_SASL_AUTHENTICATE_PLAIN = _sasl_authenticate_plain
_CLIENT_SASL_HANDSHAKE_PLAIN = _sasl_handshake_plain


def _with_kafka_client_overrides(callback, *args, **kwargs):
    overrides = {
        "_send_kafka_request": _send_kafka_request,
        "_probe_apiversions": _probe_apiversions,
        "_fetch_metadata": _fetch_metadata,
        "_parse_list_offsets_response": _parse_list_offsets_response,
        "_parse_fetch_response": _parse_fetch_response,
        "_sasl_handshake_plain": _sasl_handshake_plain,
        "_sasl_authenticate_plain": _sasl_authenticate_plain,
        "_read_topic_messages": _read_topic_messages,
    }
    saved = {name: getattr(_kafka_client, name) for name in overrides}
    try:
        for name, value in overrides.items():
            setattr(_kafka_client, name, value)
        return callback(*args, **kwargs)
    finally:
        for name, value in saved.items():
            setattr(_kafka_client, name, value)


def _sasl_handshake_plain(sock, correlation_id: int):
    return _with_kafka_client_overrides(_CLIENT_SASL_HANDSHAKE_PLAIN, sock, correlation_id)


def _sasl_authenticate_plain(sock, correlation_id: int, username: str, password: str):
    return _with_kafka_client_overrides(_CLIENT_SASL_AUTHENTICATE_PLAIN, sock, correlation_id, username, password)


def _authenticate_and_fetch_metadata(host: str, port: int, timeout: float, username: str, password: str):
    return _with_kafka_client_overrides(
        _CLIENT_AUTHENTICATE_AND_FETCH_METADATA, host, port, timeout, username, password
    )


def _read_topic_messages(
    host: str,
    port: int,
    timeout: float,
    topic: str,
    max_messages: int,
    username: str | None = None,
    password: str | None = None,
):
    return _with_kafka_client_overrides(
        _CLIENT_READ_TOPIC_MESSAGES,
        host,
        port,
        timeout,
        topic,
        max_messages,
        username=username,
        password=password,
    )


def _read_dump_topics(
    *,
    host: str,
    port: int,
    timeout: float,
    topics: list[str],
    max_messages: int,
    username: str | None,
    password: str | None,
):
    return _with_kafka_client_overrides(
        _CLIENT_READ_DUMP_TOPICS,
        host=host,
        port=port,
        timeout=timeout,
        topics=topics,
        max_messages=max_messages,
        username=username,
        password=password,
    )


def _audit_kafka_via_sasl_fallback(
    host: str,
    port: int,
    timeout: float,
    username: str | None,
    password: str | None,
    show_topics: bool,
    query_topic: str | None,
    dump: bool,
    max_messages: int,
) -> dict[str, Any] | None:
    provided_credentials = bool(username and password)
    started = time.monotonic()

    try:
        with open_kafka_socket(host, port, timeout) as sock:
            correlation = 1
            hs_ok, correlation, hs_error = _sasl_handshake_plain(sock, correlation)
            if not hs_ok:
                return None

            auth_required = True
            provided_credentials_ok: bool | None = None
            topic_map: dict[str, int] | None = None
            error_parts: list[str] = []

            if provided_credentials and username and password:
                auth_ok, correlation, auth_error = _sasl_authenticate_plain(sock, correlation, username, password)
                provided_credentials_ok = auth_ok
                if auth_ok:
                    metadata, metadata_error = _fetch_metadata(sock, correlation, topics=None)
                    if metadata is not None:
                        topic_map = dict(metadata.get("topic_map") or {})
                    elif metadata_error:
                        error_parts.append(metadata_error)
                elif auth_error:
                    error_parts.append(auth_error)
            elif hs_error:
                error_parts.append(hs_error)

            topic_names = sorted(topic_map.keys()) if isinstance(topic_map, dict) else None
            topic_count = len(topic_names) if isinstance(topic_names, list) else None

            query_topic_name = (query_topic or "").strip()
            query_topic_value: str | None = None
            if query_topic_name:
                if isinstance(topic_map, dict):
                    if query_topic_name in topic_map:
                        query_topic_value = f"{query_topic_name} (partitions:{int(topic_map[query_topic_name])})"
                    else:
                        query_topic_value = f"{query_topic_name}:<not found>"
                elif provided_credentials_ok:
                    query_topic_value = f"{query_topic_name}:<not available>"
                else:
                    query_topic_value = f"{query_topic_name}:<authentication required>"

            dump_topics: list[str] = []
            dump_results: dict[str, list[str]] = {}
            dump_errors: dict[str, str] = {}
            dump_error: str | None = None
            if dump:
                if isinstance(topic_map, dict):
                    if query_topic_name:
                        if query_topic_name in topic_map:
                            dump_topics = [query_topic_name]
                        else:
                            dump_error = "topic not found"
                    else:
                        dump_topics = sorted(topic_map.keys())
                elif provided_credentials_ok:
                    dump_error = "topic metadata unavailable"
                else:
                    dump_error = "authentication required"

                if dump_topics:
                    dump_results, dump_errors = _read_dump_topics(
                        host=host,
                        port=port,
                        timeout=timeout,
                        topics=dump_topics,
                        max_messages=max_messages,
                        username=username if provided_credentials_ok else None,
                        password=password if provided_credentials_ok else None,
                    )

            topic_messages: list[str] | None = None
            topic_read_error: str | None = None
            if dump and query_topic_name:
                topic_messages = dump_results.get(query_topic_name)
                topic_read_error = dump_errors.get(query_topic_name) or dump_error

            status = "valid_credentials" if provided_credentials_ok else "auth_required"
            error = "; ".join(item for item in error_parts if str(item).strip()) or None

            return {
                "timestamp": utc_now_iso(),
                "host": host,
                "port": port,
                "is_kafka": True,
                "status": status,
                "auth_required": auth_required,
                "provided_credentials": provided_credentials,
                "provided_username": username,
                "provided_password": password if provided_credentials else None,
                "provided_credentials_ok": provided_credentials_ok,
                "show_topics": show_topics,
                "query_topic": query_topic_name or None,
                "topic_count": topic_count,
                "topics": topic_names,
                "query_topic_value": query_topic_value,
                "dump": bool(dump),
                "max_messages": max_messages if dump else None,
                "dump_topics": dump_topics if dump else None,
                "dump_results": dump_results if dump else None,
                "dump_errors": dump_errors if dump else None,
                "dump_error": dump_error,
                "topic_messages": topic_messages,
                "topic_read_error": topic_read_error,
                "elapsed_ms": int((time.monotonic() - started) * 1000),
                "error": error,
            }
    except (TimeoutError, ConnectionError, OSError, ValueError):
        return None


def _audit_kafka_host(
    host: str,
    port: int,
    timeout: float,
    retries: int,
    username: str | None,
    password: str | None,
    show_topics: bool,
    query_topic: str | None,
    dump: bool,
    max_messages: int,
) -> dict[str, Any]:
    attempts = max(1, retries + 1)
    provided_credentials = bool(username and password)
    last_error: str | None = None

    for attempt in range(attempts):
        started = time.monotonic()
        try:
            with open_kafka_socket(host, port, timeout) as sock:
                correlation = 1
                is_kafka, api_error_code, api_error = _probe_apiversions(sock, correlation)
                correlation += 1
                if not is_kafka:
                    if _is_sasl_probe_candidate(api_error):
                        fallback_record = _audit_kafka_via_sasl_fallback(
                            host=host,
                            port=port,
                            timeout=timeout,
                            username=username,
                            password=password,
                            show_topics=show_topics,
                            query_topic=query_topic,
                            dump=dump,
                            max_messages=max_messages,
                        )
                        if fallback_record is not None:
                            return fallback_record
                    return {
                        "timestamp": utc_now_iso(),
                        "host": host,
                        "port": port,
                        "is_kafka": False,
                        "status": "fail",
                        "auth_required": None,
                        "provided_credentials": provided_credentials,
                        "provided_username": username,
                        "provided_password": password if provided_credentials else None,
                        "provided_credentials_ok": None,
                        "show_topics": show_topics,
                        "query_topic": query_topic,
                        "dump": bool(dump),
                        "max_messages": max_messages if dump else None,
                        "topic_count": None,
                        "topics": None,
                        "query_topic_value": None,
                        "dump_topics": None,
                        "dump_results": None,
                        "dump_errors": None,
                        "dump_error": None,
                        "topic_messages": None,
                        "topic_read_error": None,
                        "elapsed_ms": int((time.monotonic() - started) * 1000),
                        "error": api_error
                        or (
                            f"ApiVersions failed ({_kafka_error_name(int(api_error_code))})"
                            if api_error_code is not None
                            else "service is not kafka"
                        ),
                    }

                metadata, metadata_error = _fetch_metadata(sock, correlation, topics=None)

                auth_required: bool | None = None
                topic_map: dict[str, int] | None = None
                error_parts: list[str] = []

                if metadata is not None:
                    auth_required = bool(metadata.get("auth_required"))
                    if not auth_required:
                        topic_map = dict(metadata.get("topic_map") or {})
                    else:
                        error_codes = metadata.get("error_codes")
                        if isinstance(error_codes, list) and error_codes:
                            names = sorted(
                                {
                                    _kafka_error_name(int(code))
                                    for code in error_codes
                                    if int(code) in KAFKA_AUTH_ERROR_CODES
                                }
                            )
                            if names:
                                error_parts.append(f"auth errors: {','.join(names)}")
                else:
                    if _is_probable_auth_error(metadata_error):
                        auth_required = True
                    else:
                        auth_required = None
                    if metadata_error:
                        error_parts.append(metadata_error)

                provided_credentials_ok: bool | None = None
                if provided_credentials and username and password:
                    auth_ok, auth_metadata, auth_error = _authenticate_and_fetch_metadata(
                        host, port, timeout, username, password
                    )
                    provided_credentials_ok = auth_ok
                    if auth_ok and auth_metadata is not None:
                        if auth_required is not False:
                            auth_required = True
                        if topic_map is None:
                            topic_map = dict(auth_metadata.get("topic_map") or {})
                        error_parts = []
                    elif auth_error:
                        error_parts.append(auth_error)
                        if auth_required is None:
                            auth_required = True

                topic_names = sorted(topic_map.keys()) if isinstance(topic_map, dict) else None
                topic_count = len(topic_names) if isinstance(topic_names, list) else None

                query_topic_name = (query_topic or "").strip()
                query_topic_value: str | None = None
                if query_topic_name:
                    if isinstance(topic_map, dict):
                        if query_topic_name in topic_map:
                            query_topic_value = f"{query_topic_name} (partitions:{int(topic_map[query_topic_name])})"
                        else:
                            query_topic_value = f"{query_topic_name}:<not found>"
                    elif auth_required is True and not bool(provided_credentials_ok):
                        query_topic_value = f"{query_topic_name}:<authentication required>"
                    else:
                        query_topic_value = f"{query_topic_name}:<not available>"

                dump_topics: list[str] = []
                dump_results: dict[str, list[str]] = {}
                dump_errors: dict[str, str] = {}
                dump_error: str | None = None
                if dump:
                    if isinstance(topic_map, dict):
                        if query_topic_name:
                            if query_topic_name in topic_map:
                                dump_topics = [query_topic_name]
                            else:
                                dump_error = "topic not found"
                        else:
                            dump_topics = sorted(topic_map.keys())
                    elif auth_required is True and not bool(provided_credentials_ok):
                        dump_error = "authentication required"
                    else:
                        dump_error = "topic metadata unavailable"

                    if dump_topics:
                        dump_results, dump_errors = _read_dump_topics(
                            host=host,
                            port=port,
                            timeout=timeout,
                            topics=dump_topics,
                            max_messages=max_messages,
                            username=username if bool(provided_credentials_ok) else None,
                            password=password if bool(provided_credentials_ok) else None,
                        )

                topic_messages: list[str] | None = None
                topic_read_error: str | None = None
                if dump and query_topic_name:
                    topic_messages = dump_results.get(query_topic_name)
                    topic_read_error = dump_errors.get(query_topic_name) or dump_error

                if auth_required is False:
                    if provided_credentials and provided_credentials_ok is False:
                        status = "invalid_credentials_anonymous"
                    elif provided_credentials_ok:
                        status = "valid_credentials"
                    else:
                        status = "open_no_auth"
                elif provided_credentials_ok:
                    status = "valid_credentials"
                elif auth_required is True:
                    status = "auth_required"
                else:
                    status = "unknown_auth"

                error = "; ".join(item for item in error_parts if str(item).strip()) or None

                return {
                    "timestamp": utc_now_iso(),
                    "host": host,
                    "port": port,
                    "is_kafka": True,
                    "status": status,
                    "auth_required": auth_required,
                    "provided_credentials": provided_credentials,
                    "provided_username": username,
                    "provided_password": password if provided_credentials else None,
                    "provided_credentials_ok": provided_credentials_ok,
                    "show_topics": show_topics,
                    "query_topic": query_topic_name or None,
                    "dump": bool(dump),
                    "max_messages": max_messages if dump else None,
                    "topic_count": topic_count,
                    "topics": topic_names,
                    "query_topic_value": query_topic_value,
                    "dump_topics": dump_topics if dump else None,
                    "dump_results": dump_results if dump else None,
                    "dump_errors": dump_errors if dump else None,
                    "dump_error": dump_error,
                    "topic_messages": topic_messages,
                    "topic_read_error": topic_read_error,
                    "elapsed_ms": int((time.monotonic() - started) * 1000),
                    "error": error,
                }
        except (TimeoutError, ConnectionError, OSError, ValueError) as exc:
            last_error = _friendly_error_from_exception(exc)
            if _is_sasl_probe_candidate(last_error):
                fallback_record = _audit_kafka_via_sasl_fallback(
                    host=host,
                    port=port,
                    timeout=timeout,
                    username=username,
                    password=password,
                    show_topics=show_topics,
                    query_topic=query_topic,
                    dump=dump,
                    max_messages=max_messages,
                )
                if fallback_record is not None:
                    return fallback_record
            if attempt >= attempts - 1:
                break
            time.sleep(_retry_delay(attempt))

    return {
        "timestamp": utc_now_iso(),
        "host": host,
        "port": port,
        "is_kafka": False,
        "status": "fail",
        "auth_required": None,
        "provided_credentials": provided_credentials,
        "provided_username": username,
        "provided_password": password if provided_credentials else None,
        "provided_credentials_ok": None,
        "show_topics": show_topics,
        "query_topic": (query_topic or "").strip() or None,
        "dump": bool(dump),
        "max_messages": max_messages if dump else None,
        "topic_count": None,
        "topics": None,
        "query_topic_value": None,
        "dump_topics": None,
        "dump_results": None,
        "dump_errors": None,
        "dump_error": None,
        "topic_messages": None,
        "topic_read_error": None,
        "elapsed_ms": None,
        "error": last_error or "connection failed",
    }


def _nxc_prefix(record: dict[str, Any]) -> str:
    host = _clip(str(record.get("host") or "-"), 64)
    port = str(record.get("port") or "-")
    return f"{'KAFKA':<8}\t{host}\t{port}\t"


def _with_optional_topics(record: dict[str, Any], message: str) -> str:
    topic_count = record.get("topic_count")
    if not isinstance(topic_count, int):
        return f"{message} (topics:-)"
    return f"{message} (topics:{topic_count})"


def _format_detect_record(record: dict[str, Any], output_format: str) -> str:
    auth_required_value = record.get("auth_required")
    auth_required_text = (
        "True" if auth_required_value is True else "False" if auth_required_value is False else "unknown"
    )
    if output_format == "json":
        return json.dumps(
            {
                "timestamp": record.get("timestamp"),
                "type": "detect",
                "host": record.get("host"),
                "port": record.get("port"),
                "service": "kafka",
                "detected": bool(record.get("is_kafka")),
                "auth_required": auth_required_value,
            },
            ensure_ascii=False,
        )
    return f"{_nxc_prefix(record)} [*] Kafka Broker (auth required:{auth_required_text})"


def _format_record(record: dict[str, Any], output_format: str) -> str:
    if output_format == "json":
        return json.dumps(record, ensure_ascii=False)

    status = str(record.get("status") or "fail")
    prefix = _nxc_prefix(record)
    err = _clip(str(record.get("error") or "-"), 72)

    if status == "open_no_auth":
        return _with_optional_topics(record, f"{prefix} [+] anonymous access")

    if status == "invalid_credentials_anonymous":
        username = str(record.get("provided_username") or "user").strip() or "user"
        provided_password = record.get("provided_password")
        password_text = "<empty>" if provided_password == "" else str(provided_password or "")
        return f"{prefix} [-] {username}:{password_text}"

    if status == "valid_credentials":
        username = str(record.get("provided_username") or "user").strip() or "user"
        provided_password = record.get("provided_password")
        password_text = "<empty>" if provided_password == "" else str(provided_password or "")
        return _with_optional_topics(record, f"{prefix} [+] {username}:{password_text}")

    if status == "auth_required":
        if record.get("provided_credentials"):
            username = str(record.get("provided_username") or "user").strip() or "user"
            provided_password = record.get("provided_password")
            password_text = "<empty>" if provided_password == "" else str(provided_password or "")
            base = f"{prefix} [-] {username}:{password_text}"
        else:
            base = f"{prefix} [-] authentication required"
        return base

    if status == "unknown_auth":
        line = f"{prefix} [!] auth status unknown"
        if err != "-":
            return f"{line} err={err}"
        return line

    line = f"{prefix} [!] connection failed"
    if err != "-":
        return f"{line} err={err}"
    return line


def _format_topics_detail_records(record: dict[str, Any], output_format: str) -> list[str]:
    show_topics = bool(record.get("show_topics"))
    query_topic = str(record.get("query_topic") or "").strip()
    query_topic_value = record.get("query_topic_value")
    dump = bool(record.get("dump"))
    max_messages = int(record.get("max_messages") or 0)
    topic_messages_raw = record.get("topic_messages")
    topic_messages: list[str] = (
        [str(item) for item in topic_messages_raw] if isinstance(topic_messages_raw, list) else []
    )
    topic_read_error = str(record.get("topic_read_error") or "").strip()

    topics = record.get("topics")
    topic_names: list[str] = []
    if isinstance(topics, list):
        topic_names = sorted(str(item) for item in topics)

    dump_topics_raw = record.get("dump_topics")
    dump_topics: list[str] = []
    if isinstance(dump_topics_raw, list):
        dump_topics = [str(item) for item in dump_topics_raw if str(item).strip()]

    dump_results_raw = record.get("dump_results")
    dump_results: dict[str, list[str]] = {}
    if isinstance(dump_results_raw, dict):
        for topic_name, values in dump_results_raw.items():
            key = str(topic_name).strip()
            if not key:
                continue
            if isinstance(values, list):
                dump_results[key] = [str(item) for item in values]
            else:
                dump_results[key] = []

    dump_errors_raw = record.get("dump_errors")
    dump_errors: dict[str, str] = {}
    if isinstance(dump_errors_raw, dict):
        for topic_name, value in dump_errors_raw.items():
            key = str(topic_name).strip()
            if not key:
                continue
            dump_errors[key] = str(value or "").strip()

    dump_error = str(record.get("dump_error") or "").strip()

    # Keep compatibility with older record fields for query-topic dump.
    if query_topic:
        if query_topic not in dump_results and topic_messages:
            dump_results[query_topic] = topic_messages
        if query_topic not in dump_errors and topic_read_error:
            dump_errors[query_topic] = topic_read_error
        if query_topic not in dump_topics and (query_topic in dump_results or query_topic in dump_errors):
            dump_topics.append(query_topic)

    if not show_topics and not query_topic and not dump:
        return []

    if output_format == "json":
        lines: list[str] = []
        if show_topics and topic_names:
            lines.append(
                json.dumps(
                    {
                        "timestamp": record.get("timestamp"),
                        "type": "topics_list",
                        "service": "kafka",
                        "host": record.get("host"),
                        "port": record.get("port"),
                        "topic_count": record.get("topic_count"),
                        "topics": topic_names,
                    },
                    ensure_ascii=False,
                )
            )
        if query_topic:
            lines.append(
                json.dumps(
                    {
                        "timestamp": record.get("timestamp"),
                        "type": "topic_query",
                        "service": "kafka",
                        "host": record.get("host"),
                        "port": record.get("port"),
                        "topic": query_topic,
                        "value": query_topic_value,
                    },
                    ensure_ascii=False,
                )
            )
        if dump:
            if dump_topics:
                for topic_name in dump_topics:
                    topic_dump_messages = dump_results.get(topic_name, [])
                    topic_dump_error = dump_errors.get(topic_name) or None
                    lines.append(
                        json.dumps(
                            {
                                "timestamp": record.get("timestamp"),
                                "type": "topic_dump",
                                "service": "kafka",
                                "host": record.get("host"),
                                "port": record.get("port"),
                                "topic": topic_name,
                                "max_messages": max_messages,
                                "message_count": len(topic_dump_messages),
                                "messages": topic_dump_messages,
                                "error": topic_dump_error,
                            },
                            ensure_ascii=False,
                        )
                    )
            elif dump_error:
                lines.append(
                    json.dumps(
                        {
                            "timestamp": record.get("timestamp"),
                            "type": "topic_dump",
                            "service": "kafka",
                            "host": record.get("host"),
                            "port": record.get("port"),
                            "topic": query_topic or None,
                            "max_messages": max_messages,
                            "message_count": 0,
                            "messages": [],
                            "error": dump_error,
                        },
                        ensure_ascii=False,
                    )
                )
        return lines

    prefix = _nxc_prefix(record)
    lines: list[str] = []
    if show_topics and topic_names:
        lines.append(f"{prefix} [*] Show Topics")
        for item in topic_names:
            lines.append(f"{prefix} {item}")
    if query_topic:
        lines.append(f"{prefix} [*] Topic {query_topic}")
        if isinstance(query_topic_value, str):
            lines.append(f"{prefix} {query_topic_value}")
    if dump:
        if query_topic:
            lines.append(f"{prefix} [*] Dump Topic {query_topic} (max:{max_messages})")
            topic_dump_messages = dump_results.get(query_topic, [])
            topic_dump_error = dump_errors.get(query_topic) or dump_error
            if topic_dump_messages:
                for item in topic_dump_messages:
                    lines.append(f"{prefix} {item}")
            elif topic_dump_error:
                lines.append(f"{prefix} [-] {topic_dump_error}")
            else:
                lines.append(f"{prefix} <no messages>")
        else:
            lines.append(f"{prefix} [*] Dump Topics (max:{max_messages})")
            if dump_topics:
                for topic_name in dump_topics:
                    lines.append(f"{prefix} [*] Topic {topic_name}")
                    topic_dump_messages = dump_results.get(topic_name, [])
                    topic_dump_error = dump_errors.get(topic_name, "")
                    if topic_dump_messages:
                        for item in topic_dump_messages:
                            lines.append(f"{prefix} {item}")
                    elif topic_dump_error:
                        lines.append(f"{prefix} [-] {topic_dump_error}")
                    else:
                        lines.append(f"{prefix} <no messages>")
            elif dump_error:
                lines.append(f"{prefix} [-] {dump_error}")
            else:
                lines.append(f"{prefix} <no topics>")
    return lines


def _render_colored_kafka_line(console: Console, line: str) -> bool:
    return render_colored_marker_line(console, line, tag="KAFKA", counts=(CountColorRule("topics", "red"),))


def _emit_line(out_fh: Any, emit_line: Callable[[str], None] | None, line: str) -> None:
    if out_fh is not None:
        out_fh.write(line + "\n")
        out_fh.flush()
    if emit_line is not None:
        emit_line(line)


def _call_audit_kafka_host_with_stage_debug(
    host: str,
    port: int,
    timeout: float,
    retries: int,
    username: str | None,
    password: str | None,
    show_topics: bool,
    query_topic: str | None,
    dump: bool,
    max_messages: int,
    *,
    run_deep_checks: bool,
    debug: bool,
    debug_emit: Callable[[str], None] | None,
) -> dict[str, Any]:
    started = time.monotonic()
    record = _audit_kafka_host(
        host,
        port,
        timeout,
        retries,
        username,
        password,
        show_topics if run_deep_checks else False,
        query_topic if run_deep_checks else None,
        dump if run_deep_checks else False,
        max_messages,
    )

    result: dict[str, Any] = dict(record)
    status = str(result.get("status") or "fail")
    is_kafka = bool(result.get("is_kafka"))
    attempts = max(1, retries + 1)
    elapsed_ms = int((time.monotonic() - started) * 1000)
    telemetry = StageTelemetryBuilder(host=host, port=port, attempts=attempts, debug=debug, debug_emit=debug_emit)

    if attempts > 1 and status == "fail":
        telemetry.retry(_STAGE_DETECT_PROTOCOL, 1, _retry_delay(0), "error")

    detect_result = "ok" if is_kafka else ("error" if status == "fail" else "skip")
    detect_error = str(result.get("error") or "") if detect_result == "error" else None
    telemetry.stage(_STAGE_DETECT_PROTOCOL, detect_result, detect_error, 0)

    auth_result = "ok" if is_kafka and status in _KAFKA_DEEP_STATUSES.union({"auth_required"}) else detect_result
    telemetry.stage(_STAGE_AUTH_INFERENCE, auth_result, detect_error if auth_result == "error" else None, 0)

    if run_deep_checks and status in _KAFKA_DEEP_STATUSES:
        telemetry.stage(_STAGE_ACCESS_CAPABILITIES, "ok", None, 0)
        data_result = "error" if status == "fail" and result.get("error") else "ok"
        telemetry.stage(
            _STAGE_DATA,
            data_result,
            str(result.get("error") or "") if data_result == "error" else None,
            elapsed_ms,
        )
    else:
        telemetry.stage(_STAGE_ACCESS_CAPABILITIES, "skip", "deep checks disabled", 0)
        telemetry.stage(_STAGE_DATA, "skip", "deep checks disabled", 0)

    stage_durations_ms = {
        str(item.get("stage_name") or ""): int(item.get("duration_ms") or 0) for item in telemetry.stages
    }
    telemetry.debug(
        f"stage_timing_summary status={status} attempts=1/{attempts} "
        f"detect_ms={stage_durations_ms.get(_STAGE_DETECT_PROTOCOL, 0)} "
        f"auth_ms={stage_durations_ms.get(_STAGE_AUTH_INFERENCE, 0)} "
        f"capabilities_ms={stage_durations_ms.get(_STAGE_ACCESS_CAPABILITIES, 0)} "
        f"data_ms={stage_durations_ms.get(_STAGE_DATA, 0)} total_ms={elapsed_ms}"
    )

    return telemetry.attach(result, status=status, total_ms=elapsed_ms)


def _merge_stage2_record(detect_record: dict[str, Any], deep_record: dict[str, Any]) -> dict[str, Any]:
    return merge_stage_records(detect_record, deep_record)


def audit_kafka_targets(
    hosts: list[str],
    port: int,
    timeout: float,
    retries: int,
    workers: int,
    username: str | None,
    password: str | None,
    show_topics: bool,
    query_topic: str | None,
    dump: bool,
    max_messages: int,
    output_path: str | None,
    output_format: str,
    emit_line: Callable[[str], None] | None = None,
    logger: AttemptLogger | None = None,
    append_output: bool = False,
    suppress_connection_refused_status_lines: bool = False,
    debug_emit: Callable[[str], None] | None = None,
    show_progress: bool = False,
) -> tuple[int, int, int, int, int]:
    total = 0
    open_no_auth = 0
    valid = 0
    auth_required = 0
    failed = 0

    out_fh: Any = None
    if output_path:
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        out_fh = open(output_path, "a" if append_output else "w", encoding="utf-8")

    progress = None
    try:
        indexed_hosts = list(enumerate(hosts))
        progress = start_audit_progress("KAFKA", len(indexed_hosts), enabled=show_progress, leave=True)
        deep_requested = bool(show_topics or query_topic or dump)

        def _detect_task(host: str) -> dict[str, Any]:
            return _call_audit_kafka_host_with_stage_debug(
                host,
                port,
                timeout,
                retries,
                username,
                password,
                show_topics,
                query_topic,
                dump,
                max_messages,
                run_deep_checks=False,
                debug=bool(debug_emit),
                debug_emit=debug_emit,
            )

        def _deep_task(host: str) -> dict[str, Any]:
            return _call_audit_kafka_host_with_stage_debug(
                host,
                port,
                timeout,
                retries,
                username,
                password,
                show_topics,
                query_topic,
                dump,
                max_messages,
                run_deep_checks=True,
                debug=bool(debug_emit),
                debug_emit=debug_emit,
            )

        def _deep_gate(detect_record: dict[str, Any]) -> tuple[bool, str]:
            detect_status = str(detect_record.get("status") or "fail")
            if deep_requested and detect_status in _KAFKA_DEEP_STATUSES:
                return True, f"status={detect_status}"
            return False, "no_data_actions" if not deep_requested else f"status={detect_status}"

        runner = TwoPassAuditRunner(
            label="KAFKA",
            workers=workers,
            debug_emit=debug_emit,
            progress=progress,
            detected_name="kafka",
        )
        pass_result = runner.run(
            indexed_hosts,
            detect_task=_detect_task,
            deep_task=_deep_task,
            is_detected=lambda record: bool(record.get("is_kafka")),
            deep_gate=_deep_gate,
            emit_detect=lambda record: (
                _emit_line(out_fh, emit_line, _format_detect_record(record, output_format))
                if bool(record.get("is_kafka")) and output_format == "txt"
                else None
            ),
            merge_records=_merge_stage2_record,
            not_detected_reason="not_kafka",
        )
        if progress is not None:
            progress.close()
            progress = None

        final_records = pass_result.final_records

        for idx, _host in indexed_hosts:
            record = final_records[idx]
            total += 1
            status = str(record.get("status") or "fail")
            if status in {"open_no_auth", "invalid_credentials_anonymous"}:
                open_no_auth += 1
            elif status == "valid_credentials":
                valid += 1
            elif status == "auth_required":
                auth_required += 1
            else:
                failed += 1

            if debug_emit is not None and not bool(record.get("debug_events_streamed")):
                for event in record.get("debug_events") or []:
                    if isinstance(event, str) and event.strip():
                        debug_emit(event)

            if output_format != "txt" and bool(record.get("is_kafka")):
                _emit_line(out_fh, emit_line, _format_detect_record(record, output_format))

            suppress_auth_required_status_line = (
                output_format == "txt"
                and bool(record.get("is_kafka"))
                and status == "auth_required"
                and not bool(record.get("provided_credentials"))
            )
            suppress_connection_refused_status_line = (
                suppress_connection_refused_status_lines
                and output_format == "txt"
                and _is_suppressed_fail_record(record)
            )
            if not suppress_auth_required_status_line and not suppress_connection_refused_status_line:
                _emit_line(out_fh, emit_line, _format_record(record, output_format))
            if bool(record.get("is_kafka")):
                for topics_line in _format_topics_detail_records(record, output_format):
                    _emit_line(out_fh, emit_line, topics_line)

            if logger is not None and not (
                suppress_connection_refused_status_lines and _is_suppressed_fail_record(record)
            ):
                logger.log(
                    "kafka",
                    (str(record.get("host") or "-"), int(record.get("port") or port)),
                    phase="audit",
                    status=record.get("status"),
                    auth_required=record.get("auth_required"),
                    provided_credentials_ok=record.get("provided_credentials_ok"),
                    topic_count=record.get("topic_count"),
                    topic=record.get("query_topic"),
                    dump=record.get("dump"),
                    dump_topics=record.get("dump_topics"),
                    dump_error=record.get("dump_error"),
                    topic_read_error=record.get("topic_read_error"),
                    error=record.get("error"),
                )
    finally:
        if progress is not None:
            progress.close()
        if out_fh is not None:
            out_fh.close()

    return total, open_no_auth, valid, auth_required, failed


def run_kafka_stage(args: argparse.Namespace, logger: AttemptLogger) -> int:
    console = Console(debug=args.debug)

    if args.timeout <= 0:
        console.error("--timeout must be > 0")
        return 2
    if args.retries < 0:
        console.error("--retries must be >= 0")
        return 2
    if args.max_messages <= 0:
        console.error("--max-messages must be > 0")
        return 2
    try:
        credential_file_entries = parse_username_password_credential_file(args.username, args.password)
    except ValueError as exc:
        console.error(str(exc))
        return 2
    if credential_file_entries is None and bool(args.username) != bool(args.password):
        console.error("--username and --password must be set together")
        return 2
    defcreds = bool(getattr(args, "defcreds", False))
    credential_runs = (
        [(entry.username, entry.password) for entry in credential_file_entries]
        if credential_file_entries is not None
        else _build_credential_runs(args.username, args.password, defcreds)
    )
    try:
        ports = collect_scan_ports(getattr(args, "ports", None))
    except ValueError as exc:
        console.error(f"failed to parse --port: {exc}")
        return 2
    if not ports:
        ports = [int(args.port)]

    targets = getattr(args, "targets", None) or getattr(args, "hosts", None)
    hosts_file = getattr(args, "hosts_file", None)
    if hosts_file:
        targets = f"{targets},{hosts_file}" if targets else hosts_file

    try:
        hosts = collect_scan_targets(targets)
    except (OSError, ValueError) as exc:
        console.error(f"failed to parse targets: {exc}")
        return 2

    if not hosts:
        console.error("kafka requires -t/--targets")
        return 2

    stream_to_stdout = not bool(args.output)

    def emit_line(line: str) -> None:
        if args.output_format != "txt":
            print(line, flush=True)
            return
        if line.startswith("KAFKA") and all(token not in line for token in (" [*] ", " [+] ", " [-] ", " [!] ")):
            if console.render_tagged_payload_line(line, "KAFKA", payload_color="orange"):
                return
            console.plain(line, color="white")
            return
        if _render_colored_kafka_line(console, line):
            return
        if args.debug:
            console.plain(line)

    def emit_debug(message: str) -> None:
        if not args.debug:
            return
        debug_method = getattr(console, "debug", None)
        if callable(debug_method):
            debug_method(message)
            return
        console.info(message)

    if args.debug and stream_to_stdout and args.output_format == "txt":
        mode_parts: list[str] = []
        if credential_file_entries is not None:
            mode_parts.append(f"credfile={len(credential_file_entries)}")
        elif args.username and args.password:
            mode_parts.append("provided-creds")
        elif defcreds:
            mode_parts.append("defcreds")
        if args.show_topics:
            mode_parts.append("show-topics")
        if args.topic:
            mode_parts.append(f"topic={args.topic}")
        if args.dump:
            mode_parts.append(f"dump,max={args.max_messages}")
        mode = ",".join(mode_parts) if mode_parts else "detect-only"
        console.info(
            f"kafka audit started: hosts={len(hosts)} ports={len(ports)} timeout={args.timeout}s "
            f"workers={args.workers} retries={args.retries} mode={mode} format=txt"
        )
    if args.debug and not stream_to_stdout:
        mode_parts = []
        if credential_file_entries is not None:
            mode_parts.append(f"credfile={len(credential_file_entries)}")
        elif args.username and args.password:
            mode_parts.append("provided-creds")
        elif defcreds:
            mode_parts.append("defcreds")
        if args.show_topics:
            mode_parts.append("show-topics")
        if args.topic:
            mode_parts.append(f"topic={args.topic}")
        if args.dump:
            mode_parts.append(f"dump,max={args.max_messages}")
        mode = ",".join(mode_parts) if mode_parts else "detect-only"
        console.info(
            f"kafka audit started: hosts={len(hosts)} ports={len(ports)} timeout={args.timeout}s "
            f"workers={args.workers} retries={args.retries} mode={mode} "
            f"format={args.output_format} output={args.output}"
        )

    total = 0
    open_no_auth = 0
    valid = 0
    auth_required = 0
    failed = 0
    hosts_by_port: dict[int, list[str]] = {int(port): list(hosts) for port in ports}
    if credential_file_entries is not None:
        for audit_port in ports:
            hosts_by_port[int(audit_port)] = filter_open_tcp_hosts_for_credential_file(
                hosts,
                int(audit_port),
                timeout=args.timeout,
                workers=args.workers,
            )
            if args.debug:
                emit_debug(
                    f"credential_prefilter port={int(audit_port)} open={len(hosts_by_port[int(audit_port)])}/"
                    f"{len(hosts)}"
                )
    outer_progress = None
    use_single_global_progress = (
        args.output_format == "txt" and credential_file_entries is not None
    ) or should_use_global_progress(
        args.output_format, len(ports), len(credential_runs) if credential_file_entries is None else 1
    )
    if use_single_global_progress:
        outer_progress = start_command_progress(
            args,
            "KAFKA",
            progress_total_from_groups(
                hosts_by_port.values(), 1 if credential_file_entries is not None else len(credential_runs)
            ),
            enabled=True,
            leave=True,
        )
    output_written = False
    output_sink = LineOutputSink(args.output, emit_line)

    def run_kafka_capture(
        host: str,
        audit_port: int,
        run_username: str | None,
        run_password: str | None,
        *,
        include_data: bool,
    ) -> tuple[list[str], tuple[int, int, int, int, int]]:
        lines: list[str] = []
        counts = audit_kafka_targets(
            hosts=[host],
            port=audit_port,
            timeout=args.timeout,
            retries=args.retries,
            workers=args.workers,
            username=run_username,
            password=run_password,
            show_topics=args.show_topics and include_data,
            query_topic=args.topic if include_data else None,
            dump=args.dump and include_data,
            max_messages=args.max_messages,
            output_path=None,
            output_format=args.output_format,
            emit_line=lines.append,
            logger=logger if args.debug else None,
            append_output=False,
            suppress_connection_refused_status_lines=not bool(args.debug),
            debug_emit=emit_debug if args.debug else None,
            show_progress=False,
        )
        return lines, counts

    try:
        if credential_file_entries is not None:
            for audit_port in ports:
                audit_hosts = hosts_by_port[int(audit_port)]
                if not audit_hosts:
                    continue
                for host in audit_hosts:
                    selected_lines, selected_counts = run_kafka_capture(
                        host, int(audit_port), None, None, include_data=False
                    )
                    _base_total, base_open, base_valid, base_auth, _base_failed = selected_counts
                    selected_username: str | None = None
                    selected_password: str | None = None

                    if base_open == 0 and base_valid == 0 and base_auth > 0:
                        for run_username, run_password in credential_runs:
                            _attempt_lines, attempt_counts = run_kafka_capture(
                                host,
                                int(audit_port),
                                run_username,
                                run_password,
                                include_data=False,
                            )
                            _attempt_total, attempt_open, attempt_valid, _attempt_auth, _attempt_failed = attempt_counts
                            if attempt_open > 0 or attempt_valid > 0:
                                selected_username = run_username
                                selected_password = run_password
                                break
                    elif base_open > 0 or base_valid > 0:
                        selected_username = None
                        selected_password = None

                    if (
                        selected_username is not None
                        or selected_password is not None
                        or base_open > 0
                        or base_valid > 0
                    ):
                        selected_lines, selected_counts = run_kafka_capture(
                            host,
                            int(audit_port),
                            selected_username,
                            selected_password,
                            include_data=True,
                        )

                    output_sink.emit_many(selected_lines)
                    output_written = output_sink.output_written
                    part_total, part_open, part_valid, part_auth, part_failed = selected_counts
                    total += part_total
                    open_no_auth += part_open
                    valid += part_valid
                    auth_required += part_auth
                    failed += part_failed
                    if outer_progress is not None:
                        outer_progress.advance(1)
        else:
            for audit_port in ports:
                audit_hosts = hosts_by_port[int(audit_port)]
                if not audit_hosts:
                    continue
                host_batches = [[host] for host in audit_hosts] if len(credential_runs) > 1 else [audit_hosts]
                for host_batch in host_batches:
                    deep_already_emitted = False
                    for run_username, run_password in credential_runs:
                        run_show_deep = not deep_already_emitted
                        part_total, part_open, part_valid, part_auth, part_failed = audit_kafka_targets(
                            hosts=host_batch,
                            port=audit_port,
                            timeout=args.timeout,
                            retries=args.retries,
                            workers=args.workers,
                            username=run_username,
                            password=run_password,
                            show_topics=args.show_topics and run_show_deep,
                            query_topic=args.topic if run_show_deep else None,
                            dump=args.dump and run_show_deep,
                            max_messages=args.max_messages,
                            output_path=args.output,
                            output_format=args.output_format,
                            emit_line=emit_line,
                            logger=logger if args.debug else None,
                            append_output=output_written,
                            suppress_connection_refused_status_lines=not bool(args.debug),
                            debug_emit=emit_debug if args.debug else None,
                            show_progress=not use_single_global_progress,
                        )
                        total += part_total
                        open_no_auth += part_open
                        valid += part_valid
                        auth_required += part_auth
                        failed += part_failed
                        if outer_progress is not None:
                            outer_progress.advance(part_total)
                        if part_open > 0 or part_valid > 0:
                            deep_already_emitted = True
                        output_written = True
    except OSError as exc:
        console.error(f"failed to process kafka output: {exc}")
        return 2
    finally:
        if outer_progress is not None:
            outer_progress.close()

    if stream_to_stdout:
        if (
            total > 0
            and open_no_auth == 0
            and valid == 0
            and auth_required == 0
            and failed == total
            and args.output_format == "txt"
        ):
            console.warn("all kafka targets are unreachable; check host/port, network reachability, and service status")

    if args.debug:
        console.info(
            f"kafka audit complete: total={total} anonymous={open_no_auth} valid={valid} "
            f"auth_required={auth_required} fail={failed}"
        )

    return 0
