"""Bounded real CreateTopics/DeleteTopics proof for one verified identity."""

from __future__ import annotations

import json
import secrets
import struct
import time
from collections.abc import Callable
from typing import Any

from ...clients import kafka


def _array(reader: kafka._KafkaReader, minimum_size: int) -> range:
    count = reader.read_i32()
    if count < 0 or count > reader.remaining() // minimum_size:
        raise ValueError("invalid lifecycle response array")
    return range(count)


def _metadata(payload: bytes, correlation: int, topic: str) -> tuple[int, dict[int, tuple[str, int]], int]:
    """Metadata v4: exact topic lookup with auto-creation disabled."""
    reader = kafka._KafkaReader(payload)
    if reader.read_i32() != correlation:
        raise ValueError("unexpected lifecycle correlation id")
    reader.read_i32()  # throttle
    brokers = {}
    for _ in _array(reader, 12):
        node = reader.read_i32()
        host = reader.read_string(nullable=False) or ""
        port = reader.read_i32()
        reader.read_string(nullable=True)  # rack
        brokers[node] = (host, port)
    reader.read_string(nullable=True)  # cluster id
    controller = reader.read_i32()
    found = []
    for _ in _array(reader, 9):
        error = reader.read_i16()
        name = reader.read_string(nullable=False)
        reader.read_i8()  # internal
        for _ in _array(reader, 18):
            reader.read_i16()
            reader.read_i32()
            reader.read_i32()
            reader.skip_i32_array()
            reader.skip_i32_array()
        if name == topic:
            found.append(error)
    if reader.remaining() or len(found) != 1:
        raise ValueError("missing, duplicate or trailing lifecycle metadata")
    return controller, brokers, found[0]


def _mutation_result(payload: bytes, correlation: int, topic: str, *, create: bool) -> int:
    reader = kafka._KafkaReader(payload)
    if reader.read_i32() != correlation:
        raise ValueError("unexpected lifecycle correlation id")
    reader.read_i32()  # throttle
    found = []
    for _ in _array(reader, 6 if create else 4):
        name = reader.read_string(nullable=False)
        error = reader.read_i16()
        if create:
            reader.read_string(nullable=True)
        if name == topic:
            found.append(error)
    if reader.remaining() or len(found) != 1:
        raise ValueError("missing, duplicate or trailing lifecycle mutation result")
    return found[0]


def probe_topic_lifecycle(
    host: str,
    port: int,
    timeout: float,
    *,
    username: str | None,
    password: str | None,
    existing_session: kafka.KafkaSession | None = None,
    use_tls: bool | None = None,
    tls_config: kafka.KafkaTlsConfig | None = None,
    sasl_first: bool = False,
    debug_emit: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    """Create one empty random topic, then confirm its removal.

    Never Produce into it, never delete a collision, never replay an uncertain
    Create. Metadata v4 verification cannot auto-create the deleted topic.
    Cleanup gets a separate bounded deadline, also on cancellation.
    """
    topic = "__redposture_probe_" + secrets.token_hex(16)
    result: dict[str, Any] = {"create": None, "delete": None, "topic": topic, "cleanup_complete": None, "errors": []}
    owned: list[kafka.KafkaSession] = []
    session = existing_session
    timeout = max(0.001, timeout)
    deadline = time.monotonic() + 2 * timeout
    controller: tuple[str, int] | None = None
    sent_create = False
    collision = False
    confirmed_absent = False

    def error(phase: str, exc: object) -> None:
        result["errors"].append(f"{phase}: {exc}")

    def connect(endpoint: tuple[str, int] | None = None) -> kafka.KafkaSession:
        peer = endpoint or (host, port)
        candidate = kafka.KafkaSession.open(
            *peer, timeout, username=username, password=password, use_tls=use_tls, tls_config=tls_config
        )
        owned.append(candidate)
        ok, why = candidate.bootstrap(known_kafka=True, sasl_first=sasl_first)
        if ok is not True:
            raise OSError(why or "lifecycle session authentication unverified")
        return candidate

    def request(api: int, version: int, body: bytes) -> tuple[bytes, int]:
        nonlocal session
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("topic lifecycle deadline")
        if session is None or session.closed:
            session = connect()
        correlation = session.correlation_id
        session.correlation_id += 1
        previous = session.sock.gettimeout()
        session.sock.settimeout(min(timeout, remaining, previous) if previous is not None else min(timeout, remaining))
        try:
            payload = kafka._send_kafka_request(
                session.sock,
                api_key=api,
                api_version=version,
                correlation_id=correlation,
                client_id=kafka.KAFKA_CLIENT_ID,
                body=body,
            )
            return payload, correlation
        except (OSError, ValueError):
            session.close()
            raise
        finally:
            if not session.closed:
                session.sock.settimeout(previous)

    def observe() -> int:
        nonlocal controller
        payload, correlation = request(3, 4, struct.pack(">i", 1) + kafka._encode_kafka_string(topic) + b"\x00")
        node, brokers, code = _metadata(payload, correlation, topic)
        controller = brokers.get(node)
        return code

    def mutate(api: int, version: int, body: bytes) -> int:
        nonlocal session
        payload, correlation = request(api, version, body)
        code = _mutation_result(payload, correlation, topic, create=api == 19)
        if code == 41 and controller is not None:  # authoritative NOT_CONTROLLER: no mutation happened
            session = connect(controller)
            payload, correlation = request(api, version, body)
            code = _mutation_result(payload, correlation, topic, create=api == 19)
        return code

    def wait_for(available: bool) -> bool:
        while time.monotonic() < deadline:
            code = observe()
            if code == (0 if available else 3):
                return True
            if code not in {0, 3, 5, 6}:
                raise ValueError(f"topic visibility: {kafka._kafka_error_name(code)}")
            time.sleep(min(0.05, max(0, deadline - time.monotonic())))
        return False

    try:
        if session is None:
            session = connect()
        versions = getattr(session, "api_versions", None) or {}
        create_min, create_max = versions.get(19, (0, -1))
        delete_min, delete_max = versions.get(20, (0, -1))
        metadata_min, metadata_max = versions.get(3, (0, -1))
        create_version, delete_version = min(4, create_max), min(3, delete_max)
        if not (
            create_min <= create_version
            and create_version >= 2
            and delete_min <= delete_version
            and delete_version >= 1
            and metadata_min <= 4 <= metadata_max
        ):
            error("probe", "required non-flexible Create/Delete/Metadata API versions unavailable")
            return result
        initial = observe()
        confirmed_absent = initial == 3
        if initial == 0:
            collision = True
            error("preflight", "probe name already exists; nothing modified")
            return result
        if not confirmed_absent:
            error("preflight", kafka._kafka_error_name(initial))
        configs = (("retention.ms", "60000"),)
        body = (
            struct.pack(">i", 1)
            + kafka._encode_kafka_string(topic)
            + struct.pack(">ih", 1, -1 if create_version >= 4 else 1)
            + struct.pack(">ii", 0, len(configs))
            + b"".join(kafka._encode_kafka_string(key) + kafka._encode_kafka_string(value) for key, value in configs)
            + struct.pack(">i", max(1, int(timeout * 1000)))
            + b"\x00"
        )
        sent_create = True
        code = mutate(19, create_version, body)
        collision = code == 36
        if code == 0:
            result["create"] = True  # a complete named CreateTopics acknowledgment
        elif code in {29, 31, 37, 38, 40, 42, 44}:
            result["create"] = False
            sent_create = False
        else:
            error("create", kafka._kafka_error_name(code))
        if result["create"] is True and not wait_for(True):
            error("create", "created topic visibility not confirmed before deadline")
    except (OSError, ValueError) as exc:
        error("create", exc)
    finally:
        if sent_create and not collision:
            deadline = time.monotonic() + 2 * timeout
            try:
                present = result["create"] is True or (confirmed_absent and wait_for(True))
                if present:
                    deadline = time.monotonic() + 2 * timeout
                    result["create"] = True
                    code = mutate(
                        20,
                        delete_version,
                        struct.pack(">i", 1)
                        + kafka._encode_kafka_string(topic)
                        + struct.pack(">i", max(1, int(timeout * 1000))),
                    )
                    if code in {29, 31, 73}:
                        result["delete"] = False
                        error("delete", kafka._kafka_error_name(code))
                    elif code not in {0, 3}:
                        error("delete", kafka._kafka_error_name(code))
                    if code in {0, 3} and wait_for(False):
                        result["delete"] = True
                        result["cleanup_complete"] = True
                    else:
                        result["cleanup_complete"] = False
                else:
                    result["cleanup_complete"] = False
                    error("cleanup", "creation outcome unverified; no visible owned topic")
            except (OSError, ValueError) as exc:
                result["cleanup_complete"] = False
                error("cleanup", exc)
                # A missing DeleteTopics reply is not a failed deletion. A
                # fresh, non-auto-creating observation can still prove cleanup.
                try:
                    if result["create"] is True and observe() == 3:
                        result["delete"] = True
                        result["cleanup_complete"] = True
                except (OSError, ValueError) as recovery:
                    error("cleanup verification", recovery)
            except BaseException as interrupted:
                for candidate in owned:
                    candidate.close()
                interrupted.add_note(f"Kafka probe cleanup interrupted; check temporary topic {topic}")
                raise
        for candidate in owned:
            candidate.close()
        if debug_emit is not None:
            try:
                debug_emit("kafka topic lifecycle " + json.dumps(result, ensure_ascii=True))
            except Exception:
                pass  # A diagnostic sink cannot change a verified auth result.
    return result
