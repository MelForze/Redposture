"""Kafka protocol client helpers."""

from __future__ import annotations

import secrets
import socket
import ssl
import struct
from typing import Any

from . import transport

KAFKA_CLIENT_ID = "redposture"
KAFKA_API_VERSIONS = 18
KAFKA_METADATA = 3
KAFKA_FETCH = 1
KAFKA_LIST_OFFSETS = 2
KAFKA_PRODUCE = 0
KAFKA_CREATE_TOPICS = 19
KAFKA_DELETE_TOPICS = 20
KAFKA_SASL_HANDSHAKE = 17
KAFKA_SASL_AUTHENTICATE = 36
KAFKA_AUTH_ERROR_CODES = {29, 31, 58}
KAFKA_MAX_FRAME = 16 * 1024 * 1024
KAFKA_FETCH_MAX_BYTES = 1024 * 1024
_KAFKA_DEFAULT_CREDENTIALS: tuple[tuple[str, str], ...] = (
    ("admin", "admin"),
    ("kafka", "kafka"),
    ("kafka", "password"),
)

# Connection-error classification + framed reads are shared via the transport layer.
_is_connection_refused_error = transport.is_connection_refused
_is_connection_timeout_error = transport.is_connection_timeout
_is_connection_refused_fail_record = transport.is_connection_refused_fail_record
_recv_exact = transport.recv_exact


class _TlsProbeError(Exception):
    """Raised when a plaintext-read yields a TLS record prelude.

    Signals the caller to close the socket, re-open it wrapped in TLS, and
    replay the Kafka protocol from ApiVersions. Kept as a distinct exception
    (not `ValueError`) so plain framing errors stay distinguishable from
    "listener is TLS, retry with wrap_socket".
    """


def _is_tls_record_prelude(raw: bytes) -> bool:
    """Return True if `raw` looks like the first bytes of a TLS record header.

    TLS record types: 0x14 ChangeCipherSpec, 0x15 Alert, 0x16 Handshake,
    0x17 ApplicationData. Second byte is the TLS major version (always 0x03
    for TLS 1.0-1.3 at the record layer); third byte is the minor version
    (0x00-0x04 in practice). Kafka frame lengths never look like this — a
    valid Kafka response of ~350 MiB would exceed `KAFKA_MAX_FRAME` and be
    rejected anyway.
    """
    if len(raw) < 3:
        return False
    return raw[0] in (0x14, 0x15, 0x16, 0x17) and raw[1] == 0x03 and raw[2] in (0x00, 0x01, 0x02, 0x03, 0x04)


# Well-known Kafka SASL_SSL / SSL listener ports. Mixed odd/even by
# convention: even = plaintext / SASL_PLAINTEXT, odd = SASL_SSL / SSL.
# We treat these as "TLS-first" when `use_tls=None` — the auto-detect path
# for the plaintext side stays a `_TlsProbeError` retry, but this shortcut
# spares a round-trip on ports we know are TLS-shaped.
_TLS_FIRST_PORTS = frozenset({9093, 19093, 29093})


def _classify_ssl_error(exc: ssl.SSLError) -> str:
    """Turn a raw OpenSSL exception into a short, non-scary explanation.

    The default `str(SSLError)` is `[SSL: WRONG_VERSION_NUMBER] wrong
    version number (_ssl.c:992)` — technically accurate, but for an
    auditor scanning hundreds of hosts it's noise. Boil it down to the
    root cause the operator actually cares about.
    """
    text = str(exc or "").lower()
    if "wrong_version_number" in text or "wrong version number" in text:
        # Client sent TLS ClientHello, peer answered plaintext (or a
        # totally different protocol). Almost always means "this port
        # isn't TLS at all".
        return "peer answered plaintext to TLS ClientHello (not a TLS listener)"
    if "unexpected_eof_while_reading" in text or "connection has been closed (eof)" in text:
        # Peer accepted the TCP handshake and then immediately hung up on
        # the TLS layer without an alert. Typical for SNI-firewalls,
        # service meshes, or LBs that vet clients before forwarding.
        return "peer closed TLS handshake without alert (SNI filter / firewall / non-Kafka listener)"
    if "sslv3_alert_bad_certificate" in text or "bad_certificate" in text:
        # Peer requires a client certificate (mutual TLS) and rejected
        # our anonymous handshake. Fine — just not something the audit
        # tool can bypass without --tls-cert.
        return "peer requires client certificate (mTLS) — need --tls-cert to proceed"
    if "sslv3_alert_handshake_failure" in text or "handshake_failure" in text:
        return "peer rejected TLS handshake (cipher/protocol mismatch or client auth required)"
    if "certificate_unknown" in text or "certificate verify failed" in text:
        return "peer's TLS certificate is unrecognised (should be masked by CERT_NONE — file bug)"
    if "record layer failure" in text or "no shared cipher" in text:
        return "peer has no shared TLS cipher with client"
    # Last-resort fallback: keep the exception text but strip the noisy
    # _ssl.c:LINE trailer that changes across Python patch releases.
    trimmed = str(exc or "").strip()
    if " (_ssl.c:" in trimmed:
        trimmed = trimmed.split(" (_ssl.c:", 1)[0]
    return trimmed or "TLS handshake failed"


def open_kafka_socket(
    host: str,
    port: int,
    timeout: float,
    *,
    use_tls: bool | None = None,
) -> tuple[socket.socket, str]:
    """Open a TCP (or TLS-wrapped) socket to a Kafka broker.

    Returns `(sock, transport_mode)` where transport_mode is `"plaintext"` or
    `"tls"`. When `use_tls is None`, the well-known SASL_SSL ports
    (9093 / 19093 / 29093) are treated as TLS by default; all other ports
    open plaintext and rely on the caller catching `_TlsProbeError` from
    `_recv_kafka_frame` to retry.

    TLS handshake errors get an auto-fallback to plaintext when `use_tls`
    was inferred (None). That covers the symmetrical case of the TLS-record
    prelude path: instead of a scary `[SSL: WRONG_VERSION_NUMBER]` on a
    port that turns out to be plaintext, we quietly retry as plaintext
    and let the ApiVersions probe decide if it's Kafka.

    Uses `check_hostname=False` + `verify_mode=CERT_NONE` — audit tool posture
    (recon over self-signed brokers is the common case). Mirrors
    `_open_grpc_socket` in `redposture_core/clients/grpc.py`.
    """
    tls_inferred = use_tls is None
    resolved = use_tls if use_tls is not None else (port in _TLS_FIRST_PORTS)
    base = socket.create_connection((host, port), timeout=timeout)
    base.settimeout(timeout)
    if not resolved:
        return base, "plaintext"
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        wrapped = ctx.wrap_socket(base, server_hostname=host)
        wrapped.settimeout(timeout)
    except ssl.SSLError as ssl_exc:
        try:
            base.close()
        except OSError:
            pass
        if tls_inferred:
            # Auto-fallback: reopen as plaintext. If it really is Kafka
            # on the "TLS-first" port, the ApiVersions probe upstairs
            # will confirm; if it isn't, the non-Kafka detection path
            # (`_identify_non_kafka_prelude`) surfaces a clean summary.
            fallback = socket.create_connection((host, port), timeout=timeout)
            fallback.settimeout(timeout)
            return fallback, "plaintext"
        # Caller forced TLS explicitly — surface the friendly reason so
        # the audit line reads e.g. `not a TLS listener` instead of
        # `[SSL: WRONG_VERSION_NUMBER] wrong version number (_ssl.c:992)`.
        raise ValueError(f"TLS handshake failed: {_classify_ssl_error(ssl_exc)}") from ssl_exc
    except BaseException:
        try:
            base.close()
        except OSError:
            pass
        raise
    return wrapped, "tls"


def _clip(text: str, width: int = 64) -> str:
    if len(text) <= width:
        return text
    if width <= 3:
        return text[:width]
    return text[: width - 3] + "..."


def _retry_delay(attempt_index: int) -> float:
    return min(1.50, 0.20 * (2**attempt_index))


def _build_credential_runs(
    username: str | None,
    password: str | None,
    defcreds: bool,
) -> list[tuple[str | None, str | None]]:
    runs: list[tuple[str | None, str | None]] = []
    seen: set[tuple[str | None, str | None]] = set()
    if username is not None and password is not None:
        pair = (username, password)
        runs.append(pair)
        seen.add(pair)
    if defcreds:
        for user, secret in _KAFKA_DEFAULT_CREDENTIALS:
            pair = (user, secret)
            if pair in seen:
                continue
            runs.append(pair)
            seen.add(pair)
    return runs or [(username, password)]


def _friendly_error_text(value: str) -> str:
    from ..utils import friendly_error_text

    return friendly_error_text(value)


def _friendly_error_from_exception(exc: BaseException) -> str:
    from ..utils import friendly_error_from_exception

    return friendly_error_from_exception(exc)


def _is_suppressed_fail_record(record: dict[str, Any]) -> bool:
    return str(record.get("status") or "") == "fail"


def _kafka_error_name(code: int) -> str:
    # Complete map of Kafka wire-protocol error codes from `Errors.java`.
    # Any opaque `ERR_XX` in the audit output means the broker returned a
    # code we don't recognize yet — file an issue with the number so it can
    # be added here. All commonly-hit codes are covered.
    names = {
        0: "NO_ERROR",
        1: "OFFSET_OUT_OF_RANGE",
        2: "CORRUPT_MESSAGE",
        3: "UNKNOWN_TOPIC_OR_PARTITION",
        4: "INVALID_FETCH_SIZE",
        5: "LEADER_NOT_AVAILABLE",
        6: "NOT_LEADER_OR_FOLLOWER",
        7: "REQUEST_TIMED_OUT",
        8: "BROKER_NOT_AVAILABLE",
        9: "REPLICA_NOT_AVAILABLE",
        10: "MESSAGE_TOO_LARGE",
        11: "STALE_CONTROLLER_EPOCH",
        12: "OFFSET_METADATA_TOO_LARGE",
        13: "NETWORK_EXCEPTION",
        14: "COORDINATOR_LOAD_IN_PROGRESS",
        15: "COORDINATOR_NOT_AVAILABLE",
        16: "NOT_COORDINATOR",
        17: "INVALID_TOPIC_EXCEPTION",
        18: "RECORD_LIST_TOO_LARGE",
        19: "NOT_ENOUGH_REPLICAS",
        20: "NOT_ENOUGH_REPLICAS_AFTER_APPEND",
        21: "INVALID_REQUIRED_ACKS",
        22: "ILLEGAL_GENERATION",
        23: "INCONSISTENT_GROUP_PROTOCOL",
        24: "INVALID_GROUP_ID",
        25: "UNKNOWN_MEMBER_ID",
        26: "INVALID_SESSION_TIMEOUT",
        27: "REBALANCE_IN_PROGRESS",
        28: "INVALID_COMMIT_OFFSET_SIZE",
        29: "TOPIC_AUTHORIZATION_FAILED",
        30: "GROUP_AUTHORIZATION_FAILED",
        31: "CLUSTER_AUTHORIZATION_FAILED",
        32: "INVALID_TIMESTAMP",
        33: "UNSUPPORTED_SASL_MECHANISM",
        34: "ILLEGAL_SASL_STATE",
        35: "UNSUPPORTED_VERSION",
        36: "TOPIC_ALREADY_EXISTS",
        37: "INVALID_PARTITIONS",
        38: "INVALID_REPLICATION_FACTOR",
        39: "INVALID_REPLICA_ASSIGNMENT",
        40: "INVALID_CONFIG",
        41: "NOT_CONTROLLER",
        42: "INVALID_REQUEST",
        43: "UNSUPPORTED_FOR_MESSAGE_FORMAT",
        44: "POLICY_VIOLATION",
        45: "OUT_OF_ORDER_SEQUENCE_NUMBER",
        46: "DUPLICATE_SEQUENCE_NUMBER",
        47: "INVALID_PRODUCER_EPOCH",
        48: "INVALID_TXN_STATE",
        49: "INVALID_PRODUCER_ID_MAPPING",
        50: "INVALID_TRANSACTION_TIMEOUT",
        51: "CONCURRENT_TRANSACTIONS",
        52: "TRANSACTION_COORDINATOR_FENCING",
        53: "TRANSACTIONAL_ID_AUTHORIZATION_FAILED",
        54: "SECURITY_DISABLED",
        55: "OPERATION_NOT_ATTEMPTED",
        56: "KAFKA_STORAGE_ERROR",
        57: "LOG_DIR_NOT_FOUND",
        58: "SASL_AUTHENTICATION_FAILED",
        59: "UNKNOWN_PRODUCER_ID",
        60: "REASSIGNMENT_IN_PROGRESS",
        61: "DELEGATION_TOKEN_AUTH_DISABLED",
        62: "DELEGATION_TOKEN_NOT_FOUND",
        63: "DELEGATION_TOKEN_OWNER_MISMATCH",
        64: "DELEGATION_TOKEN_REQUEST_NOT_ALLOWED",
        65: "DELEGATION_TOKEN_AUTHORIZATION_FAILED",
        66: "DELEGATION_TOKEN_EXPIRED",
        67: "INVALID_PRINCIPAL_TYPE",
        68: "NON_EMPTY_GROUP",
        69: "GROUP_ID_NOT_FOUND",
        70: "FETCH_SESSION_ID_NOT_FOUND",
        71: "INVALID_FETCH_SESSION_EPOCH",
        72: "LISTENER_NOT_FOUND",
        73: "TOPIC_DELETION_DISABLED",
        74: "FENCED_LEADER_EPOCH",
        75: "UNKNOWN_LEADER_EPOCH",
        # 76 = UNSUPPORTED_COMPRESSION_TYPE — legacy Fetch API versions can't
        # decode records the broker stored with certain codecs (notably zstd,
        # KIP-110). The client now sends Fetch v10 which supports every
        # codec zstd/snappy/lz4/gzip out of the box, so this shouldn't
        # surface on a modern deployment.
        76: "UNSUPPORTED_COMPRESSION_TYPE",
        77: "STALE_BROKER_EPOCH",
        78: "OFFSET_NOT_AVAILABLE",
        79: "MEMBER_ID_REQUIRED",
        80: "PREFERRED_LEADER_NOT_AVAILABLE",
        81: "GROUP_MAX_SIZE_REACHED",
        82: "FENCED_INSTANCE_ID",
        83: "ELIGIBLE_LEADERS_NOT_AVAILABLE",
        84: "ELECTION_NOT_NEEDED",
        85: "NO_REASSIGNMENT_IN_PROGRESS",
        86: "GROUP_SUBSCRIBED_TO_TOPIC",
        87: "INVALID_RECORD",
        88: "UNSTABLE_OFFSET_COMMIT",
        89: "THROTTLING_QUOTA_EXCEEDED",
        90: "PRODUCER_FENCED",
    }
    return names.get(code, f"ERR_{code}")


def _is_probable_auth_error(message: str | None, error_codes: list[int] | None = None) -> bool:
    if error_codes and any(code in KAFKA_AUTH_ERROR_CODES for code in error_codes):
        return True
    text = str(message or "").lower()
    needles = (
        "authentication",
        "sasl",
        "authorization",
        "not authorized",
    )
    return any(needle in text for needle in needles)


def _is_sasl_probe_candidate(message: str | None) -> bool:
    text = str(message or "").strip().lower()
    if not text:
        return False
    needles = (
        "unexpected eof",
        "connection reset",
        "connection aborted",
        "broken pipe",
        "forcibly closed",
        "end of file",
    )
    return any(needle in text for needle in needles)


# HTTP request-method / response prefixes we may see when the peer is an
# HTTP server rather than a Kafka broker. Confluent REST Proxy, misconfigured
# admin panels and general web servers behind SSH tunnels all show up here.
_HTTP_REQUEST_PREFIXES = frozenset({b"GET ", b"POST", b"PUT ", b"HEAD", b"OPTI", b"DELE", b"PATC", b"TRAC", b"CONN"})
# `HTTP/1.x` server responses (e.g. `HTTP/1.1 400 Bad Request`).
_HTTP_RESPONSE_PREFIX = b"HTTP"


def _identify_non_kafka_prelude(raw: bytes) -> str | None:
    """Return a human-readable hint when the first 4 bytes of a "Kafka
    frame" are clearly speaking a different protocol.

    Kafka frame_size is a big-endian int32 in [1, 16 MiB]. If we see the
    peer respond with printable ASCII, chances are it's not Kafka at all
    (typical decoded values like 1213486160 = 0x48545450 = 'HTTP' or
    1195725856 = 0x47455420 = 'GET ' are dead giveaways). This helper lets
    the caller report "this port isn't Kafka" instead of the cryptic
    "invalid Kafka frame size N".

    Returns:
      "HTTP request"  — first bytes look like an HTTP request method
      "HTTP response" — starts with `HTTP` (e.g. `HTTP/1.1 400`)
      "ASCII text"    — all 4 bytes are printable ASCII, no known match
      None            — first bytes look genuinely binary; fall through
                        to the generic "invalid Kafka frame size" path.
    """
    if len(raw) < 4:
        return None
    if raw[:4] == _HTTP_RESPONSE_PREFIX:
        return "HTTP response"
    if raw[:4] in _HTTP_REQUEST_PREFIXES:
        return "HTTP request"
    if all(0x20 <= byte <= 0x7E for byte in raw):
        return "ASCII text"
    return None


def _recv_kafka_frame(sock: socket.socket) -> bytes:
    raw_size = _recv_exact(sock, 4)
    if _is_tls_record_prelude(raw_size):
        raise _TlsProbeError(f"plaintext read returned TLS record prelude: {raw_size!r}")
    non_kafka_kind = _identify_non_kafka_prelude(raw_size)
    if non_kafka_kind is not None:
        # Peek a bit more to preview what the peer is actually saying so the
        # operator can jump straight to the culprit. Non-blocking best-effort:
        # if the socket has no more data ready or it errors, we still surface
        # the first 4 bytes.
        peek = b""
        previous_timeout = sock.gettimeout()
        try:
            sock.settimeout(0.2)
            peek = sock.recv(120)
        except (OSError, TimeoutError, ValueError):
            peek = b""
        finally:
            try:
                sock.settimeout(previous_timeout)
            except (OSError, ValueError):
                pass
        preview = (raw_size + peek).decode("ascii", errors="replace").strip().splitlines()
        first_line = preview[0][:60] if preview else raw_size.decode("ascii", errors="replace")
        raise ValueError(
            f"not a Kafka broker: peer sent {non_kafka_kind} "
            f"({first_line!r}). Check the port — an HTTP service or admin "
            f"panel is likely listening here instead of Kafka."
        )
    (frame_size,) = struct.unpack(">i", raw_size)
    if frame_size <= 0 or frame_size > KAFKA_MAX_FRAME:
        # Fall-through: printable-ASCII was already filtered above, so if we
        # got here the bytes are genuinely binary garbage. Include the raw
        # hex so the operator can eyeball it against a wire trace.
        raise ValueError(
            f"invalid Kafka frame size {frame_size} (raw bytes: 0x{raw_size.hex()}; "
            f"expected 1..{KAFKA_MAX_FRAME}). The peer may be a load balancer "
            f"or proxy speaking an unknown protocol."
        )
    return _recv_exact(sock, frame_size)


def _encode_kafka_string(value: str) -> bytes:
    raw = value.encode("utf-8")
    if len(raw) > 32767:
        raise ValueError("Kafka string exceeds int16 length")
    return struct.pack(">h", len(raw)) + raw


def _encode_kafka_nullable_string(value: str | None) -> bytes:
    if value is None:
        return struct.pack(">h", -1)
    return _encode_kafka_string(value)


def _encode_kafka_bytes(value: bytes) -> bytes:
    return struct.pack(">i", len(value)) + value


def _build_request_header(api_key: int, api_version: int, correlation_id: int, client_id: str) -> bytes:
    return (
        struct.pack(">hh", int(api_key), int(api_version))
        + struct.pack(">i", int(correlation_id))
        + _encode_kafka_string(client_id)
    )


def _send_kafka_request(
    sock: socket.socket,
    *,
    api_key: int,
    api_version: int,
    correlation_id: int,
    client_id: str,
    body: bytes = b"",
) -> bytes:
    frame = _build_request_header(api_key, api_version, correlation_id, client_id) + body
    sock.sendall(struct.pack(">i", len(frame)) + frame)
    return _recv_kafka_frame(sock)


class _KafkaReader:
    def __init__(self, data: bytes) -> None:
        self._data = data
        self._pos = 0

    def remaining(self) -> int:
        return len(self._data) - self._pos

    def _read(self, size: int) -> bytes:
        if size < 0:
            raise ValueError("negative read size")
        end = self._pos + size
        if end > len(self._data):
            raise ValueError("unexpected EOF while parsing Kafka response")
        chunk = self._data[self._pos : end]
        self._pos = end
        return chunk

    def read_i16(self) -> int:
        return struct.unpack(">h", self._read(2))[0]

    def read_i8(self) -> int:
        return struct.unpack(">b", self._read(1))[0]

    def read_i32(self) -> int:
        return struct.unpack(">i", self._read(4))[0]

    def read_i64(self) -> int:
        return struct.unpack(">q", self._read(8))[0]

    def read_string(self, *, nullable: bool = False) -> str | None:
        size = self.read_i16()
        if size < 0:
            if nullable:
                return None
            raise ValueError("Kafka non-nullable string is null")
        return self._read(size).decode("utf-8", errors="replace")

    def read_bytes(self, *, nullable: bool = False) -> bytes | None:
        size = self.read_i32()
        if size < 0:
            if nullable:
                return None
            raise ValueError("Kafka non-nullable bytes is null")
        return self._read(size)

    def skip_i32_array(self) -> None:
        count = self.read_i32()
        if count < 0:
            return
        self._read(4 * count)

    def read_string_array(self) -> list[str]:
        count = self.read_i32()
        if count < 0:
            return []
        result: list[str] = []
        for _ in range(count):
            value = self.read_string(nullable=False)
            result.append(str(value))
        return result


def _parse_apiversions_response(payload: bytes, expected_correlation_id: int) -> tuple[bool, int | None, str | None]:
    try:
        reader = _KafkaReader(payload)
        correlation_id = reader.read_i32()
        if correlation_id != expected_correlation_id:
            return False, None, f"unexpected correlation id {correlation_id} (expected {expected_correlation_id})"

        error_code = reader.read_i16()
        if reader.remaining() >= 4:
            count = reader.read_i32()
            if count >= 0:
                for _ in range(count):
                    if reader.remaining() < 6:
                        return False, error_code, "invalid ApiVersions entry payload"
                    _ = reader.read_i16()
                    _ = reader.read_i16()
                    _ = reader.read_i16()
        return True, int(error_code), None
    except (ValueError, struct.error) as exc:
        return False, None, f"invalid ApiVersions response: {exc}"


def _parse_metadata_response(
    payload: bytes,
    expected_correlation_id: int,
) -> tuple[dict[str, Any] | None, str | None]:
    try:
        reader = _KafkaReader(payload)
        correlation_id = reader.read_i32()
        if correlation_id != expected_correlation_id:
            return None, f"unexpected correlation id {correlation_id} (expected {expected_correlation_id})"

        broker_count = reader.read_i32()
        if broker_count < 0:
            return None, "invalid broker array size"
        # `broker_map` is what makes partition-aware routing possible: on
        # multi-broker clusters each partition's leader can live on a
        # different broker, and ListOffsets/Fetch requests must go to that
        # specific leader (otherwise the broker returns NOT_LEADER_OR_FOLLOWER
        # = error code 6). Previously we discarded these fields entirely
        # and paid for it with cryptic dump failures on real clusters.
        broker_map: dict[int, tuple[str, int]] = {}
        for _ in range(broker_count):
            broker_node_id = reader.read_i32()
            broker_host = reader.read_string(nullable=False) or ""
            broker_port = reader.read_i32()
            if broker_host:
                broker_map[int(broker_node_id)] = (broker_host, int(broker_port))

        topic_count_raw = reader.read_i32()
        if topic_count_raw < 0:
            return None, "invalid topic metadata array size"

        topic_map: dict[str, int] = {}
        topic_errors: dict[str, int] = {}
        all_error_codes: list[int] = []
        accessible_topics = 0
        partition_leaders: dict[str, dict[int, int]] = {}

        for _ in range(topic_count_raw):
            topic_error = reader.read_i16()
            topic_name = reader.read_string(nullable=False) or ""
            partition_count_raw = reader.read_i32()
            partition_count = 0 if partition_count_raw < 0 else partition_count_raw
            all_error_codes.append(int(topic_error))

            topic_partition_leaders: dict[int, int] = {}
            for _ in range(partition_count):
                partition_error = reader.read_i16()
                partition_id = reader.read_i32()
                leader_id = reader.read_i32()
                reader.skip_i32_array()  # replicas
                reader.skip_i32_array()  # isr
                all_error_codes.append(int(partition_error))
                if leader_id >= 0:
                    topic_partition_leaders[int(partition_id)] = int(leader_id)

            if topic_name:
                topic_map[topic_name] = partition_count
                topic_errors[topic_name] = int(topic_error)
                if topic_partition_leaders:
                    partition_leaders[topic_name] = topic_partition_leaders
            if topic_error == 0:
                accessible_topics += 1

        auth_hits = [code for code in all_error_codes if code in KAFKA_AUTH_ERROR_CODES]
        auth_required = bool(auth_hits) and accessible_topics == 0

        topics_sorted = sorted(topic_map.keys())
        return (
            {
                "topic_map": topic_map,
                "topics": topics_sorted,
                "topic_count": len(topics_sorted),
                "topic_errors": topic_errors,
                "error_codes": all_error_codes,
                "auth_required": auth_required,
                "broker_map": broker_map,
                "partition_leaders": partition_leaders,
            },
            None,
        )
    except (ValueError, struct.error) as exc:
        return None, f"invalid Metadata response: {exc}"


def _build_metadata_request_body(topics: list[str] | None) -> bytes:
    if topics is None:
        return struct.pack(">i", 0)
    encoded = [struct.pack(">i", len(topics))]
    for topic in topics:
        encoded.append(_encode_kafka_string(topic))
    return b"".join(encoded)


def _probe_apiversions(sock: socket.socket, correlation_id: int) -> tuple[bool, int | None, str | None]:
    payload = _send_kafka_request(
        sock,
        api_key=KAFKA_API_VERSIONS,
        api_version=0,
        correlation_id=correlation_id,
        client_id=KAFKA_CLIENT_ID,
        body=b"",
    )
    return _parse_apiversions_response(payload, correlation_id)


def _fetch_metadata(
    sock: socket.socket,
    correlation_id: int,
    *,
    topics: list[str] | None = None,
) -> tuple[dict[str, Any] | None, str | None]:
    payload = _send_kafka_request(
        sock,
        api_key=KAFKA_METADATA,
        api_version=0,
        correlation_id=correlation_id,
        client_id=KAFKA_CLIENT_ID,
        body=_build_metadata_request_body(topics),
    )
    return _parse_metadata_response(payload, correlation_id)


def _build_list_offsets_request_body(topic: str, partition: int, *, time_value: int = -2) -> bytes:
    return (
        struct.pack(">i", -1)
        + struct.pack(">i", 1)
        + _encode_kafka_string(topic)
        + struct.pack(">i", 1)
        + struct.pack(">i", int(partition))
        + struct.pack(">q", int(time_value))
        + struct.pack(">i", 1)
    )


def _parse_list_offsets_response(payload: bytes, expected_correlation_id: int) -> tuple[int | None, str | None]:
    try:
        reader = _KafkaReader(payload)
        correlation_id = reader.read_i32()
        if correlation_id != expected_correlation_id:
            return None, f"unexpected correlation id {correlation_id} (expected {expected_correlation_id})"

        topic_count = reader.read_i32()
        if topic_count <= 0:
            return None, "ListOffsets returned empty topic list"

        _ = reader.read_string(nullable=False) or ""
        partition_count = reader.read_i32()
        if partition_count <= 0:
            return None, "ListOffsets returned empty partition list"

        _ = reader.read_i32()
        error_code = reader.read_i16()
        if error_code != 0:
            return None, f"ListOffsets failed: {_kafka_error_name(int(error_code))}"

        offset_count = reader.read_i32()
        if offset_count <= 0:
            return None, "ListOffsets returned no offsets"

        return int(reader.read_i64()), None
    except (ValueError, struct.error) as exc:
        return None, f"invalid ListOffsets response: {exc}"


KAFKA_FETCH_API_VERSION = 10  # Kafka 2.3+; required for zstd (KIP-110). Fixes ERR_76.


def _build_fetch_request_body(
    topic: str, partition: int, offset: int, *, max_bytes: int = KAFKA_FETCH_MAX_BYTES
) -> bytes:
    # Fetch v10 wire format:
    #   replica_id (-1)             | int32
    #   max_wait_ms                 | int32
    #   min_bytes                   | int32
    #   max_bytes (whole response)  | int32  <- new in v3
    #   isolation_level             | int8   <- new in v4 (0 = READ_UNCOMMITTED)
    #   session_id                  | int32  <- new in v7 (0 = no fetch session)
    #   session_epoch               | int32  <- new in v7 (-1 = INITIAL_EPOCH)
    #   topics [                    | int32 count
    #     topic name                | string
    #     partitions [              | int32 count
    #       partition_id            | int32
    #       current_leader_epoch    | int32  <- new in v9 (-1 = unknown)
    #       fetch_offset            | int64
    #       log_start_offset        | int64  <- new in v5 (-1 = broker default)
    #       partition_max_bytes     | int32
    #     ]
    #   ]
    #   forgotten_topics [          | int32 count  <- new in v7
    #     topic name                | string
    #     partitions [int32]        | int32 count
    #   ]
    #
    # v10 is important: KIP-110 wired the response schema so brokers can
    # send zstd-compressed records without upgrading the client further.
    # Fetch v4 gets ERR_76 (UNSUPPORTED_COMPRESSION_TYPE) on any topic
    # whose stored batches use zstd — very common on high-throughput topics.
    return (
        struct.pack(">i", -1)  # replica_id
        + struct.pack(">i", 300)  # max_wait_ms
        + struct.pack(">i", 1)  # min_bytes
        + struct.pack(">i", int(max_bytes) * 2)  # max_bytes (whole response)
        + struct.pack(">b", 0)  # isolation_level READ_UNCOMMITTED
        + struct.pack(">i", 0)  # session_id (v7+)
        + struct.pack(">i", -1)  # session_epoch (v7+)
        + struct.pack(">i", 1)  # topics count
        + _encode_kafka_string(topic)
        + struct.pack(">i", 1)  # partitions count
        + struct.pack(">i", int(partition))
        + struct.pack(">i", -1)  # current_leader_epoch (v9+)
        + struct.pack(">q", int(offset))
        + struct.pack(">q", -1)  # log_start_offset (v5+)
        + struct.pack(">i", int(max_bytes))
        + struct.pack(">i", 0)  # forgotten_topics count (v7+)
    )


def _read_unsigned_varint(reader: _KafkaReader) -> int:
    shift = 0
    result = 0
    while shift < 35:
        byte = reader.read_i8() & 0xFF
        result |= (byte & 0x7F) << shift
        if (byte & 0x80) == 0:
            return result
        shift += 7
    raise ValueError("Kafka varint is too long")


def _read_varint(reader: _KafkaReader) -> int:
    raw = _read_unsigned_varint(reader)
    return (raw >> 1) ^ -(raw & 1)


def _read_varlong(reader: _KafkaReader) -> int:
    shift = 0
    result = 0
    while shift < 70:
        byte = reader.read_i8() & 0xFF
        result |= (byte & 0x7F) << shift
        if (byte & 0x80) == 0:
            return (result >> 1) ^ -(result & 1)
        shift += 7
    raise ValueError("Kafka varlong is too long")


def _read_var_bytes(reader: _KafkaReader) -> bytes | None:
    size = _read_varint(reader)
    if size < 0:
        return None
    if size > reader.remaining():
        raise ValueError("unexpected EOF while parsing Kafka varbytes")
    return reader._read(size)  # noqa: SLF001


def _skip_record_headers(reader: _KafkaReader) -> None:
    header_count = _read_varint(reader)
    if header_count < 0:
        raise ValueError("invalid Kafka record header count")
    for _ in range(header_count):
        key_size = _read_varint(reader)
        if key_size < 0 or key_size > reader.remaining():
            raise ValueError("invalid Kafka record header key size")
        reader._read(key_size)  # noqa: SLF001
        value = _read_var_bytes(reader)
        _ = value


def _parse_record_batch_entries(base_offset: int, batch: bytes, max_messages: int) -> list[tuple[int, str]]:
    items: list[tuple[int, str]] = []
    reader = _KafkaReader(batch)
    if reader.remaining() < 49:
        return items
    _ = reader.read_i32()  # partition leader epoch
    magic = reader.read_i8()
    if magic != 2:
        return items
    _ = reader.read_i32()  # crc
    attributes = reader.read_i16()
    compression = int(attributes) & 0x07
    _ = reader.read_i32()  # last offset delta
    _ = reader.read_i64()  # first timestamp
    _ = reader.read_i64()  # max timestamp
    _ = reader.read_i64()  # producer id
    _ = reader.read_i16()  # producer epoch
    _ = reader.read_i32()  # base sequence
    record_count = reader.read_i32()
    if compression:
        return items
    if record_count < 0:
        raise ValueError("invalid Kafka record batch count")

    for _ in range(record_count):
        if len(items) >= max_messages:
            break
        record_size = _read_varint(reader)
        if record_size < 0:
            raise ValueError("invalid Kafka record size")
        if record_size > reader.remaining():
            raise ValueError("unexpected EOF while parsing Kafka record")
        record_reader = _KafkaReader(reader._read(record_size))  # noqa: SLF001
        _ = record_reader.read_i8()  # attributes
        _ = _read_varlong(record_reader)  # timestamp delta
        offset_delta = _read_varint(record_reader)
        _ = _read_var_bytes(record_reader)  # key
        value = _read_var_bytes(record_reader)
        _skip_record_headers(record_reader)
        if value is None:
            continue
        decoded = value.decode("utf-8", errors="replace")
        if decoded:
            items.append((int(base_offset) + int(offset_delta), decoded))
    return items


def _parse_message_set_entries(message_set: bytes, max_messages: int) -> list[tuple[int, str]]:
    items: list[tuple[int, str]] = []
    reader = _KafkaReader(message_set)

    while reader.remaining() >= 12 and len(items) < max_messages:
        try:
            offset = reader.read_i64()
            message_size = reader.read_i32()
            if message_size <= 0 or message_size > reader.remaining():
                break

            message_body = reader._read(message_size)  # noqa: SLF001
            if len(message_body) >= 5 and message_body[4] == 2:
                items.extend(_parse_record_batch_entries(int(offset), message_body, max_messages - len(items)))
                continue

            message_reader = _KafkaReader(message_body)
            if message_reader.remaining() < 6:
                continue

            _ = message_reader.read_i32()  # crc
            magic = message_reader.read_i8()
            _ = message_reader.read_i8()  # attributes
            if magic >= 1 and message_reader.remaining() >= 8:
                _ = message_reader.read_i64()  # timestamp

            _ = message_reader.read_bytes(nullable=True)  # key
            value = message_reader.read_bytes(nullable=True)
            if value is None:
                continue

            decoded = value.decode("utf-8", errors="replace")
            if decoded:
                items.append((int(offset), decoded))
        except (ValueError, struct.error):
            break

    return items


def _parse_fetch_response(
    payload: bytes,
    expected_correlation_id: int,
    *,
    expected_partition: int,
    max_messages: int,
) -> tuple[list[tuple[int, str]] | None, str | None]:
    """Parse a Fetch v10 response.

    Wire format:
      throttle_time_ms        | int32   (v1+)
      top_error_code          | int16   (v7+ — session-level error)
      session_id              | int32   (v7+ — for incremental fetch)
      topics [                | int32 count
        topic_name            | string
        partitions [          | int32 count
          partition_id        | int32
          error_code          | int16
          high_watermark      | int64
          last_stable_offset  | int64   (v4+)
          log_start_offset    | int64   (v5+)
          aborted_txns [      | int32 count (nullable, -1 = null)
            producer_id       | int64
            first_offset      | int64
          ]
          records_size        | int32   (nullable, -1 = null)
          records             | bytes   (record-batch v2 format)
        ]
      ]
    """
    try:
        reader = _KafkaReader(payload)
        correlation_id = reader.read_i32()
        if correlation_id != expected_correlation_id:
            return None, f"unexpected correlation id {correlation_id} (expected {expected_correlation_id})"

        _ = reader.read_i32()  # throttle_time_ms
        top_error_code = reader.read_i16()  # v7+
        if top_error_code != 0:
            # Session-level error — the whole response is invalid.
            return None, f"Fetch session error: {_kafka_error_name(int(top_error_code))}"
        _ = reader.read_i32()  # session_id (v7+)

        topic_count = reader.read_i32()
        if topic_count <= 0:
            return [], None

        for _ in range(topic_count):
            topic_name = reader.read_string(nullable=False) or ""
            partition_count = reader.read_i32()
            for _ in range(max(0, partition_count)):
                partition = reader.read_i32()
                error_code = reader.read_i16()
                high_watermark = reader.read_i64()
                last_stable_offset = reader.read_i64()  # v4+
                log_start_offset = reader.read_i64()  # v5+
                aborted_count = reader.read_i32()
                if aborted_count > 0:
                    # Skip aborted transactions: each is two int64s.
                    for _ in range(aborted_count):
                        _ = reader.read_i64()  # producer_id
                        _ = reader.read_i64()  # first_offset
                records_size = reader.read_i32()
                # Kafka spec: `records` is a NULLABLE_BYTES field
                # (nullableVersions "0+" in FetchResponse.json). A `-1` size is
                # the null-sentinel and means "broker sent no records for this
                # partition" — common for empty partitions or when the
                # requested offset equals high_watermark.
                if records_size == -1:
                    records = b""
                elif records_size < 0 or records_size > reader.remaining():
                    return None, (
                        f"invalid Fetch message set size: got {records_size} "
                        f"but only {reader.remaining()} bytes remain "
                        f"(topic={topic_name!r}, partition={partition}, "
                        f"error_code={error_code} = {_kafka_error_name(int(error_code))}, "
                        f"high_watermark={high_watermark}, "
                        f"last_stable_offset={last_stable_offset}, "
                        f"log_start_offset={log_start_offset})"
                    )
                else:
                    records = reader._read(records_size)  # noqa: SLF001

                if partition != expected_partition:
                    continue
                if error_code != 0:
                    return None, (
                        f"Fetch failed: {_kafka_error_name(int(error_code))} "
                        f"(topic={topic_name!r}, partition={partition}, "
                        f"high_watermark={high_watermark}, "
                        f"log_start_offset={log_start_offset})"
                    )
                entries = _parse_message_set_entries(records, max_messages)
                if not entries and records:
                    # Broker returned records bytes but our parser produced
                    # zero decodable messages. Most common cause: the batch
                    # uses a compression codec (zstd/snappy/lz4/gzip) and
                    # `_parse_record_batch_entries` skips compressed batches
                    # because we don't ship decompression libs. Surface a
                    # hint so the operator understands why (max:N) shows
                    # zero.
                    return None, (
                        f"Fetch returned {len(records)} bytes of records but zero "
                        f"decodable messages — likely a compressed record batch "
                        f"(zstd/snappy/lz4/gzip). Decompression is not implemented "
                        f"in the audit client. (topic={topic_name!r}, "
                        f"partition={partition}, high_watermark={high_watermark})"
                    )
                return entries, None

        return [], None
    except (ValueError, struct.error) as exc:
        return None, f"invalid Fetch response: {exc}"


def _authenticate_or_probe(
    sock: socket.socket,
    correlation: int,
    username: str | None,
    password: str | None,
    *,
    sasl_first: bool = False,
) -> tuple[bool, int, str | None]:
    """Bootstrap a Kafka session on ``sock``.

    The normal path starts with ApiVersions (many brokers require it as the
    opening exchange even on SASL_SSL), then uses SASL PLAIN when credentials
    are provided. ``sasl_first`` is the compatibility retry for brokers that
    reject ApiVersions until the SASL handshake completes.

    Returns `(ok, next_correlation_id, error)`.
    """
    if sasl_first:
        if username is None or password is None:
            return False, correlation, "SASL authentication requires credentials"
        hs_ok, correlation, hs_error = _sasl_handshake_plain(sock, correlation)
        if not hs_ok:
            return False, correlation, hs_error or "SASL handshake failed"
        auth_ok, correlation, auth_error = _sasl_authenticate_plain(sock, correlation, username, password)
        if not auth_ok:
            return False, correlation, auth_error or "authentication failed"
        return True, correlation, None

    is_kafka, _api_error_code, api_error = _probe_apiversions(sock, correlation)
    correlation += 1
    if not is_kafka:
        return False, correlation, api_error or "service is not kafka"
    if username is not None and password is not None:
        hs_ok, correlation, hs_error = _sasl_handshake_plain(sock, correlation)
        if not hs_ok:
            return False, correlation, hs_error or "SASL handshake failed"
        auth_ok, correlation, auth_error = _sasl_authenticate_plain(sock, correlation, username, password)
        if not auth_ok:
            return False, correlation, auth_error or "authentication failed"
    return True, correlation, None


def _read_partition_messages_on_leader(
    leader_sock: socket.socket,
    correlation: int,
    topic: str,
    partition: int,
    remaining: int,
) -> tuple[list[str], int, str | None]:
    """Do ListOffsets + Fetch for a single partition on the leader socket.
    Returns `(items, next_correlation, error)`. Items are `[f"p{partition}@{offset} text", ...]`.
    """
    list_offsets_payload = _send_kafka_request(
        leader_sock,
        api_key=KAFKA_LIST_OFFSETS,
        api_version=0,
        correlation_id=correlation,
        client_id=KAFKA_CLIENT_ID,
        body=_build_list_offsets_request_body(topic, partition, time_value=-2),
    )
    earliest_offset, list_offsets_error = _parse_list_offsets_response(list_offsets_payload, correlation)
    correlation += 1
    if list_offsets_error:
        return [], correlation, list_offsets_error
    if earliest_offset is None:
        return [], correlation, None

    fetch_payload = _send_kafka_request(
        leader_sock,
        api_key=KAFKA_FETCH,
        api_version=KAFKA_FETCH_API_VERSION,
        correlation_id=correlation,
        client_id=KAFKA_CLIENT_ID,
        body=_build_fetch_request_body(
            topic,
            partition,
            earliest_offset,
            max_bytes=KAFKA_FETCH_MAX_BYTES,
        ),
    )
    fetch_items, fetch_error = _parse_fetch_response(
        fetch_payload,
        correlation,
        expected_partition=partition,
        max_messages=remaining,
    )
    correlation += 1
    if fetch_error:
        return [], correlation, fetch_error
    if not fetch_items:
        return [], correlation, None
    items = [f"p{partition}@{offset} {text}" for offset, text in fetch_items[:remaining]]
    return items, correlation, None


def _probe_topic_read_permission(
    sock: socket.socket,
    correlation: int,
    topic: str,
    partition: int = 0,
) -> tuple[bool | None, int]:
    """Probe whether the current SASL session can Read a topic.

    Sends a tiny `Fetch(topic, partition, offset=0, max_bytes=1)` — this is
    the standard non-destructive way to check the Kafka `Read` ACL. Broker
    replies with:
      - error_code = 29 (TOPIC_AUTHORIZATION_FAILED) → read = False
      - error_code = 0                              → read = True
      - anything else (transient / not-leader / storage errors) → None
        (inconclusive; the caller renders the topic without a marker)

    Returns `(read_or_none, next_correlation_id)`.
    """
    try:
        payload = _send_kafka_request(
            sock,
            api_key=KAFKA_FETCH,
            api_version=KAFKA_FETCH_API_VERSION,
            correlation_id=correlation,
            client_id=KAFKA_CLIENT_ID,
            body=_build_fetch_request_body(topic, partition, offset=0, max_bytes=1),
        )
    except (TimeoutError, ConnectionError, OSError, ValueError):
        return None, correlation + 1
    correlation += 1
    # Walk the response manually so a per-partition error surfaces even
    # when max_bytes=1 truncates the batch to zero records.
    try:
        reader = _KafkaReader(payload)
        _ = reader.read_i32()  # correlation
        _ = reader.read_i32()  # throttle_time_ms
        top_error = reader.read_i16()  # v7+ top-level error
        if top_error == 29:
            return False, correlation
        _ = reader.read_i32()  # session_id
        topic_count = reader.read_i32()
        for _ in range(max(0, topic_count)):
            _ = reader.read_string(nullable=False) or ""
            partition_count = reader.read_i32()
            for _ in range(max(0, partition_count)):
                _ = reader.read_i32()  # partition_id
                error_code = reader.read_i16()
                _ = reader.read_i64()  # high_watermark
                _ = reader.read_i64()  # last_stable_offset
                _ = reader.read_i64()  # log_start_offset
                aborted_count = reader.read_i32()
                if aborted_count > 0:
                    for _ in range(aborted_count):
                        _ = reader.read_i64()  # producer_id
                        _ = reader.read_i64()  # first_offset
                records_size = reader.read_i32()
                if records_size > 0:
                    _ = reader._read(records_size)  # noqa: SLF001
                if error_code == 29:
                    return False, correlation
                if error_code == 0:
                    return True, correlation
                # Any other code (LEADER_NOT_AVAILABLE, NOT_LEADER, etc.)
                # is inconclusive for the Read ACL — don't paint a marker.
                return None, correlation
        return None, correlation
    except (ValueError, struct.error):
        return None, correlation


_WRITE_PROBE_MARKER = b"[REDPOSTURE-AUDIT-PROBE-DO-NOT-USE]"


def _build_produce_probe_batch() -> bytes:
    """Build a minimal but VALID Kafka v2 record batch containing one marker
    record (`[REDPOSTURE-AUDIT-PROBE-DO-NOT-USE]`). Used by
    `_probe_topic_write_permission` — a `Produce` request with this batch
    goes through the broker's ACL check before it accepts the record,
    letting us see `TOPIC_AUTHORIZATION_FAILED` for topics we can't write.

    ⚠️ IF THE PROBE SUCCEEDS, THE RECORD IS ACTUALLY WRITTEN to the topic
    (destructive). Callers must gate this behind an explicit opt-in flag.
    """
    # v2 record: length(varint) | attributes(int8) | timestamp_delta(varlong) |
    #            offset_delta(varint) | key_size(varint,-1=null) |
    #            value_size(varint) | value(bytes) | headers_count(varint,0)
    value = _WRITE_PROBE_MARKER
    record_body = (
        struct.pack(">b", 0)  # attributes (no compression)
        + _write_varlong(0)  # timestamp_delta
        + _write_varint(0)  # offset_delta
        + _write_varint(-1)  # key = null
        + _write_varint(len(value))
        + value
        + _write_varint(0)  # headers count = 0
    )
    record = _write_varint(len(record_body)) + record_body
    # Batch header layout (61 bytes fixed + records):
    #   base_offset(int64) | batch_length(int32) | leader_epoch(int32) |
    #   magic(int8=2) | crc(int32) | attributes(int16) |
    #   last_offset_delta(int32) | base_timestamp(int64) |
    #   max_timestamp(int64) | producer_id(int64) | producer_epoch(int16) |
    #   base_sequence(int32) | record_count(int32) | records
    body_after_crc = (
        struct.pack(">h", 0)  # attributes
        + struct.pack(">i", 0)  # last_offset_delta
        + struct.pack(">q", 0)  # base_timestamp
        + struct.pack(">q", 0)  # max_timestamp
        + struct.pack(">q", -1)  # producer_id
        + struct.pack(">h", -1)  # producer_epoch
        + struct.pack(">i", -1)  # base_sequence
        + struct.pack(">i", 1)  # record_count
        + record
    )
    header_with_crc_placeholder = (
        struct.pack(">i", 0)
        + struct.pack(">b", 2)
        + struct.pack(">I", 0)  # partition_leader_epoch, magic, crc placeholder
    )
    # batch_length = bytes after (base_offset + batch_length) = everything
    # from `partition_leader_epoch` through the last record byte.
    batch_body = header_with_crc_placeholder + body_after_crc
    batch_length = len(batch_body)
    return struct.pack(">q", 0) + struct.pack(">i", batch_length) + batch_body


def _write_varint(value: int) -> bytes:
    return _write_unsigned_varint((int(value) << 1) ^ (int(value) >> 63))


def _write_varlong(value: int) -> bytes:
    return _write_unsigned_varint((int(value) << 1) ^ (int(value) >> 63))


def _write_unsigned_varint(value: int) -> bytes:
    value &= 0xFFFFFFFFFFFFFFFF  # constrain to 64-bit for varlong-safety
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            break
    return bytes(out)


def _probe_topic_write_permission(
    sock: socket.socket,
    correlation: int,
    topic: str,
    partition: int = 0,
) -> tuple[bool | None, int]:
    """Probe whether the current SASL session can Write a topic.

    ⚠️ **DESTRUCTIVE**: if the topic accepts writes, a marker record
    (`[REDPOSTURE-AUDIT-PROBE-DO-NOT-USE]`) is actually appended to the log.
    Callers must gate this behind an explicit opt-in flag.

    Non-destructive alternative doesn't exist in the Kafka wire protocol:
    the broker checks the topic's Write ACL BEFORE producing, but there's
    no dry-run mode for Produce. Sending an invalid batch (empty / bad crc)
    is rejected as INVALID_RECORD (code 87) before or after the ACL check
    depending on broker version — not reliable.

    Returns `(write_or_none, next_correlation_id)`:
      - error_code = 29 (TOPIC_AUTHORIZATION_FAILED) → write = False
      - error_code = 0                              → write = True (probe record written)
      - other codes → None (inconclusive)
    """
    batch = _build_produce_probe_batch()
    # Produce v3 request body:
    #   transactional_id (nullable string, null = -1)
    #   acks (int16, 1 = leader ack)
    #   timeout_ms (int32)
    #   topics [
    #     topic (string)
    #     partitions [
    #       partition (int32)
    #       records (bytes: int32 length + batch)
    #     ]
    #   ]
    body = (
        struct.pack(">h", -1)  # transactional_id = null
        + struct.pack(">h", 1)  # acks = 1 (leader)
        + struct.pack(">i", 5000)  # timeout_ms
        + struct.pack(">i", 1)  # topics count
        + _encode_kafka_string(topic)
        + struct.pack(">i", 1)  # partitions count
        + struct.pack(">i", int(partition))
        + struct.pack(">i", len(batch))
        + batch
    )
    try:
        payload = _send_kafka_request(
            sock,
            api_key=KAFKA_PRODUCE,
            api_version=3,
            correlation_id=correlation,
            client_id=KAFKA_CLIENT_ID,
            body=body,
        )
    except (TimeoutError, ConnectionError, OSError, ValueError):
        return None, correlation + 1
    correlation += 1
    # Parse Produce v3 response: correlation_id | topics [ name, partitions
    # [ partition, error_code, base_offset, log_append_time ] ] | throttle_time
    try:
        reader = _KafkaReader(payload)
        _ = reader.read_i32()  # correlation
        topic_count = reader.read_i32()
        for _ in range(max(0, topic_count)):
            _ = reader.read_string(nullable=False) or ""
            partition_count = reader.read_i32()
            for _ in range(max(0, partition_count)):
                _ = reader.read_i32()  # partition_id
                error_code = reader.read_i16()
                _ = reader.read_i64()  # base_offset
                _ = reader.read_i64()  # log_append_time (v2+)
                if error_code == 29:
                    return False, correlation
                if error_code == 0:
                    return True, correlation
                return None, correlation
        return None, correlation
    except (ValueError, struct.error):
        return None, correlation


def _probe_create_topic_permission(
    sock: socket.socket,
    correlation: int,
) -> tuple[bool | None, int]:
    """Probe the cluster's `Create` ACL for topics.

    Non-destructive: uses `CreateTopics(validateOnly=true)` — the broker
    walks the full ACL / validation path but does NOT create the topic
    when `validate_only=true`, even if the caller has permission. The
    random probe name (`__redposture_probe_create_<12hex>`) guarantees the
    request never collides with a real topic.

    Returns `(True|False|None, next_correlation_id)`:
      - True  — broker accepted the request (or said TOPIC_ALREADY_EXISTS,
                which also implies we have the `Create` ACL — improbable
                for the random name but handled)
      - False — TOPIC_AUTHORIZATION_FAILED / CLUSTER_AUTHORIZATION_FAILED
      - None  — inconclusive (unknown error / timeout / malformed response)
    """
    probe_name = f"__redposture_probe_create_{secrets.token_hex(6)}"
    # CreateTopics v2 request body:
    #   topics [
    #     name (string) | num_partitions (int32) | replication_factor (int16)
    #     replica_assignments [ partition_index (int32), broker_ids [int32] ]
    #     configs [ name (string), value (nullable_string) ]
    #   ]
    #   timeout_ms (int32) | validate_only (bool)
    body = (
        struct.pack(">i", 1)  # topics count
        + _encode_kafka_string(probe_name)
        # -1 selects the broker defaults. A fixed replication factor of one
        # can fail validation on a multi-broker cluster before the authorizer
        # evaluates Create, leaving a false "unknown" ACL marker.
        + struct.pack(">i", -1)  # num_partitions (broker default)
        + struct.pack(">h", -1)  # replication_factor (broker default)
        + struct.pack(">i", 0)  # replica_assignments count
        + struct.pack(">i", 0)  # configs count
        + struct.pack(">i", 5000)  # timeout_ms
        + struct.pack(">?", True)  # validate_only
    )
    try:
        payload = _send_kafka_request(
            sock,
            api_key=KAFKA_CREATE_TOPICS,
            api_version=2,
            correlation_id=correlation,
            client_id=KAFKA_CLIENT_ID,
            body=body,
        )
    except (TimeoutError, ConnectionError, OSError, ValueError):
        return None, correlation + 1
    correlation += 1
    # CreateTopics v2 response: correlation | throttle_time_ms | topics [ name, error_code, error_message ]
    try:
        reader = _KafkaReader(payload)
        _ = reader.read_i32()  # correlation
        _ = reader.read_i32()  # throttle_time_ms
        topic_count = reader.read_i32()
        for _ in range(max(0, topic_count)):
            _ = reader.read_string(nullable=False) or ""
            error_code = reader.read_i16()
            _ = reader.read_string(nullable=True)  # error_message (v1+)
            if error_code in (29, 31):
                return False, correlation
            if error_code in (0, 36):  # 0 = NO_ERROR, 36 = TOPIC_ALREADY_EXISTS
                return True, correlation
            return None, correlation
        return None, correlation
    except (ValueError, struct.error):
        return None, correlation


def _probe_delete_topic_permission(
    sock: socket.socket,
    correlation: int,
) -> tuple[bool | None, int]:
    """Probe the cluster's `Delete` ACL for topics.

    Non-destructive: sends `DeleteTopics` for a random probe name that
    doesn't exist. The broker walks the ACL check first; if allowed, it
    proceeds to delete and returns `UNKNOWN_TOPIC_OR_PARTITION` (3) since
    there was nothing to delete. If ACL rejects, it returns
    `TOPIC_AUTHORIZATION_FAILED` (29) or `CLUSTER_AUTHORIZATION_FAILED` (31)
    without touching the log directory.

    ⚠️ There's a tiny theoretical race: if a real topic happened to be
    created with the exact `__redposture_probe_delete_<12hex>` name in the
    window between our sending and the broker acting on the request, it
    would be deleted. Odds are astronomically low (2^48 name space) and
    the probe name is unmistakably ours by convention.

    Returns `(True|False|None, next_correlation_id)`:
      - True  — UNKNOWN_TOPIC_OR_PARTITION (delete would have succeeded)
      - False — TOPIC_AUTHORIZATION_FAILED / CLUSTER_AUTHORIZATION_FAILED
      - None  — inconclusive
    """
    probe_name = f"__redposture_probe_delete_{secrets.token_hex(6)}"
    # DeleteTopics v1 request body: topic_names [string], timeout_ms (int32)
    body = (
        struct.pack(">i", 1)  # topic_names count
        + _encode_kafka_string(probe_name)
        + struct.pack(">i", 5000)  # timeout_ms
    )
    try:
        payload = _send_kafka_request(
            sock,
            api_key=KAFKA_DELETE_TOPICS,
            api_version=1,
            correlation_id=correlation,
            client_id=KAFKA_CLIENT_ID,
            body=body,
        )
    except (TimeoutError, ConnectionError, OSError, ValueError):
        return None, correlation + 1
    correlation += 1
    # DeleteTopics v1 response: correlation | throttle_time_ms | responses [ name, error_code ]
    try:
        reader = _KafkaReader(payload)
        _ = reader.read_i32()  # correlation
        _ = reader.read_i32()  # throttle_time_ms
        response_count = reader.read_i32()
        for _ in range(max(0, response_count)):
            _ = reader.read_string(nullable=False) or ""
            error_code = reader.read_i16()
            if error_code in (29, 31):
                return False, correlation
            # 3 = UNKNOWN_TOPIC_OR_PARTITION — perfect signal that Delete
            # ACL would have applied; the topic just wasn't there.
            if error_code in (0, 3):
                return True, correlation
            return None, correlation
        return None, correlation
    except (ValueError, struct.error):
        return None, correlation


def _probe_kafka_acls(
    host: str,
    port: int,
    timeout: float,
    topics: list[str],
    *,
    username: str | None = None,
    password: str | None = None,
    use_tls: bool | None = None,
    probe_write: bool = False,
    probe_cluster: bool = True,
    debug_emit: Any = None,
) -> dict[str, Any]:
    """Probe Read (and optionally Write) ACLs per topic AND cluster-level
    Create/Delete ACLs — all on a single authenticated socket.

    Returns:
        {
            "cluster": {"create": bool | None, "delete": bool | None},
            "topics":  {topic: {"read": bool | None, "write": bool | None}},
        }

    ⚠️ `probe_write=True` is destructive — see
    `_probe_topic_write_permission`. `probe_cluster=True` (default) is
    non-destructive: create-probe uses `validateOnly=true`, delete-probe
    targets a random nonexistent name.

    ``debug_emit`` — optional callable. When set, every silent-failure path
    (socket refused, TLS handshake failed, auth rejected, probe exception)
    emits a one-line diagnostic so `--debug` can explain why the audit
    output shows no `(read:...)` markers.
    """

    def _log(reason: str) -> None:
        if callable(debug_emit):
            try:
                debug_emit(f"[!] {host}:{port} probe_kafka_acls degraded: {reason}")
            except Exception:  # noqa: BLE001
                # Never let a debug emit crash a probe.
                pass

    empty: dict[str, Any] = {
        "cluster": {"create": None, "delete": None},
        "topics": {topic: {"read": None, "write": None} for topic in topics},
    }

    # Broad exception net around the whole probe flow. Best-effort probing
    # must never sink the parent audit — degrade to `None` markers instead.
    def _probe_session(*, sasl_first: bool) -> dict[str, Any] | None:
        try:
            sock, _transport_mode = open_kafka_socket(host, port, timeout, use_tls=use_tls)
        except BaseException as exc:  # noqa: BLE001
            _log(f"open_kafka_socket failed: {exc.__class__.__name__}: {exc}")
            return None
        try:
            with sock:
                correlation = 1
                ok, correlation, session_error = _authenticate_or_probe(
                    sock,
                    correlation,
                    username,
                    password,
                    sasl_first=sasl_first,
                )
                if not ok:
                    _log(f"authenticate_or_probe rejected: {session_error!r}")
                    return None
                cluster_perms: dict[str, bool | None] = {"create": None, "delete": None}
                if probe_cluster:
                    cluster_perms["create"], correlation = _probe_create_topic_permission(sock, correlation)
                    cluster_perms["delete"], correlation = _probe_delete_topic_permission(sock, correlation)
                topic_perms: dict[str, dict[str, bool | None]] = {}
                for topic in topics:
                    read_result, correlation = _probe_topic_read_permission(sock, correlation, topic)
                    write_result: bool | None = None
                    if probe_write:
                        write_result, correlation = _probe_topic_write_permission(sock, correlation, topic)
                    topic_perms[topic] = {"read": read_result, "write": write_result}
                return {"cluster": cluster_perms, "topics": topic_perms}
        except BaseException as exc:  # noqa: BLE001
            _log(f"probe session raised: {exc.__class__.__name__}: {exc}")
            return None

    result = _probe_session(sasl_first=False)
    if result is not None:
        return result
    # A few SASL listeners reject ApiVersions until after the SASL handshake.
    # The main audit already reached this helper only after authenticating via
    # the SASL fallback, so retry on a fresh socket with that ordering.
    if username is not None and password is not None:
        _log("retrying ACL probe with a SASL-first session")
        result = _probe_session(sasl_first=True)
        if result is not None:
            return result
    return empty


# Deprecated: kept as a thin wrapper for backward-compat with older callers /
# tests that import the old name. Prefer `_probe_kafka_acls`.
def _probe_topic_permissions_bulk(
    host: str,
    port: int,
    timeout: float,
    topics: list[str],
    *,
    username: str | None = None,
    password: str | None = None,
    use_tls: bool | None = None,
    probe_write: bool = False,
) -> dict[str, dict[str, bool | None]]:
    return _probe_kafka_acls(
        host,
        port,
        timeout,
        topics,
        username=username,
        password=password,
        use_tls=use_tls,
        probe_write=probe_write,
        probe_cluster=False,
    )["topics"]


def _read_topic_messages(
    host: str,
    port: int,
    timeout: float,
    topic: str,
    max_messages: int,
    *,
    username: str | None = None,
    password: str | None = None,
    use_tls: bool | None = None,
) -> tuple[list[str] | None, str | None, str]:
    """Read up to `max_messages` messages from `topic` across all partitions.

    Partition-aware routing: after Metadata, we group each partition by its
    leader broker (multi-broker Kafka clusters have leaders spread across
    brokers) and open a fresh connection per leader for ListOffsets + Fetch.
    Sending ListOffsets to a non-leader broker returns error code 6
    (`NOT_LEADER_OR_FOLLOWER`), which is the bug this routing fixes.

    Backward-compat: when Metadata doesn't expose broker/leader info (test
    doubles, older brokers) or when the leader hostname isn't reachable
    from the client, we fall back to running everything on the bootstrap
    socket — same as the pre-fix behavior.
    """
    if max_messages <= 0:
        return [], None, "plaintext"

    try:
        sock, transport_mode = open_kafka_socket(host, port, timeout, use_tls=use_tls)
        with sock:
            correlation = 1

            ok, correlation, session_error = _authenticate_or_probe(sock, correlation, username, password)
            if not ok:
                return None, session_error, transport_mode

            metadata, metadata_error = _fetch_metadata(sock, correlation, topics=[topic])
            correlation += 1
            if metadata is None:
                return None, metadata_error or "metadata request failed", transport_mode

            topic_map = dict(metadata.get("topic_map") or {})
            if topic not in topic_map:
                return [], None, transport_mode

            partition_count = int(topic_map.get(topic) or 0)
            if partition_count <= 0:
                return [], None, transport_mode

            broker_map: dict[int, tuple[str, int]] = dict(metadata.get("broker_map") or {})
            topic_leaders: dict[int, int] = dict((metadata.get("partition_leaders") or {}).get(topic, {}))

            # Group partitions by their leader broker so we open one
            # connection per leader instead of hammering the bootstrap
            # broker with requests it can't serve.
            partitions_by_leader: dict[int, list[int]] = {}
            unassigned_partitions: list[int] = []
            for partition in range(partition_count):
                leader_id = topic_leaders.get(partition)
                if leader_id is None or leader_id not in broker_map:
                    unassigned_partitions.append(partition)
                    continue
                partitions_by_leader.setdefault(leader_id, []).append(partition)

            out: list[str] = []
            fatal_error: str | None = None

            def _handle_partitions(leader_sock: socket.socket, partitions: list[int], corr_start: int) -> int:
                nonlocal fatal_error
                corr = corr_start
                for partition in partitions:
                    if len(out) >= max_messages:
                        break
                    items, corr, err = _read_partition_messages_on_leader(
                        leader_sock, corr, topic, partition, max_messages - len(out)
                    )
                    if err:
                        # First partition failure with no data accumulated
                        # is a fatal error for the whole read; subsequent
                        # failures are recorded silently so a single bad
                        # partition doesn't kill the whole dump.
                        if not out and fatal_error is None:
                            fatal_error = err
                        continue
                    out.extend(items)
                return corr

            # 1) Per-leader connections for partitions with a known leader.
            for leader_id, partitions in partitions_by_leader.items():
                if len(out) >= max_messages:
                    break
                leader_host, leader_port = broker_map[leader_id]
                # Bootstrap-broker shortcut: if the leader IS the broker
                # we already talk to, reuse the existing socket instead of
                # spinning up a new connection.
                if (
                    (leader_host, leader_port) == (host, port)
                    or leader_host in ("", "localhost", "127.0.0.1")
                    and leader_port == port
                ):
                    correlation = _handle_partitions(sock, partitions, correlation)
                    continue
                try:
                    leader_sock, _leader_transport = open_kafka_socket(
                        leader_host, leader_port, timeout, use_tls=(transport_mode == "tls") or None
                    )
                except (TimeoutError, ConnectionError, OSError):
                    # Leader broker unreachable from the auditor's network
                    # (common for advertised-DNS-only clusters). Fall back
                    # to attempting on the bootstrap socket so we at least
                    # try; the broker will reject with NOT_LEADER but the
                    # caller sees a per-partition error, not a total fail.
                    correlation = _handle_partitions(sock, partitions, correlation)
                    continue
                try:
                    leader_corr = 1
                    ok, leader_corr, leader_session_error = _authenticate_or_probe(
                        leader_sock, leader_corr, username, password
                    )
                    if not ok:
                        if not out and fatal_error is None:
                            fatal_error = f"leader {leader_host}:{leader_port} auth failed: {leader_session_error}"
                        continue
                    _handle_partitions(leader_sock, partitions, leader_corr)
                finally:
                    try:
                        leader_sock.close()
                    except OSError:
                        pass

            # 2) Partitions without a known leader / broker_map miss:
            #    fall back to the bootstrap socket (best-effort).
            if unassigned_partitions and len(out) < max_messages:
                correlation = _handle_partitions(sock, unassigned_partitions, correlation)

            if not out and fatal_error is not None:
                return None, fatal_error, transport_mode
            return out, None, transport_mode
    except _TlsProbeError:
        if use_tls is True:
            return None, "plaintext read returned TLS record prelude", "tls"
        return _read_topic_messages(
            host,
            port,
            timeout,
            topic,
            max_messages,
            username=username,
            password=password,
            use_tls=True,
        )
    except (TimeoutError, ConnectionError, OSError, ValueError) as exc:
        return None, _friendly_error_from_exception(exc), "plaintext" if use_tls is not True else "tls"


def _sasl_handshake_plain(sock: socket.socket, correlation_id: int) -> tuple[bool, int, str | None]:
    versions = (1, 0)
    for version in versions:
        payload = _send_kafka_request(
            sock,
            api_key=KAFKA_SASL_HANDSHAKE,
            api_version=version,
            correlation_id=correlation_id,
            client_id=KAFKA_CLIENT_ID,
            body=_encode_kafka_string("PLAIN"),
        )
        try:
            reader = _KafkaReader(payload)
            response_corr = reader.read_i32()
            if response_corr != correlation_id:
                return (
                    False,
                    correlation_id + 1,
                    f"unexpected correlation id {response_corr} (expected {correlation_id})",
                )
            error_code = reader.read_i16()
            if error_code == 35:
                continue
            if error_code != 0:
                return False, correlation_id + 1, f"SASL handshake failed: {_kafka_error_name(int(error_code))}"
            _ = reader.read_string_array()
            return True, correlation_id + 1, None
        except (ValueError, struct.error) as exc:
            return False, correlation_id + 1, f"invalid SASL handshake response: {exc}"
    return False, correlation_id + 1, "SASL handshake failed: UNSUPPORTED_VERSION"


def _sasl_authenticate_plain(
    sock: socket.socket, correlation_id: int, username: str, password: str
) -> tuple[bool, int, str | None]:
    auth_bytes = b"\x00" + username.encode("utf-8") + b"\x00" + password.encode("utf-8")

    # Preferred modern flow: SASL_AUTHENTICATE request.
    try:
        payload = _send_kafka_request(
            sock,
            api_key=KAFKA_SASL_AUTHENTICATE,
            api_version=0,
            correlation_id=correlation_id,
            client_id=KAFKA_CLIENT_ID,
            body=_encode_kafka_bytes(auth_bytes),
        )
        reader = _KafkaReader(payload)
        response_corr = reader.read_i32()
        if response_corr != correlation_id:
            return False, correlation_id + 1, f"unexpected correlation id {response_corr} (expected {correlation_id})"
        error_code = reader.read_i16()
        error_message = reader.read_string(nullable=True)
        _ = reader.read_bytes(nullable=True)
        if reader.remaining() >= 8:
            _ = reader.read_i64()
        if error_code == 0:
            return True, correlation_id + 1, None
        if error_code != 35:
            detail = (
                error_message.strip()
                if isinstance(error_message, str) and error_message.strip()
                else _kafka_error_name(int(error_code))
            )
            return False, correlation_id + 1, f"SASL auth failed: {detail}"
    except (TimeoutError, ValueError, struct.error, ConnectionError, OSError):
        pass

    # Legacy fallback: raw SASL bytes over size-prefixed frame.
    try:
        sock.sendall(struct.pack(">i", len(auth_bytes)) + auth_bytes)
    except OSError as exc:
        return False, correlation_id, _friendly_error_from_exception(exc)

    previous_timeout = sock.gettimeout()
    probe_timeout = min(float(previous_timeout or 1.0), 0.40)
    try:
        sock.settimeout(probe_timeout)
        prefix = sock.recv(4)
        if prefix:
            while len(prefix) < 4:
                chunk = sock.recv(4 - len(prefix))
                if not chunk:
                    break
                prefix += chunk
            if len(prefix) == 4:
                (frame_size,) = struct.unpack(">i", prefix)
                if frame_size > 0 and frame_size <= 8192:
                    body = _recv_exact(sock, frame_size)
                    text = body.decode("utf-8", errors="replace")
                    if _is_probable_auth_error(text):
                        return False, correlation_id, _clip(text, 96)
    except TimeoutError:
        pass
    except (ConnectionError, OSError, ValueError):
        # Some brokers may close the socket on auth failure; metadata verification below will fail.
        pass
    finally:
        try:
            sock.settimeout(previous_timeout)
        except OSError:
            pass

    return True, correlation_id, None


def _authenticate_and_fetch_metadata(
    host: str,
    port: int,
    timeout: float,
    username: str,
    password: str,
    *,
    use_tls: bool | None = None,
) -> tuple[bool, dict[str, Any] | None, str | None, str]:
    try:
        sock, transport_mode = open_kafka_socket(host, port, timeout, use_tls=use_tls)
        with sock:
            correlation = 1
            is_kafka, _api_error_code, api_error = _probe_apiversions(sock, correlation)
            correlation += 1
            if not is_kafka:
                return False, None, api_error or "service is not kafka", transport_mode

            hs_ok, correlation, hs_error = _sasl_handshake_plain(sock, correlation)
            if not hs_ok:
                return False, None, hs_error or "SASL handshake failed", transport_mode

            auth_ok, correlation, auth_error = _sasl_authenticate_plain(sock, correlation, username, password)
            if not auth_ok:
                return False, None, auth_error or "authentication failed", transport_mode

            metadata, metadata_error = _fetch_metadata(sock, correlation, topics=None)
            if metadata is None:
                return False, None, metadata_error or "metadata request failed after auth", transport_mode
            if bool(metadata.get("auth_required")):
                return False, None, "authentication failed", transport_mode
            return True, metadata, None, transport_mode
    except _TlsProbeError:
        if use_tls is True:
            return False, None, "plaintext read returned TLS record prelude", "tls"
        return _authenticate_and_fetch_metadata(host, port, timeout, username, password, use_tls=True)
    except (TimeoutError, ConnectionError, OSError, ValueError) as exc:
        return (
            False,
            None,
            _friendly_error_from_exception(exc),
            "plaintext" if use_tls is not True else "tls",
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
    use_tls: bool | None = None,
) -> tuple[dict[str, list[str] | None], dict[str, str]]:
    dump_results: dict[str, list[str] | None] = {}
    dump_errors: dict[str, str] = {}
    for topic_name in topics:
        read_items, read_error, _transport = _read_topic_messages(
            host=host,
            port=port,
            timeout=timeout,
            topic=topic_name,
            max_messages=max_messages,
            username=username,
            password=password,
            use_tls=use_tls,
        )
        dump_results[topic_name] = read_items
        if read_error:
            dump_errors[topic_name] = read_error
    return dump_results, dump_errors
