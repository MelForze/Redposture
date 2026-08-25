"""ZooKeeper protocol client helpers."""

from __future__ import annotations

import base64
import errno
import re
import secrets
import socket
import ssl
import struct
import threading
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from queue import Empty, Queue
from typing import Any, Literal

from .tls_cache import shared_client_ssl_context

_ZK_PROTOCOL_VERSION = 0
_ZK_PASSWD_DEFAULT = b"\x00" * 16
_ZK_OP_CREATE = 1
_ZK_OP_DELETE = 2
_ZK_OP_GET_DATA = 4
_ZK_OP_GET_CHILDREN2 = 12
_ZK_OP_CLOSE_SESSION = -11
_ZK_OP_AUTH = 100
_ZK_ERR_OK = 0
_ZK_ERR_NONODE = -101
_ZK_ERR_NOAUTH = -102
_ZK_ERR_AUTHFAILED = -115
_ZK_ERR_REQUEST_TIMEOUT = -122
_ZK_ERR_SESSION_CLOSED_REQUIRES_AUTH = -124
_ZK_ERR_THROTTLED_OP = -127
_ZK_ERR_NODEEXISTS = -110
_ZK_MAX_FRAME = 64 * 1024 * 1024
_ZK_MAX_CHILDREN_PER_RESPONSE = 1_000_000
_ZK_SYSTEM_PREFIX = "/zookeeper"
_KEEPER_SYSTEM_PREFIX = "/keeper"
_ZK_ACL_ALL_PERMS = 0x1F
_ZK_CREATE_EPHEMERAL = 1
_ZK_AUTH_XID = -4
_ZK_ENUM_PROGRESS_INTERVAL_SECONDS = 2.0
_CONNECTION_REFUSED_PREFIX = "connection refused"
_CONNECTION_TIMEOUT_PREFIX = "connection timeout"
_UNEXPECTED_EOF_PREFIX = "unexpected eof"
_ZK_FOUR_LETTER_MAX_RESPONSE = 1024 * 1024
_ZK_FOUR_LETTER_COMMANDS = frozenset({"srvr", "stat", "mntr", "isro"})

ZkTransportMode = Literal["auto", "plaintext", "tls"]


class _ZkProtocolPayloadError(ValueError):
    """A malformed ZooKeeper payload after its transport was established."""

    def __init__(self, message: str, *, transport: Literal["plaintext", "tls"]) -> None:
        super().__init__(message)
        self.transport = transport
        self.tls_handshake_completed = transport == "tls"


@dataclass(frozen=True)
class ZkTransportConfig:
    mode: ZkTransportMode = "plaintext"
    insecure: bool = False
    ca_file: str | None = None
    cert_file: str | None = None
    key_file: str | None = None

    @property
    def has_tls_options(self) -> bool:
        return bool(self.insecure or self.ca_file or self.cert_file or self.key_file)


@dataclass(frozen=True)
class ZkFourLetterResult:
    command: str
    response: str | None = None
    error: str | None = None


def _normalize_zookeeper_version(value: str | None) -> str | None:
    """Keep only the human-relevant version prefix before build metadata."""

    normalized = str(value or "").strip()
    if not normalized:
        return None
    version, _separator, _suffix = normalized.partition("-")
    return version.strip() or None


@dataclass(frozen=True)
class ZkImplementationFingerprint:
    implementation: str
    is_keeper: bool | None
    confidence: str
    version: str | None = None
    server_state: str | None = None
    read_only: bool | None = None
    connections: int | None = None
    latency_ms: dict[str, int | float | None] = field(default_factory=lambda: {"min": None, "avg": None, "max": None})
    raft: dict[str, int | str | None] = field(default_factory=dict)
    quorum_status: str = "unknown"
    responses: dict[str, ZkFourLetterResult] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "version", _normalize_zookeeper_version(self.version))


def _friendly_error_text(value: str) -> str:
    from ..utils import friendly_error_text

    return friendly_error_text(value)


def _friendly_error_from_exception(exc: BaseException) -> str:
    from ..utils import friendly_error_from_exception

    return friendly_error_from_exception(exc)


def _retry_delay(attempt_index: int) -> float:
    return min(1.50, 0.20 * (2**attempt_index))


def _zk_error_name(code: int) -> str:
    names = {
        _ZK_ERR_OK: "OK",
        _ZK_ERR_NONODE: "NONODE",
        _ZK_ERR_NOAUTH: "NOAUTH",
        -1: "SYSTEMERROR",
        -2: "RUNTIMEINCONSISTENCY",
        -3: "DATAINCONSISTENCY",
        -4: "CONNECTIONLOSS",
        -5: "MARSHALLINGERROR",
        -6: "UNIMPLEMENTED",
        -7: "OPERATIONTIMEOUT",
        -8: "BADARGUMENTS",
        -13: "NEWCONFIGNOQUORUM",
        -14: "RECONFIGINPROGRESS",
        -100: "APIERROR",
        -101: "NONODE",
        -102: "NOAUTH",
        -103: "BADVERSION",
        -108: "NOCHILDRENFOREPHEMERALS",
        -110: "NODEEXISTS",
        -111: "NOTEMPTY",
        -112: "SESSIONEXPIRED",
        -113: "INVALIDCALLBACK",
        -114: "INVALIDACL",
        -115: "AUTHFAILED",
        -116: "CLOSING",
        -117: "NOTHING",
        -118: "SESSIONMOVED",
        -119: "NOTREADONLY",
        -120: "EPHEMERALONLOCALSESSION",
        -121: "NOWATCHER",
        -122: "REQUESTTIMEOUT",
        -123: "RECONFIGDISABLED",
        -124: "SESSIONCLOSEDREQUIRESASLAUTH",
        -125: "QUOTAEXCEEDED",
        -126: "BADAVERSION",
        -127: "THROTTLEDOP",
    }
    return names.get(code, f"ERR_{code}")


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    if size < 0:
        raise ValueError("invalid receive size")
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError("unexpected EOF")
        data.extend(chunk)
    return bytes(data)


def _recv_frame(sock: socket.socket) -> bytes:
    raw_size = _recv_exact(sock, 4)
    (frame_size,) = struct.unpack(">i", raw_size)
    if frame_size <= 0 or frame_size > _ZK_MAX_FRAME:
        raise ValueError(f"invalid ZooKeeper frame size {frame_size}")
    return _recv_exact(sock, frame_size)


def _send_frame(sock: socket.socket, payload: bytes) -> None:
    sock.sendall(struct.pack(">i", len(payload)) + payload)


def _encode_zk_string(value: str) -> bytes:
    raw = value.encode("utf-8", errors="replace")
    return struct.pack(">i", len(raw)) + raw


def _decode_zk_string(data: bytes, offset: int = 0) -> tuple[str | None, int]:
    if offset + 4 > len(data):
        raise ValueError("invalid ZooKeeper string payload")
    (size,) = struct.unpack(">i", data[offset : offset + 4])
    offset += 4
    if size == -1:
        return None, offset
    if size < -1:
        raise ValueError("invalid ZooKeeper string length")
    end = offset + size
    if end > len(data):
        raise ValueError("truncated ZooKeeper string payload")
    try:
        value = data[offset:end].decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ValueError("invalid UTF-8 in ZooKeeper string payload") from exc
    return value, end


def _decode_zk_buffer(data: bytes, offset: int = 0) -> tuple[bytes | None, int]:
    if offset + 4 > len(data):
        raise ValueError("invalid ZooKeeper buffer payload")
    (size,) = struct.unpack(">i", data[offset : offset + 4])
    offset += 4
    if size == -1:
        return None, offset
    if size < -1:
        raise ValueError("invalid ZooKeeper buffer length")
    end = offset + size
    if end > len(data):
        raise ValueError("truncated ZooKeeper buffer payload")
    return data[offset:end], end


def _encode_acl_world_anyone_all() -> bytes:
    # ACL vector with one entry: world:anyone + all permissions.
    return (
        struct.pack(">i", 1)
        + struct.pack(">i", _ZK_ACL_ALL_PERMS)
        + _encode_zk_string("world")
        + _encode_zk_string("anyone")
    )


def _valid_znode_child_name(value: str) -> bool:
    if not value or value in {".", ".."} or "/" in value:
        return False
    for char in value:
        codepoint = ord(char)
        if (
            codepoint == 0
            or 0x01 <= codepoint <= 0x1F
            or 0x7F <= codepoint <= 0x9F
            or 0xD800 <= codepoint <= 0xF8FF
            or 0xFFF0 <= codepoint <= 0xFFFF
        ):
            return False
    return True


def _parse_children_vector(payload: bytes, offset: int = 0) -> tuple[list[str] | None, int]:
    if offset + 4 > len(payload):
        raise ValueError("invalid ZooKeeper children vector")
    (count,) = struct.unpack(">i", payload[offset : offset + 4])
    offset += 4
    if count == -1:
        return None, offset
    if count < -1:
        raise ValueError("invalid ZooKeeper children vector count")
    if count > _ZK_MAX_CHILDREN_PER_RESPONSE:
        raise ValueError("ZooKeeper children vector exceeds safe limit")
    # Every valid child consumes at least a four-byte length and one byte of
    # UTF-8 data. Reject impossible counts before entering the decode loop.
    if count > (len(payload) - offset) // 5:
        raise ValueError("truncated ZooKeeper children vector")

    children: list[str] = []
    for _ in range(count):
        item, offset = _decode_zk_string(payload, offset)
        if item is None or not _valid_znode_child_name(item):
            raise ValueError("invalid ZooKeeper child name")
        children.append(item)
    return children, offset


def _parse_connect_response(payload: bytes) -> None:
    """Validate the complete ZooKeeper ConnectResponse wire record."""

    if len(payload) < 20:
        raise ValueError("invalid ZooKeeper connect response")
    protocol_version, negotiated_timeout, session_id = struct.unpack(">iiq", payload[0:16])
    if protocol_version != _ZK_PROTOCOL_VERSION or negotiated_timeout <= 0 or session_id == 0:
        raise ValueError("invalid ZooKeeper connect response")

    passwd_len = struct.unpack(">i", payload[16:20])[0]
    if passwd_len != len(_ZK_PASSWD_DEFAULT):
        raise ValueError("invalid ZooKeeper connect payload")
    payload_end = 20 + passwd_len
    if payload_end > len(payload):
        raise ValueError("invalid ZooKeeper connect payload")

    # The readOnly boolean was appended to ConnectResponse in newer protocol
    # versions. Older peers omit it; no other trailing bytes are valid.
    trailing = payload[payload_end:]
    if trailing not in {b"", b"\x00", b"\x01"}:
        raise ValueError("invalid ZooKeeper connect payload")


def _parse_stat(payload: bytes, offset: int = 0) -> tuple[dict[str, int], int]:
    # Stat: czxid,mzxid,ctime,mtime,version,cversion,aversion,ephemeralOwner,dataLength,numChildren,pzxid
    if offset + 68 > len(payload):
        raise ValueError("invalid ZooKeeper stat payload")

    (
        _czxid,
        _mzxid,
        _ctime,
        _mtime,
        _version,
        _cversion,
        _aversion,
        _ephemeral_owner,
        data_length,
        num_children,
        _pzxid,
    ) = struct.unpack(">qqqqiiiqiiq", payload[offset : offset + 68])
    offset += 68
    if data_length < 0 or num_children < 0:
        raise ValueError("invalid ZooKeeper stat counters")
    return {"data_length": int(data_length), "num_children": int(num_children)}, offset


def _normalize_znode_path(value: str | None) -> str | None:
    raw = (value or "").strip()
    if not raw:
        return None
    if raw.startswith("/"):
        return raw
    return f"/{raw}"


def _join_znode_path(parent: str, child: str) -> str:
    if parent == "/":
        return f"/{child}"
    return f"{parent.rstrip('/')}/{child}"


def _is_system_znode(path: str) -> bool:
    normalized = str(path or "").strip()
    return any(
        normalized == prefix or normalized.startswith(f"{prefix}/")
        for prefix in (_ZK_SYSTEM_PREFIX, _KEEPER_SYSTEM_PREFIX)
    )


def _format_znode_data(data: bytes | None) -> str:
    if data is None:
        return "<nil>"
    if len(data) == 0:
        return "<empty>"

    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return f"<base64:{base64.b64encode(data).decode('ascii')}>"

    if any(ord(ch) < 32 and ch not in "\r\n\t" for ch in text):
        return f"<base64:{base64.b64encode(data).decode('ascii')}>"

    return text.replace("\n", "\\n")


def _build_tls_context(config: ZkTransportConfig) -> ssl.SSLContext:
    return shared_client_ssl_context(
        insecure=config.insecure,
        ca_file=config.ca_file,
        cert_file=config.cert_file,
        key_file=config.key_file,
    )


def _open_zk_socket(
    host: str,
    port: int,
    timeout: float,
    *,
    transport: Literal["plaintext", "tls"],
    config: ZkTransportConfig,
) -> socket.socket:
    raw_sock = socket.create_connection((host, port), timeout=timeout)
    raw_sock.settimeout(timeout)
    if transport == "plaintext":
        return raw_sock
    try:
        context = _build_tls_context(config)
        wrapped = context.wrap_socket(raw_sock, server_hostname=host)
        wrapped.settimeout(timeout)
        return wrapped
    except Exception:
        raw_sock.close()
        raise


def _transport_attempt_order(config: ZkTransportConfig) -> tuple[Literal["plaintext", "tls"], ...]:
    if config.mode == "plaintext":
        return ("plaintext",)
    if config.mode == "tls":
        return ("tls",)
    if config.has_tls_options:
        return ("tls", "plaintext")
    return ("plaintext", "tls")


def _transport_error_is_endpoint_independent(exc: BaseException) -> bool:
    # SSLError inherits OSError and commonly uses small library-local error
    # numbers that overlap POSIX errno values such as EPERM.
    if isinstance(exc, ssl.SSLError):
        return False
    if isinstance(exc, socket.gaierror):
        return True
    if isinstance(exc, ConnectionRefusedError):
        return True
    return isinstance(exc, OSError) and exc.errno in {
        errno.ECONNREFUSED,
        errno.ENETUNREACH,
        errno.EHOSTUNREACH,
        errno.EADDRNOTAVAIL,
        errno.EACCES,
        errno.EPERM,
        errno.EMFILE,
        errno.ENFILE,
        errno.ENOBUFS,
    }


def _is_tls_protocol_mismatch(exc: BaseException) -> bool:
    if not isinstance(exc, ssl.SSLError):
        return False
    text = str(exc).upper().replace(" ", "_")
    return any(
        marker in text
        for marker in (
            "WRONG_VERSION_NUMBER",
            "UNKNOWN_PROTOCOL",
            "HTTP_REQUEST",
        )
    )


def _is_tls_security_error(exc: BaseException) -> bool:
    if isinstance(exc, ssl.SSLCertVerificationError):
        return True
    if isinstance(exc, (FileNotFoundError, PermissionError)):
        return True
    if isinstance(exc, ValueError) and "certificate and key" in str(exc).lower():
        return True
    if isinstance(exc, _ZkProtocolPayloadError) and isinstance(exc.__cause__, BaseException):
        if _is_tls_security_error(exc.__cause__):
            return True
    text = str(exc).upper().replace(" ", "_")
    return isinstance(exc, (ssl.SSLError, _ZkProtocolPayloadError)) and any(
        marker in text
        for marker in (
            "CERTIFICATE_VERIFY_FAILED",
            "CERTIFICATE_REQUIRED",
            "BAD_CERTIFICATE",
            "CERTIFICATE_UNKNOWN",
            "UNKNOWN_CA",
            "PEM_LIB",
            "KEY_VALUES_MISMATCH",
            "HANDSHAKE_FAILURE",
            "ACCESS_DENIED",
            "DECRYPT_ERROR",
        )
    )


def _is_transport_or_protocol_mismatch(exc: BaseException) -> bool:
    """Return whether one alternate transport attempt is meaningful."""

    if isinstance(exc, _ZkProtocolPayloadError):
        # This wrapper exists only after a socket/handshake succeeded and the
        # ZooKeeper ConnectResponse exchange failed.  EOF, timeout and a
        # malformed record are all protocol-specific evidence.
        return True
    if isinstance(exc, (TimeoutError, ConnectionResetError, BrokenPipeError)):
        return True
    if isinstance(exc, ValueError) and not _is_tls_security_error(exc):
        return True
    if _is_tls_protocol_mismatch(exc):
        return True
    if isinstance(exc, OSError) and exc.errno in {
        errno.ECONNRESET,
        errno.ECONNABORTED,
        errno.EPIPE,
        errno.ETIMEDOUT,
    }:
        return True
    text = str(exc).strip().lower()
    return any(
        marker in text
        for marker in (
            "unexpected eof",
            "unexpected_eof",
            "connection reset",
            "connection_reset",
            "remote end closed",
            "connection closed",
            "timed out",
            "timeout",
        )
    )


def _transport_error_allows_fallback(
    exc: BaseException,
    *,
    attempted_transport: Literal["plaintext", "tls"],
    config: ZkTransportConfig,
) -> bool:
    """Allow auto-detection fallback only for transport-specific failures."""

    if _transport_error_is_endpoint_independent(exc):
        return False
    if attempted_transport == "tls" and _is_tls_security_error(exc):
        return False
    _ = config
    return _is_transport_or_protocol_mismatch(exc)


def query_four_letter_word(
    host: str,
    port: int,
    timeout: float,
    command: str,
    *,
    transport: Literal["plaintext", "tls"],
    config: ZkTransportConfig,
) -> ZkFourLetterResult:
    normalized = str(command or "").strip().lower()
    if normalized not in _ZK_FOUR_LETTER_COMMANDS:
        return ZkFourLetterResult(command=normalized, error="unsupported four-letter command")

    sock: socket.socket | None = None
    try:
        sock = _open_zk_socket(host, port, timeout, transport=transport, config=config)
        sock.sendall(normalized.encode("ascii"))
        payload = bytearray()
        while True:
            chunk = sock.recv(min(65536, _ZK_FOUR_LETTER_MAX_RESPONSE + 1 - len(payload)))
            if not chunk:
                break
            payload.extend(chunk)
            if len(payload) > _ZK_FOUR_LETTER_MAX_RESPONSE:
                raise ValueError("four-letter response exceeds 1 MiB limit")
        return ZkFourLetterResult(
            command=normalized,
            response=bytes(payload).decode("utf-8", errors="replace").strip(),
        )
    except (TimeoutError, ConnectionError, OSError, ValueError, ssl.SSLError) as exc:
        return ZkFourLetterResult(command=normalized, error=_friendly_error_from_exception(exc))
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def _parse_number(value: str | None) -> int | float | None:
    raw = str(value or "").strip()
    if not raw:
        return None
    try:
        return int(raw)
    except ValueError:
        try:
            return float(raw)
        except ValueError:
            return None


def _parse_four_letter_key_values(response: str | None) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw_line in str(response or "").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if "\t" in line:
            key, value = line.split("\t", 1)
        elif ":" in line:
            key, value = line.split(":", 1)
        else:
            parts = line.split(None, 1)
            if len(parts) != 2:
                continue
            key, value = parts
        values[key.strip().lower().replace(" ", "_")] = value.strip()
    return values


def _version_from_four_letter(response: str | None) -> tuple[str | None, bool | None]:
    text = str(response or "")
    keeper_match = re.search(r"(?im)^\s*clickhouse\s+keeper\s+version\s*:\s*(.+?)\s*$", text)
    if keeper_match:
        return _normalize_zookeeper_version(keeper_match.group(1)), True
    apache_match = re.search(r"(?im)^\s*zookeeper\s+version\s*:\s*(.+?)\s*$", text)
    if apache_match:
        return _normalize_zookeeper_version(apache_match.group(1)), False
    values = _parse_four_letter_key_values(text)
    version = _normalize_zookeeper_version(values.get("zk_version"))
    return version, None


def _raft_metrics(
    values: dict[str, str], server_state: str | None, read_only: bool | None
) -> tuple[dict[str, int | str | None], str]:
    def _value(name: str) -> str | None:
        return values.get(name) or values.get(f"zk_{name}")

    def _integer(name: str) -> int | None:
        parsed = _parse_number(_value(name))
        return int(parsed) if isinstance(parsed, (int, float)) else None

    raft: dict[str, int | str | None] = {
        "peer_state": str(_value("peer_state") or "").strip() or None,
        "followers": _integer("followers"),
        "synced_followers": _integer("synced_followers"),
        "pending_syncs": _integer("pending_syncs"),
        "first_log_idx": _integer("first_log_idx"),
        "first_log_term": _integer("first_log_term"),
        "last_log_idx": _integer("last_log_idx"),
        "last_log_term": _integer("last_log_term"),
        "last_committed_idx": _integer("last_committed_idx"),
        "leader_committed_log_idx": _integer("leader_committed_log_idx"),
        "target_committed_log_idx": _integer("target_committed_log_idx"),
        "last_snapshot_idx": _integer("last_snapshot_idx"),
        "snapshot_dir_size": _integer("snapshot_dir_size"),
        "log_dir_size": _integer("log_dir_size"),
    }
    last_committed = raft["last_committed_idx"]
    lag_candidates: list[int] = []
    if isinstance(last_committed, int):
        for key in ("leader_committed_log_idx", "target_committed_log_idx"):
            target = raft[key]
            if isinstance(target, int):
                lag_candidates.append(max(0, target - last_committed))
    raft["commit_lag"] = max(lag_candidates) if lag_candidates else None

    state = str(server_state or "").lower()
    if read_only is True:
        quorum_status = "degraded"
    elif state == "standalone":
        quorum_status = "healthy"
    elif state == "leader":
        followers = raft["followers"]
        synced = raft["synced_followers"]
        if isinstance(followers, int) and isinstance(synced, int):
            cluster_nodes = followers + 1
            quorum_nodes = cluster_nodes // 2 + 1
            quorum_status = "healthy" if synced == followers else "degraded"
            if synced + 1 < quorum_nodes:
                quorum_status = "degraded"
        else:
            quorum_status = "unknown"
    elif state == "follower":
        peer_state = str(raft["peer_state"] or "").lower()
        commit_lag = raft["commit_lag"]
        if peer_state and "following" not in peer_state:
            quorum_status = "degraded"
        elif isinstance(commit_lag, int):
            quorum_status = "healthy" if commit_lag == 0 else "degraded"
        else:
            quorum_status = "unknown"
    else:
        quorum_status = "unknown"
    return raft, quorum_status


def fingerprint_zookeeper_implementation(
    host: str,
    port: int,
    timeout: float,
    *,
    transport: Literal["plaintext", "tls"],
    config: ZkTransportConfig,
) -> ZkImplementationFingerprint:
    responses: dict[str, ZkFourLetterResult] = {}

    def _query(command: str) -> ZkFourLetterResult:
        try:
            return query_four_letter_word(
                host,
                port,
                timeout,
                command,
                transport=transport,
                config=config,
            )
        except Exception as exc:  # pragma: no cover - scheduler isolation boundary
            return ZkFourLetterResult(
                command=command,
                error=_friendly_error_from_exception(exc),
            )

    version: str | None = None
    is_keeper: bool | None = None
    # Identity probes are deliberately sequential and strongest-first. Stop as
    # soon as a definitive vendor marker is observed; this keeps Apache and
    # non-compatible endpoints to the smallest possible request budget.
    for command in ("srvr", "stat", "mntr"):
        response = _query(command)
        responses[command] = response
        candidate_version, candidate_impl = _version_from_four_letter(response.response)
        if version is None and candidate_version:
            version = candidate_version
        if candidate_impl is not None:
            is_keeper = candidate_impl
            if candidate_version:
                version = candidate_version
            break

    # mntr and isro are telemetry, not parallel identity guesses. Query them
    # only after Keeper has been confirmed; re-use mntr when it was the probe
    # that supplied the strong marker.
    if is_keeper is True:
        if "mntr" not in responses:
            responses["mntr"] = _query("mntr")
        responses["isro"] = _query("isro")

    merged_values: dict[str, str] = {}
    for command in ("srvr", "stat", "mntr"):
        result = responses.get(command)
        merged_values.update(_parse_four_letter_key_values(result.response if result else None))

    state = str(merged_values.get("zk_server_state") or merged_values.get("mode") or "").strip().lower() or None
    connections_raw = merged_values.get("zk_num_alive_connections") or merged_values.get("connections")
    connections_value = _parse_number(connections_raw)
    connections = int(connections_value) if isinstance(connections_value, (int, float)) else None

    latency: dict[str, int | float | None] = {
        "min": _parse_number(merged_values.get("zk_min_latency")),
        "avg": _parse_number(merged_values.get("zk_avg_latency")),
        "max": _parse_number(merged_values.get("zk_max_latency")),
    }
    latency_combined = str(merged_values.get("latency_min/avg/max") or "").strip()
    if latency_combined:
        parts = [part.strip() for part in latency_combined.split("/")]
        if len(parts) == 3:
            for key, raw in zip(("min", "avg", "max"), parts, strict=True):
                if latency[key] is None:
                    latency[key] = _parse_number(raw)

    isro_result = str((responses.get("isro") or ZkFourLetterResult("isro")).response or "").strip().lower()
    read_only = True if isro_result == "ro" else False if isro_result == "rw" else None
    raft, quorum_status = _raft_metrics(merged_values, state, read_only)

    if is_keeper is True:
        implementation = "clickhouse-keeper"
        confidence = "confirmed"
    elif is_keeper is False:
        implementation = "apache-zookeeper"
        confidence = "rejected"
        quorum_status = "unknown"
    else:
        implementation = "zookeeper-compatible"
        confidence = "unconfirmed"

    return ZkImplementationFingerprint(
        implementation=implementation,
        is_keeper=is_keeper,
        confidence=confidence,
        version=version,
        server_state=state,
        read_only=read_only,
        connections=connections,
        latency_ms=latency,
        raft=raft,
        quorum_status=quorum_status,
        responses=responses,
    )


class _ZkClient:
    def __init__(
        self,
        host: str,
        port: int,
        timeout: float,
        *,
        transport_config: ZkTransportConfig | None = None,
    ) -> None:
        self.host = host
        self.port = port
        self.timeout = timeout
        self.transport_config = transport_config or ZkTransportConfig()
        self.selected_transport: Literal["plaintext", "tls"] | None = None
        self.sock: socket.socket | None = None
        self._xid = 1

    def connect(self) -> None:
        self.selected_transport = None
        failures: list[tuple[str, BaseException]] = []
        for transport in _transport_attempt_order(self.transport_config):
            try:
                self._connect_once(transport)
                self.selected_transport = transport
                return
            except (TimeoutError, ConnectionError, OSError, ValueError, ssl.SSLError) as exc:
                failures.append((transport, exc))
                self._close_socket_only()
                if not _transport_error_allows_fallback(
                    exc,
                    attempted_transport=transport,
                    config=self.transport_config,
                ):
                    raise
        if len(failures) == 1:
            raise failures[0][1]
        details = "; ".join(f"{mode}: {_friendly_error_from_exception(exc)}" for mode, exc in failures)
        raise ConnectionError(f"ZooKeeper transport auto-detection failed ({details})")

    def connect_and_get_root(self) -> tuple[list[str] | None, int, dict[str, int] | None]:
        """Select a transport only after a complete root request succeeds.

        A valid ConnectResponse alone is not enough to distinguish a real
        ZooKeeper endpoint from a protocol look-alike.  Initial detection uses
        this combined operation so a plaintext reset/EOF/timeout or malformed
        root response can consume the single TLS fallback.  Confirmed
        certificate/mTLS failures and permanent endpoint errors never trigger
        a downgrade; protocol mismatch/reset/EOF/bounded timeout may consume
        one alternate attempt.
        """

        self.selected_transport = None
        failures: list[tuple[str, BaseException]] = []
        for transport in _transport_attempt_order(self.transport_config):
            try:
                self._connect_once(transport)
            except (TimeoutError, ConnectionError, OSError, ValueError, ssl.SSLError) as exc:
                failures.append((transport, exc))
                self._close_socket_only()
                if not _transport_error_allows_fallback(
                    exc,
                    attempted_transport=transport,
                    config=self.transport_config,
                ):
                    raise
                continue

            try:
                root = self.get_children2("/")
            except (TimeoutError, ConnectionError, OSError, ValueError, ssl.SSLError) as exc:
                failures.append((transport, exc))
                self._close_socket_only()
                # A fully decoded root response is required before selection.
                # Certificate/mTLS failures and permanent endpoint errors do
                # not downgrade, while reset/EOF/timeout/malformed protocol
                # evidence may consume the single alternate attempt.
                if not _transport_error_allows_fallback(
                    exc,
                    attempted_transport=transport,
                    config=self.transport_config,
                ):
                    raise
                continue

            self.selected_transport = transport
            return root

        if len(failures) == 1:
            raise failures[0][1]
        details = "; ".join(f"{mode}: {_friendly_error_from_exception(exc)}" for mode, exc in failures)
        raise ConnectionError(f"ZooKeeper transport auto-detection failed ({details})")

    def _connect_once(self, transport: Literal["plaintext", "tls"]) -> None:
        self.sock = _open_zk_socket(
            self.host,
            self.port,
            self.timeout,
            transport=transport,
            config=self.transport_config,
        )
        try:
            session_timeout_ms = max(1000, int(self.timeout * 1000))
            connect_payload = (
                struct.pack(">i", _ZK_PROTOCOL_VERSION)
                + struct.pack(">q", 0)
                + struct.pack(">i", session_timeout_ms)
                + struct.pack(">q", 0)
                + struct.pack(">i", len(_ZK_PASSWD_DEFAULT))
                + _ZK_PASSWD_DEFAULT
                + b"\x00"
            )
            _send_frame(self._require_sock(), connect_payload)
            response = _recv_frame(self._require_sock())
            _parse_connect_response(response)
        except (TimeoutError, ConnectionError, OSError, ValueError) as exc:
            # ``_open_zk_socket`` performs the TLS handshake before returning.
            # Every failure below this point therefore belongs to the
            # ZooKeeper ConnectRequest/ConnectResponse exchange. Preserve the
            # boundary so certificate failures remain distinguishable from an
            # EOF/timeout/malformed protocol response eligible for one fallback.
            raise _ZkProtocolPayloadError(str(exc), transport=transport) from exc

    def _close_socket_only(self) -> None:
        sock = self.sock
        if sock is None:
            return
        try:
            sock.close()
        except OSError:
            pass
        self.sock = None

    def close(self) -> None:
        sock = self.sock
        if sock is None:
            return
        try:
            xid = self._next_xid()
            payload = struct.pack(">ii", xid, _ZK_OP_CLOSE_SESSION)
            _send_frame(sock, payload)
        except Exception:
            pass
        try:
            sock.close()
        except OSError:
            pass
        self.sock = None

    def _require_sock(self) -> socket.socket:
        if self.sock is None:
            raise RuntimeError("ZooKeeper socket is not connected")
        return self.sock

    def _next_xid(self) -> int:
        xid = self._xid
        self._xid += 1
        return xid

    def _request_with_xid(self, xid: int, opcode: int, payload: bytes = b"") -> tuple[int, bytes]:
        sock = self._require_sock()
        frame = struct.pack(">ii", xid, int(opcode)) + payload
        _send_frame(sock, frame)
        response = _recv_frame(sock)

        if len(response) < 16:
            raise ValueError("invalid ZooKeeper response header")

        rxid = struct.unpack(">i", response[0:4])[0]
        _zxid = struct.unpack(">q", response[4:12])[0]
        err = struct.unpack(">i", response[12:16])[0]
        if rxid != xid:
            raise ValueError(f"unexpected ZooKeeper xid {rxid} (expected {xid})")
        return int(err), response[16:]

    def _request(self, opcode: int, payload: bytes = b"") -> tuple[int, bytes]:
        return self._request_with_xid(self._next_xid(), opcode, payload)

    def auth_digest(self, username: str, password: str) -> tuple[bool, str | None]:
        raw_auth = f"{username}:{password}".encode("utf-8", errors="replace")
        payload = struct.pack(">i", 0) + _encode_zk_string("digest") + struct.pack(">i", len(raw_auth)) + raw_auth
        # Only a protocol response can reject a credential.  Transport and
        # malformed-response failures must remain exceptions so lifecycle
        # callers classify the attempt as unverified/retryable rather than as
        # a definitive authentication failure.
        err, _ = self._request_with_xid(_ZK_AUTH_XID, _ZK_OP_AUTH, payload)

        if err == _ZK_ERR_OK:
            return True, None
        return False, f"authentication failed: {_zk_error_name(err)}"

    def get_children2(self, path: str) -> tuple[list[str] | None, int, dict[str, int] | None]:
        payload = _encode_zk_string(path) + b"\x00"
        err, response_payload = self._request(_ZK_OP_GET_CHILDREN2, payload)
        if err != _ZK_ERR_OK:
            if response_payload:
                raise ValueError("unexpected ZooKeeper error payload")
            return None, err, None

        children, offset = _parse_children_vector(response_payload, 0)
        if children is None:
            raise ValueError("invalid null ZooKeeper children vector")
        stat, offset = _parse_stat(response_payload, offset)
        # ClickHouse Keeper exposes virtual nodes below /keeper but reports
        # numChildren=0 in their Stat record. The children vector is still
        # fully framed and authoritative, so tolerate this vendor-specific
        # inconsistency without weakening validation for user znodes.
        if len(children) != stat["num_children"] and not (
            path == _KEEPER_SYSTEM_PREFIX or path.startswith(f"{_KEEPER_SYSTEM_PREFIX}/")
        ):
            raise ValueError("ZooKeeper children vector/stat count mismatch")
        if offset != len(response_payload):
            raise ValueError("unexpected trailing ZooKeeper getChildren2 payload")
        return children, err, stat

    def get_data(self, path: str) -> tuple[bytes | None, int, dict[str, int] | None]:
        payload = _encode_zk_string(path) + b"\x00"
        err, response_payload = self._request(_ZK_OP_GET_DATA, payload)
        if err != _ZK_ERR_OK:
            if response_payload:
                raise ValueError("unexpected ZooKeeper error payload")
            return None, err, None

        data, offset = _decode_zk_buffer(response_payload, 0)
        stat, offset = _parse_stat(response_payload, offset)
        if offset != len(response_payload):
            raise ValueError("unexpected trailing ZooKeeper getData payload")
        return data, err, stat

    def create(self, path: str, data: bytes = b"", flags: int = _ZK_CREATE_EPHEMERAL) -> int:
        payload = (
            _encode_zk_string(path)
            + struct.pack(">i", len(data))
            + data
            + _encode_acl_world_anyone_all()
            + struct.pack(">i", int(flags))
        )
        err, _response_payload = self._request(_ZK_OP_CREATE, payload)
        return int(err)

    def delete(self, path: str, version: int = -1) -> int:
        payload = _encode_zk_string(path) + struct.pack(">i", int(version))
        err, _response_payload = self._request(_ZK_OP_DELETE, payload)
        return int(err)


def _enumerate_znodes(
    client: _ZkClient,
    max_znodes: int,
    progress_hook: Callable[[dict[str, Any]], None] | None = None,
    progress_interval_s: float = _ZK_ENUM_PROGRESS_INTERVAL_SECONDS,
    collect_paths: bool = True,
    enum_workers: int = 1,
    auth_username: str | None = None,
    auth_password: str | None = None,
    transport_config: ZkTransportConfig | None = None,
    nested_scheduler: Any | None = None,
) -> tuple[list[str], int, bool, dict[str, dict[str, Any]], str | None]:
    worker_count = max(1, int(enum_workers))
    parallel_capable = all(hasattr(client, attr) for attr in ("host", "port", "timeout"))
    if worker_count > 1 and parallel_capable:
        return _enumerate_znodes_parallel(
            host=client.host,
            port=client.port,
            timeout=client.timeout,
            max_znodes=max_znodes,
            progress_hook=progress_hook,
            progress_interval_s=progress_interval_s,
            collect_paths=collect_paths,
            enum_workers=worker_count,
            auth_username=auth_username,
            auth_password=auth_password,
            transport_config=transport_config,
            nested_scheduler=nested_scheduler,
        )

    node_budget = max(0, int(max_znodes))
    if node_budget == 0:
        if progress_hook is not None:
            progress_hook(
                {
                    "event": "enumerate_done",
                    "processed_parents": 0,
                    "queued": 0,
                    "total_count": 0,
                    "listed_count": 0,
                    "elapsed_s": 0.0,
                }
            )
        return [], 0, True, {}, None
    queue = deque(["/"])
    visited: set[str] = {"/"}
    listed_nodes: list[str] = []
    listed_meta: dict[str, dict[str, Any]] = {}
    total_count = 0
    budget_truncated = False
    processed_parents = 0
    started = time.monotonic()
    last_report_at = started
    last_report_count = 0
    last_report_processed = 0

    while queue:
        parent = queue.popleft()
        processed_parents += 1
        try:
            children, err, _stat = client.get_children2(parent)
        except (TimeoutError, ConnectionError, OSError, ValueError) as exc:
            return (
                listed_nodes,
                total_count,
                budget_truncated or (collect_paths and total_count > len(listed_nodes)),
                listed_meta,
                (f"getChildren failed for {parent}: {_friendly_error_from_exception(exc)}"),
            )
        parent_meta = listed_meta.get(parent) if collect_paths else None
        if err == _ZK_ERR_NONODE:
            if parent_meta is not None:
                parent_meta["error"] = "not found"
            continue
        if err == _ZK_ERR_NOAUTH:
            # Parent exists, but subtree is not readable without auth.
            if parent_meta is None and collect_paths:
                parent_meta = listed_meta.setdefault(
                    parent,
                    {"path": parent, "children": None, "bytes": None, "error": None},
                )
            if parent_meta is not None:
                parent_meta["error"] = "Access Denied"
            continue
        if err != _ZK_ERR_OK:
            if parent_meta is not None:
                parent_meta["error"] = _zk_error_name(err)
            return (
                listed_nodes,
                total_count,
                budget_truncated or (collect_paths and total_count > len(listed_nodes)),
                listed_meta,
                (f"getChildren failed for {parent}: {_zk_error_name(err)}"),
            )
        if children is None:
            continue
        if parent_meta is not None:
            parent_meta["children"] = int(len(children))
            parent_meta["bytes"] = int((_stat or {}).get("data_length") or 0)
            parent_meta["error"] = None

        for child in children:
            full_path = _join_znode_path(parent, child)
            if full_path in visited:
                continue
            if len(visited) >= node_budget:
                budget_truncated = True
                break
            visited.add(full_path)
            total_count += 1
            if collect_paths:
                listed_nodes.append(full_path)
                listed_meta[full_path] = {"path": full_path, "children": None, "bytes": None, "error": None}
            queue.append(full_path)
            if progress_hook is not None and progress_interval_s > 0:
                now = time.monotonic()
                elapsed_since_report = max(0.0, now - last_report_at)
                if elapsed_since_report >= progress_interval_s:
                    interval_count = int(total_count - last_report_count)
                    progress_hook(
                        {
                            "event": "enumerate_progress",
                            "processed_parents": processed_parents,
                            "queued": len(queue),
                            "total_count": total_count,
                            "listed_count": len(listed_nodes),
                            "elapsed_s": max(0.0, now - started),
                            "interval_s": elapsed_since_report,
                            "interval_count": interval_count,
                            "interval_processed": int(processed_parents - last_report_processed),
                        }
                    )
                    last_report_at = now
                    last_report_count = total_count
                    last_report_processed = processed_parents
        if progress_hook is not None and progress_interval_s > 0 and total_count > 0:
            now = time.monotonic()
            elapsed_since_report = max(0.0, now - last_report_at)
            if elapsed_since_report >= progress_interval_s:
                interval_count = int(total_count - last_report_count)
                progress_hook(
                    {
                        "event": "enumerate_progress",
                        "processed_parents": processed_parents,
                        "queued": len(queue),
                        "total_count": total_count,
                        "listed_count": len(listed_nodes),
                        "elapsed_s": max(0.0, now - started),
                        "interval_s": elapsed_since_report,
                        "interval_count": interval_count,
                        "interval_processed": int(processed_parents - last_report_processed),
                    }
                )
                last_report_at = now
                last_report_count = total_count
                last_report_processed = processed_parents

    truncated = budget_truncated or (collect_paths and total_count > len(listed_nodes))
    if progress_hook is not None:
        progress_hook(
            {
                "event": "enumerate_done",
                "processed_parents": processed_parents,
                "queued": len(queue),
                "total_count": total_count,
                "listed_count": len(listed_nodes),
                "elapsed_s": max(0.0, time.monotonic() - started),
            }
        )
    return listed_nodes, total_count, truncated, listed_meta, None


def _enumerate_znodes_parallel(
    *,
    host: str,
    port: int,
    timeout: float,
    max_znodes: int,
    progress_hook: Callable[[dict[str, Any]], None] | None = None,
    progress_interval_s: float = _ZK_ENUM_PROGRESS_INTERVAL_SECONDS,
    collect_paths: bool = True,
    enum_workers: int = 3,
    auth_username: str | None = None,
    auth_password: str | None = None,
    transport_config: ZkTransportConfig | None = None,
    nested_scheduler: Any | None = None,
) -> tuple[list[str], int, bool, dict[str, dict[str, Any]], str | None]:
    worker_count = max(1, int(enum_workers))
    task_queue: Queue[str | None] = Queue()
    result_queue: Queue[dict[str, Any]] = Queue()
    stop_event = threading.Event()
    active_clients_lock = threading.Lock()
    active_clients: dict[int, _ZkClient] = {}

    node_budget = max(0, int(max_znodes))
    if node_budget == 0:
        if progress_hook is not None:
            progress_hook(
                {
                    "event": "enumerate_done",
                    "processed_parents": 0,
                    "queued": 0,
                    "total_count": 0,
                    "listed_count": 0,
                    "elapsed_s": 0.0,
                }
            )
        return [], 0, True, {}, None
    queue_set: set[str] = {"/"}
    listed_nodes: list[str] = []
    listed_meta: dict[str, dict[str, Any]] = {}
    total_count = 0
    budget_truncated = False
    processed_parents = 0
    in_flight = 1

    started = time.monotonic()
    last_report_at = started
    last_report_count = 0
    last_report_processed = 0
    worker_init_failures = 0

    task_queue.put("/")

    def _emit_progress(now: float) -> None:
        nonlocal last_report_at, last_report_count, last_report_processed
        if progress_hook is None or progress_interval_s <= 0 or total_count <= 0:
            return
        elapsed_since_report = max(0.0, now - last_report_at)
        if elapsed_since_report < progress_interval_s:
            return
        interval_count = int(total_count - last_report_count)
        interval_processed = int(processed_parents - last_report_processed)
        progress_hook(
            {
                "event": "enumerate_progress",
                "processed_parents": processed_parents,
                "queued": max(0, int(in_flight)),
                "total_count": total_count,
                "listed_count": len(listed_nodes),
                "elapsed_s": max(0.0, now - started),
                "interval_s": elapsed_since_report,
                "interval_count": interval_count,
                "interval_processed": interval_processed,
            }
        )
        last_report_at = now
        last_report_count = total_count
        last_report_processed = processed_parents

    def _worker_inner() -> None:
        client: _ZkClient | None = None
        try:
            if transport_config is None:
                client = _ZkClient(host, port, timeout)
            else:
                client = _ZkClient(host, port, timeout, transport_config=transport_config)
            with active_clients_lock:
                if stop_event.is_set():
                    return
                active_clients[id(client)] = client
            client.connect()
            if auth_username is not None and auth_password is not None:
                auth_ok, auth_error = client.auth_digest(auth_username, auth_password)
                if not auth_ok:
                    result_queue.put(
                        {
                            "kind": "worker_error",
                            "error": str(auth_error or "authentication failed"),
                        }
                    )
                    return
            while not stop_event.is_set():
                try:
                    parent = task_queue.get(timeout=0.2)
                except Empty:
                    continue
                if parent is None:
                    return
                try:
                    children, err, stat = client.get_children2(parent)
                    result_queue.put(
                        {
                            "kind": "result",
                            "parent": parent,
                            "children": children,
                            "err": int(err),
                            "stat": stat,
                            "error": None,
                        }
                    )
                except (TimeoutError, ConnectionError, OSError, ValueError) as exc:
                    result_queue.put(
                        {
                            "kind": "result",
                            "parent": parent,
                            "children": None,
                            "err": None,
                            "stat": None,
                            "error": _friendly_error_from_exception(exc),
                        }
                    )
                except Exception as exc:  # pragma: no cover - worker isolation boundary
                    # A dequeued parent must always produce a parent-bound result.
                    # Publishing an anonymous worker_error here would leave the
                    # coordinator's in_flight counter permanently elevated.
                    result_queue.put(
                        {
                            "kind": "result",
                            "parent": parent,
                            "children": None,
                            "err": None,
                            "stat": None,
                            "error": _friendly_error_from_exception(exc),
                        }
                    )
                    return
        except (TimeoutError, ConnectionError, OSError, ValueError) as exc:
            result_queue.put(
                {
                    "kind": "worker_error",
                    "error": _friendly_error_from_exception(exc),
                }
            )
        except Exception as exc:  # pragma: no cover - worker isolation boundary
            result_queue.put(
                {
                    "kind": "worker_error",
                    "error": _friendly_error_from_exception(exc),
                }
            )
        finally:
            if client is not None:
                with active_clients_lock:
                    active_clients.pop(id(client), None)
                client.close()

    def _worker() -> None:
        if nested_scheduler is None:
            _worker_inner()
            return
        with nested_scheduler.slot():
            _worker_inner()

    threads = [threading.Thread(target=_worker, daemon=True) for _ in range(worker_count)]
    for thread in threads:
        thread.start()

    enum_error: str | None = None
    try:
        while in_flight > 0 and enum_error is None:
            try:
                item = result_queue.get(timeout=0.2)
            except Empty:
                _emit_progress(time.monotonic())
                continue

            kind = str(item.get("kind") or "")
            if kind == "worker_error":
                worker_init_failures += 1
                if worker_init_failures >= worker_count:
                    enum_error = f"worker init failed: {str(item.get('error') or 'connection failed')}"
                continue

            parent = str(item.get("parent") or "/")
            in_flight = max(0, int(in_flight - 1))
            processed_parents += 1

            item_error = str(item.get("error") or "").strip()
            if item_error:
                enum_error = f"getChildren failed for {parent}: {item_error}"
                break

            err = int(err_raw) if (err_raw := item.get("err")) is not None else _ZK_ERR_OK
            children = item.get("children")
            stat = item.get("stat")
            parent_meta = listed_meta.get(parent) if collect_paths else None

            if err == _ZK_ERR_NONODE:
                if parent_meta is not None:
                    parent_meta["error"] = "not found"
                _emit_progress(time.monotonic())
                continue
            if err == _ZK_ERR_NOAUTH:
                if parent_meta is None and collect_paths:
                    parent_meta = listed_meta.setdefault(
                        parent,
                        {"path": parent, "children": None, "bytes": None, "error": None},
                    )
                if parent_meta is not None:
                    parent_meta["error"] = "Access Denied"
                _emit_progress(time.monotonic())
                continue
            if err != _ZK_ERR_OK:
                if parent_meta is not None:
                    parent_meta["error"] = _zk_error_name(err)
                enum_error = f"getChildren failed for {parent}: {_zk_error_name(err)}"
                break
            if children is None:
                _emit_progress(time.monotonic())
                continue
            if parent_meta is not None:
                parent_meta["children"] = int(len(children))
                parent_meta["bytes"] = int((stat or {}).get("data_length") or 0)
                parent_meta["error"] = None

            for child in children:
                full_path = _join_znode_path(parent, child)
                if full_path in queue_set:
                    continue
                if len(queue_set) >= node_budget:
                    budget_truncated = True
                    break
                queue_set.add(full_path)
                total_count += 1
                if collect_paths:
                    listed_nodes.append(full_path)
                    listed_meta[full_path] = {"path": full_path, "children": None, "bytes": None, "error": None}
                in_flight += 1
                task_queue.put(full_path)

            _emit_progress(time.monotonic())
    finally:
        # Closing the live sockets is what interrupts workers currently blocked
        # in recv(); the event alone is only observed between requests.  Take
        # the snapshot under the same lock used for registration so no worker
        # can publish a new live client after cancellation starts.
        with active_clients_lock:
            stop_event.set()
            clients_to_cancel = list(active_clients.values())
        for active_client in clients_to_cancel:
            try:
                close_socket = getattr(active_client, "_close_socket_only", None)
                if callable(close_socket):
                    close_socket()
                else:
                    active_client.close()
            except Exception:  # pragma: no cover - best-effort cancellation boundary
                continue
        for _ in range(worker_count):
            task_queue.put(None)
        for thread in threads:
            thread.join(timeout=1.0)

    truncated = budget_truncated or (collect_paths and total_count > len(listed_nodes))
    if progress_hook is not None:
        progress_hook(
            {
                "event": "enumerate_done",
                "processed_parents": processed_parents,
                "queued": max(0, int(in_flight)),
                "total_count": total_count,
                "listed_count": len(listed_nodes),
                "elapsed_s": max(0.0, time.monotonic() - started),
            }
        )
    return listed_nodes, total_count, truncated, listed_meta, enum_error


def _probe_znode_create_delete(client: _ZkClient, host: str, port: int) -> tuple[bool | None, bool | None, str | None]:
    base_name = (
        f"/redposture_probe_{host.replace('.', '_').replace(':', '_')}_{port}_"
        f"{int(time.time() * 1000)}_{secrets.token_hex(6)}"
    )
    try:
        for index in range(3):
            probe_path = base_name if index == 0 else f"{base_name}_{index}"
            create_err = int(client.create(probe_path))
            if create_err == _ZK_ERR_NODEEXISTS:
                continue
            if create_err != _ZK_ERR_OK:
                return False, None, _zk_error_name(create_err)

            delete_err = int(client.delete(probe_path, -1))
            if delete_err == _ZK_ERR_OK:
                return True, True, None
            return True, False, _zk_error_name(delete_err)
    except AttributeError:
        return None, None, "capability probe unsupported"
    except (TimeoutError, ConnectionError, OSError, ValueError) as exc:
        return None, None, _friendly_error_from_exception(exc)

    return None, None, "NODEEXISTS"


def _znode_detail_entry(path: str, meta: dict[str, Any] | None) -> dict[str, Any]:
    state = "unknown"
    children_value: int | None = None
    bytes_value: int | None = None
    error_value: str | None = None

    if isinstance(meta, dict):
        raw_error = str(meta.get("error") or "").strip()
        if raw_error:
            error_value = raw_error
            state = "denied" if raw_error.lower() == "access denied" else "error"
        else:
            raw_children = meta.get("children")
            raw_bytes = meta.get("bytes")
            if isinstance(raw_children, int):
                children_value = raw_children
            if isinstance(raw_bytes, int):
                bytes_value = raw_bytes
            if children_value is not None and bytes_value is not None:
                state = "empty" if children_value == 0 and bytes_value == 0 else "readable"

    return {
        "path": path,
        "state": state,
        "children": children_value,
        "bytes": bytes_value,
        "error": error_value,
    }
