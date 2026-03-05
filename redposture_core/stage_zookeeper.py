"""ZooKeeper audit stage."""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import socket
import struct
import sys
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from .console import Console
from .logger import AttemptLogger
from .progress import iter_completed_with_progress
from .utils import collect_scan_ports, collect_scan_targets, utc_now_iso

_ZK_PROTOCOL_VERSION = 0
_ZK_PASSWD_DEFAULT = b"\x00" * 16
_ZK_OP_GET_DATA = 4
_ZK_OP_GET_CHILDREN2 = 12
_ZK_OP_CLOSE_SESSION = -11
_ZK_OP_AUTH = 100
_ZK_ERR_OK = 0
_ZK_ERR_NONODE = -101
_ZK_ERR_NOAUTH = -102
_ZK_ERR_RETRYABLE_ROOT_QUERY = -124
_ZK_MAX_FRAME = 64 * 1024 * 1024
_ZK_SYSTEM_PREFIX = "/zookeeper"
_CONNECTION_REFUSED_PREFIX = "connection refused"
_CONNECTION_TIMEOUT_PREFIX = "connection timeout"
_UNEXPECTED_EOF_PREFIX = "unexpected eof"
_ROOT_QUERY_ERR_124_PREFIX = "root query failed: err_-124"
_ZK_AUTH_XID = -4


def _clip(text: str, width: int = 64) -> str:
    if len(text) <= width:
        return text
    if width <= 3:
        return text[:width]
    return text[: width - 3] + "..."


def _retry_delay(attempt_index: int) -> float:
    return min(1.50, 0.20 * (2**attempt_index))


def _friendly_error_text(value: str) -> str:
    text = (value or "").strip()
    if not text:
        return "connection failed"

    lower = text.lower()
    if "connection refused" in lower:
        return "connection refused (service is not listening on target port)"
    if "timed out" in lower or "timeout" in lower:
        return "connection timeout"
    if "name or service not known" in lower or "nodename nor servname provided" in lower:
        return "dns lookup failed"
    if "temporary failure in name resolution" in lower:
        return "dns lookup temporary failure"
    if "no route to host" in lower or "network is unreachable" in lower:
        return "network unreachable"
    if "operation not permitted" in lower:
        return "operation not permitted by local environment"

    match = re.search(r"\[errno\s+(-?\d+)\]\s*(.*)", text, flags=re.IGNORECASE)
    if match:
        errno_num = match.group(1)
        detail = (match.group(2) or "").strip()
        if errno_num in {"61", "111"}:
            return "connection refused (service is not listening on target port)"
        if errno_num in {"60", "110"}:
            return "connection timeout"
        if errno_num in {"8", "-2"}:
            return "dns lookup failed"
        if errno_num in {"65", "101", "113"}:
            return "network unreachable"
        if detail:
            return detail

    return text


def _friendly_error_from_exception(exc: BaseException) -> str:
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return "connection timeout"
    return _friendly_error_text(str(exc))


def _is_connection_refused_error(value: Any) -> bool:
    text = str(value or "").strip().lower()
    return bool(text) and text.startswith(_CONNECTION_REFUSED_PREFIX)


def _is_connection_refused_fail_record(record: dict[str, Any]) -> bool:
    return str(record.get("status") or "") == "fail" and _is_connection_refused_error(record.get("error"))


def _is_connection_timeout_error(value: Any) -> bool:
    text = str(value or "").strip().lower()
    return bool(text) and text.startswith(_CONNECTION_TIMEOUT_PREFIX)


def _is_unexpected_eof_error(value: Any) -> bool:
    text = str(value or "").strip().lower()
    return bool(text) and text.startswith(_UNEXPECTED_EOF_PREFIX)


def _is_root_query_err_124_error(value: Any) -> bool:
    text = str(value or "").strip().lower()
    return bool(text) and text.startswith(_ROOT_QUERY_ERR_124_PREFIX)


def _is_suppressed_fail_record(record: dict[str, Any]) -> bool:
    return str(record.get("status") or "") == "fail" and (
        _is_connection_refused_error(record.get("error"))
        or _is_connection_timeout_error(record.get("error"))
        or _is_unexpected_eof_error(record.get("error"))
        or _is_root_query_err_124_error(record.get("error"))
    )


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
        -103: "BADVERSION",
        -108: "NOCHILDRENFOREPHEMERALS",
        -110: "NODEEXISTS",
        -111: "NOTEMPTY",
        -112: "SESSIONEXPIRED",
        -113: "INVALIDCALLBACK",
        -114: "INVALIDACL",
        -115: "AUTHFAILED",
        -118: "SESSIONMOVED",
        -119: "NOTREADONLY",
    }
    return names.get(code, f"ERR_{code}")


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError("unexpected EOF")
        data += chunk
    return data


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
    if size < 0:
        return None, offset
    end = offset + size
    if end > len(data):
        raise ValueError("truncated ZooKeeper string payload")
    return data[offset:end].decode("utf-8", errors="replace"), end


def _decode_zk_buffer(data: bytes, offset: int = 0) -> tuple[bytes | None, int]:
    if offset + 4 > len(data):
        raise ValueError("invalid ZooKeeper buffer payload")
    (size,) = struct.unpack(">i", data[offset : offset + 4])
    offset += 4
    if size < 0:
        return None, offset
    end = offset + size
    if end > len(data):
        raise ValueError("truncated ZooKeeper buffer payload")
    return data[offset:end], end


def _parse_children_vector(payload: bytes, offset: int = 0) -> tuple[list[str], int]:
    if offset + 4 > len(payload):
        raise ValueError("invalid ZooKeeper children vector")
    (count,) = struct.unpack(">i", payload[offset : offset + 4])
    offset += 4
    if count < 0:
        return [], offset

    children: list[str] = []
    for _ in range(count):
        item, offset = _decode_zk_string(payload, offset)
        children.append(str(item or ""))
    return children, offset


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
    return normalized == _ZK_SYSTEM_PREFIX or normalized.startswith(f"{_ZK_SYSTEM_PREFIX}/")


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


class _ZkClient:
    def __init__(self, host: str, port: int, timeout: float) -> None:
        self.host = host
        self.port = port
        self.timeout = timeout
        self.sock: socket.socket | None = None
        self._xid = 1

    def connect(self) -> None:
        self.sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        self.sock.settimeout(self.timeout)

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

        if len(response) < 20:
            raise ValueError("invalid ZooKeeper connect response")
        _ = struct.unpack(">i", response[0:4])[0]
        _ = struct.unpack(">i", response[4:8])[0]
        _ = struct.unpack(">q", response[8:16])[0]
        passwd_len = struct.unpack(">i", response[16:20])[0]
        if passwd_len < 0 or 20 + passwd_len > len(response):
            raise ValueError("invalid ZooKeeper connect payload")

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
        try:
            err, _ = self._request_with_xid(_ZK_AUTH_XID, _ZK_OP_AUTH, payload)
        except (TimeoutError, ConnectionError, OSError, ValueError) as exc:
            return False, _friendly_error_from_exception(exc)

        if err == _ZK_ERR_OK:
            return True, None
        return False, f"authentication failed: {_zk_error_name(err)}"

    def get_children2(self, path: str) -> tuple[list[str] | None, int, dict[str, int] | None]:
        payload = _encode_zk_string(path) + b"\x00"
        err, response_payload = self._request(_ZK_OP_GET_CHILDREN2, payload)
        if err != _ZK_ERR_OK:
            return None, err, None

        children, offset = _parse_children_vector(response_payload, 0)
        stat: dict[str, int] | None = None
        if offset < len(response_payload):
            stat, _ = _parse_stat(response_payload, offset)
        return children, err, stat

    def get_data(self, path: str) -> tuple[bytes | None, int, dict[str, int] | None]:
        payload = _encode_zk_string(path) + b"\x00"
        err, response_payload = self._request(_ZK_OP_GET_DATA, payload)
        if err != _ZK_ERR_OK:
            return None, err, None

        data, offset = _decode_zk_buffer(response_payload, 0)
        stat: dict[str, int] | None = None
        if offset < len(response_payload):
            stat, _ = _parse_stat(response_payload, offset)
        return data, err, stat


def _enumerate_znodes(client: _ZkClient, max_znodes: int) -> tuple[list[str], bool, str | None]:
    queue = ["/"]
    visited = {"/"}
    nodes: list[str] = []
    truncated = False

    while queue:
        parent = queue.pop(0)
        children, err, _stat = client.get_children2(parent)
        if err == _ZK_ERR_NONODE:
            continue
        if err == _ZK_ERR_NOAUTH:
            # Parent exists, but subtree is not readable without auth.
            continue
        if err != _ZK_ERR_OK:
            return nodes, truncated, f"getChildren failed for {parent}: {_zk_error_name(err)}"
        if children is None:
            continue

        for child in children:
            full_path = _join_znode_path(parent, child)
            if _is_system_znode(full_path):
                continue
            if full_path in visited:
                continue
            visited.add(full_path)
            nodes.append(full_path)
            if len(nodes) >= max_znodes:
                truncated = True
                return nodes, truncated, None
            queue.append(full_path)

    return nodes, truncated, None


def _audit_zookeeper_host(
    host: str,
    port: int,
    timeout: float,
    retries: int,
    username: str | None,
    password: str | None,
    show_znodes: bool,
    dump: bool,
    query_znode: str | None,
    max_znodes: int,
) -> dict[str, Any]:
    base_attempts = max(1, retries + 1)
    bonus_retry_for_root_query_124 = False
    last_error: str | None = None
    provided_credentials = bool(username and password)

    for attempt in range(base_attempts + 1):
        max_attempts = base_attempts + (1 if bonus_retry_for_root_query_124 else 0)
        if attempt >= max_attempts:
            break
        started = time.monotonic()
        client = _ZkClient(host, port, timeout)
        try:
            client.connect()

            provided_credentials_ok: bool | None = None
            invalid_provided_credentials = False
            auth_applied_ok: bool | None = None
            auth_error: str | None = None
            root_children, root_err, _ = client.get_children2("/")
            anonymous_root_err = root_err

            if root_err == _ZK_ERR_RETRYABLE_ROOT_QUERY and not bonus_retry_for_root_query_124:
                bonus_retry_for_root_query_124 = True
                last_error = f"root query failed: {_zk_error_name(root_err)}"
                time.sleep(_retry_delay(attempt))
                continue

            if provided_credentials and username and password:
                auth_applied_ok, auth_error = client.auth_digest(username, password)
                if auth_applied_ok:
                    root_children, root_err, _ = client.get_children2("/")
                    if anonymous_root_err == _ZK_ERR_NOAUTH and root_err == _ZK_ERR_OK:
                        provided_credentials_ok = True
                    elif anonymous_root_err in {_ZK_ERR_NOAUTH, _ZK_ERR_OK}:
                        provided_credentials_ok = False
                else:
                    provided_credentials_ok = False
                if not auth_applied_ok and not auth_error:
                    auth_error = "authentication failed"

            if provided_credentials and provided_credentials_ok is False:
                auth_required_value: bool | None
                if anonymous_root_err == _ZK_ERR_NOAUTH:
                    auth_required_value = True
                elif anonymous_root_err == _ZK_ERR_OK:
                    auth_required_value = False
                else:
                    auth_required_value = None

                auth_error_text = str(auth_error or "").strip()
                if (
                    auth_required_value is not False
                    and auth_error_text
                    and not auth_error_text.lower().startswith("authentication failed")
                ):
                    return {
                        "timestamp": utc_now_iso(),
                        "host": host,
                        "port": port,
                        "is_zookeeper": True,
                        "status": "fail",
                        "auth_required": auth_required_value,
                        "provided_credentials": provided_credentials,
                        "provided_username": username,
                        "provided_password": password if provided_credentials else None,
                        "provided_credentials_ok": provided_credentials_ok,
                        "show_znodes": show_znodes,
                        "dump": dump,
                        "query_znode": query_znode,
                        "max_znodes": max_znodes,
                        "znode_count": None,
                        "znodes": None,
                        "znode_values": None,
                        "znodes_truncated": False,
                        "query_znode_value": None,
                        "query_znode_dump": None,
                        "query_znode_dump_error": None,
                        "elapsed_ms": int((time.monotonic() - started) * 1000),
                        "error": auth_error_text,
                    }
                if auth_required_value is False:
                    invalid_provided_credentials = True
                else:
                    invalid_status = "auth_required" if auth_required_value is True else "fail"
                    return {
                        "timestamp": utc_now_iso(),
                        "host": host,
                        "port": port,
                        "is_zookeeper": True,
                        "status": invalid_status,
                        "auth_required": auth_required_value,
                        "provided_credentials": provided_credentials,
                        "provided_username": username,
                        "provided_password": password if provided_credentials else None,
                        "provided_credentials_ok": provided_credentials_ok,
                        "show_znodes": show_znodes,
                        "dump": dump,
                        "query_znode": query_znode,
                        "max_znodes": max_znodes,
                        "znode_count": None,
                        "znodes": None,
                        "znode_values": None,
                        "znodes_truncated": False,
                        "query_znode_value": None,
                        "query_znode_dump": None,
                        "query_znode_dump_error": "authentication required",
                        "elapsed_ms": int((time.monotonic() - started) * 1000),
                        "error": auth_error_text or "authentication failed",
                    }

            if root_err == _ZK_ERR_NOAUTH:
                return {
                    "timestamp": utc_now_iso(),
                    "host": host,
                    "port": port,
                    "is_zookeeper": True,
                    "status": "auth_required",
                    "auth_required": True,
                    "provided_credentials": provided_credentials,
                    "provided_username": username,
                    "provided_password": password if provided_credentials else None,
                    "provided_credentials_ok": provided_credentials_ok,
                    "show_znodes": show_znodes,
                    "dump": dump,
                    "query_znode": query_znode,
                    "max_znodes": max_znodes,
                    "znode_count": None,
                    "znodes": None,
                    "znode_values": None,
                    "znodes_truncated": False,
                    "query_znode_value": None,
                    "query_znode_dump": None,
                    "query_znode_dump_error": (
                        "access denied" if (provided_credentials and auth_applied_ok) else "authentication required"
                    ),
                    "elapsed_ms": int((time.monotonic() - started) * 1000),
                    "error": auth_error,
                }

            if root_err == _ZK_ERR_RETRYABLE_ROOT_QUERY and not bonus_retry_for_root_query_124:
                bonus_retry_for_root_query_124 = True
                last_error = f"root query failed: {_zk_error_name(root_err)}"
                time.sleep(_retry_delay(attempt))
                continue

            if root_err != _ZK_ERR_OK:
                return {
                    "timestamp": utc_now_iso(),
                    "host": host,
                    "port": port,
                    "is_zookeeper": True,
                    "status": "fail",
                    "auth_required": None,
                    "provided_credentials": provided_credentials,
                    "provided_username": username,
                    "provided_password": password if provided_credentials else None,
                    "provided_credentials_ok": provided_credentials_ok,
                    "show_znodes": show_znodes,
                    "dump": dump,
                    "query_znode": query_znode,
                    "max_znodes": max_znodes,
                    "znode_count": None,
                    "znodes": None,
                    "znode_values": None,
                    "znodes_truncated": False,
                    "query_znode_value": None,
                    "query_znode_dump": None,
                    "query_znode_dump_error": None,
                    "elapsed_ms": int((time.monotonic() - started) * 1000),
                    "error": f"root query failed: {_zk_error_name(root_err)}",
                }

            noauth_detail_text = (
                "access denied" if (provided_credentials and auth_applied_ok) else "authentication required"
            )

            znodes, truncated, enum_error = _enumerate_znodes(client, max_znodes)
            if enum_error:
                last_error = enum_error

            znode_values: list[str] | None = None
            if dump and not query_znode:
                znode_values = []
                for path in znodes:
                    value_bytes, value_err, _value_stat = client.get_data(path)
                    if value_err == _ZK_ERR_OK:
                        znode_values.append(f"{path}:{_format_znode_data(value_bytes)}")
                    elif value_err == _ZK_ERR_NOAUTH:
                        znode_values.append(f"{path}:<{noauth_detail_text}>")
                    elif value_err == _ZK_ERR_NONODE:
                        znode_values.append(f"{path}:<not found>")
                    else:
                        znode_values.append(f"{path}:<error:{_zk_error_name(value_err)}>")

            query_znode_value: str | None = None
            query_znode_dump: str | None = None
            query_znode_dump_error: str | None = None
            if query_znode:
                q_children, q_err, q_stat = client.get_children2(query_znode)
                if q_err == _ZK_ERR_NONODE:
                    query_znode_value = f"{query_znode}:<not found>"
                    if dump:
                        query_znode_dump_error = "znode not found"
                elif q_err == _ZK_ERR_NOAUTH:
                    query_znode_value = f"{query_znode}:<{noauth_detail_text}>"
                    if dump:
                        query_znode_dump_error = noauth_detail_text
                elif q_err == _ZK_ERR_OK:
                    child_count = len(q_children or [])
                    data_length = int((q_stat or {}).get("data_length") or 0)
                    query_znode_value = f"{query_znode} (children:{child_count},bytes:{data_length})"
                    if dump:
                        value_bytes, value_err, _value_stat = client.get_data(query_znode)
                        if value_err == _ZK_ERR_OK:
                            query_znode_dump = _format_znode_data(value_bytes)
                        elif value_err == _ZK_ERR_NONODE:
                            query_znode_dump_error = "znode not found"
                        elif value_err == _ZK_ERR_NOAUTH:
                            query_znode_dump_error = noauth_detail_text
                        else:
                            query_znode_dump_error = _zk_error_name(value_err)
                else:
                    query_znode_value = f"{query_znode}:<error:{_zk_error_name(q_err)}>"
                    if dump:
                        query_znode_dump_error = _zk_error_name(q_err)

            root_count = len(root_children or [])
            total_count = len(znodes)
            if total_count == 0 and root_count > 0:
                total_count = root_count

            auth_required_value: bool | None
            if anonymous_root_err == _ZK_ERR_NOAUTH:
                auth_required_value = True
            elif anonymous_root_err == _ZK_ERR_OK:
                auth_required_value = False
            else:
                auth_required_value = None

            return {
                "timestamp": utc_now_iso(),
                "host": host,
                "port": port,
                "is_zookeeper": True,
                "status": (
                    "valid_credentials"
                    if provided_credentials_ok
                    else "invalid_credentials_anonymous"
                    if invalid_provided_credentials
                    else "open_no_auth"
                ),
                "auth_required": auth_required_value,
                "provided_credentials": provided_credentials,
                "provided_username": username,
                "provided_password": password if provided_credentials else None,
                "provided_credentials_ok": provided_credentials_ok,
                "show_znodes": show_znodes,
                "dump": dump,
                "query_znode": query_znode,
                "max_znodes": max_znodes,
                "znode_count": total_count,
                "znodes": sorted(znodes),
                "znode_values": znode_values,
                "znodes_truncated": truncated,
                "query_znode_value": query_znode_value,
                "query_znode_dump": query_znode_dump,
                "query_znode_dump_error": query_znode_dump_error,
                "elapsed_ms": int((time.monotonic() - started) * 1000),
                "error": last_error if not invalid_provided_credentials else (auth_error or "authentication failed"),
            }
        except (TimeoutError, ConnectionError, OSError, ValueError) as exc:
            last_error = _friendly_error_from_exception(exc)
            max_attempts = base_attempts + (1 if bonus_retry_for_root_query_124 else 0)
            if attempt >= max_attempts - 1:
                break
            time.sleep(_retry_delay(attempt))
        finally:
            client.close()

    return {
        "timestamp": utc_now_iso(),
        "host": host,
        "port": port,
        "is_zookeeper": False,
        "status": "fail",
        "auth_required": None,
        "provided_credentials": provided_credentials,
        "provided_username": username,
        "provided_password": password if provided_credentials else None,
        "provided_credentials_ok": None,
        "show_znodes": show_znodes,
        "dump": dump,
        "query_znode": query_znode,
        "max_znodes": max_znodes,
        "znode_count": None,
        "znodes": None,
        "znode_values": None,
        "znodes_truncated": False,
        "query_znode_value": None,
        "query_znode_dump": None,
        "query_znode_dump_error": None,
        "elapsed_ms": None,
        "error": last_error or "connection failed",
    }


def _nxc_prefix(record: dict[str, Any]) -> str:
    host = _clip(str(record.get("host") or "-"), 64)
    port = str(record.get("port") or "-")
    return f"{'ZOOKEEPER':<12}\t{host}\t{port}\t"


def _with_optional_znodes(record: dict[str, Any], message: str) -> str:
    znode_count = record.get("znode_count")
    truncated = bool(record.get("znodes_truncated"))
    if not isinstance(znode_count, int):
        return f"{message} (znodes:-)"
    if truncated:
        return f"{message} (znodes:{znode_count}+)"
    return f"{message} (znodes:{znode_count})"


def _credentials_label(record: dict[str, Any]) -> str:
    username = str(record.get("provided_username") or "user").strip() or "user"
    provided_password = record.get("provided_password")
    password_text = (
        "<empty>" if provided_password == "" else str(provided_password) if provided_password is not None else "<none>"
    )
    return f"{username}:{password_text}"


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
                "service": "zookeeper",
                "detected": bool(record.get("is_zookeeper")),
                "auth_required": auth_required_value,
            },
            ensure_ascii=False,
        )

    prefix = _nxc_prefix(record)
    return f"{prefix} [*] ZooKeeper Service (auth required:{auth_required_text})"


def _format_record(record: dict[str, Any], output_format: str) -> str:
    if output_format == "json":
        return json.dumps(record, ensure_ascii=False)

    status = str(record.get("status") or "fail")
    prefix = _nxc_prefix(record)
    err = _clip(str(record.get("error") or "-"), 72)

    if status == "open_no_auth":
        return _with_optional_znodes(record, f"{prefix} [+] anonymous access")

    if status == "invalid_credentials_anonymous":
        return f"{prefix} [-] {_credentials_label(record)}"

    if status == "valid_credentials":
        return _with_optional_znodes(record, f"{prefix} [+] {_credentials_label(record)}")

    if status == "auth_required":
        if record.get("provided_credentials"):
            return f"{prefix} [-] {_credentials_label(record)}"
        return f"{prefix} [-] authentication required"

    if status == "fail" and record.get("provided_credentials") and err.lower().startswith("authentication failed"):
        return f"{prefix} [-] {_credentials_label(record)}"

    line = f"{prefix} [!] connection failed"
    if err != "-":
        return f"{line} err={err}"
    return line


def _format_znodes_detail_records(record: dict[str, Any], output_format: str) -> list[str]:
    show_znodes = bool(record.get("show_znodes"))
    dump = bool(record.get("dump"))
    query_znode = str(record.get("query_znode") or "").strip()
    query_znode_value = record.get("query_znode_value")
    query_znode_dump = record.get("query_znode_dump")
    query_znode_dump_error = str(record.get("query_znode_dump_error") or "").strip()

    znodes_raw = record.get("znodes")
    znode_values_raw = record.get("znode_values")

    znodes: list[str] = []
    if isinstance(znodes_raw, list):
        znodes = sorted(str(item) for item in znodes_raw)

    znode_values: list[str] = []
    if isinstance(znode_values_raw, list):
        znode_values = [str(item) for item in znode_values_raw]

    if not show_znodes and not dump and not query_znode:
        return []

    if output_format == "json":
        lines: list[str] = []
        if show_znodes and znodes:
            lines.append(
                json.dumps(
                    {
                        "timestamp": record.get("timestamp"),
                        "type": "znodes_list",
                        "service": "zookeeper",
                        "host": record.get("host"),
                        "port": record.get("port"),
                        "znode_count": record.get("znode_count"),
                        "znodes": znodes,
                    },
                    ensure_ascii=False,
                )
            )
        if query_znode:
            lines.append(
                json.dumps(
                    {
                        "timestamp": record.get("timestamp"),
                        "type": "znode_detail",
                        "service": "zookeeper",
                        "host": record.get("host"),
                        "port": record.get("port"),
                        "znode": query_znode,
                        "value": query_znode_value,
                    },
                    ensure_ascii=False,
                )
            )
        if dump and query_znode:
            lines.append(
                json.dumps(
                    {
                        "timestamp": record.get("timestamp"),
                        "type": "znode_dump",
                        "service": "zookeeper",
                        "host": record.get("host"),
                        "port": record.get("port"),
                        "znode": query_znode,
                        "data": query_znode_dump,
                        "error": query_znode_dump_error or None,
                    },
                    ensure_ascii=False,
                )
            )
        if dump and not query_znode and znode_values:
            lines.append(
                json.dumps(
                    {
                        "timestamp": record.get("timestamp"),
                        "type": "znodes_dump",
                        "service": "zookeeper",
                        "host": record.get("host"),
                        "port": record.get("port"),
                        "znode_count": record.get("znode_count"),
                        "znode_values": znode_values,
                    },
                    ensure_ascii=False,
                )
            )
        return lines

    prefix = _nxc_prefix(record)
    lines: list[str] = []
    if show_znodes and znodes:
        lines.append(f"{prefix} [*] Show Znodes")
        for item in znodes:
            lines.append(f"{prefix} {item}")
    if query_znode:
        lines.append(f"{prefix} [*] Znode {query_znode}")
        if isinstance(query_znode_value, str):
            lines.append(f"{prefix} {query_znode_value}")
    if dump and query_znode:
        lines.append(f"{prefix} [*] Dump Znode {query_znode}")
        if isinstance(query_znode_dump, str):
            lines.append(f"{prefix} {query_znode_dump}")
        elif query_znode_dump_error:
            lines.append(f"{prefix} [-] {query_znode_dump_error}")
        else:
            lines.append(f"{prefix} <no data>")
    if dump and not query_znode and znode_values:
        lines.append(f"{prefix} [*] Dump Znodes")
        for item in znode_values:
            lines.append(f"{prefix} {item}")
    return lines


def _render_colored_zookeeper_line(console: Console, line: str) -> bool:
    if not line.startswith("ZOOKEEPER"):
        return False

    marker_color = {
        "[*]": "cyan",
        "[+]": "bright_green",
        "[-]": "red",
        "[!]": "red",
    }

    for marker in ("[!]", "[-]", "[+]", "[*]"):
        token = f" {marker} "
        if token not in line:
            continue

        left, right = line.split(token, 1)
        tag = "ZOOKEEPER"
        rest = left[len(tag) :] if left.startswith(tag) else left

        spans: list[tuple[int, int, str]] = []
        auth_true = "(auth required:True)"
        auth_false = "(auth required:False)"
        auth_unknown = "(auth required:unknown)"

        idx_true = right.find(auth_true)
        if idx_true >= 0:
            spans.append((idx_true, idx_true + len(auth_true), "bright_green"))
        idx_false = right.find(auth_false)
        if idx_false >= 0:
            spans.append((idx_false, idx_false + len(auth_false), "red"))
        idx_unknown = right.find(auth_unknown)
        if idx_unknown >= 0:
            spans.append((idx_unknown, idx_unknown + len(auth_unknown), "yellow"))

        znodes_match = re.search(r"\(znodes:(\d+)(?:\+)?(?: [^)]*)?\)", right)
        if znodes_match:
            znodes_value = znodes_match.group(1).strip()
            if znodes_value.isdigit() and int(znodes_value) > 0:
                spans.append((znodes_match.start(), znodes_match.end(), "red"))

        if not spans:
            right_colored = console._paint(right, "white", sys.stdout)
        else:
            chunks: list[str] = []
            cursor = 0
            for start, end, color in sorted(spans, key=lambda item: item[0]):
                if start < cursor:
                    continue
                if start > cursor:
                    chunks.append(console._paint(right[cursor:start], "white", sys.stdout))
                chunks.append(console._paint(right[start:end], color, sys.stdout))
                cursor = end
            if cursor < len(right):
                chunks.append(console._paint(right[cursor:], "white", sys.stdout))
            right_colored = "".join(chunks)

        colored = (
            f"{console._paint(tag, 'blue', sys.stdout)}"
            f"{console._paint(rest, 'white', sys.stdout)} "
            f"{console._paint(marker, marker_color[marker], sys.stdout)} "
            f"{right_colored}"
        )
        console.plain(colored)
        return True

    return False


def _emit_line(out_fh: Any, emit_line: Callable[[str], None] | None, line: str) -> None:
    if out_fh is not None:
        out_fh.write(line + "\n")
        out_fh.flush()
    if emit_line is not None:
        emit_line(line)


def audit_zookeeper_targets(
    hosts: list[str],
    port: int,
    timeout: float,
    retries: int,
    workers: int,
    username: str | None,
    password: str | None,
    show_znodes: bool,
    dump: bool,
    query_znode: str | None,
    max_znodes: int,
    output_path: str | None,
    output_format: str,
    emit_line: Callable[[str], None] | None = None,
    logger: AttemptLogger | None = None,
    append_output: bool = False,
    suppress_connection_refused_status_lines: bool = False,
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

    try:
        with ThreadPoolExecutor(max_workers=max(1, workers)) as executor:
            future_map = {
                executor.submit(
                    _audit_zookeeper_host,
                    host,
                    port,
                    timeout,
                    retries,
                    username,
                    password,
                    show_znodes,
                    dump,
                    query_znode,
                    max_znodes,
                ): host
                for host in hosts
            }

            for future in iter_completed_with_progress(future_map, label="ZOOKEEPER"):
                record = future.result()
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

                if bool(record.get("is_zookeeper")):
                    _emit_line(out_fh, emit_line, _format_detect_record(record, output_format))

                suppress_auth_required_status_line = (
                    output_format == "txt"
                    and bool(record.get("is_zookeeper"))
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

                if bool(record.get("is_zookeeper")):
                    for detail in _format_znodes_detail_records(record, output_format):
                        _emit_line(out_fh, emit_line, detail)

                if logger is not None and not (
                    suppress_connection_refused_status_lines and _is_suppressed_fail_record(record)
                ):
                    logger.log(
                        "zookeeper",
                        (str(record.get("host") or "-"), int(record.get("port") or port)),
                        phase="audit",
                        status=record.get("status"),
                        auth_required=record.get("auth_required"),
                        provided_credentials_ok=record.get("provided_credentials_ok"),
                        znode_count=record.get("znode_count"),
                        error=record.get("error"),
                    )
    finally:
        if out_fh is not None:
            out_fh.close()

    return total, open_no_auth, valid, auth_required, failed


def run_zookeeper_stage(args: argparse.Namespace, logger: AttemptLogger) -> int:
    console = Console(debug=args.debug)

    if args.timeout <= 0:
        console.error("--timeout must be > 0")
        return 2
    if args.retries < 0:
        console.error("--retries must be >= 0")
        return 2
    if args.max_znodes <= 0:
        console.error("--max-znodes must be > 0")
        return 2
    if bool(args.username) != bool(args.password):
        console.error("--username and --password must be set together")
        return 2
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
        console.error("zookeeper requires -t/--targets")
        return 2

    stream_to_stdout = not bool(args.output)
    query_znode = _normalize_znode_path(getattr(args, "znode", None))
    show_znodes = bool(args.show_znodes)
    dump = bool(getattr(args, "dump", False))

    def emit_line(line: str) -> None:
        if args.output_format != "txt":
            print(line, flush=True)
            return
        if line.startswith("ZOOKEEPER") and all(token not in line for token in (" [*] ", " [+] ", " [-] ", " [!] ")):
            if console.render_tagged_payload_line(line, "ZOOKEEPER", payload_color="orange"):
                return
            console.plain(line, color="white")
            return
        if _render_colored_zookeeper_line(console, line):
            return
        if args.debug:
            console.plain(line)

    if args.debug and stream_to_stdout and args.output_format == "txt":
        mode_parts = ["count-znodes"]
        if args.username and args.password:
            mode_parts.append("provided-creds")
        if show_znodes:
            mode_parts.append("show-znodes")
        if dump:
            mode_parts.append("dump")
        if query_znode:
            mode_parts.append(f"znode={query_znode}")
        mode = "+".join(mode_parts)
        console.info(
            f"zookeeper audit started: hosts={len(hosts)} ports={len(ports)} timeout={args.timeout}s "
            f"workers={args.workers} retries={args.retries} max_znodes={args.max_znodes} "
            f"mode={mode} format=txt"
        )
    if args.debug and not stream_to_stdout:
        mode_parts = ["count-znodes"]
        if args.username and args.password:
            mode_parts.append("provided-creds")
        if show_znodes:
            mode_parts.append("show-znodes")
        if dump:
            mode_parts.append("dump")
        if query_znode:
            mode_parts.append(f"znode={query_znode}")
        mode = "+".join(mode_parts)
        console.info(
            f"zookeeper audit started: hosts={len(hosts)} ports={len(ports)} timeout={args.timeout}s "
            f"workers={args.workers} retries={args.retries} max_znodes={args.max_znodes} "
            f"mode={mode} format={args.output_format} output={args.output}"
        )

    total = 0
    open_no_auth = 0
    valid = 0
    auth_required = 0
    failed = 0
    try:
        for idx, audit_port in enumerate(ports):
            part_total, part_open, part_valid, part_auth, part_failed = audit_zookeeper_targets(
                hosts=hosts,
                port=audit_port,
                timeout=args.timeout,
                retries=args.retries,
                workers=args.workers,
                username=args.username,
                password=args.password,
                show_znodes=show_znodes,
                dump=dump,
                query_znode=query_znode,
                max_znodes=args.max_znodes,
                output_path=args.output,
                output_format=args.output_format,
                emit_line=emit_line,
                logger=logger if args.debug else None,
                append_output=idx > 0,
                suppress_connection_refused_status_lines=not bool(args.debug),
            )
            total += part_total
            open_no_auth += part_open
            valid += part_valid
            auth_required += part_auth
            failed += part_failed
    except OSError as exc:
        console.error(f"failed to process zookeeper output: {exc}")
        return 2

    if stream_to_stdout:
        if (
            total > 0
            and open_no_auth == 0
            and valid == 0
            and auth_required == 0
            and failed == total
            and args.output_format == "txt"
        ):
            console.warn(
                "all zookeeper targets are unreachable; check host/port, network reachability, and service status"
            )
        if args.debug and args.output_format == "txt":
            console.info(
                f"zookeeper audit complete: total={total} anonymous={open_no_auth} valid={valid} "
                f"auth_required={auth_required} fail={failed}"
            )
        return 0

    if args.debug:
        console.info(
            f"zookeeper audit complete: total={total} anonymous={open_no_auth} valid={valid} "
            f"auth_required={auth_required} fail={failed} "
            f"format={args.output_format} output={args.output}"
        )
    return 0
