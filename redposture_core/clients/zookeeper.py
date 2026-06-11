"""ZooKeeper protocol client helpers."""

from __future__ import annotations

import base64
import socket
import struct
import threading
import time
from collections import deque
from collections.abc import Callable
from queue import Empty, Queue
from typing import Any

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
_ZK_ERR_RETRYABLE_ROOT_QUERY = -124
_ZK_ERR_NODEEXISTS = -110
_ZK_MAX_FRAME = 64 * 1024 * 1024
_ZK_SYSTEM_PREFIX = "/zookeeper"
_ZK_ACL_ALL_PERMS = 0x1F
_ZK_CREATE_EPHEMERAL = 1
_ZK_AUTH_XID = -4
_ZK_ENUM_PROGRESS_INTERVAL_SECONDS = 2.0
_CONNECTION_REFUSED_PREFIX = "connection refused"
_CONNECTION_TIMEOUT_PREFIX = "connection timeout"
_UNEXPECTED_EOF_PREFIX = "unexpected eof"
_ROOT_QUERY_ERR_124_PREFIX = "root query failed: err_-124"


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


def _encode_acl_world_anyone_all() -> bytes:
    # ACL vector with one entry: world:anyone + all permissions.
    return (
        struct.pack(">i", 1)
        + struct.pack(">i", _ZK_ACL_ALL_PERMS)
        + _encode_zk_string("world")
        + _encode_zk_string("anyone")
    )


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
        )

    queue = deque(["/"])
    visited: set[str] | None = {"/"} if collect_paths else None
    listed_nodes: list[str] = []
    listed_meta: dict[str, dict[str, Any]] = {}
    total_count = 0
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
                total_count > len(listed_nodes),
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
            if parent_meta is not None:
                parent_meta["error"] = "Access Denied"
            continue
        if err != _ZK_ERR_OK:
            if parent_meta is not None:
                parent_meta["error"] = _zk_error_name(err)
            return (
                listed_nodes,
                total_count,
                total_count > len(listed_nodes),
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
            if _is_system_znode(full_path):
                continue
            if visited is not None:
                if full_path in visited:
                    continue
                visited.add(full_path)
            total_count += 1
            if collect_paths and len(listed_nodes) < max_znodes:
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

    truncated = (total_count > len(listed_nodes)) if collect_paths else False
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
) -> tuple[list[str], int, bool, dict[str, dict[str, Any]], str | None]:
    worker_count = max(1, int(enum_workers))
    task_queue: Queue[str | None] = Queue()
    result_queue: Queue[dict[str, Any]] = Queue()
    stop_event = threading.Event()

    queue_set: set[str] | None = {"/"} if collect_paths else None
    listed_nodes: list[str] = []
    listed_meta: dict[str, dict[str, Any]] = {}
    total_count = 0
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

    def _worker() -> None:
        client: _ZkClient | None = None
        try:
            client = _ZkClient(host, port, timeout)
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
        except (TimeoutError, ConnectionError, OSError, ValueError) as exc:
            result_queue.put(
                {
                    "kind": "worker_error",
                    "error": _friendly_error_from_exception(exc),
                }
            )
        finally:
            if client is not None:
                client.close()

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

            err = int(item.get("err")) if item.get("err") is not None else _ZK_ERR_OK
            children = item.get("children")
            stat = item.get("stat")
            parent_meta = listed_meta.get(parent) if collect_paths else None

            if err == _ZK_ERR_NONODE:
                if parent_meta is not None:
                    parent_meta["error"] = "not found"
                _emit_progress(time.monotonic())
                continue
            if err == _ZK_ERR_NOAUTH:
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
                if _is_system_znode(full_path):
                    continue
                if queue_set is not None:
                    if full_path in queue_set:
                        continue
                    queue_set.add(full_path)
                total_count += 1
                if collect_paths and len(listed_nodes) < max_znodes:
                    listed_nodes.append(full_path)
                    listed_meta[full_path] = {"path": full_path, "children": None, "bytes": None, "error": None}
                in_flight += 1
                task_queue.put(full_path)

            _emit_progress(time.monotonic())
    finally:
        stop_event.set()
        for _ in range(worker_count):
            task_queue.put(None)
        for thread in threads:
            thread.join(timeout=1.0)

    truncated = (total_count > len(listed_nodes)) if collect_paths else False
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
    base_name = f"/redposture_probe_{host.replace('.', '_')}_{port}_{int(time.time() * 1000)}"
    try:
        for index in range(3):
            probe_path = base_name if index == 0 else f"{base_name}_{index}"
            create_err = int(client.create(probe_path))
            if create_err == _ZK_ERR_NODEEXISTS:
                continue
            if create_err != _ZK_ERR_OK:
                return False, False, _zk_error_name(create_err)

            delete_err = int(client.delete(probe_path, -1))
            if delete_err == _ZK_ERR_OK:
                return True, True, None
            return True, False, _zk_error_name(delete_err)
    except AttributeError:
        return None, None, "capability probe unsupported"
    except (TimeoutError, ConnectionError, OSError, ValueError) as exc:
        return None, None, _friendly_error_from_exception(exc)

    return False, False, "NODEEXISTS"


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
