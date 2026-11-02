"""Reuse only fully authenticated PostgreSQL sessions with the exact identity."""

from __future__ import annotations

import socket
import ssl
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import Any

from ...clients.session_handoff import SessionHandoff


def session_key(host: str, port: int, username: str, password: str | None, database: str, tls: Any) -> tuple[Any, ...]:
    return host, int(port), username, password, database, tls


def idle_socket_alive(sock: socket.socket, timeout: float) -> bool:
    if not isinstance(sock, socket.socket):
        return False
    try:
        sock.setblocking(False)
        sock.recv(1)
        return False
    except (BlockingIOError, ssl.SSLWantReadError):
        return True
    except OSError:
        return False
    finally:
        try:
            sock.settimeout(timeout)
        except OSError:
            pass


@contextmanager
def session_scope(
    host: str,
    port: int,
    timeout: float,
    *,
    username: str,
    password: str | None,
    database: str,
    tls_config: Any,
    cache: SessionHandoff | None = None,
    reuse: bool = False,
    retain: bool | Callable[[], bool] = False,
) -> Iterator[tuple[Any, Any]]:
    from . import actions

    key = session_key(host, port, username, password, database, tls_config)
    lease = cache.take(key) if cache is not None and reuse else None
    if lease is not None and not idle_socket_alive(lease.value[0], timeout):
        assert cache is not None
        cache.finish(lease)
        lease = None
    manager = None
    if lease is None:
        manager = actions._pg_open_socket(host, port, timeout, tls_config=tls_config)
        sock = manager.__enter__()

        def close() -> None:
            try:
                actions._pg_send_terminate(sock)
            except Exception:
                pass
            manager.__exit__(None, None, None)

        try:
            lease = cache.track(key, (sock, None), close) if cache is not None else None
            session = actions._pg_startup_and_auth(sock, username=username, password=password, database=database)
            if lease is not None:
                lease.value = (sock, session)
        except BaseException:
            if lease is not None:
                assert cache is not None
                cache.finish(lease)
            else:
                close()
            raise
    else:
        sock, session = lease.value
    completed = False
    try:
        yield sock, session
        completed = True
    finally:
        if lease is not None and cache is not None:
            cache.finish(lease, keep=completed and (retain() if callable(retain) else retain))
        else:
            try:
                actions._pg_send_terminate(sock)
            except Exception:
                pass
            if manager is not None:
                manager.__exit__(None, None, None)
