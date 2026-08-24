"""Bounded, process-wide cache for immutable client TLS contexts."""

from __future__ import annotations

import os
import ssl
import threading
from collections import OrderedDict
from dataclasses import dataclass

_TLS_CONTEXT_CACHE_SIZE = 64


@dataclass(frozen=True)
class _FileIdentity:
    path: str
    mtime_ns: int
    size: int


@dataclass(frozen=True)
class TlsContextKey:
    insecure: bool
    check_hostname: bool
    ca_file: _FileIdentity | None
    cert_file: _FileIdentity | None
    key_file: _FileIdentity | None
    alpn: tuple[str, ...]


def _file_identity(path: str | None) -> _FileIdentity | None:
    value = str(path or "").strip()
    if not value:
        return None
    realpath = os.path.realpath(value)
    try:
        stat = os.stat(realpath)
    except OSError:
        return _FileIdentity(realpath, -1, -1)
    return _FileIdentity(realpath, int(stat.st_mtime_ns), int(stat.st_size))


_CACHE: OrderedDict[TlsContextKey, ssl.SSLContext] = OrderedDict()
_CACHE_LOCK = threading.Lock()
_CACHE_HITS = 0
_CACHE_MISSES = 0


def shared_client_ssl_context(
    *,
    insecure: bool,
    ca_file: str | None = None,
    cert_file: str | None = None,
    key_file: str | None = None,
    alpn: tuple[str, ...] = (),
    check_hostname: bool = True,
) -> ssl.SSLContext:
    """Return a fully configured context that callers must not mutate."""

    if key_file and not cert_file:
        raise ValueError("TLS client key requires a certificate")
    key = TlsContextKey(
        insecure=bool(insecure),
        check_hostname=bool(check_hostname and not insecure),
        ca_file=None if insecure else _file_identity(ca_file),
        cert_file=_file_identity(cert_file),
        key_file=_file_identity(key_file),
        alpn=tuple(str(item) for item in alpn if str(item)),
    )
    global _CACHE_HITS, _CACHE_MISSES
    # Context construction loads and parses the platform trust store.  Keep it
    # inside the cache lock so a cold concurrent scan cannot create the same
    # expensive context once per target worker before any of them publishes it.
    with _CACHE_LOCK:
        cached = _CACHE.get(key)
        if cached is not None:
            _CACHE.move_to_end(key)
            _CACHE_HITS += 1
            return cached

        if key.insecure:
            context = ssl._create_unverified_context()
        elif ca_file:
            context = ssl.create_default_context(cafile=str(ca_file))
        else:
            context = ssl.create_default_context()
        if key.cert_file is not None:
            try:
                context.load_cert_chain(certfile=str(cert_file), keyfile=str(key_file) if key_file else None)
            except TypeError:
                context.load_cert_chain(str(cert_file), str(key_file) if key_file else None)
        if hasattr(context, "check_hostname"):
            context.check_hostname = key.check_hostname
        if key.insecure and hasattr(context, "verify_mode"):
            context.verify_mode = ssl.CERT_NONE
        if key.alpn:
            context.set_alpn_protocols(list(key.alpn))

        _CACHE[key] = context
        _CACHE_MISSES += 1
        while len(_CACHE) > _TLS_CONTEXT_CACHE_SIZE:
            _CACHE.popitem(last=False)
    return context


def tls_context_cache_stats() -> dict[str, int]:
    with _CACHE_LOCK:
        return {"size": len(_CACHE), "hits": _CACHE_HITS, "misses": _CACHE_MISSES}


def clear_tls_context_cache() -> None:
    global _CACHE_HITS, _CACHE_MISSES
    with _CACHE_LOCK:
        _CACHE.clear()
        _CACHE_HITS = 0
        _CACHE_MISSES = 0


__all__ = ["clear_tls_context_cache", "shared_client_ssl_context", "tls_context_cache_stats"]
