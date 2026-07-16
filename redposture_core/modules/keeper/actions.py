"""ClickHouse Keeper host audit adapter over the ZooKeeper protocol audit."""

from __future__ import annotations

from dataclasses import replace
from typing import Any, Literal, cast

from ...clients.zookeeper import (
    ZkImplementationFingerprint,
    ZkTransportConfig,
    fingerprint_zookeeper_implementation,
)
from ..zookeeper import actions as zookeeper_actions
from .types import KeeperFingerprintCache


def _transport_config(
    *,
    tls: bool,
    no_tls: bool,
    insecure: bool,
    ca_file: str | None,
    tls_cert: str | None,
    tls_key: str | None,
) -> ZkTransportConfig:
    mode: Literal["auto", "plaintext", "tls"] = "tls" if tls else "plaintext" if no_tls else "auto"
    return ZkTransportConfig(
        mode=mode,
        insecure=bool(insecure),
        ca_file=str(ca_file).strip() if ca_file else None,
        cert_file=str(tls_cert).strip() if tls_cert else None,
        key_file=str(tls_key).strip() if tls_key else None,
    )


def _fingerprint_errors(fingerprint: ZkImplementationFingerprint) -> dict[str, str]:
    return {command: str(result.error) for command, result in sorted(fingerprint.responses.items()) if result.error}


def _audit_keeper_host(
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
    debug: bool,
    run_deep_checks: bool,
    enum_workers: int,
    debug_emit: Any,
    tls: bool,
    no_tls: bool,
    insecure: bool,
    ca_file: str | None,
    tls_cert: str | None,
    tls_key: str | None,
    keeper_probe_cache: KeeperFingerprintCache,
    dump_limit: int | None = None,
) -> dict[str, Any]:
    config = _transport_config(
        tls=tls,
        no_tls=no_tls,
        insecure=insecure,
        ca_file=ca_file,
        tls_cert=tls_cert,
        tls_key=tls_key,
    )
    transport_cache_key = (
        str(host),
        int(port),
        config.mode,
        bool(config.insecure),
        config.ca_file,
        config.cert_file,
        config.key_file,
    )
    cached_transport = keeper_probe_cache.get_transport(transport_cache_key)
    audit_config = replace(config, mode=cached_transport) if cached_transport is not None else config
    # The normal command runner always performs detect before deep checks. Keep
    # the adapter safe when called directly as well: fingerprint first, then
    # allow znode/capability probes only for Keeper or an unknown compatible
    # implementation.
    initial_deep_checks = bool(run_deep_checks and cached_transport is not None)

    previous_emitter = getattr(zookeeper_actions._THREAD_LOCAL_DEBUG_EMIT, "callback", None)
    if debug_emit is not None:
        zookeeper_actions._THREAD_LOCAL_DEBUG_EMIT.callback = debug_emit
    try:
        record = zookeeper_actions._audit_zookeeper_host(
            host=host,
            port=port,
            timeout=timeout,
            retries=retries,
            username=username,
            password=password,
            show_znodes=show_znodes,
            dump=dump,
            query_znode=query_znode,
            max_znodes=max_znodes,
            debug=debug,
            run_deep_checks=initial_deep_checks,
            enum_workers=enum_workers,
            dump_limit=dump_limit,
            transport_config=audit_config,
        )
    finally:
        if previous_emitter is not None:
            zookeeper_actions._THREAD_LOCAL_DEBUG_EMIT.callback = previous_emitter
        else:
            try:
                delattr(zookeeper_actions._THREAD_LOCAL_DEBUG_EMIT, "callback")
            except AttributeError:
                pass

    compatible = bool(record.get("is_zookeeper"))
    record.update(
        {
            "service": "zookeeper-compatible",
            "protocol": "zookeeper",
            "is_zookeeper_compatible": compatible,
            "is_keeper": None,
            "fingerprint_confidence": "unconfirmed",
            "version": None,
            "server_state": None,
            "read_only": None,
            "connections": None,
            "latency_ms": {"min": None, "avg": None, "max": None},
            "raft": {},
            "quorum_status": "unknown",
            "fingerprint_errors": {},
        }
    )
    if not compatible:
        return record

    selected_transport = cast(Literal["plaintext", "tls"], str(record.get("transport") or "plaintext"))
    fixed_config = replace(config, mode=selected_transport)
    cache_key = (
        str(host),
        int(port),
        selected_transport,
        bool(config.insecure),
        config.ca_file,
        config.cert_file,
        config.key_file,
    )
    fingerprint = keeper_probe_cache.get_or_probe(
        cache_key,
        lambda: fingerprint_zookeeper_implementation(
            host,
            port,
            timeout,
            transport=selected_transport,
            config=fixed_config,
        ),
    )
    keeper_probe_cache.remember_transport(transport_cache_key, selected_transport)

    if run_deep_checks and not initial_deep_checks and fingerprint.is_keeper is not False:
        record = zookeeper_actions._audit_zookeeper_host(
            host=host,
            port=port,
            timeout=timeout,
            retries=retries,
            username=username,
            password=password,
            show_znodes=show_znodes,
            dump=dump,
            query_znode=query_znode,
            max_znodes=max_znodes,
            debug=debug,
            run_deep_checks=True,
            enum_workers=enum_workers,
            dump_limit=dump_limit,
            transport_config=fixed_config,
        )
    record.update(
        {
            "service": fingerprint.implementation,
            "is_keeper": fingerprint.is_keeper,
            "fingerprint_confidence": fingerprint.confidence,
            "version": fingerprint.version,
            "server_state": fingerprint.server_state,
            "read_only": fingerprint.read_only,
            "connections": fingerprint.connections,
            "latency_ms": dict(fingerprint.latency_ms),
            "raft": dict(fingerprint.raft),
            "quorum_status": fingerprint.quorum_status,
            "fingerprint_errors": _fingerprint_errors(fingerprint),
        }
    )
    if fingerprint.is_keeper is False:
        record["status"] = "not_keeper"
        record["error"] = "Apache ZooKeeper fingerprint; ClickHouse Keeper not detected"
    return record


# Typed runner boundary -----------------------------------------------------
host_stage = _audit_keeper_host

__all__ = ["host_stage", "_audit_keeper_host", "_transport_config"]
