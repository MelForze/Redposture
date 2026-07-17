"""ClickHouse Keeper host audit adapter over the ZooKeeper protocol audit."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from typing import Any, Literal, cast

from ...clients.zookeeper import (
    ZkImplementationFingerprint,
    ZkTransportConfig,
    fingerprint_zookeeper_implementation,
)
from ..zookeeper import actions as zookeeper_actions
from .types import KeeperFingerprintCache

_STAGE_DETECT_PROTOCOL = "detect_protocol"
_STAGE_AUTH_INFERENCE = "auth_inference_credentials"

_ZOOKEEPER_TELEMETRY_FIELDS = (
    "attempts",
    "max_attempts",
    "stages",
    "stage_failed_at",
    "stage_durations_ms",
    "stage_attempts",
    "debug_events",
    "debug_events_streamed",
    "connect_error",
)


@dataclass
class KeeperLifecycleState:
    requested_config: ZkTransportConfig
    zookeeper_state: zookeeper_actions.ZooKeeperLifecycleState = field(
        default_factory=zookeeper_actions.ZooKeeperLifecycleState
    )
    fingerprint: ZkImplementationFingerprint | None = None

    def close(self) -> None:
        self.zookeeper_state.close()


def _transport_config(
    *,
    insecure: bool,
    ca_file: str | None,
    tls_cert: str | None,
    tls_key: str | None,
) -> ZkTransportConfig:
    return ZkTransportConfig(
        mode="auto",
        insecure=bool(insecure),
        ca_file=str(ca_file).strip() if ca_file else None,
        cert_file=str(tls_cert).strip() if tls_cert else None,
        key_file=str(tls_key).strip() if tls_key else None,
    )


def _fingerprint_errors(fingerprint: ZkImplementationFingerprint) -> dict[str, str]:
    return {command: str(result.error) for command, result in sorted(fingerprint.responses.items()) if result.error}


def _decorate_keeper_record(
    record: dict[str, Any],
    fingerprint: ZkImplementationFingerprint,
) -> dict[str, Any]:
    record.update(
        {
            "service": fingerprint.implementation,
            "protocol": "zookeeper",
            "is_zookeeper_compatible": bool(record.get("is_zookeeper")),
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
        raw_durations = record.get("stage_durations_ms")
        prior_durations = dict(raw_durations) if isinstance(raw_durations, dict) else {}
        detect_duration = max(0, int(prior_durations.get(_STAGE_DETECT_PROTOCOL, 0) or 0))
        auth_duration = max(0, int(prior_durations.get(_STAGE_AUTH_INFERENCE, 0) or 0))
        record.update(
            {
                # A positive ZooKeeper protocol detect followed by a rejected
                # Keeper fingerprint is the complete negative-control path.
                # It must not acquire synthetic deep stages afterwards.
                "stages": [
                    {
                        "stage_name": _STAGE_DETECT_PROTOCOL,
                        "attempt": 1,
                        "duration_ms": detect_duration,
                        "result": "ok",
                        "error": None,
                    },
                    {
                        "stage_name": _STAGE_AUTH_INFERENCE,
                        "attempt": 1,
                        "duration_ms": auth_duration,
                        "result": "ok",
                        "error": None,
                    },
                ],
                "stage_failed_at": None,
                "stage_durations_ms": {
                    _STAGE_DETECT_PROTOCOL: detect_duration,
                    _STAGE_AUTH_INFERENCE: auth_duration,
                },
                "stage_attempts": {
                    _STAGE_DETECT_PROTOCOL: 1,
                    _STAGE_AUTH_INFERENCE: 1,
                },
            }
        )
    return record


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
    insecure: bool,
    ca_file: str | None,
    tls_cert: str | None,
    tls_key: str | None,
    keeper_probe_cache: KeeperFingerprintCache,
    dump_limit: int | None = None,
) -> dict[str, Any]:
    config = _transport_config(
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
    return _decorate_keeper_record(record, fingerprint)


def _keeper_detection_payload(
    ctx: Any,
    options: Mapping[str, Any],
    *,
    status: str,
    auth_required: bool | None,
    transport: str | None,
    fingerprint: ZkImplementationFingerprint | None,
    error: str | None = None,
) -> dict[str, Any]:
    detected = status not in {"fail", "not_keeper"}
    payload = {
        "timestamp": zookeeper_actions.utc_now_iso(),
        "host": str(ctx.host),
        "port": int(ctx.port),
        "service": fingerprint.implementation if fingerprint is not None else "zookeeper-compatible",
        "protocol": "zookeeper",
        "is_zookeeper": detected,
        "is_zookeeper_compatible": detected,
        "is_keeper": fingerprint.is_keeper if fingerprint is not None else None,
        "fingerprint_confidence": fingerprint.confidence if fingerprint is not None else "unconfirmed",
        "version": fingerprint.version if fingerprint is not None else None,
        "server_state": fingerprint.server_state if fingerprint is not None else None,
        "read_only": fingerprint.read_only if fingerprint is not None else None,
        "connections": fingerprint.connections if fingerprint is not None else None,
        "latency_ms": dict(fingerprint.latency_ms) if fingerprint is not None else {},
        "raft": dict(fingerprint.raft) if fingerprint is not None else {},
        "quorum_status": fingerprint.quorum_status if fingerprint is not None else "unknown",
        "fingerprint_errors": _fingerprint_errors(fingerprint) if fingerprint is not None else {},
        "status": status,
        "auth_required": auth_required,
        "provided_credentials": False,
        "provided_username": None,
        "provided_password": None,
        "provided_credentials_ok": None,
        "credential_verdict": None,
        "show_znodes": bool(options["show_znodes"]),
        "dump": bool(options["dump"]),
        "dump_limit": options["dump_limit"],
        "query_znode": options["query_znode"],
        "max_znodes": int(options["max_znodes"]),
        "znode_count": None,
        "znodes": None,
        "znode_details": None,
        "znode_values": None,
        "znodes_truncated": False,
        "query_znode_value": None,
        "query_znode_dump": None,
        "query_znode_dump_error": None,
        "can_create_znode": None,
        "can_delete_znode": None,
        "znode_capability_error": None,
        "auth_inference_source": "anonymous_root",
        "auth_probe_trace": [],
        "transport": transport,
        "error": error,
    }
    if fingerprint is not None and fingerprint.is_keeper is False:
        payload["status"] = "not_keeper"
        payload["is_keeper"] = False
        payload["error"] = "Apache ZooKeeper fingerprint; ClickHouse Keeper not detected"
    return payload


def detect_keeper(ctx: Any, options: Mapping[str, Any]) -> dict[str, Any]:
    state = ctx.lifecycle_state
    if not isinstance(state, KeeperLifecycleState):
        raise TypeError("keeper lifecycle state is unavailable")
    zookeeper_options = {**options, "transport_config": state.requested_config}
    zookeeper_ctx = replace(ctx, lifecycle_state=state.zookeeper_state)
    record = zookeeper_actions.detect_zookeeper(zookeeper_ctx, zookeeper_options)
    if not bool(record.get("is_zookeeper")):
        payload = _keeper_detection_payload(
            ctx,
            options,
            status=str(record.get("status") or "fail"),
            auth_required=record.get("auth_required"),
            transport=None,
            fingerprint=None,
            error=str(record.get("error") or "") or None,
        )
        for field_name in _ZOOKEEPER_TELEMETRY_FIELDS:
            if field_name in record:
                payload[field_name] = record[field_name]
        return payload

    selected_config = state.zookeeper_state.selected_transport_config
    selected_transport = (
        selected_config.mode
        if selected_config is not None and selected_config.mode in {"plaintext", "tls"}
        else "plaintext"
    )
    fingerprint = options["keeper_probe_cache"].get_or_probe(
        (
            str(ctx.host),
            int(ctx.port),
            selected_transport,
            bool(state.requested_config.insecure),
            state.requested_config.ca_file,
            state.requested_config.cert_file,
            state.requested_config.key_file,
        ),
        lambda selected=selected_transport: fingerprint_zookeeper_implementation(
            str(ctx.host),
            int(ctx.port),
            float(getattr(ctx.args, "timeout", 5.0)),
            transport=selected,
            config=selected_config or replace(state.requested_config, mode=selected),
        ),
    )
    state.fingerprint = fingerprint
    record["transport"] = selected_transport
    return _decorate_keeper_record(record, fingerprint)


def authenticate_keeper(ctx: Any, detect_record: Any, options: Mapping[str, Any]) -> dict[str, Any]:
    state = ctx.lifecycle_state
    if not isinstance(state, KeeperLifecycleState):
        raise TypeError("keeper lifecycle state is unavailable")
    fingerprint = state.fingerprint
    if fingerprint is None or fingerprint.is_keeper is False:
        return dict(detect_record.to_dict() if hasattr(detect_record, "to_dict") else detect_record)
    zookeeper_ctx = replace(ctx, lifecycle_state=state.zookeeper_state)
    result = zookeeper_actions.authenticate_zookeeper(zookeeper_ctx, detect_record, options)
    return _decorate_keeper_record(result, fingerprint)


def collect_keeper_data(ctx: Any, record: Any, options: Mapping[str, Any]) -> dict[str, Any]:
    state = ctx.lifecycle_state
    if not isinstance(state, KeeperLifecycleState):
        raise TypeError("keeper lifecycle state is unavailable")
    fingerprint = state.fingerprint
    if fingerprint is None or fingerprint.is_keeper is False:
        return dict(record.to_dict() if hasattr(record, "to_dict") else record)
    zookeeper_ctx = replace(ctx, lifecycle_state=state.zookeeper_state)
    result = zookeeper_actions.collect_zookeeper_data(zookeeper_ctx, record, options)
    return _decorate_keeper_record(result, fingerprint)


# Typed runner boundary -----------------------------------------------------
host_stage = _audit_keeper_host

__all__ = [
    "host_stage",
    "KeeperLifecycleState",
    "_audit_keeper_host",
    "_transport_config",
    "authenticate_keeper",
    "collect_keeper_data",
    "detect_keeper",
]
