"""Canonical ZooKeeper/Keeper implementation orchestration engine."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from typing import Any

from ...clients.zookeeper import (
    ZkImplementationFingerprint,
    ZkTransportConfig,
    fingerprint_zookeeper_implementation,
)
from . import actions as zookeeper_actions

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
class ZooKeeperImplementationLifecycleState:
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


def _canonical_implementation_fields(fingerprint: ZkImplementationFingerprint) -> dict[str, Any]:
    vendor = "clickhouse" if fingerprint.is_keeper is True else "apache" if fingerprint.is_keeper is False else None
    return {
        "implementation": fingerprint.implementation,
        "implementation_confidence": "confirmed" if fingerprint.is_keeper is not None else "unconfirmed",
        "vendor": vendor,
    }


def _decorate_implementation_record(
    record: dict[str, Any],
    fingerprint: ZkImplementationFingerprint,
) -> dict[str, Any]:
    record.update(
        {
            "service": "zookeeper",
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
    record.update(_canonical_implementation_fields(fingerprint))
    return record


def _implementation_detection_payload(
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
        "service": "zookeeper",
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
        "credential_verification_requested": False,
        "credential_verification_status": "not_requested",
        "credential_verification_path": None,
        "credential_verification_reason": None,
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
        "probe_write_requested": bool(options.get("probe_write", False)),
        "znode_capability_scope": "/" if bool(options.get("probe_write", False)) else None,
        "znode_capability_identity": None,
        "auth_inference_source": "anonymous_root",
        "auth_probe_trace": [],
        "transport": transport,
        "error": error,
    }
    payload.update(
        {
            "implementation": fingerprint.implementation if fingerprint is not None else None,
            "implementation_confidence": "confirmed"
            if fingerprint is not None and fingerprint.is_keeper is not None
            else "unconfirmed",
            "vendor": "clickhouse"
            if fingerprint is not None and fingerprint.is_keeper is True
            else "apache"
            if fingerprint is not None and fingerprint.is_keeper is False
            else None,
        }
    )
    return payload


def detect_zookeeper_implementation(ctx: Any, options: Mapping[str, Any]) -> dict[str, Any]:
    state = ctx.lifecycle_state
    if not isinstance(state, ZooKeeperImplementationLifecycleState):
        raise TypeError("ZooKeeper implementation lifecycle state is unavailable")
    zookeeper_options = {**options, "transport_config": state.requested_config}
    zookeeper_ctx = replace(ctx, lifecycle_state=state.zookeeper_state)
    record = zookeeper_actions.detect_zookeeper(zookeeper_ctx, zookeeper_options)
    if not bool(record.get("is_zookeeper")):
        payload = _implementation_detection_payload(
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
    fingerprint = options["fingerprint_cache"].get_or_probe(
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
    return _decorate_implementation_record(record, fingerprint)


def authenticate_zookeeper_implementation(
    ctx: Any,
    detect_record: Any,
    options: Mapping[str, Any],
) -> dict[str, Any]:
    state = ctx.lifecycle_state
    if not isinstance(state, ZooKeeperImplementationLifecycleState):
        raise TypeError("ZooKeeper implementation lifecycle state is unavailable")
    fingerprint = state.fingerprint
    if fingerprint is None:
        return dict(detect_record.to_dict() if hasattr(detect_record, "to_dict") else detect_record)
    zookeeper_ctx = replace(ctx, lifecycle_state=state.zookeeper_state)
    result = zookeeper_actions.authenticate_zookeeper(zookeeper_ctx, detect_record, options)
    return _decorate_implementation_record(result, fingerprint)


def collect_zookeeper_implementation_data(
    ctx: Any,
    record: Any,
    options: Mapping[str, Any],
) -> dict[str, Any]:
    state = ctx.lifecycle_state
    if not isinstance(state, ZooKeeperImplementationLifecycleState):
        raise TypeError("ZooKeeper implementation lifecycle state is unavailable")
    fingerprint = state.fingerprint
    if fingerprint is None:
        return dict(record.to_dict() if hasattr(record, "to_dict") else record)
    zookeeper_ctx = replace(ctx, lifecycle_state=state.zookeeper_state)
    result = zookeeper_actions.collect_zookeeper_data(zookeeper_ctx, record, options)
    return _decorate_implementation_record(result, fingerprint)


def probe_zookeeper_implementation_capabilities(
    ctx: Any,
    record: Any,
    options: Mapping[str, Any],
) -> dict[str, Any]:
    state = ctx.lifecycle_state
    if not isinstance(state, ZooKeeperImplementationLifecycleState):
        raise TypeError("ZooKeeper implementation lifecycle state is unavailable")
    zookeeper_ctx = replace(ctx, lifecycle_state=state.zookeeper_state)
    result = zookeeper_actions.probe_zookeeper_capabilities(zookeeper_ctx, record, options)
    if state.fingerprint is None:
        return result
    return _decorate_implementation_record(result, state.fingerprint)


__all__ = [
    "ZooKeeperImplementationLifecycleState",
    "_transport_config",
    "detect_zookeeper_implementation",
    "authenticate_zookeeper_implementation",
    "collect_zookeeper_implementation_data",
    "probe_zookeeper_implementation_capabilities",
]
