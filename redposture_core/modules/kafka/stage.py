"""Runtime entrypoint for the kafka audit module."""

from __future__ import annotations

from dataclasses import replace
from typing import Any

from ...audit_config import AuditConfig
from ...audit_models import AuditRecord
from ...clients.kafka import KafkaTlsConfig
from ...console import Console
from ...show_limits import dump_flag_enabled, dump_flag_limit, show_flag_enabled, show_flag_limit
from ...stage_runtime import (
    AuditCommandPlan,
    AuditCommandRunner,
    AuditCredentialRun,
    AuditHookContext,
    ModuleAuditSpec,
    build_basic_audit_plan,
    command_result_exit_code,
    merge_audit_credential_runs,
    sort_default_audit_credential_runs,
)
from . import actions, policy, render

_DEFAULT_PORT = 9092
# 9093 = the well-known Kafka SASL_SSL / SSL listener. Many production
# clusters expose plaintext SASL_PLAINTEXT on 9092 and TLS-wrapped
# SASL_SSL on 9093 side-by-side, and users often only have 9093 exposed
# externally. Adding it to the default scan set means `redposture kafka -t
# <host>` covers both listeners without extra flags.
#
# TLS listeners are auto-detected: `open_kafka_socket` opens 9093 as TLS by
# default, and `_recv_kafka_frame` recognises the TLS record prelude
# (0x14/0x15/0x16/0x17 + 0x03) on any port and triggers a retry with
# `wrap_socket`. See `_is_tls_record_prelude` and `_TlsProbeError` in
# `redposture_core/clients/kafka.py`; the transport used ends up as the
# `transport_mode` field on the audit record, rendered as `(transport:tls)`
# in text output — same convention as docker/grpc/oracle.
_DEFAULT_PORTS: tuple[int, ...] | None = (9092, 9093, 19092, 19093, 29092, 29093)
_PRODUCTION_HOST_STAGE = actions.host_stage
_PRODUCTION_AUDIT_HOST = actions._audit_kafka_host


def build_kafka_plan(args: Any) -> AuditCommandPlan:
    plan = build_basic_audit_plan(args, default_port=_DEFAULT_PORT, default_ports=_DEFAULT_PORTS)
    default_runs = (
        sort_default_audit_credential_runs(
            AuditCredentialRun(username=username, password=password, source="default")
            for username, password in actions._build_credential_runs(None, None, True)
            if username is not None and password is not None
        )
        if bool(getattr(args, "defcreds", False))
        else ()
    )
    return replace(
        plan,
        credential_runs=merge_audit_credential_runs(plan.credential_runs, default_runs),
    )


def _build_kafka_lifecycle_options(args: Any) -> dict[str, Any]:
    dump = dump_flag_enabled(getattr(args, "dump", False))
    dump_limit = dump_flag_limit(getattr(args, "dump", False))
    explicit_max = getattr(args, "max_messages", None)
    max_messages = int(explicit_max if explicit_max is not None else dump_limit if dump_limit is not None else 10)
    return {
        "show_topics": show_flag_enabled(getattr(args, "show_topics", False)),
        "show_topics_limit": show_flag_limit(getattr(args, "show_topics", False)),
        "query_topic": str(getattr(args, "topic", None) or getattr(args, "query_topic", None) or "").strip() or None,
        "dump": dump,
        "max_messages": max_messages,
        "max_messages_explicit": explicit_max is not None or dump_limit is not None,
        "probe_write": bool(getattr(args, "probe_write", False)),
    }


def _kafka_credential_gate(credential: AuditCredentialRun, record: AuditRecord) -> tuple[bool, str]:
    """Only select a credential after Kafka has verified that identity."""

    has_credentials = credential.username is not None or credential.password is not None
    if not has_credentials:
        accepted = str(record.status or "") in {
            "open_no_auth",
            "valid_credentials",
            "weak_default_creds",
            "invalid_credentials_anonymous",
        }
        return accepted, f"status={record.status}"
    verified = record.extra.get("provided_credentials_ok") is True or str(record.status or "") in {
        "valid_credentials",
        "weak_default_creds",
    }
    return verified, "kafka credential verified" if verified else "kafka credential rejected or unverified"


def build_kafka_spec(args: Any) -> ModuleAuditSpec:
    full_credential_sweep = bool(getattr(args, "defcreds", False))
    options = _build_kafka_lifecycle_options(args)
    resolved_host_stage = getattr(actions, _PRODUCTION_HOST_STAGE.__name__, _PRODUCTION_HOST_STAGE)
    use_lifecycle_hooks = (
        actions.host_stage is _PRODUCTION_HOST_STAGE
        and resolved_host_stage is _PRODUCTION_HOST_STAGE
        and actions._audit_kafka_host is _PRODUCTION_AUDIT_HOST
    )

    def _state_factory(ctx: AuditHookContext) -> actions.KafkaLifecycleState:
        target_scheme = str(getattr(getattr(ctx, "target", None), "scheme", "") or "").lower()
        tls_material = any(
            (
                bool(getattr(args, "insecure", False)),
                bool(getattr(args, "tls_ca", None)),
                bool(getattr(args, "tls_cert", None)),
                bool(getattr(args, "tls_server_name", None)),
            )
        )
        if bool(getattr(args, "plaintext", False)):
            requested_use_tls: bool | None = False
        elif (
            bool(getattr(args, "tls", False))
            or tls_material
            or target_scheme
            in {
                "kafka+ssl",
                "kafkas",
                "ssl",
                "tls",
            }
        ):
            requested_use_tls = True
        else:
            requested_use_tls = None
        tls_config = KafkaTlsConfig(
            insecure=bool(getattr(args, "insecure", False)) or requested_use_tls is None,
            ca_file=getattr(args, "tls_ca", None),
            cert_file=getattr(args, "tls_cert", None),
            key_file=getattr(args, "tls_key", None),
            server_name=str(getattr(args, "tls_server_name", "") or "").strip() or None,
        )
        return actions.KafkaLifecycleState(
            requested_use_tls=requested_use_tls,
            tls_config=tls_config,
        )

    def _detect(ctx: AuditHookContext) -> AuditRecord:
        return AuditRecord.from_mapping(actions.detect_kafka(ctx, options), module="kafka", service="kafka")

    def _auth(ctx: AuditHookContext, record: AuditRecord) -> AuditRecord:
        return AuditRecord.from_mapping(
            actions.authenticate_kafka(ctx, record, options),
            module="kafka",
            service="kafka",
        )

    def _data(ctx: AuditHookContext, record: AuditRecord) -> AuditRecord:
        return AuditRecord.from_mapping(
            actions.collect_kafka_data(ctx, record, options),
            module="kafka",
            service="kafka",
        )

    return ModuleAuditSpec(
        module="kafka",
        label="KAFKA",
        default_port=_DEFAULT_PORT,
        host_stage=actions.host_stage,
        detect=_detect if use_lifecycle_hooks else None,
        auth=_auth if use_lifecycle_hooks else None,
        data=_data if use_lifecycle_hooks else None,
        lifecycle_state_factory=_state_factory if use_lifecycle_hooks else None,
        lifecycle_state_close=(lambda state: state.close()) if use_lifecycle_hooks else None,
        record_all_credential_attempts=full_credential_sweep,
        continue_after_credential_success=full_credential_sweep,
        continue_after_credential_error=full_credential_sweep,
        credential_gate=_kafka_credential_gate,
        fallback_to_anonymous_detect_record=full_credential_sweep,
        render_module=render,
        colorize=render._render_colored_kafka_line,
    )


def run_kafka_stage(args: Any, logger: Any) -> int:
    cfg = AuditConfig.from_namespace(args)
    console = Console(debug=cfg.debug)
    if hasattr(console, "set_structured_output"):
        console.set_structured_output(cfg.output_format == "json")
    validation_rc = policy.validate_args(args, console)
    if validation_rc is not None:
        return int(validation_rc)
    try:
        plan = build_kafka_plan(args)
    except ValueError as exc:
        console.error(str(exc))
        return 2
    if cfg.debug and not getattr(args, "debug_emit", None):
        args.debug_emit = console.info
    if cfg.debug:
        suffix = f" format={cfg.output_format}"
        if cfg.output:
            suffix += f" output={args.output}"
        console.info("kafka audit started: mode=" + _kafka_mode(args) + suffix)
    runner = AuditCommandRunner(args=args, spec=build_kafka_spec(args), logger=logger, console=console)
    try:
        result = runner.run_plan(plan)
    except OSError as exc:
        console.error(f"failed to process kafka output: {exc}")
        return 2
    if cfg.debug and result.detected_count == 0 and hasattr(console, "warn"):
        console.warn("all kafka targets are unreachable")
    return command_result_exit_code(result)


__all__ = ["build_kafka_plan", "build_kafka_spec", "run_kafka_stage"]


def _kafka_mode(args: Any) -> str:
    parts: list[str] = []
    if bool(getattr(args, "show_topics", False)):
        parts.append("show-topics")
    topic = getattr(args, "topic", None) or getattr(args, "query_topic", None)
    if topic:
        parts.append(f"topic={topic}")
    if bool(getattr(args, "dump", False)):
        parts.append("dump")
        max_messages = getattr(args, "max_messages", None)
        if max_messages is not None:
            parts.append(f"max={max_messages}")
    return ",".join(parts) if parts else "detect"
