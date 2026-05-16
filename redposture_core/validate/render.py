"""Validation text rendering helpers."""

from __future__ import annotations

import re
import sys

from ..console import Console
from .context import _key_looks_sensitive, _key_looks_username
from .parsers import (
    _AUTH_BASIC_RE,
    _AUTH_BEARER_RE,
    _AWS_ACCESS_KEY_RE,
    _JWT_RE,
    _PEM_PRIVATE_KEY_RE,
    _REDIS_PASS_RE,
    _URL_CANDIDATE_RE,
)
from .scoring import _signal_base_code, _split_reason_signals

_EXPORTER_DISPLAY_NAMES = {
    "nats_exporter": "NATS Exporter",
    "statsd_exporter": "StatsD Exporter",
    "mysqld_exporter": "MySQLd Exporter",
    "blackbox_exporter": "Blackbox Exporter",
    "elasticsearch_exporter": "Elasticsearch Exporter",
    "nginx_exporter": "Nginx Exporter",
    "haproxy_exporter": "HAProxy Exporter",
    "kafka_exporter": "Kafka Exporter",
    "node_exporter": "Node Exporter",
    "memcached_exporter": "Memcached Exporter",
    "postgres_exporter": "Postgres Exporter",
    "redis_exporter": "Redis Exporter",
    "clickhouse_exporter": "ClickHouse Exporter",
    "snmp_exporter": "SNMP Exporter",
    "apache_exporter": "Apache Exporter",
    "bind_exporter": "BIND Exporter",
    "mongodb_exporter": "MongoDB Exporter",
    "pgbouncer_exporter": "PgBouncer Exporter",
    "pgbackrest_exporter": "pgBackRest Exporter",
    "victoriametrics_exporter": "VictoriaMetrics Exporter",
    "ceph_exporter": "Ceph Exporter",
    "varnish_exporter": "Varnish Exporter",
    "windows_exporter": "Windows Exporter",
    "ipmi_exporter": "IPMI Exporter",
    "gobgp_exporter": "GoBGP Exporter",
    "frr_exporter": "FRR Exporter",
    "named_process_exporter": "Named Process Exporter",
    "sql_exporter": "SQL Exporter",
    "ping_exporter": "Ping Exporter",
    "rabbitmq_exporter": "RabbitMQ Exporter",
    "proxmox_exporter": "Proxmox Exporter",
}


def _clip(text: str, width: int = 180) -> str:
    if len(text) <= width:
        return text
    if width <= 3:
        return text[:width]
    return text[: width - 3] + "..."


def _signal_path_leaf(signal: str) -> str:
    token = str(signal or "").strip()
    if not token:
        return ""
    if ":" in token:
        token = token.split(":", 1)[0]
    leaf = token.split(".")[-1]
    leaf = leaf.split("[", 1)[0].strip()
    return leaf.lower()


def _signal_reason_phrase(signal: str) -> str:
    base = _signal_base_code(signal)
    if base == "private_key_pem":
        return "private key"
    if base == "jwt_token":
        return "JWT token"
    if base == "aws_access_key_id":
        return "AWS access key"
    if base == "authorization_basic":
        return "basic auth header"
    if base == "authorization_bearer":
        return "bearer auth header"
    if base.endswith("connection_string_auth"):
        return "conn creds"
    if base.endswith("connection_string_query_secret"):
        return "conn query secret"
    if base == "pgpass_line":
        return "pgpass line"
    if base.startswith("redis_"):
        redis_key = base[len("redis_") :].replace("_", " ").strip()
        return f"redis {redis_key}".strip()
    if base.startswith("flag_"):
        return f"flag {base[len('flag_') :]}"
    if base.endswith("=value"):
        return f"{base[: -len('=value')]} value"
    if base == "default_creds_known_pair":
        return "default creds pair"
    if base == "cred_marker":
        return "cred marker"
    if base == "correlated_with_strong":
        return "cross-line strong corroboration"
    if base == "correlated_with_medium":
        return "cross-line corroboration"
    if base == "correlated_user_password":
        return "cross-line user/password pair"

    leaf = _signal_path_leaf(signal)
    if leaf and _key_looks_sensitive(leaf):
        return f"{leaf} field"
    if leaf and _key_looks_username(leaf):
        return f"{leaf} field"

    compact = base.replace("_", " ").strip()
    return compact if compact else "credential indicator"


def _all_reasons_from_signals(signals: list[str]) -> str:
    reasons: list[str] = []
    for signal in signals:
        phrase = _signal_reason_phrase(signal)
        if phrase and phrase not in reasons:
            reasons.append(phrase)
    return ", ".join(reasons) if reasons else "credential indicator"


def _find_key_value_spans(sample: str, key: str) -> list[tuple[int, int]]:
    key_text = str(key or "").strip()
    if not key_text:
        return []
    pattern = re.compile(rf"(?i)[\"']?{re.escape(key_text)}[\"']?\s*[:=]\s*(\"[^\"]+\"|'[^']+'|[^\s,;]+)")
    return [(match.start(), match.end()) for match in pattern.finditer(sample)]


def _find_flag_spans(sample: str, key: str) -> list[tuple[int, int]]:
    key_text = str(key or "").strip()
    if not key_text:
        return []
    pattern = re.compile(
        rf"(?i)(?:^|\s)((?:--|-D|/)?{re.escape(key_text)}\s*(?:=|:|\s)\s*(\"[^\"]+\"|'[^']+'|[^\s,;]+))"
    )
    return [(match.start(1), match.end(1)) for match in pattern.finditer(sample)]


def _find_signal_spans(sample: str, signal: str) -> list[tuple[int, int]]:
    spans: list[tuple[int, int]] = []
    base = _signal_base_code(signal)
    leaf = _signal_path_leaf(signal)

    if base.endswith("=value"):
        key = base[: -len("=value")]
        spans.extend(_find_key_value_spans(sample, key))
    elif base.startswith("flag_"):
        key = base[len("flag_") :]
        spans.extend(_find_flag_spans(sample, key))
    elif base == "authorization_basic":
        spans.extend((match.start(), match.end()) for match in _AUTH_BASIC_RE.finditer(sample))
    elif base == "authorization_bearer":
        spans.extend((match.start(), match.end()) for match in _AUTH_BEARER_RE.finditer(sample))
    elif base == "jwt_token":
        spans.extend((match.start(), match.end()) for match in _JWT_RE.finditer(sample))
    elif base == "private_key_pem":
        spans.extend((match.start(), match.end()) for match in _PEM_PRIVATE_KEY_RE.finditer(sample))
    elif base == "aws_access_key_id":
        spans.extend((match.start(), match.end()) for match in _AWS_ACCESS_KEY_RE.finditer(sample))
    elif base == "pgpass_line":
        stripped = sample.strip()
        if stripped:
            start = sample.find(stripped)
            spans.append((start, start + len(stripped)))
    elif base.startswith("redis_"):
        spans.extend((match.start(), match.end()) for match in _REDIS_PASS_RE.finditer(sample))
    elif base.startswith("url_") or "connection_string_auth" in base or "connection_string_query_secret" in base:
        spans.extend((match.start(), match.end()) for match in _URL_CANDIDATE_RE.finditer(sample))
    elif base == "cred_marker":
        marker = "[CRED]"
        offset = sample.upper().find(marker)
        if offset >= 0:
            spans.append((offset, offset + len(marker)))

    if not spans and leaf and _key_looks_sensitive(leaf):
        spans.extend(_find_key_value_spans(sample, leaf))
    if not spans and leaf and _key_looks_username(leaf):
        spans.extend(_find_key_value_spans(sample, leaf))
    if not spans and base == "default_creds_known_pair":
        pattern = re.compile(r"(?i)\b[^:/\s]+:[^@\s]+@")
        spans.extend((match.start(), match.end()) for match in pattern.finditer(sample))

    return spans


def _collect_signal_spans(sample: str, signals: list[str]) -> list[tuple[int, int]]:
    spans: list[tuple[int, int]] = []
    seen: set[tuple[int, int]] = set()
    for signal in signals:
        for start, end in _find_signal_spans(sample, signal):
            if end <= start:
                continue
            key = (start, end)
            if key in seen:
                continue
            seen.add(key)
            spans.append(key)
    spans.sort(key=lambda item: (item[0], item[1]))
    return spans


def _highlight_evidence(sample: str, signals: list[str]) -> str:
    evidence = str(sample or "").strip()
    if not evidence:
        return "-"
    spans = _collect_signal_spans(evidence, signals)
    if not spans:
        return evidence
    return evidence


def _normalize_reason_render(reason: str, sample: str) -> tuple[str, str, str]:
    signals = _split_reason_signals(reason)
    if not signals:
        return "-", "-", _highlight_evidence(sample, [])
    return (
        _all_reasons_from_signals(signals),
        ",".join(signals),
        _highlight_evidence(sample, signals),
    )


def _exporter_display_name(raw: str) -> str:
    key = (raw or "").strip().lower()
    return _EXPORTER_DISPLAY_NAMES.get(key, raw or "-")


def _render_validate_row(
    out: Console,
    *,
    host: str,
    port: str,
    exporter: str,
    reason: str,
    endpoint: str,
    sample: str,
    count: int = 1,
    hit_score: int | None = None,
    score_reasons: str = "-",
    gated_non_debug: bool = False,
    endpoint_policy: str = "-",
    debug: bool = False,
) -> None:
    reason_human, signals, evidence_value = _normalize_reason_render(reason, sample)
    tag = f"{'VALIDATE':<8}"
    prefix = f"\t{_clip(host, 64)}\t{_clip(port, 16)}\t"
    endpoint_row_label = out._paint("Endpoint:", "white", sys.stdout)
    endpoint_row_value = out._paint(endpoint, "orange", sys.stdout)
    reason_label = out._paint("Reason:", "white", sys.stdout)
    reason_value = out._paint(reason_human, "orange", sys.stdout)
    signals_label = out._paint("Signals:", "white", sys.stdout)
    signals_value = out._paint(signals, "orange", sys.stdout)
    score_label = out._paint("Score:", "white", sys.stdout)
    score_value = out._paint(str(hit_score if hit_score is not None else "-"), "orange", sys.stdout)
    gate_label = out._paint("Gate:", "white", sys.stdout)
    gate_value = out._paint("gated_non_debug=yes" if gated_non_debug else "gated_non_debug=no", "orange", sys.stdout)
    policy_label = out._paint("Policy:", "white", sys.stdout)
    policy_value = out._paint(str(endpoint_policy or "-"), "orange", sys.stdout)
    score_reasons_label = out._paint("ScoreSignals:", "white", sys.stdout)
    score_reasons_value = out._paint(str(score_reasons or "-"), "orange", sys.stdout)
    leak_label = out._paint("Leak:", "white", sys.stdout)
    leak_value = out._paint(evidence_value, "orange", sys.stdout)
    count_label = out._paint("Count:", "white", sys.stdout)
    count_value = out._paint(str(max(1, int(count))), "orange", sys.stdout)
    header = (
        f"{out._paint(tag, 'blue', sys.stdout)}"
        f"{out._paint(prefix, 'white', sys.stdout)}"
        f" {out._paint('[*]', 'blue', sys.stdout)} "
        f"{out._paint(f'Dump Validate {_exporter_display_name(exporter)}', 'white', sys.stdout)}"
    )
    endpoint_row = (
        f"{out._paint(tag, 'blue', sys.stdout)}"
        f"{out._paint(prefix, 'white', sys.stdout)}"
        f" {endpoint_row_label} {endpoint_row_value}"
    )
    details = (
        f"{out._paint(tag, 'blue', sys.stdout)}{out._paint(prefix, 'white', sys.stdout)} {reason_label} {reason_value}"
    )
    evidence = (
        f"{out._paint(tag, 'blue', sys.stdout)}{out._paint(prefix, 'white', sys.stdout)} {leak_label} {leak_value}"
    )
    count_row = (
        f"{out._paint(tag, 'blue', sys.stdout)}{out._paint(prefix, 'white', sys.stdout)} {count_label} {count_value}"
    )
    out.plain(header)
    out.plain(endpoint_row)
    out.plain(details)
    if debug:
        signals_row = (
            f"{out._paint(tag, 'blue', sys.stdout)}"
            f"{out._paint(prefix, 'white', sys.stdout)}"
            f" {signals_label} {signals_value}"
        )
        out.plain(signals_row)
        score_row = (
            f"{out._paint(tag, 'blue', sys.stdout)}"
            f"{out._paint(prefix, 'white', sys.stdout)}"
            f" {score_label} {score_value} {gate_label} {gate_value} {policy_label} {policy_value}"
        )
        out.plain(score_row)
        score_reasons_row = (
            f"{out._paint(tag, 'blue', sys.stdout)}"
            f"{out._paint(prefix, 'white', sys.stdout)}"
            f" {score_reasons_label} {score_reasons_value}"
        )
        out.plain(score_reasons_row)
    out.plain(evidence)
    if count > 1:
        out.plain(count_row)


def _render_validate_source_row(
    out: Console,
    *,
    source: str,
    reason: str,
    sample: str,
    count: int = 1,
    hit_score: int | None = None,
    score_reasons: str = "-",
    gated_non_debug: bool = False,
    endpoint_policy: str = "-",
    debug: bool = False,
) -> None:
    reason_human, signals, evidence_value = _normalize_reason_render(reason, sample)
    tag = f"{'VALIDATE':<8}"
    prefix = f"\t{_clip(source, 64)}\t-\t"
    reason_label = out._paint("Reason:", "white", sys.stdout)
    reason_value = out._paint(reason_human, "orange", sys.stdout)
    signals_label = out._paint("Signals:", "white", sys.stdout)
    signals_value = out._paint(signals, "orange", sys.stdout)
    score_label = out._paint("Score:", "white", sys.stdout)
    score_value = out._paint(str(hit_score if hit_score is not None else "-"), "orange", sys.stdout)
    gate_label = out._paint("Gate:", "white", sys.stdout)
    gate_value = out._paint("gated_non_debug=yes" if gated_non_debug else "gated_non_debug=no", "orange", sys.stdout)
    policy_label = out._paint("Policy:", "white", sys.stdout)
    policy_value = out._paint(str(endpoint_policy or "-"), "orange", sys.stdout)
    score_reasons_label = out._paint("ScoreSignals:", "white", sys.stdout)
    score_reasons_value = out._paint(str(score_reasons or "-"), "orange", sys.stdout)
    leak_label = out._paint("Leak:", "white", sys.stdout)
    leak_value = out._paint(evidence_value, "orange", sys.stdout)
    count_label = out._paint("Count:", "white", sys.stdout)
    count_value = out._paint(str(max(1, int(count))), "orange", sys.stdout)
    header = (
        f"{out._paint(tag, 'blue', sys.stdout)}"
        f"{out._paint(prefix, 'white', sys.stdout)}"
        f" {out._paint('[*]', 'blue', sys.stdout)} "
        f"{out._paint('Dump Validate Source', 'white', sys.stdout)}"
    )
    details = (
        f"{out._paint(tag, 'blue', sys.stdout)}{out._paint(prefix, 'white', sys.stdout)} {reason_label} {reason_value}"
    )
    evidence = (
        f"{out._paint(tag, 'blue', sys.stdout)}{out._paint(prefix, 'white', sys.stdout)} {leak_label} {leak_value}"
    )
    count_row = (
        f"{out._paint(tag, 'blue', sys.stdout)}{out._paint(prefix, 'white', sys.stdout)} {count_label} {count_value}"
    )
    out.plain(header)
    out.plain(details)
    if debug:
        signals_row = (
            f"{out._paint(tag, 'blue', sys.stdout)}"
            f"{out._paint(prefix, 'white', sys.stdout)}"
            f" {signals_label} {signals_value}"
        )
        out.plain(signals_row)
        score_row = (
            f"{out._paint(tag, 'blue', sys.stdout)}"
            f"{out._paint(prefix, 'white', sys.stdout)}"
            f" {score_label} {score_value} {gate_label} {gate_value} {policy_label} {policy_value}"
        )
        out.plain(score_row)
        score_reasons_row = (
            f"{out._paint(tag, 'blue', sys.stdout)}"
            f"{out._paint(prefix, 'white', sys.stdout)}"
            f" {score_reasons_label} {score_reasons_value}"
        )
        out.plain(score_reasons_row)
    out.plain(evidence)
    if count > 1:
        out.plain(count_row)


def _resolve_validate_summary_target(matches: list[dict[str, str | int]]) -> tuple[str, str]:
    if not matches:
        return "-", "-"
    hosts = {str(item.get("host") or "-") for item in matches if str(item.get("host") or "-") != "-"}
    ports = {str(item.get("port") or "-") for item in matches if str(item.get("port") or "-") != "-"}
    exporters = {str(item.get("exporter") or "-") for item in matches if str(item.get("exporter") or "-") != "-"}

    if len(hosts) == 1:
        host = next(iter(hosts))
    else:
        host = "-"

    # Avoid misleading summaries like "VALIDATE ... 9116" when hits came from multiple exporters/ports.
    if len(ports) == 1 and len(exporters) <= 1 and host != "-":
        port = next(iter(ports))
    else:
        port = "-"

    return host, port


def _render_validate_complete_row(
    out: Console,
    *,
    host: str,
    port: str,
    total_lines: int,
    credential_hits: int,
    unique_hits: int | None = None,
    ok: bool,
) -> None:
    tag = f"{'VALIDATE':<8}"
    prefix = f"\t{_clip(host, 64)}\t{_clip(port, 16)}\t"
    mark = "[+]" if ok else "[!]"
    mark_color = "green" if ok else "red"
    message = f"validate complete: lines={total_lines} credential_hits={credential_hits}"
    if unique_hits is not None:
        message += f" unique_hits={unique_hits}"
    row = (
        f"{out._paint(tag, 'blue', sys.stdout)}"
        f"{out._paint(prefix, 'white', sys.stdout)}"
        f" {out._paint(mark, mark_color, sys.stdout)} "
        f"{out._paint(message, mark_color, sys.stdout)}"
    )
    out.plain(row)


__all__ = [name for name in globals() if name.startswith("_")]
