"""Saved-output validation orchestration helpers."""

# ruff: noqa: F401

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from ..console import Console
from .context import (
    VALIDATION_PRECISION_COLLECT_STRICT,
    VALIDATION_PRECISION_LEGACY,
    _bump_suppressed_value_counter,
    _clean_value_text,
    _context_tokens_present,
    _is_dummy_secret_value,
    _is_empty_or_masked,
    _is_known_default_pair,
    _is_placeholder_value,
    _key_looks_connection,
    _key_looks_sensitive,
    _key_looks_token_like,
    _key_looks_username,
    _maybe_add_reason,
    _normalize_dummy_secret_token,
    _normalize_key_token,
    _normalize_precision_profile,
    _token_value_quality_ok,
    _value_looks_identifier,
    _value_looks_secret,
    _value_looks_secret_for_key,
    _value_looks_token_secret,
)
from .parsers import (
    _AUTH_BASIC_RE,
    _AUTH_BEARER_RE,
    _AWS_ACCESS_KEY_RE,
    _CMD_FLAG_GENERIC_RE,
    _CMD_FLAG_SECRET_RE,
    _JWT_RE,
    _PEM_PRIVATE_KEY_RE,
    _PORT_PREFIX_RE,
    _REDIS_PASS_RE,
    _TEXT_GENERIC_KV_RE,
    _TEXT_KV_RE,
    _URL_CANDIDATE_RE,
    _analyze_url_candidate,
    _apply_cross_line_correlation,
    _collect_json_hits,
    _connection_query_reason,
    _connection_reason,
    _detect_connection_and_default_hits,
    _detect_connection_value_hits,
    _detect_hits_in_text,
    _detect_hits_in_text_core,
    _detect_kv_connection_string_hits,
    _detect_line_hits,
    _detect_mysql_style_dsn_hits,
    _detect_structured_cmdline_hits,
    _detect_url_based_hits,
    _extract_line_correlation_context,
    _extract_metric_query_label_values,
    _extract_vulnerable_credentials_from_hit,
    _extract_vulnerable_credentials_from_text,
    _extract_vulnerable_login_pairs_from_hit,
    _extract_vulnerable_login_pairs_from_text,
    _kv_pairs_from_text,
    _line_no_for_sample,
    _safe_decode_basic,
    _sample_line_for_json_reasons,
    _scan_body_hits,
    _should_suppress_metric_query_only_noise,
    _vulnerable_dedupe,
    _vulnerable_key_bucket,
    _vulnerable_secret_allowed,
    _vulnerable_source_api_keys,
    _vulnerable_source_host_port,
    _vulnerable_username_allowed,
)
from .render import (
    _all_reasons_from_signals,
    _clip,
    _collect_signal_spans,
    _exporter_display_name,
    _find_flag_spans,
    _find_key_value_spans,
    _find_signal_spans,
    _highlight_evidence,
    _normalize_reason_render,
    _render_validate_complete_row,
    _render_validate_row,
    _render_validate_source_row,
    _resolve_validate_summary_target,
    _signal_path_leaf,
    _signal_reason_phrase,
)
from .scoring import (
    _endpoint_policy,
    _has_medium_signal,
    _is_explicit_key_value_signal,
    _is_strong_signal,
    _match_validate_suppress_rule,
    _score_and_gate_hit,
    _signal_base_code,
    _signal_score,
    _split_reason_signals,
    _suppress_rule_id_for_hit,
)


def _validate_group_key(
    *,
    host: str,
    port: str,
    exporter: str,
    endpoint: str,
    reason: str,
) -> tuple[str, str, str, str, str]:
    return (
        str(host or "-"),
        str(port or "-"),
        str(exporter or "-"),
        str(endpoint or "-"),
        str(reason or "-"),
    )


def _validate_group_key_from_match(item: dict[str, str | int]) -> tuple[str, str, str, str, str]:
    return _validate_group_key(
        host=str(item.get("host") or "-"),
        port=str(item.get("port") or "-"),
        exporter=str(item.get("exporter") or "-"),
        endpoint=str(item.get("endpoint") or "-"),
        reason=str(item.get("reason") or "-"),
    )


def _group_validate_matches(
    matches: list[dict[str, str | int]],
    group_counts: dict[tuple[str, str, str, str, str], int] | None = None,
) -> list[dict[str, str | int]]:
    grouped: dict[tuple[str, str, str, str, str], dict[str, str | int]] = {}
    order: list[tuple[str, str, str, str, str]] = []

    for item in matches:
        key = _validate_group_key_from_match(item)
        existing = grouped.get(key)
        if existing is None:
            merged = dict(item)
            merged["count"] = 1
            grouped[key] = merged
            order.append(key)
            continue
        existing["count"] = int(existing.get("count") or 1) + 1
        existing["sample"] = str(item.get("sample") or "")
        if "hit_score" in item:
            existing["hit_score"] = int(item.get("hit_score") or 0)
        if "score_reasons" in item:
            existing["score_reasons"] = str(item.get("score_reasons") or "-")
        if "gated_out" in item:
            existing["gated_out"] = bool(item.get("gated_out"))
        if "endpoint_policy" in item:
            existing["endpoint_policy"] = str(item.get("endpoint_policy") or "-")
        if "line_no" in item:
            existing["line_no"] = int(item.get("line_no") or 1)
        if "record_no" in item:
            existing["record_no"] = int(item.get("record_no") or 0)
        if "rel" in item:
            existing["rel"] = str(item.get("rel") or "")

    if group_counts:
        for key in order:
            grouped[key]["count"] = int(group_counts.get(key, int(grouped[key].get("count") or 1)))

    return [grouped[key] for key in order]


def _load_collect_index(input_dir: Path) -> dict[str, dict[str, Any]]:
    index_path = input_dir / "index.jsonl"
    if not index_path.exists() or not index_path.is_file():
        return {}
    result: dict[str, dict[str, Any]] = {}
    try:
        with index_path.open("r", encoding="utf-8", errors="replace") as fh:
            for raw in fh:
                line = raw.strip()
                if not line:
                    continue
                try:
                    payload = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(payload, dict):
                    continue
                rel = str(payload.get("response_file") or "").strip()
                if not rel:
                    continue
                result[rel] = payload
    except OSError:
        return {}
    return result


def _fallback_meta_from_rel(rel: str) -> dict[str, str]:
    path_obj = Path(rel)
    if path_obj.is_absolute():
        return {"host": "-", "port": "-", "exporter": "-", "endpoint": "-"}
    parts = path_obj.parts
    if len(parts) < 3:
        return {"host": "-", "port": "-", "exporter": "-", "endpoint": "-"}
    host = parts[0]
    exporter = parts[1]
    filename = parts[-1]
    port = "-"
    match = _PORT_PREFIX_RE.match(filename)
    if match:
        port = match.group(1)
    return {"host": host, "port": port, "exporter": exporter, "endpoint": "-"}


def run_validation(
    input_path: str,
    *,
    input_format: str = "auto",
    precision_profile: str = VALIDATION_PRECISION_LEGACY,
    show: bool = False,
    max_lines: int = 20,
    fail_on_creds: bool = False,
    debug: bool = False,
    console: Console | None = None,
) -> int:
    out = console or Console(debug=debug)
    pipeline_started_at = time.monotonic()
    normalized_precision_profile = _normalize_precision_profile(precision_profile)
    path_obj = Path(input_path)
    if not path_obj.exists():
        out.error(f"input not found: {path_obj}")
        return 2

    files: list[Path]
    if path_obj.is_file():
        files = [path_obj]
    else:
        files = [path for path in sorted(path_obj.rglob("*")) if path.is_file()]

    if not files:
        out.error(f"no files to validate: {path_obj}")
        return 2

    if debug:
        out.info(f"validate started: input={path_obj} files={len(files)} format={input_format}")
        out.debug(f"pass=1 detect start total={len(files)}")

    index_map: dict[str, dict[str, Any]] = {}
    if path_obj.is_dir():
        index_map = _load_collect_index(path_obj)

    total_lines = 0
    hit_count = 0
    matches: list[dict[str, str | int]] = []
    group_counts: dict[tuple[str, str, str, str, str], int] = {}
    suppressed_hits = 0
    suppressed_rules: dict[str, int] = {}
    suppressed_value_counters: dict[str, int] = {}
    gated_non_debug_hits = 0
    unlimited = max_lines <= 0

    for file_path in files:
        try:
            body = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            out.warn(f"skip file={file_path}: {exc}")
            continue

        line_count, hits = _scan_body_hits(
            body,
            input_format,
            precision_profile=normalized_precision_profile,
            suppressed_value_counters=suppressed_value_counters,
        )
        total_lines += line_count
        if not hits:
            continue

        rel = str(file_path.relative_to(path_obj)) if path_obj.is_dir() else str(file_path)
        meta = index_map.get(rel) or _fallback_meta_from_rel(rel)
        for hit in hits:
            reason = str(hit.get("reason") or "-")
            sample = str(hit.get("sample") or "")
            host = str(meta.get("host") or "-")
            port = str(meta.get("port") or "-")
            exporter = str(meta.get("exporter") or "-")
            endpoint = str(meta.get("endpoint") or "-")

            suppress_rule_id = _suppress_rule_id_for_hit(
                exporter=exporter,
                endpoint=endpoint,
                reason=reason,
                sample=sample,
            )
            if suppress_rule_id is not None:
                suppressed_hits += 1
                suppressed_rules[suppress_rule_id] = int(suppressed_rules.get(suppress_rule_id, 0)) + 1
                continue

            score_info = _score_and_gate_hit(
                reason=reason,
                endpoint=endpoint,
                sample=sample,
                precision_profile=normalized_precision_profile,
            )
            if not debug and bool(score_info.get("gated_out")):
                gated_non_debug_hits += 1
                continue

            hit_count += 1
            group_key = _validate_group_key(
                host=host,
                port=port,
                exporter=exporter,
                endpoint=endpoint,
                reason=reason,
            )
            group_counts[group_key] = int(group_counts.get(group_key, 0)) + 1
            if not unlimited and len(matches) >= max_lines:
                continue
            matches.append(
                {
                    "rel": rel,
                    "line_no": int(hit.get("line_no") or 1),
                    "reason": reason,
                    "sample": sample,
                    "host": host,
                    "port": port,
                    "exporter": exporter,
                    "endpoint": endpoint,
                    "hit_score": int(score_info.get("hit_score") or 0),
                    "score_reasons": str(score_info.get("score_reasons") or "-"),
                    "gated_out": bool(score_info.get("gated_out")),
                    "endpoint_policy": str(score_info.get("endpoint_policy") or "-"),
                }
            )

    detect_ms = int((time.monotonic() - pipeline_started_at) * 1000)
    if debug:
        out.debug(f"pass=1 detect complete files={len(files)} credential_hits={hit_count}")
        out.debug(f"stage_trace stage_name=detect_protocol attempt=1 duration_ms={detect_ms} result=ok error=-")

    if debug and suppressed_hits > 0:
        rules_text = ",".join(f"{key}:{suppressed_rules[key]}" for key in sorted(suppressed_rules))
        out.debug(f"validate suppressed hits: count={suppressed_hits} rules={rules_text}")
    if debug and normalized_precision_profile == VALIDATION_PRECISION_COLLECT_STRICT and gated_non_debug_hits > 0:
        out.debug(f"validate score gate: profile=collect_strict gated_non_debug_hits={gated_non_debug_hits}")
    if debug:
        placeholder_count = int(suppressed_value_counters.get("suppressed_placeholders", 0))
        dummy_count = int(suppressed_value_counters.get("suppressed_dummy_values", 0))
        non_secret_count = int(suppressed_value_counters.get("suppressed_non_secret_values", 0))
        if placeholder_count or dummy_count or non_secret_count:
            out.debug(
                "validate value suppressions: "
                f"profile={normalized_precision_profile} "
                f"suppressed_placeholders={placeholder_count} "
                f"suppressed_dummy_values={dummy_count} "
                f"suppressed_non_secret_values={non_secret_count}"
            )

    if hit_count <= 0:
        if debug:
            out.debug("pass=2 deep start total=0")
            out.debug("stage2_gate=skip reason=credential_hits=0")
            out.debug("pass=2 deep complete processed=0")
            out.debug("stage_trace stage_name=data attempt=1 duration_ms=0 result=skip error=no_credential_hits")
            total_ms = int((time.monotonic() - pipeline_started_at) * 1000)
            out.debug(
                f"stage_timing_summary status=clean attempts=1/1 detect_ms={detect_ms} data_ms=0 total_ms={total_ms}"
            )
        _render_validate_complete_row(
            out,
            host="-",
            port="-",
            total_lines=total_lines,
            credential_hits=0,
            unique_hits=0,
            ok=True,
        )
        return 0

    grouped_matches = _group_validate_matches(matches, group_counts)
    render_started_at = time.monotonic()
    if debug:
        out.debug(f"pass=2 deep start total={len(grouped_matches)}")
        out.debug("stage2_gate=run reason=credential_hits>0")

    if show:
        for item in grouped_matches:
            host = str(item.get("host") or "-")
            port = str(item.get("port") or "-")
            exporter = str(item.get("exporter") or "-")
            endpoint = str(item.get("endpoint") or "-")
            reason = str(item.get("reason") or "-")
            sample = str(item.get("sample") or "")
            count = int(item.get("count") or 1)
            if host == "-":
                rel = str(item.get("rel") or "-")
                line_no = int(item.get("line_no") or 0)
                _render_validate_source_row(
                    out,
                    source=f"{rel}:{line_no}",
                    reason=reason,
                    sample=sample,
                    count=count,
                    hit_score=int(item.get("hit_score") or 0),
                    score_reasons=str(item.get("score_reasons") or "-"),
                    gated_non_debug=bool(item.get("gated_out")),
                    endpoint_policy=str(item.get("endpoint_policy") or "-"),
                    debug=debug,
                )
                continue
            _render_validate_row(
                out,
                host=host,
                port=port,
                exporter=exporter,
                reason=reason,
                endpoint=endpoint,
                sample=sample,
                count=count,
                hit_score=int(item.get("hit_score") or 0),
                score_reasons=str(item.get("score_reasons") or "-"),
                gated_non_debug=bool(item.get("gated_out")),
                endpoint_policy=str(item.get("endpoint_policy") or "-"),
                debug=debug,
            )
        hidden = hit_count - len(matches)
        if hidden > 0:
            out.warn(f"... {hidden} additional hit(s) hidden")

    summary_host, summary_port = _resolve_validate_summary_target(grouped_matches)
    unique_hits = len(group_counts)
    _render_validate_complete_row(
        out,
        host=summary_host,
        port=summary_port,
        total_lines=total_lines,
        credential_hits=hit_count,
        unique_hits=unique_hits,
        ok=False,
    )
    data_ms = int((time.monotonic() - render_started_at) * 1000)
    if debug:
        out.debug(f"pass=2 deep complete processed={len(grouped_matches)}")
        out.debug(f"stage_trace stage_name=data attempt=1 duration_ms={data_ms} result=ok error=-")
        total_ms = int((time.monotonic() - pipeline_started_at) * 1000)
        out.debug(
            f"stage_timing_summary status=hits attempts=1/1 detect_ms={detect_ms} data_ms={data_ms} total_ms={total_ms}"
        )
    if fail_on_creds:
        return 1
    return 0


def run_validation_records(
    records: list[dict[str, Any]],
    *,
    input_format: str = "auto",
    precision_profile: str = VALIDATION_PRECISION_LEGACY,
    show: bool = False,
    max_lines: int = 20,
    fail_on_creds: bool = False,
    debug: bool = False,
    console: Console | None = None,
) -> int:
    accumulator = ValidationRecordAccumulator(
        input_format=input_format,
        max_lines=max_lines,
        precision_profile=precision_profile,
    )
    for record in records:
        accumulator.feed(record)
    return accumulator.finish(
        show=show,
        fail_on_creds=fail_on_creds,
        debug=debug,
        console=console,
        source="memory",
        records_total=len(records),
    )


def scan_validation_hits(
    body: str,
    *,
    input_format: str = "auto",
    precision_profile: str = VALIDATION_PRECISION_LEGACY,
) -> tuple[int, list[dict[str, str | int]]]:
    """Return line count and validation hits for a body without rendering output."""
    return _scan_body_hits(body, input_format, precision_profile=precision_profile)


class ValidationRecordAccumulator:
    """Streaming credential-hit accumulator for in-memory validation records."""

    def __init__(
        self,
        *,
        input_format: str = "auto",
        max_lines: int = 20,
        precision_profile: str = VALIDATION_PRECISION_LEGACY,
    ) -> None:
        self._input_format = input_format
        self._precision_profile = _normalize_precision_profile(precision_profile)
        self._max_lines = max_lines
        self._unlimited = max_lines <= 0
        self._started_at = time.monotonic()
        self._record_no = 0
        self.total_lines = 0
        self.hit_count = 0
        self.raw_hit_count = 0
        self.shown_hit_count = 0
        self.suppressed_hits = 0
        self._suppressed_rules: dict[str, int] = {}
        self._suppressed_value_counters: dict[str, int] = {}
        self._raw_group_counts: dict[tuple[str, str, str, str, str], int] = {}
        self._shown_group_counts: dict[tuple[str, str, str, str, str], int] = {}
        self.matches_raw: list[dict[str, str | int]] = []
        self.matches_shown: list[dict[str, str | int]] = []

    def vulnerable_targets_from_shown_hits(self) -> tuple[list[str], list[str]]:
        hosts: set[str] = set()
        urls: set[str] = set()
        for host, port, _exporter, endpoint, _reason in self._shown_group_counts:
            host_text = str(host or "").strip()
            port_text = str(port or "").strip()
            endpoint_text = str(endpoint or "").strip()
            if not host_text or host_text == "-" or not port_text.isdigit():
                continue
            if not endpoint_text.startswith("/"):
                continue
            urls.add(f"http://{host_text}:{int(port_text)}{endpoint_text}")
        hosts.update(row[0] for row in self.vulnerable_login_rows_from_shown_hits() if row[0] != "-")
        return sorted(hosts), sorted(urls)

    def vulnerable_login_rows_from_shown_hits(self) -> list[tuple[str, str, str]]:
        rows: list[tuple[str, str, str]] = []
        seen: set[tuple[str, str, str]] = set()
        for hit in self.matches_shown:
            host, _port = _vulnerable_source_host_port(hit)
            for username, password in _extract_vulnerable_login_pairs_from_hit(hit):
                row = (host, username, password)
                if row in seen:
                    continue
                seen.add(row)
                rows.append(row)
        return rows

    def vulnerable_credentials_from_shown_hits(self) -> tuple[list[str], list[str], list[str]]:
        login_rows = self.vulnerable_login_rows_from_shown_hits()
        users = [row[1] for row in login_rows]
        passwords = [row[2] for row in login_rows]
        api_keys: list[str] = []
        for hit in self.matches_shown:
            _hit_users, _hit_passwords, hit_api_keys = _extract_vulnerable_credentials_from_hit(hit)
            api_keys.extend(_vulnerable_source_api_keys(hit, hit_api_keys))
        return _vulnerable_dedupe(users), _vulnerable_dedupe(passwords), _vulnerable_dedupe(api_keys)

    def vulnerable_findings_from_shown_hits(self) -> list[dict[str, object]]:
        findings: list[dict[str, object]] = []
        seen: set[tuple[str, str, str, str, str, str, str, str]] = set()
        for hit in self.matches_shown:
            users, passwords, api_keys = _extract_vulnerable_credentials_from_hit(hit)
            source_api_keys = _vulnerable_source_api_keys(hit, api_keys)
            if not users and not passwords and not source_api_keys:
                continue
            host, port = _vulnerable_source_host_port(hit)
            endpoint = str(hit.get("endpoint") or "-").strip() or "-"
            exporter = str(hit.get("exporter") or "-").strip() or "-"
            reason = str(hit.get("reason") or "-").strip() or "-"
            key = (
                host,
                port,
                endpoint,
                exporter,
                reason,
                ",".join(users),
                ",".join(passwords),
                ",".join(source_api_keys),
            )
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                {
                    "host": host,
                    "port": port,
                    "endpoint": endpoint,
                    "exporter": exporter,
                    "reason": reason,
                    "users": users,
                    "passwords": passwords,
                    "api_keys": source_api_keys,
                }
            )
        return findings

    def feed(self, record: dict[str, Any]) -> None:
        self._record_no += 1
        body = str(record.get("body") or "")
        if not body:
            return

        host = str(record.get("host") or "-")
        port = str(record.get("port") or "-")
        exporter = str(record.get("exporter") or "-")
        endpoint = str(record.get("endpoint") or "-")

        line_count, hits = _scan_body_hits(
            body,
            self._input_format,
            precision_profile=self._precision_profile,
            suppressed_value_counters=self._suppressed_value_counters,
        )
        self.total_lines += line_count
        if not hits:
            return

        for hit in hits:
            reason = str(hit.get("reason") or "-")
            sample = str(hit.get("sample") or "")
            suppress_rule_id = _suppress_rule_id_for_hit(
                exporter=exporter,
                endpoint=endpoint,
                reason=reason,
                sample=sample,
            )
            if suppress_rule_id is not None:
                self.suppressed_hits += 1
                self._suppressed_rules[suppress_rule_id] = int(self._suppressed_rules.get(suppress_rule_id, 0)) + 1
                continue

            score_info = _score_and_gate_hit(
                reason=reason,
                endpoint=endpoint,
                sample=sample,
                precision_profile=self._precision_profile,
            )
            gated_out = bool(score_info.get("gated_out"))

            self.raw_hit_count += 1
            group_key = _validate_group_key(
                host=host,
                port=port,
                exporter=exporter,
                endpoint=endpoint,
                reason=reason,
            )
            self._raw_group_counts[group_key] = int(self._raw_group_counts.get(group_key, 0)) + 1

            hit_payload: dict[str, str | int] = {
                "record_no": self._record_no,
                "line_no": int(hit.get("line_no") or 1),
                "reason": reason,
                "sample": sample,
                "body": body,
                "host": host,
                "port": port,
                "exporter": exporter,
                "endpoint": endpoint,
                "hit_score": int(score_info.get("hit_score") or 0),
                "score_reasons": str(score_info.get("score_reasons") or "-"),
                "gated_out": gated_out,
                "endpoint_policy": str(score_info.get("endpoint_policy") or "-"),
            }
            if self._unlimited or len(self.matches_raw) < self._max_lines:
                self.matches_raw.append(hit_payload)

            if gated_out:
                continue
            self.shown_hit_count += 1
            self._shown_group_counts[group_key] = int(self._shown_group_counts.get(group_key, 0)) + 1
            if self._unlimited or len(self.matches_shown) < self._max_lines:
                self.matches_shown.append(hit_payload)

        self.hit_count = self.shown_hit_count

    def finish(
        self,
        *,
        show: bool,
        fail_on_creds: bool,
        debug: bool,
        console: Console | None = None,
        source: str = "memory",
        records_total: int | None = None,
    ) -> int:
        out = console or Console(debug=debug)
        finish_started_at = time.monotonic()
        if debug:
            records_value = records_total if records_total is not None else self._record_no
            out.info(f"validate started: source={source} records={records_value} format={self._input_format}")
            out.debug(f"pass=1 detect start total={records_value}")
            detect_ms = int((finish_started_at - self._started_at) * 1000)
            raw_hits = self.raw_hit_count
            shown_hits = self.shown_hit_count
            if self._precision_profile == VALIDATION_PRECISION_COLLECT_STRICT:
                out.debug(
                    f"pass=1 detect complete records={records_value} credential_hits={raw_hits} shown_hits={shown_hits}"
                )
            else:
                out.debug(f"pass=1 detect complete records={records_value} credential_hits={raw_hits}")
            out.debug(f"stage_trace stage_name=detect_protocol attempt=1 duration_ms={detect_ms} result=ok error=-")
            if self.suppressed_hits > 0:
                rules_text = ",".join(f"{key}:{self._suppressed_rules[key]}" for key in sorted(self._suppressed_rules))
                out.debug(f"validate suppressed hits: count={self.suppressed_hits} rules={rules_text}")
            placeholder_count = int(self._suppressed_value_counters.get("suppressed_placeholders", 0))
            dummy_count = int(self._suppressed_value_counters.get("suppressed_dummy_values", 0))
            non_secret_count = int(self._suppressed_value_counters.get("suppressed_non_secret_values", 0))
            if placeholder_count or dummy_count or non_secret_count:
                out.debug(
                    "validate value suppressions: "
                    f"profile={self._precision_profile} "
                    f"suppressed_placeholders={placeholder_count} "
                    f"suppressed_dummy_values={dummy_count} "
                    f"suppressed_non_secret_values={non_secret_count}"
                )
        else:
            detect_ms = 0

        effective_hit_count = self.raw_hit_count if debug else self.shown_hit_count
        effective_matches = self.matches_raw if debug else self.matches_shown
        effective_group_counts = self._raw_group_counts if debug else self._shown_group_counts

        if effective_hit_count <= 0:
            if debug:
                out.debug("pass=2 deep start total=0")
                out.debug("stage2_gate=skip reason=credential_hits=0")
                out.debug("pass=2 deep complete processed=0")
                out.debug("stage_trace stage_name=data attempt=1 duration_ms=0 result=skip error=no_credential_hits")
                total_ms = int((time.monotonic() - self._started_at) * 1000)
                out.debug(
                    f"stage_timing_summary status=clean attempts=1/1 "
                    f"detect_ms={detect_ms} data_ms=0 total_ms={total_ms}"
                )
            _render_validate_complete_row(
                out,
                host="-",
                port="-",
                total_lines=self.total_lines,
                credential_hits=0,
                unique_hits=0,
                ok=True,
            )
            return 0

        grouped_matches = _group_validate_matches(effective_matches, effective_group_counts)
        render_started_at = time.monotonic()
        if debug:
            out.debug(f"pass=2 deep start total={len(grouped_matches)}")
            out.debug("stage2_gate=run reason=credential_hits>0")

        if show:
            for item in grouped_matches:
                host = str(item.get("host") or "-")
                port = str(item.get("port") or "-")
                exporter = str(item.get("exporter") or "-")
                endpoint = str(item.get("endpoint") or "-")
                reason = str(item.get("reason") or "-")
                sample = str(item.get("sample") or "")
                count = int(item.get("count") or 1)
                if host == "-":
                    record_no = int(item.get("record_no") or 0)
                    line_no = int(item.get("line_no") or 0)
                    _render_validate_source_row(
                        out,
                        source=f"record#{record_no}:{line_no}",
                        reason=reason,
                        sample=sample,
                        count=count,
                        hit_score=int(item.get("hit_score") or 0),
                        score_reasons=str(item.get("score_reasons") or "-"),
                        gated_non_debug=bool(item.get("gated_out")),
                        endpoint_policy=str(item.get("endpoint_policy") or "-"),
                        debug=debug,
                    )
                    continue
                _render_validate_row(
                    out,
                    host=host,
                    port=port,
                    exporter=exporter,
                    reason=reason,
                    endpoint=endpoint,
                    sample=sample,
                    count=count,
                    hit_score=int(item.get("hit_score") or 0),
                    score_reasons=str(item.get("score_reasons") or "-"),
                    gated_non_debug=bool(item.get("gated_out")),
                    endpoint_policy=str(item.get("endpoint_policy") or "-"),
                    debug=debug,
                )
            hidden = effective_hit_count - len(effective_matches)
            if hidden > 0:
                out.warn(f"... {hidden} additional hit(s) hidden")

        summary_host, summary_port = _resolve_validate_summary_target(grouped_matches)
        _render_validate_complete_row(
            out,
            host=summary_host,
            port=summary_port,
            total_lines=self.total_lines,
            credential_hits=effective_hit_count,
            unique_hits=len(effective_group_counts),
            ok=False,
        )
        if debug:
            data_ms = int((time.monotonic() - render_started_at) * 1000)
            out.debug(f"pass=2 deep complete processed={len(grouped_matches)}")
            out.debug(f"stage_trace stage_name=data attempt=1 duration_ms={data_ms} result=ok error=-")
            total_ms = int((time.monotonic() - self._started_at) * 1000)
            out.debug(
                f"stage_timing_summary status=hits attempts=1/1 "
                f"detect_ms={detect_ms} data_ms={data_ms} total_ms={total_ms}"
            )
        if fail_on_creds:
            return 1
        return 0
