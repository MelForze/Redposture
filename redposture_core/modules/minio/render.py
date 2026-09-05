"""TXT/JSON rendering and terminal coloring for the MinIO module.

Mirrors the house convention used by other modules (see clickhouse/grafana):
- `_format_detect_record` — the one-line detection summary `[*] MinIO (auth required:X)`.
- `_format_record` — the per-credential line `[+] <access-key> (admin:True)`.
- `_format_minio_detail_records` — enumeration/discovery detail lines.
Coloring goes through the shared `render_colored_marker_line` (declarative
BooleanColorRule + span helpers); no hardcoded ANSI. JSON output is produced by
the runtime from the AuditRecord, so the renderers emit nothing for `json`.
"""

from __future__ import annotations

import json
import re
from typing import Any

from ...console import Console
from ...rendering import (
    BooleanColorRule,
    CountColorRule,
    render_colored_marker_line,
    render_tagged_detail_line,
)

_UNDETECTED = {"not_minio", "transport_failure", ""}


def _prefix(record: dict[str, Any]) -> str:
    return f"MINIO\t{record.get('host') or '?'}\t{int(record.get('port') or 0)}\t"


def _bool_text(value: Any) -> str:
    return "True" if value is True else "False" if value is False else "unknown"


def _format_detect_record(record: dict[str, Any], output_format: str) -> str:
    """One-line detection summary: `[*] MinIO (auth required:X) [(version:Y)]`."""
    if output_format != "txt":
        return ""
    if str(record.get("detection_status") or "") in _UNDETECTED:
        return ""
    line = f"{_prefix(record)} [*] MinIO (auth required:{_bool_text(record.get('auth_required'))})"
    version = record.get("version")
    if version:
        line += f" (version:{version})"
    return line


def _admin_text(record: dict[str, Any]) -> str:
    # Boolean-style like clickhouse's (read/execute/admin) fields: an
    # admin-equivalent identity is True, a plain S3 user False, an unreachable
    # admin plane unknown. The precise 4-state capability stays in JSON.
    capability = str(record.get("admin_capability") or "")
    if capability in {"confirmed", "partial"}:
        return "True"
    if capability == "not_confirmed":
        return "False"
    return "unknown"


def _format_record(record: dict[str, Any], output_format: str) -> str:
    """Per-credential line, shown only when a credential was accepted.

    The `[+]` marker already means the credential is valid, so the line does not
    repeat a `(credential:valid)` field. Capabilities are boolean (`admin:True`).
    When enumeration ran, the discovered counts are appended as `(buckets:N)` /
    `(objects:N)`, mirroring zookeeper's `(znodes:N)`.
    """
    if output_format != "txt":
        return ""
    state = str(record.get("credential_state") or "")
    if state not in {"valid", "valid_but_restricted"}:
        return ""  # anonymous / invalid: the detect line already carries the summary
    results = record.get("credential_results") or []
    access_key = None
    if results and isinstance(results[0], dict):
        access_key = results[0].get("access_key")
    parts = [f"(admin:{_admin_text(record)})"]
    # A present list means the corresponding flag ran; show the count (even 0).
    buckets = record.get("buckets")
    if isinstance(buckets, list):
        parts.append(f"(buckets:{len(buckets)})")
    # Objects are streamed to a file (not held in the record); the count is
    # captured while streaming, so `(objects:N)` still shows the real total.
    objects_count = record.get("objects_count")
    if isinstance(objects_count, int):
        parts.append(f"(objects:{objects_count})")
    return f"{_prefix(record)} [+] {access_key or '?'} {' '.join(parts)}"


def _password_text(password: Any) -> str:
    if password is None:
        return "<no-password>"
    if password == "":
        return "<empty>"
    return str(password)


def _format_credential_attempts_records(record: dict[str, Any], output_format: str) -> list[str]:
    """Per-credential lines for `--defcreds` (every pair checked), like zookeeper.

    The accepted, selected credential is rendered by `_format_record` (with its
    admin/enumeration suffix), so it is skipped here; the remaining attempts show as
    `[-] user:pass` (rejected) or `[+] user` (another working default).
    """
    if output_format != "txt":
        return []
    attempts = record.get("attempted_credentials")
    if not isinstance(attempts, list) or len(attempts) < 2:
        return []
    prefix = _prefix(record)
    results = record.get("credential_results") or []
    selected_key = results[0].get("access_key") if results and isinstance(results[0], dict) else None
    winner_skipped = False
    lines: list[str] = []
    for attempt in attempts:
        if not isinstance(attempt, dict):
            continue
        username = str(attempt.get("username") or "")
        accepted = str(attempt.get("credential_state") or "") in {"valid", "valid_but_restricted"}
        if accepted and not winner_skipped and username == selected_key:
            winner_skipped = True  # the winning credential is shown by _format_record
            continue
        if accepted:
            lines.append(f"{prefix} [+] {username}")
        else:
            lines.append(f"{prefix} [-] {username}:{_password_text(attempt.get('password'))}")
    return lines


def object_stream_line(host: Any, port: Any, obj: dict[str, Any], output_format: str) -> str:
    """Format one streamed object as its final output line (TXT bare item or NDJSON).

    `data_record` writes these into the stream file; the runtime emits them
    verbatim (TXT lines get colored orange by the colorize hook on emit).
    """
    if output_format == "json":
        return json.dumps(
            {
                "type": "object",
                "host": host,
                "port": int(port or 0),
                "bucket": obj.get("bucket"),
                "key": obj.get("key"),
                "size": obj.get("size", 0),
            },
            ensure_ascii=False,
        )
    meta = f"(size:{obj.get('size', 0)})"
    if obj.get("content_type"):
        meta += f" (ctype:{obj['content_type']})"
    return f"MINIO\t{host or '?'}\t{int(port or 0)}\t {obj.get('bucket', '?')}/{obj.get('key', '?')} {meta}"


def _prefix_hp(host: Any, port: Any) -> str:
    return f"MINIO\t{host or '?'}\t{int(port or 0)}\t"


def format_finding_line(host: Any, port: Any, finding: dict[str, Any]) -> str:
    """One discovered-secret line `[+] <type> value=<full> place=<bucket/key$>`.

    Shows the full value (like clickhouse/elastic discover), falling back to the
    masked form only if no full value was retained. Reused by the batch renderer
    and by real-time (self-emitted) discovery.
    """
    shown = finding.get("value")
    if shown is None:
        shown = finding.get("masked_value")
    value = json.dumps(str(shown or ""), ensure_ascii=False, separators=(",", ":"))
    place = json.dumps(
        f"{finding.get('bucket', '?')}/{finding.get('key', '?')}{finding.get('object_path', '$')}",
        ensure_ascii=False,
        separators=(",", ":"),
    )
    return f"{_prefix_hp(host, port)} [+] {finding.get('type', 'secret')} value={value} place={place}"


def format_discover_summary(
    host: Any, port: Any, *, status: str, coverage_percent: float, findings: int, objects_scanned: int
) -> str:
    """The clickhouse-style `[*] Discover Secrets (...)` summary line."""
    return (
        f"{_prefix_hp(host, port)} [*] Discover Secrets (status:{status}) "
        f"(coverage:{float(coverage_percent):.2f}%) (findings:{int(findings)}) (objects:{int(objects_scanned)})"
    )


def _format_minio_detail_records(record: dict[str, Any], output_format: str) -> list[str]:
    """Enumeration + discovery detail lines (buckets / objects / secrets).

    Buckets and objects follow zookeeper's listing shape: a `[*] Show … (Count:N)`
    section header followed by bare, unmarked items (the header names the type, so
    the items carry no `[+]` and no type word). The coloring path paints those
    marker-less items orange.
    """
    if output_format != "txt":
        return []
    if str(record.get("detection_status") or "") in _UNDETECTED:
        return []
    prefix = _prefix(record)
    lines: list[str] = []
    write_probe = record.get("write_probe")
    write_probe = write_probe if isinstance(write_probe, dict) else {}
    buckets = [b for b in (record.get("buckets") or []) if isinstance(b, dict) and b.get("name")]
    if buckets:
        lines.append(f"{prefix} [*] Show Buckets (Count:{len(buckets)})")
        for bucket in buckets:
            name = bucket["name"]
            wp = write_probe.get(name)
            suffix = f" (write:{wp.get('write')})" if isinstance(wp, dict) else ""
            lines.append(f"{prefix} {name}{suffix}")
    elif write_probe:
        # --probe-write without --show-buckets: dedicated write-probe section.
        lines.append(f"{prefix} [*] Write Probe (Count:{len(write_probe)})")
        for name, wp in write_probe.items():
            state = wp.get("write") if isinstance(wp, dict) else "unknown"
            lines.append(f"{prefix} {name} (write:{state})")
    # Objects are streamed from a file by the runtime; here we only emit the
    # section header carrying the total count captured during streaming.
    objects_count = record.get("objects_count")
    if record.get("objects_streamed") and isinstance(objects_count, int):
        lines.append(f"{prefix} [*] Show Objects (Count:{objects_count})")
    for leftover in record.get("write_probe_leftovers") or []:
        if isinstance(leftover, dict):
            lines.append(f"{prefix} [!] canary left behind: {leftover.get('bucket', '?')}/{leftover.get('key', '?')}")
    # Secret discovery follows clickhouse's shape: a `[*] Discover Secrets` summary
    # (colored by health) over `[+] <type> value= place=` finding lines. The same
    # formatters are reused for real-time (self-emitted) discovery output.
    host, port = record.get("host"), record.get("port")
    if record.get("discover_requested"):
        lines.append(
            format_discover_summary(
                host,
                port,
                status=str(record.get("discover_coverage") or "unknown"),
                coverage_percent=float(record.get("discover_coverage_percent") or 0.0),
                findings=int(record.get("discover_findings_count") or len(record.get("secret_findings") or [])),
                objects_scanned=int(record.get("discover_objects_scanned") or 0),
            )
        )
    for finding in record.get("secret_findings") or []:
        if isinstance(finding, dict):
            lines.append(format_finding_line(host, port, finding))
    reasons = record.get("discover_partial_reasons") or []
    if reasons:
        lines.append(f"{prefix} [!] Discover partial: {','.join(str(r) for r in reasons)}")
    dump = record.get("object_dump")
    if isinstance(dump, dict):
        lines.append(f"{prefix} [*] Dump {dump.get('bucket', '?')}/{dump.get('key', '?')} (size:{dump.get('size', 0)})")
        # Raw object content, one line per line, without the MINIO tag prefix.
        lines.extend(str(dump.get("content") or "").splitlines())
    download = record.get("object_download")
    if isinstance(download, dict):
        lines.append(
            f"{prefix} [+] downloaded {download.get('bucket', '?')}/{download.get('key', '?')}"
            f" -> {download.get('path', '?')} (size:{download.get('size', 0)})"
        )
    op_error = record.get("object_op_error")
    if op_error:
        lines.append(f"{prefix} [!] object error: {op_error}")
    return lines


_DISCOVER_STATUS_RE = re.compile(r"\(status:([a-z_]+)\)")
_DISCOVER_COVERAGE_RE = re.compile(r"\(coverage:([0-9.]+)%\)")
_DISCOVER_FINDINGS_RE = re.compile(r"\(findings:(\d+)\)")


def _minio_extra_spans(_marker: str, payload: str) -> list[tuple[int, int, str]]:
    # A discovered secret finding line -> whole payload orange (like clickhouse).
    if " value=" in payload and " place=" in payload:
        return [(0, len(payload), "orange")]
    # The `Discover Secrets` summary is ranked by health, mirroring clickhouse:
    # status complete=green/partial=yellow/else red; coverage green>=100/yellow>=50/red;
    # findings green at 0, red once anything is found.
    if not payload.startswith("Discover Secrets"):
        return []
    spans: list[tuple[int, int, str]] = []
    status_match = _DISCOVER_STATUS_RE.search(payload)
    if status_match:
        value = status_match.group(1).strip().lower()
        color = "bright_green" if value == "complete" else "yellow" if value == "partial" else "true_red"
        spans.append((status_match.start(), status_match.end(), color))
    coverage_match = _DISCOVER_COVERAGE_RE.search(payload)
    if coverage_match:
        try:
            coverage = float(coverage_match.group(1))
        except ValueError:
            coverage = 0.0
        color = "bright_green" if coverage >= 100.0 else "yellow" if coverage >= 50.0 else "true_red"
        spans.append((coverage_match.start(), coverage_match.end(), color))
    findings_match = _DISCOVER_FINDINGS_RE.search(payload)
    if findings_match:
        spans.append(
            (
                findings_match.start(),
                findings_match.end(),
                "bright_green" if findings_match.group(1) == "0" else "true_red",
            )
        )
    return spans


_WRITE_RE = re.compile(r"\((write:(True|False|unknown))\)")


def _minio_detail_spans(line: str) -> tuple[tuple[int, int, str], ...]:
    # A bucket line may carry a write-probe verdict. Render `(write:...)` like the
    # credential-line fields — neutral white parens with a red (True) / green
    # (False) value — so it reads as a clean verdict, not orange. The bucket name
    # keeps the bare-item orange (the default color). Object lines carry no
    # `(write:...)`, so they keep the auto count-pattern path.
    right = line.rsplit("\t", 1)[1] if "\t" in line else line
    match = _WRITE_RE.search(right)
    if not match:
        return ()
    value = match.group(2)
    color = "true_red" if value == "True" else "bright_green" if value == "False" else "yellow"
    return (
        (match.start(0), match.start(1), "white"),  # opening paren
        (match.start(1), match.end(1), color),  # write:True / write:False
        (match.end(1), match.end(0), "white"),  # closing paren
    )


def _render_colored_minio_line(console: Console, line: str) -> bool:
    if render_colored_marker_line(
        console,
        line,
        tag="MINIO",
        # Own the `auth required` coloring below (use true_red, not the built-in
        # ANSI red) so it matches the rest of the module on orange-red themes.
        include_auth_required=False,
        booleans=(
            # auth required:True == server enforces auth (good) -> green;
            # False == anonymous access is open (exposure) -> red. `true_red` (256)
            # stays clearly red beside the orange listing on themes where ANSI
            # bright-red reads orange.
            BooleanColorRule("auth required", true_color="bright_green", false_color="true_red"),
            # admin:True == admin-capable credential (high risk) -> red.
            BooleanColorRule("admin", true_color="true_red"),
        ),
        counts=(
            # Enumerated data resources are exposure -> red (like zookeeper znodes).
            CountColorRule("buckets", "true_red"),
            CountColorRule("objects", "true_red"),
            # The `[*] Show … (Count:N)` section headers tie to their orange items.
            CountColorRule("Count", "orange"),
        ),
        extra_spans=_minio_extra_spans,
    ):
        return True
    if line.startswith("MINIO") and "\t" in line:
        # Bare bucket/object items (no marker) are exposure -> orange, with their
        # (size:..) metadata kept a dimmer white (mirrors zookeeper's listing).
        # A `(write:...)` verdict on a bucket line is colored by exposure instead.
        return render_tagged_detail_line(
            console,
            line,
            tag="MINIO",
            spans=_minio_detail_spans(line),
            default_color="orange",
            count_pattern_color="white",
            strip_paren_wrappers=False,
        )
    return False


__all__ = [
    "_format_detect_record",
    "_format_record",
    "_format_credential_attempts_records",
    "_format_minio_detail_records",
    "_render_colored_minio_line",
]
