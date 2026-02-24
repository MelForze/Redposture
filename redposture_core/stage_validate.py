"""Saved-output validation helpers."""

from __future__ import annotations

import base64
import binascii
import json
import re
import sys
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from .console import Console

# key=value / key: value for secret-looking keys (quoted/unquoted keys/values)
_TEXT_KV_RE = re.compile(
    r"(?i)[\"']?((?:[A-Za-z_][A-Za-z0-9_.-]*)?(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|secret[_-]?key|session[_-]?token|id[_-]?token|auth[_-]?token|bearer[_-]?token))[\"']?\s*[:=]\s*([^\s,;]+)"
)
_CMD_FLAG_SECRET_RE = re.compile(
    r"(?i)(?:^|\s)(?:--|-D|/)?((?:[A-Za-z_][A-Za-z0-9_.-]*)?(?:password|passwd|pwd|secret|token|api[_-]?key|private[_-]?key|client[_-]?secret|session[_-]?token|id[_-]?token|auth[_-]?token|bearer[_-]?token|access[_-]?key|secret[_-]?key))\s*(?:=|\s)\s*(\"[^\"]+\"|'[^']+'|[^\s,;]+)"
)
_URL_CANDIDATE_RE = re.compile(
    r"(?i)\b(?:https?|ftp|postgres(?:ql)?|mysql|mariadb|redis|mongodb(?:\+srv)?|amqp|kafka)://[^\s\"'<>]+"
)
_AUTH_BASIC_RE = re.compile(r"(?i)\bauthorization\s*[:=]\s*basic\s+([A-Za-z0-9+/=]{8,})")
_AUTH_BEARER_RE = re.compile(r"(?i)\bauthorization\s*[:=]\s*bearer\s+([A-Za-z0-9._~+/-]{10,})")
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\b")
_PEM_PRIVATE_KEY_RE = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
_AWS_ACCESS_KEY_RE = re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")
_REDIS_PASS_RE = re.compile(r"(?i)\b(requirepass|masterauth)\s+([^\s]+)")
_PORT_PREFIX_RE = re.compile(r"^(\d+)_")

_EXPORTER_DISPLAY_NAMES = {
    "blackbox_exporter": "Blackbox Exporter",
    "kafka_exporter": "Kafka Exporter",
    "node_exporter": "Node Exporter",
    "postgres_exporter": "Postgres Exporter",
    "redis_exporter": "Redis Exporter",
    "clickhouse_exporter": "ClickHouse Exporter",
    "mongodb_exporter": "MongoDB Exporter",
    "pgbouncer_exporter": "PgBouncer Exporter",
    "gobgp_exporter": "GoBGP Exporter",
    "frr_exporter": "FRR Exporter",
    "named_process_exporter": "Named Process Exporter",
    "ping_exporter": "Ping Exporter",
    "proxmox_exporter": "Proxmox Exporter",
}

_SENSITIVE_KEY_TOKENS = (
    "password",
    "passwd",
    "passphrase",
    "pwd",
    "secret",
    "token",
    "authtoken",
    "securitytoken",
    "apikey",
    "accesskey",
    "secretkey",
    "accesskeyid",
    "secretaccesskey",
    "accesstoken",
    "refreshtoken",
    "idtoken",
    "sessiontoken",
    "bearertoken",
    "clientsecret",
    "oauthsecret",
    "signingkey",
    "privatetoken",
    "privatekey",
    "tlskey",
    "sshkey",
    "masterauth",
    "requirepass",
    "saslpassword",
    "credentials",
)

_URL_SENSITIVE_QUERY_KEYS = (
    "password",
    "passwd",
    "passphrase",
    "pwd",
    "secret",
    "token",
    "apikey",
    "accesstoken",
    "refreshtoken",
    "clientsecret",
    "sessiontoken",
    "idtoken",
    "securitytoken",
    "signature",
    "sig",
    "auth",
    "credential",
)

_USERNAME_KEY_TOKENS = (
    "username",
    "login",
    "principal",
    "userid",
    "sasluser",
    "dbuser",
)

_USERNAME_EXCLUDE_TOKENS = ("useragent",)

_NON_SECRET_LITERALS = {
    "-",
    "<empty>",
    "<none>",
    "none",
    "null",
    "n/a",
    "na",
    "false",
    "true",
    "on",
    "off",
    "yes",
    "no",
    "enabled",
    "disabled",
}


def _normalize_key_token(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", value.lower())


def _is_empty_or_masked(value: Any) -> bool:
    text = str(value if value is not None else "").strip().strip(",;")
    if text == "":
        return True
    lowered = text.lower()
    if lowered in _NON_SECRET_LITERALS:
        return True
    if set(text) <= {"*", "x", "X", "."} and len(text) >= 3:
        return True
    return False


def _clean_value_text(value: Any) -> str:
    text = str(value if value is not None else "").strip()
    if text.endswith(",") or text.endswith(";"):
        text = text[:-1].strip()
    if len(text) >= 2 and (
        (text.startswith('"') and text.endswith('"')) or (text.startswith("'") and text.endswith("'"))
    ):
        text = text[1:-1].strip()
    return text


def _value_looks_secret(value: Any) -> bool:
    if isinstance(value, bool):
        return False
    if isinstance(value, (int, float)):
        return False
    text = _clean_value_text(value)
    if _is_empty_or_masked(text):
        return False
    if len(text) < 3:
        return False
    return True


def _key_looks_sensitive(key: str) -> bool:
    normalized = _normalize_key_token(key)
    if not normalized:
        return False
    return any(token in normalized for token in _SENSITIVE_KEY_TOKENS)


def _key_looks_username(key: str) -> bool:
    normalized = _normalize_key_token(key)
    if not normalized:
        return False
    if any(token in normalized for token in _USERNAME_EXCLUDE_TOKENS):
        return False
    if any(token in normalized for token in _USERNAME_KEY_TOKENS):
        return True
    return normalized.endswith("user") or normalized.endswith("account")


def _maybe_add_reason(reasons: list[str], reason: str) -> None:
    if reason and reason not in reasons:
        reasons.append(reason)


def _safe_decode_basic(value: str) -> str | None:
    token = value.strip()
    if not token:
        return None
    padding = "=" * ((4 - (len(token) % 4)) % 4)
    try:
        raw = base64.b64decode(token + padding, validate=False)
    except (binascii.Error, ValueError):
        return None
    decoded = raw.decode("utf-8", errors="replace")
    return decoded if decoded else None


def _detect_url_based_hits(text: str) -> list[str]:
    reasons: list[str] = []
    for match in _URL_CANDIDATE_RE.finditer(text):
        candidate = match.group(0)
        try:
            parsed = urlsplit(candidate)
        except ValueError:
            continue

        username = parsed.username
        password = parsed.password
        if username and _value_looks_secret(password):
            _maybe_add_reason(reasons, "url_basic_auth")
            _maybe_add_reason(reasons, "url_basic_auth_username")

        if parsed.query:
            try:
                query_items = parse_qsl(parsed.query, keep_blank_values=True)
            except ValueError:
                query_items = []
            found_secret_query = False
            for key, value in query_items:
                normalized = _normalize_key_token(key)
                if any(token in normalized for token in _URL_SENSITIVE_QUERY_KEYS) and _value_looks_secret(value):
                    _maybe_add_reason(reasons, f"url_query_{key.lower()}")
                    found_secret_query = True
            if found_secret_query:
                for key, value in query_items:
                    if _key_looks_username(key) and _value_looks_secret(value):
                        _maybe_add_reason(reasons, f"url_query_{key.lower()}")
    return reasons


def _collect_json_hits(payload: Any, path: str = "") -> list[str]:
    hits: list[str] = []
    if isinstance(payload, dict):
        username_candidates: list[str] = []
        found_sensitive_in_object = False
        for key, value in payload.items():
            key_text = str(key)
            sub_path = f"{path}.{key_text}" if path else key_text
            if _key_looks_sensitive(key_text) and _value_looks_secret(value):
                _maybe_add_reason(hits, sub_path)
                found_sensitive_in_object = True
            if _key_looks_username(key_text) and _value_looks_secret(value):
                username_candidates.append(sub_path)
            if isinstance(value, str):
                for reason in _detect_hits_in_text(value):
                    _maybe_add_reason(hits, f"{sub_path}:{reason}")
            hits.extend(_collect_json_hits(value, sub_path))
        if found_sensitive_in_object:
            for username_path in username_candidates:
                _maybe_add_reason(hits, username_path)
        return hits
    if isinstance(payload, list):
        for idx, value in enumerate(payload):
            sub_path = f"{path}[{idx}]" if path else f"[{idx}]"
            if isinstance(value, str):
                for reason in _detect_hits_in_text(value):
                    _maybe_add_reason(hits, f"{sub_path}:{reason}")
            hits.extend(_collect_json_hits(value, sub_path))
    return hits


def _detect_hits_in_text(line: str) -> list[str]:
    reasons: list[str] = []
    cleaned = line.strip()
    line_upper = cleaned.upper()
    if "[CRED]" in line_upper:
        _maybe_add_reason(reasons, "cred_marker")

    for match in _TEXT_KV_RE.finditer(cleaned):
        key = str(match.group(1) or "").lower()
        value = _clean_value_text(str(match.group(2) or ""))
        if _value_looks_secret(value):
            _maybe_add_reason(reasons, f"{key}=value")

    for match in _CMD_FLAG_SECRET_RE.finditer(cleaned):
        key = str(match.group(1) or "").lower()
        value = _clean_value_text(str(match.group(2) or ""))
        if _value_looks_secret(value):
            _maybe_add_reason(reasons, f"flag_{key}")

    for reason in _detect_url_based_hits(cleaned):
        _maybe_add_reason(reasons, reason)

    for match in _AUTH_BASIC_RE.finditer(cleaned):
        decoded = _safe_decode_basic(str(match.group(1) or ""))
        if not decoded or ":" not in decoded:
            continue
        _, password = decoded.split(":", 1)
        if _value_looks_secret(password):
            _maybe_add_reason(reasons, "authorization_basic")

    for match in _AUTH_BEARER_RE.finditer(cleaned):
        token = _clean_value_text(str(match.group(1) or ""))
        if _value_looks_secret(token):
            _maybe_add_reason(reasons, "authorization_bearer")

    if _JWT_RE.search(cleaned):
        _maybe_add_reason(reasons, "jwt_token")

    if _PEM_PRIVATE_KEY_RE.search(cleaned):
        _maybe_add_reason(reasons, "private_key_pem")

    if _AWS_ACCESS_KEY_RE.search(cleaned):
        _maybe_add_reason(reasons, "aws_access_key_id")

    redis_match = _REDIS_PASS_RE.search(cleaned)
    if redis_match and _value_looks_secret(redis_match.group(2)):
        _maybe_add_reason(reasons, f"redis_{redis_match.group(1).lower()}")

    # Username fields by themselves are noisy; keep them only when line also contains secret indicators.
    line_has_secret_context = bool(
        _TEXT_KV_RE.search(cleaned)
        or _CMD_FLAG_SECRET_RE.search(cleaned)
        or _AUTH_BASIC_RE.search(cleaned)
        or _AUTH_BEARER_RE.search(cleaned)
    )
    if line_has_secret_context:
        for match in re.finditer(r"(?i)[\"']?([A-Za-z_][A-Za-z0-9_.-]*)[\"']?\s*[:=]\s*([^\s,;]+)", cleaned):
            key = str(match.group(1) or "")
            value = _clean_value_text(str(match.group(2) or ""))
            if _key_looks_username(key) and _value_looks_secret(value):
                _maybe_add_reason(reasons, f"{key.lower()}=value")

    pgpass_parts = cleaned.split(":")
    if len(pgpass_parts) == 5:
        host, port, database, username, password = pgpass_parts
        if host and (port.isdigit() or port == "*") and database and username and _value_looks_secret(password):
            _maybe_add_reason(reasons, "pgpass_line")

    return list(dict.fromkeys(reasons))


def _clip(text: str, width: int = 180) -> str:
    if len(text) <= width:
        return text
    if width <= 3:
        return text[:width]
    return text[: width - 3] + "..."


def _sample_line_for_json_reasons(body: str, reasons: list[str]) -> str:
    lines = [line.strip() for line in body.splitlines() if line.strip()]
    if not lines:
        return ""
    for reason in reasons:
        reason_path = reason.split(":", 1)[0]
        leaf = reason_path.split(".")[-1].split("[", 1)[0].strip()
        if not leaf:
            continue
        for line in lines:
            if leaf in line:
                return line
    return lines[0]


def _exporter_display_name(raw: str) -> str:
    key = (raw or "").strip().lower()
    return _EXPORTER_DISPLAY_NAMES.get(key, raw or "-")


def _detect_line_hits(line: str, input_format: str) -> list[str]:
    stripped = line.strip()
    if not stripped:
        return []

    if input_format == "txt":
        return _detect_hits_in_text(stripped)

    if input_format == "json":
        try:
            payload = json.loads(stripped)
        except json.JSONDecodeError:
            return []
        return _collect_json_hits(payload)

    # auto
    if stripped.startswith("{") or stripped.startswith("["):
        try:
            payload = json.loads(stripped)
        except json.JSONDecodeError:
            return _detect_hits_in_text(stripped)
        return _collect_json_hits(payload)
    return _detect_hits_in_text(stripped)


def _line_no_for_sample(lines: list[str], sample: str) -> int:
    if not lines:
        return 1
    sample_clean = sample.strip()
    if not sample_clean:
        return 1
    for idx, line in enumerate(lines, start=1):
        if line.strip() == sample_clean:
            return idx
    for idx, line in enumerate(lines, start=1):
        if sample_clean in line:
            return idx
    return 1


def _scan_body_hits(body: str, input_format: str) -> tuple[int, list[dict[str, str | int]]]:
    text = body if isinstance(body, str) else str(body)
    lines = text.splitlines()
    line_count = len(lines)
    stripped = text.strip()
    if line_count == 0 and stripped:
        line_count = 1

    should_try_json = input_format == "json" or (
        input_format == "auto" and (stripped.startswith("{") or stripped.startswith("["))
    )
    if should_try_json and stripped:
        try:
            payload = json.loads(stripped)
        except json.JSONDecodeError:
            pass
        else:
            reasons = list(dict.fromkeys(_collect_json_hits(payload)))
            if reasons:
                sample = _sample_line_for_json_reasons(text, reasons) or stripped
                return (
                    line_count,
                    [
                        {
                            "reason": ",".join(reasons),
                            "sample": sample,
                            "line_no": _line_no_for_sample(lines, sample),
                        }
                    ],
                )
            return line_count, []

    if input_format == "json":
        hits: list[dict[str, str | int]] = []
        for line_no, raw_line in enumerate(lines, start=1):
            line = raw_line.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                reasons = _detect_hits_in_text(line)
            else:
                reasons = _collect_json_hits(payload)
            if not reasons:
                continue
            hits.append(
                {
                    "reason": ",".join(dict.fromkeys(reasons)),
                    "sample": line,
                    "line_no": line_no,
                }
            )
        return line_count, hits

    # Fallback to line-by-line text heuristics for truncated/invalid JSON and plaintext outputs.
    line_mode = input_format
    hits: list[dict[str, str | int]] = []
    for line_no, raw_line in enumerate(lines, start=1):
        reasons = _detect_line_hits(raw_line, line_mode)
        if not reasons:
            continue
        hits.append(
            {
                "reason": ",".join(dict.fromkeys(reasons)),
                "sample": raw_line.strip(),
                "line_no": line_no,
            }
        )
    return line_count, hits


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


def _render_validate_row(
    out: Console,
    *,
    host: str,
    port: str,
    exporter: str,
    reason: str,
    endpoint: str,
    sample: str,
) -> None:
    tag = f"{'VALIDATE':<8}"
    prefix = f"\t{_clip(host, 64)}\t{_clip(port, 16)}\t"
    header = (
        f"{out._paint(tag, 'blue', sys.stdout)}"
        f"{out._paint(prefix, 'white', sys.stdout)}"
        f" {out._paint('[*]', 'blue', sys.stdout)} "
        f"{out._paint(f'Dump Validate {_exporter_display_name(exporter)}', 'white', sys.stdout)}"
    )
    details = (
        f"{out._paint(tag, 'blue', sys.stdout)}"
        f"{out._paint(prefix, 'white', sys.stdout)}"
        f" {out._paint(f'reason={reason} endpoint={endpoint}', 'orange', sys.stdout)}"
    )
    evidence = (
        f"{out._paint(tag, 'blue', sys.stdout)}"
        f"{out._paint(prefix, 'white', sys.stdout)}"
        f" {out._paint(sample, 'orange', sys.stdout)}"
    )
    out.plain(header)
    out.plain(details)
    out.plain(evidence)


def _render_validate_source_row(
    out: Console,
    *,
    source: str,
    reason: str,
    sample: str,
) -> None:
    tag = f"{'VALIDATE':<8}"
    prefix = f"\t{_clip(source, 64)}\t-\t"
    header = (
        f"{out._paint(tag, 'blue', sys.stdout)}"
        f"{out._paint(prefix, 'white', sys.stdout)}"
        f" {out._paint('[*]', 'blue', sys.stdout)} "
        f"{out._paint('Dump Validate Source', 'white', sys.stdout)}"
    )
    details = (
        f"{out._paint(tag, 'blue', sys.stdout)}"
        f"{out._paint(prefix, 'white', sys.stdout)}"
        f" {out._paint(f'reason={reason}', 'orange', sys.stdout)}"
    )
    evidence = (
        f"{out._paint(tag, 'blue', sys.stdout)}"
        f"{out._paint(prefix, 'white', sys.stdout)}"
        f" {out._paint(sample, 'orange', sys.stdout)}"
    )
    out.plain(header)
    out.plain(details)
    out.plain(evidence)


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
    ok: bool,
) -> None:
    tag = f"{'VALIDATE':<8}"
    prefix = f"\t{_clip(host, 64)}\t{_clip(port, 16)}\t"
    mark = "[+]" if ok else "[!]"
    mark_color = "green" if ok else "red"
    message = f"validate complete: lines={total_lines} credential_hits={credential_hits}"
    row = (
        f"{out._paint(tag, 'blue', sys.stdout)}"
        f"{out._paint(prefix, 'white', sys.stdout)}"
        f" {out._paint(mark, mark_color, sys.stdout)} "
        f"{out._paint(message, mark_color, sys.stdout)}"
    )
    out.plain(row)


def run_validation(
    input_path: str,
    *,
    input_format: str = "auto",
    show: bool = False,
    max_lines: int = 20,
    fail_on_creds: bool = False,
    debug: bool = False,
    console: Console | None = None,
) -> int:
    out = console or Console(debug=debug)
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

    index_map: dict[str, dict[str, Any]] = {}
    if path_obj.is_dir():
        index_map = _load_collect_index(path_obj)

    total_lines = 0
    hit_count = 0
    matches: list[dict[str, str | int]] = []
    unlimited = max_lines <= 0

    for file_path in files:
        try:
            body = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            out.warn(f"skip file={file_path}: {exc}")
            continue

        line_count, hits = _scan_body_hits(body, input_format)
        total_lines += line_count
        if not hits:
            continue

        rel = str(file_path.relative_to(path_obj)) if path_obj.is_dir() else str(file_path)
        meta = index_map.get(rel) or _fallback_meta_from_rel(rel)
        for hit in hits:
            hit_count += 1
            if not unlimited and len(matches) >= max_lines:
                continue
            matches.append(
                {
                    "rel": rel,
                    "line_no": int(hit.get("line_no") or 1),
                    "reason": str(hit.get("reason") or "-"),
                    "sample": str(hit.get("sample") or ""),
                    "host": str(meta.get("host") or "-"),
                    "port": str(meta.get("port") or "-"),
                    "exporter": str(meta.get("exporter") or "-"),
                    "endpoint": str(meta.get("endpoint") or "-"),
                }
            )

    if hit_count <= 0:
        _render_validate_complete_row(
            out,
            host="-",
            port="-",
            total_lines=total_lines,
            credential_hits=0,
            ok=True,
        )
        return 0

    if show:
        for item in matches:
            host = str(item.get("host") or "-")
            port = str(item.get("port") or "-")
            exporter = str(item.get("exporter") or "-")
            endpoint = str(item.get("endpoint") or "-")
            reason = str(item.get("reason") or "-")
            sample = str(item.get("sample") or "")
            if host == "-":
                rel = str(item.get("rel") or "-")
                line_no = int(item.get("line_no") or 0)
                _render_validate_source_row(
                    out,
                    source=f"{rel}:{line_no}",
                    reason=reason,
                    sample=sample,
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
            )
        hidden = hit_count - len(matches)
        if hidden > 0:
            out.warn(f"... {hidden} additional hit(s) hidden")

    summary_host, summary_port = _resolve_validate_summary_target(matches)
    _render_validate_complete_row(
        out,
        host=summary_host,
        port=summary_port,
        total_lines=total_lines,
        credential_hits=hit_count,
        ok=False,
    )
    if fail_on_creds:
        return 1
    return 0


def run_validation_records(
    records: list[dict[str, Any]],
    *,
    input_format: str = "auto",
    show: bool = False,
    max_lines: int = 20,
    fail_on_creds: bool = False,
    debug: bool = False,
    console: Console | None = None,
) -> int:
    out = console or Console(debug=debug)
    if debug:
        out.info(f"validate started: source=memory records={len(records)} format={input_format}")

    total_lines = 0
    hit_count = 0
    matches: list[dict[str, str | int]] = []
    unlimited = max_lines <= 0

    for record_no, record in enumerate(records, start=1):
        body = str(record.get("body") or "")
        if not body:
            continue

        host = str(record.get("host") or "-")
        port = str(record.get("port") or "-")
        exporter = str(record.get("exporter") or "-")
        endpoint = str(record.get("endpoint") or "-")

        line_count, hits = _scan_body_hits(body, input_format)
        total_lines += line_count
        if not hits:
            continue

        for hit in hits:
            hit_count += 1
            if not unlimited and len(matches) >= max_lines:
                continue
            matches.append(
                {
                    "record_no": record_no,
                    "line_no": int(hit.get("line_no") or 1),
                    "reason": str(hit.get("reason") or "-"),
                    "sample": str(hit.get("sample") or ""),
                    "host": host,
                    "port": port,
                    "exporter": exporter,
                    "endpoint": endpoint,
                }
            )

    if hit_count <= 0:
        _render_validate_complete_row(
            out,
            host="-",
            port="-",
            total_lines=total_lines,
            credential_hits=0,
            ok=True,
        )
        return 0

    if show:
        for item in matches:
            host = str(item.get("host") or "-")
            port = str(item.get("port") or "-")
            exporter = str(item.get("exporter") or "-")
            endpoint = str(item.get("endpoint") or "-")
            reason = str(item.get("reason") or "-")
            sample = str(item.get("sample") or "")
            if host == "-":
                record_no = int(item.get("record_no") or 0)
                line_no = int(item.get("line_no") or 0)
                _render_validate_source_row(
                    out,
                    source=f"record#{record_no}:{line_no}",
                    reason=reason,
                    sample=sample,
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
            )
        hidden = hit_count - len(matches)
        if hidden > 0:
            out.warn(f"... {hidden} additional hit(s) hidden")

    summary_host, summary_port = _resolve_validate_summary_target(matches)
    _render_validate_complete_row(
        out,
        host=summary_host,
        port=summary_port,
        total_lines=total_lines,
        credential_hits=hit_count,
        ok=False,
    )
    if fail_on_creds:
        return 1
    return 0
