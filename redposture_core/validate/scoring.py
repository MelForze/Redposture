"""Validation signal scoring and suppress-rule helpers."""

from __future__ import annotations

import re
from typing import Any

from .context import (
    VALIDATION_PRECISION_COLLECT_STRICT,
    _context_tokens_present,
    _normalize_precision_profile,
)

_SCORE_STRONG = 8
_SCORE_MEDIUM = 4
_SCORE_WEAK = 1
_DENY_CONTEXT_TOKENS = (
    "example",
    "sample",
    "template",
    "placeholder",
    "docs",
    "documentation",
    "dummy",
    "mock",
    "testdata",
)
_ALLOW_CONTEXT_TOKENS = (
    "credential",
    "auth",
    "authorization",
    "password",
    "secret",
    "token",
    "apikey",
)
_SUPPRESS_SQL_METRIC_QUERY_RE = re.compile(
    r'(?is)\bpg_stat[a-z0-9_]*\b.*\bquery\s*=\s*"[^"]*\b(?:passwd|password)\b[^"]*\bfrom\b[^"]*"'
)
_EXPLICIT_SECRET_ASSIGN_RE = re.compile(r"(?i)\b(?:passwd|password|pwd|secret|token)\s*[:=]\s*[^\s,;\"']+")
_DEFAULT_VALIDATE_SUPPRESS_RULES = (
    {
        "id": "pg_stat_query_passwd_from_noise",
        "exporter": "postgres_exporter",
        "endpoint": "/metrics",
        "signals_any": {"flag_passwd", "flag_password", "passwd=value", "password=value"},
        "sample_re": _SUPPRESS_SQL_METRIC_QUERY_RE,
    },
)


def _split_reason_signals(reason: str) -> list[str]:
    signals: list[str] = []
    for chunk in str(reason or "").split(","):
        token = chunk.strip()
        if token and token not in signals:
            signals.append(token)
    return signals


def _signal_base_code(signal: str) -> str:
    text = str(signal or "").strip()
    if not text:
        return ""
    if ":" in text:
        return text.rsplit(":", 1)[1].strip()
    return text


def _is_explicit_key_value_signal(signal: str) -> bool:
    base = _signal_base_code(signal)
    return base.endswith("=value")


def _is_strong_signal(signal: str) -> bool:
    base = _signal_base_code(signal)
    if not base:
        return False
    if base == "correlated_with_strong":
        return True
    if base in {
        "authorization_basic",
        "authorization_bearer",
        "jwt_token",
        "private_key_pem",
        "aws_access_key_id",
        "pgpass_line",
    }:
        return True
    if base.startswith("redis_"):
        return True
    if base.endswith("connection_string_auth") or base.endswith("connection_string_query_secret"):
        return True
    return False


def _signal_score(signal: str) -> tuple[int, str]:
    base = _signal_base_code(signal)
    if base == "correlated_with_strong":
        return _SCORE_STRONG, "strong:correlated_with_strong"
    if base in {"correlated_with_medium", "correlated_user_password"}:
        return _SCORE_MEDIUM, f"medium:{base}"
    if _is_strong_signal(signal):
        return _SCORE_STRONG, f"strong:{base}"
    if _is_explicit_key_value_signal(signal) or base.startswith("flag_"):
        return _SCORE_MEDIUM, f"medium:{base}"
    return _SCORE_WEAK, f"weak:{base}"


def _endpoint_policy(endpoint: str, *, precision_profile: str) -> dict[str, Any]:
    profile = _normalize_precision_profile(precision_profile)
    if profile != VALIDATION_PRECISION_COLLECT_STRICT:
        return {"name": "legacy", "threshold": 0, "require_strong": False, "enabled": False}

    path = str(endpoint or "").split("?", 1)[0].strip() or "/debug/vars"
    if path == "/metrics":
        return {"name": "metrics_profile", "threshold": 8, "require_strong": True, "enabled": True}
    if path.startswith("/debug/pprof"):
        return {"name": "pprof_profile", "threshold": 5, "require_strong": False, "enabled": True}
    return {"name": "vars_profile", "threshold": 6, "require_strong": False, "enabled": True}


def _score_and_gate_hit(
    *,
    reason: str,
    endpoint: str,
    sample: str,
    precision_profile: str,
) -> dict[str, Any]:
    signals = _split_reason_signals(reason)
    score = 0
    strong_count = 0
    score_reasons: list[str] = []
    for signal in signals:
        points, label = _signal_score(signal)
        score += int(points)
        score_reasons.append(label)
        if _is_strong_signal(signal):
            strong_count += 1

    policy = _endpoint_policy(endpoint, precision_profile=precision_profile)
    profile = _normalize_precision_profile(precision_profile)
    deny_context = (
        _context_tokens_present(sample, _DENY_CONTEXT_TOKENS) if profile == VALIDATION_PRECISION_COLLECT_STRICT else []
    )
    allow_context = (
        _context_tokens_present(sample, _ALLOW_CONTEXT_TOKENS) if profile == VALIDATION_PRECISION_COLLECT_STRICT else []
    )

    context_penalty_applied = False
    context_bonus_applied = False
    context_gate_deny = False
    if deny_context:
        if strong_count < 1:
            context_gate_deny = True
            score_reasons.append("context:deny")
        else:
            score = max(0, score - 2)
            context_penalty_applied = True
            score_reasons.append("penalty:deny_context")
    elif allow_context:
        score += 1
        context_bonus_applied = True
        score_reasons.append("bonus:allow_context")

    gated_out = False
    if bool(policy.get("enabled")):
        threshold = int(policy.get("threshold") or 0)
        require_strong = bool(policy.get("require_strong"))
        if score < threshold:
            gated_out = True
        if require_strong and strong_count < 1:
            gated_out = True
    if context_gate_deny:
        gated_out = True

    return {
        "hit_score": score,
        "score_reasons": ",".join(score_reasons) if score_reasons else "-",
        "gated_out": gated_out,
        "strong_signal_count": strong_count,
        "endpoint_policy": str(policy.get("name") or "legacy"),
        "context_deny_tokens": ",".join(deny_context) if deny_context else "-",
        "context_allow_tokens": ",".join(allow_context) if allow_context else "-",
        "context_penalty_applied": context_penalty_applied,
        "context_bonus_applied": context_bonus_applied,
    }


def _match_validate_suppress_rule(
    rule: dict[str, Any],
    *,
    exporter: str,
    endpoint: str,
    signals: list[str],
    sample: str,
) -> bool:
    rule_exporter = str(rule.get("exporter") or "").strip().lower()
    if rule_exporter and exporter.strip().lower() != rule_exporter:
        return False

    rule_endpoint = str(rule.get("endpoint") or "").strip()
    if rule_endpoint and endpoint.strip() != rule_endpoint:
        return False

    wanted_signals = set(rule.get("signals_any") or ())
    if wanted_signals:
        base_signals = {_signal_base_code(signal) for signal in signals}
        if not (base_signals & wanted_signals):
            return False

    sample_re = rule.get("sample_re")
    if isinstance(sample_re, re.Pattern):
        if not sample_re.search(sample):
            return False
    elif sample_re:
        return False

    if _EXPLICIT_SECRET_ASSIGN_RE.search(sample):
        return False
    return True


def _suppress_rule_id_for_hit(
    *,
    exporter: str,
    endpoint: str,
    reason: str,
    sample: str,
) -> str | None:
    signals = _split_reason_signals(reason)
    for rule in _DEFAULT_VALIDATE_SUPPRESS_RULES:
        if _match_validate_suppress_rule(
            rule,
            exporter=exporter,
            endpoint=endpoint,
            signals=signals,
            sample=sample,
        ):
            return str(rule.get("id") or "default_suppress_rule")
    return None


def _has_medium_signal(signal: str) -> bool:
    base = _signal_base_code(signal)
    if base in {"correlated_with_medium", "correlated_user_password"}:
        return True
    return _is_explicit_key_value_signal(signal) or base.startswith("flag_")


__all__ = [name for name in globals() if name.startswith("_")]
