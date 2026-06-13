from __future__ import annotations

from redposture_core.validate import context, parsers, render, scoring


def test_validate_context_exports_value_quality_helpers() -> None:
    assert context._is_placeholder_value("$ES_PASSWORD") is True
    assert context._is_dummy_secret_value("changeme") is True
    assert context._value_looks_secret_for_key("password", "RealPass!2026") is True


def test_validate_context_quality_and_key_classification_edges() -> None:
    counters: dict[str, int] = {}

    assert context._normalize_precision_profile("unknown") == context.VALIDATION_PRECISION_LEGACY
    assert context._normalize_precision_profile("COLLECT_STRICT") == context.VALIDATION_PRECISION_COLLECT_STRICT
    assert context._clean_value_text('"SecretPass2026";') == "SecretPass2026"
    assert context._clean_value_text("(SecretPass2026),") == "SecretPass2026"
    assert (
        context._value_looks_secret(True, precision_profile="collect_strict", suppressed_value_counters=counters)
        is False
    )
    assert (
        context._value_looks_secret(123, precision_profile="collect_strict", suppressed_value_counters=counters)
        is False
    )
    assert (
        context._value_looks_secret("***", precision_profile="collect_strict", suppressed_value_counters=counters)
        is False
    )
    assert (
        context._value_looks_secret(
            "$ES_PASSWORD", precision_profile="collect_strict", suppressed_value_counters=counters
        )
        is False
    )
    assert (
        context._value_looks_secret("changeme", precision_profile="collect_strict", suppressed_value_counters=counters)
        is False
    )
    assert counters["suppressed_non_secret_values"] >= 3
    assert counters["suppressed_placeholders"] == 1
    assert counters["suppressed_dummy_values"] == 1

    token_counters: dict[str, int] = {}
    assert (
        context._value_looks_secret_for_key(
            "api_token",
            "short",
            precision_profile="collect_strict",
            suppressed_value_counters=token_counters,
        )
        is False
    )
    assert token_counters["suppressed_non_secret_values"] == 1
    assert (
        context._value_looks_secret_for_key(
            "api_token",
            "A1b2C3d4E5f6G7h8I9j0",
            precision_profile="collect_strict",
        )
        is True
    )
    assert (
        context._value_looks_token_secret(
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature",
            precision_profile="collect_strict",
        )
        is True
    )
    assert context._value_looks_identifier("***") is False
    assert context._value_looks_identifier("metrics") is True
    assert context._key_looks_username("user_agent") is False
    assert context._key_looks_username("db_user") is True
    assert context._key_looks_sensitive("secret_access_key") is True
    assert context._key_looks_connection("database_url") is True
    assert context._is_known_default_pair("postgres", "postgres") is True
    assert context._is_known_default_pair("", "postgres") is False
    assert context._context_tokens_present("sample password template", ("sample", "password", "missing")) == [
        "sample",
        "password",
    ]


def test_validate_scoring_exports_endpoint_gate_helpers() -> None:
    info = scoring._score_and_gate_hit(
        reason="authorization_bearer",
        endpoint="/metrics",
        sample="authorization: bearer eyJhbGciOiJIUzI1NiJ9.abc.def",
        precision_profile="collect_strict",
    )
    assert info["hit_score"] >= 8
    assert info["gated_out"] is False


def test_validate_scoring_policy_context_and_suppression_edges() -> None:
    assert scoring._split_reason_signals("a,b,a,, c ") == ["a", "b", "c"]
    assert scoring._signal_base_code("json.password:authorization_basic") == "authorization_basic"
    assert scoring._signal_score("flag_password") == (4, "medium:flag_password")
    assert scoring._has_medium_signal("correlated_user_password") is True
    assert scoring._is_strong_signal("redis_requirepass") is True
    assert scoring._endpoint_policy("/metrics", precision_profile="collect_strict")["require_strong"] is True
    assert (
        scoring._endpoint_policy("/debug/pprof/cmdline?debug=1", precision_profile="collect_strict")["threshold"] == 5
    )
    assert scoring._endpoint_policy("/debug/vars", precision_profile="legacy")["enabled"] is False

    denied = scoring._score_and_gate_hit(
        reason="password=value",
        endpoint="/metrics",
        sample="template password=SecretPass2026",
        precision_profile="collect_strict",
    )
    assert denied["gated_out"] is True
    assert denied["context_deny_tokens"] == "template"

    penalized = scoring._score_and_gate_hit(
        reason="authorization_basic,password=value",
        endpoint="/metrics",
        sample="template Authorization: Basic abc password=SecretPass2026",
        precision_profile="collect_strict",
    )
    assert penalized["gated_out"] is False
    assert penalized["context_penalty_applied"] is True

    bonus = scoring._score_and_gate_hit(
        reason="password=value",
        endpoint="/debug/vars",
        sample="real password=SecretPass2026",
        precision_profile="collect_strict",
    )
    assert bonus["context_bonus_applied"] is True
    assert bonus["gated_out"] is True

    assert (
        scoring._suppress_rule_id_for_hit(
            exporter="postgres_exporter",
            endpoint="/metrics",
            reason="password=value",
            sample='pg_stat_activity{query="select password from users"} 1',
        )
        == "pg_stat_query_passwd_from_noise"
    )
    assert (
        scoring._suppress_rule_id_for_hit(
            exporter="node_exporter",
            endpoint="/metrics",
            reason="password=value",
            sample='pg_stat_activity{query="select password from users"} 1',
        )
        is None
    )


def test_validate_parsers_and_render_exports_core_helpers() -> None:
    reasons = parsers._detect_hits_in_text(
        "redis://default:RedisPass!2026@redis.internal:6379",
        precision_profile="collect_strict",
    )
    assert any("connection_string_auth" in reason for reason in reasons)

    human_reason, signals, leak = render._normalize_reason_render(
        "connection_string_auth",
        "redis://default:RedisPass!2026@redis.internal:6379",
    )
    assert human_reason
    assert signals == "connection_string_auth"
    assert "redis://" in leak
