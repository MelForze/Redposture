from __future__ import annotations

from redposture_core.validate import context, parsers, render, scoring


def test_validate_context_exports_value_quality_helpers() -> None:
    assert context._is_placeholder_value("$ES_PASSWORD") is True
    assert context._is_dummy_secret_value("changeme") is True
    assert context._value_looks_secret_for_key("password", "RealPass!2026") is True


def test_validate_scoring_exports_endpoint_gate_helpers() -> None:
    info = scoring._score_and_gate_hit(
        reason="authorization_bearer",
        endpoint="/metrics",
        sample="authorization: bearer eyJhbGciOiJIUzI1NiJ9.abc.def",
        precision_profile="collect_strict",
    )
    assert info["hit_score"] >= 8
    assert info["gated_out"] is False


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
