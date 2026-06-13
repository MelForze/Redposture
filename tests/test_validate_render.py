from __future__ import annotations

from redposture_core.validate import render


class _Console:
    def __init__(self) -> None:
        self.lines: list[str] = []

    def _paint(self, text: str, _color: str, _stream=None) -> str:
        return str(text)

    def plain(self, message: str) -> None:
        self.lines.append(message)


def test_validate_render_reason_phrases_and_signal_spans() -> None:
    sample = (
        "Authorization: Basic YWxpY2U6c2VjcmV0 Authorization: Bearer token "
        "password=Secret123 --api-key secret redis_password=redispass "
        "AWS_ACCESS_KEY_ID=AKIAABCDEFGHIJKLMNOP pg:5432:*:user:pass [CRED] "
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature "
        "-----BEGIN PRIVATE KEY-----abc-----END PRIVATE KEY----- "
        "postgresql://user:pass@db.local/app"
    )
    signals = [
        "authorization_basic",
        "authorization_bearer",
        "password=value",
        "flag_api-key",
        "redis_password",
        "aws_access_key_id",
        "pgpass_line",
        "cred_marker",
        "jwt_token",
        "private_key_pem",
        "postgres_connection_string_auth",
        "default_creds_known_pair",
        "json.username=value",
        "json.username",
    ]

    reasons, normalized, evidence = render._normalize_reason_render(",".join(signals), sample)
    spans = render._collect_signal_spans(sample, signals)

    assert "basic auth header" in reasons
    assert "bearer auth header" in reasons
    assert "private key" in reasons
    assert "AWS access key" in reasons
    assert "redis password" in reasons
    assert "username field" in reasons
    assert "authorization_basic" in normalized
    assert evidence == sample
    assert spans == sorted(set(spans))
    assert render._highlight_evidence("", signals) == "-"
    assert render._all_reasons_from_signals([]) == "credential indicator"
    assert render._signal_path_leaf("1items[0].password") == "password"
    assert render._clip("abcdef", 3) == "abc"


def test_validate_render_rows_and_summary_target() -> None:
    out = _Console()
    render._render_validate_row(
        out,
        host="127.0.0.1",
        port="9100",
        exporter="node_exporter",
        reason="authorization_bearer;password=value",
        endpoint="/metrics",
        sample="Authorization: Bearer token password=Secret123",
        count=2,
        hit_score=90,
        score_reasons="strong_signal",
        gated_non_debug=True,
        endpoint_policy="allowed",
        debug=True,
    )

    joined = "\n".join(out.lines)
    assert "Dump Validate Node Exporter" in joined
    assert "Endpoint:" in joined
    assert "Signals:" in joined
    assert "ScoreSignals:" in joined
    assert "Count:" in joined

    source_out = _Console()
    render._render_validate_source_row(
        source_out,
        source="collect.jsonl",
        reason="private_key_pem",
        sample="-----BEGIN PRIVATE KEY-----x-----END PRIVATE KEY-----",
        count=3,
        hit_score=100,
        score_reasons="pem",
        gated_non_debug=False,
        endpoint_policy="source",
        debug=True,
    )
    assert "Dump Validate Source" in "\n".join(source_out.lines)
    assert "Count:" in "\n".join(source_out.lines)

    assert render._resolve_validate_summary_target([]) == ("-", "-")
    assert render._resolve_validate_summary_target(
        [
            {"host": "10.0.0.1", "port": "9100", "exporter": "node_exporter"},
            {"host": "10.0.0.1", "port": "9100", "exporter": "node_exporter"},
        ]
    ) == ("10.0.0.1", "9100")
    assert render._resolve_validate_summary_target(
        [
            {"host": "10.0.0.1", "port": "9100", "exporter": "node_exporter"},
            {"host": "10.0.0.2", "port": "9100", "exporter": "node_exporter"},
        ]
    ) == ("-", "-")

    complete = _Console()
    render._render_validate_complete_row(
        complete,
        host="10.0.0.1",
        port="9100",
        total_lines=10,
        credential_hits=2,
        unique_hits=1,
        ok=False,
    )
    assert "unique_hits=1" in complete.lines[0]
