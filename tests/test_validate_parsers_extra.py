from __future__ import annotations

import base64

from redposture_core.validate import parsers


def test_validate_parser_low_level_detection_helpers() -> None:
    assert parsers._safe_decode_basic("") is None
    assert parsers._safe_decode_basic("!!!!") is None
    assert parsers._safe_decode_basic(base64.b64encode(b"metrics:secret").decode()) == "metrics:secret"

    assert parsers._analyze_url_candidate("http://[::1") == []
    assert "url_basic_auth" in parsers._analyze_url_candidate("https://admin:admin@db.local/app")
    assert "url_query_password" in parsers._analyze_url_candidate("https://db.local/app?user=admin&password=admin")

    kv_reasons = parsers._detect_kv_connection_string_hits(
        "host=db;user=postgres;password=postgres",
        connection_context="connection",
    )
    assert kv_reasons == ["connection_string_auth", "default_creds_known_pair"]
    assert (
        parsers._detect_kv_connection_string_hits("user=postgres password=postgres", connection_context="connection")
        == []
    )

    mysql_reasons = parsers._detect_mysql_style_dsn_hits(
        "metrics:Sup3rSecret2026@tcp(mysql.internal:3306)/app",
        connection_context="connection",
    )
    assert mysql_reasons == ["connection_string_auth"]

    jdbc_reasons = parsers._detect_connection_value_hits(
        "jdbc:postgresql://postgres:postgres@db.local/app",
        from_flag=True,
    )
    assert "cmd_connection_string_auth" in jdbc_reasons
    assert "default_creds_known_pair" in jdbc_reasons

    assert parsers._extract_metric_query_label_values("metric_without_labels 1") == []
    assert parsers._extract_metric_query_label_values('bad metric{query="select password"} 1') == []
    assert parsers._extract_metric_query_label_values('pg_stat{query="select \\"password\\"",other="x"} 1') == [
        'select "password"'
    ]


def test_validate_parser_json_scan_and_correlation_helpers() -> None:
    hits = parsers._collect_json_hits(
        {
            "items": [
                "password=Sup3rSecret2026",
                {"username": "postgres", "password": "postgres"},
            ]
        }
    )
    assert "items[0]:password=value" in hits
    assert "items[1].password:default_creds_known_pair" in hits

    line_count, body_hits = parsers._scan_body_hits('{"username":"postgres","password":"postgres"}', "auto")
    assert line_count == 1
    assert body_hits[0]["line_no"] == 1
    assert "default_creds_known_pair" in str(body_hits[0]["reason"])

    line_count, jsonl_hits = parsers._scan_body_hits('{bad}\n{"password":"Sup3rSecret2026"}', "json")
    assert line_count == 2
    assert jsonl_hits == [{"reason": "password", "sample": '{"password":"Sup3rSecret2026"}', "line_no": 2}]

    assert parsers._detect_line_hits("{bad password=Sup3rSecret2026", "json") == []
    assert "password=value" in parsers._detect_line_hits("{bad password=Sup3rSecret2026", "auto")
    assert parsers._line_no_for_sample([], "sample") == 1
    assert parsers._line_no_for_sample(["alpha", "beta secret"], "secret") == 2
    assert parsers._sample_line_for_json_reasons("", ["password"]) == ""
    assert parsers._sample_line_for_json_reasons('{"password":"x"}\n{"token":"y"}', ["token"]) == '{"token":"y"}'

    correlated_hits: list[dict[str, str | int]] = [
        {"reason": "password=value", "sample": "password=Sup3rSecret2026", "line_no": 2},
        {"reason": "username=value", "sample": "username=metrics", "line_no": 1},
        {"reason": "", "sample": "empty", "line_no": 99},
    ]
    parsers._apply_cross_line_correlation(
        lines=["username=metrics", "password=Sup3rSecret2026"],
        hits=correlated_hits,
        precision_profile=parsers.VALIDATION_PRECISION_COLLECT_STRICT,
    )
    assert "correlated_user_password" in str(correlated_hits[0]["reason"])
    assert "correlated_user_password" in str(correlated_hits[1]["reason"])
    assert correlated_hits[2]["reason"] == ""


def test_validate_parser_vulnerable_extraction_helpers() -> None:
    text = (
        "https://user:Sup3rSecret2026@db.local/app?api_key=A1b2C3d4E5f6G7h8I9j0 "
        "Authorization: Bearer Z1h2I3j4K5l6M7n8O9p0Q1r2 "
        "requirepass RedisPass2026 "
        "username=metrics password=MetricsPass2026"
    )
    users, passwords, api_keys = parsers._extract_vulnerable_credentials_from_text(text)
    assert users == ["user", "metrics"]
    assert "Sup3rSecret2026" in passwords
    assert "RedisPass2026" in passwords
    assert "MetricsPass2026" in passwords
    assert "A1b2C3d4E5f6G7h8I9j0" in api_keys
    assert "Z1h2I3j4K5l6M7n8O9p0Q1r2" in api_keys

    hit = {"host": "10.0.0.1", "port": 9100, "sample": text}
    assert parsers._vulnerable_source_host_port(hit) == ("10.0.0.1", "9100")
    assert parsers._vulnerable_source_api_keys(hit, ["token", "token"]) == ["10.0.0.1:9100:token"]
    assert parsers._extract_vulnerable_credentials_from_hit(hit)[0] == ["user", "metrics"]

    pairs = parsers._extract_vulnerable_login_pairs_from_text(
        "https://reader:ReaderPass2026@db.local username=metrics password=MetricsPass2026"
    )
    assert pairs == [("reader", "ReaderPass2026"), ("metrics", "MetricsPass2026")]
    assert parsers._extract_vulnerable_login_pairs_from_hit(
        {"sample": "username=metrics password=MetricsPass2026"}
    ) == [("metrics", "MetricsPass2026")]
