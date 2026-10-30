from __future__ import annotations

import base64
import io
import json
from pathlib import Path
from typing import Any

import pytest

from redposture_core.discovery_values import DiskBackedText, iter_json_chunks
from redposture_core.modules.elastic import actions
from redposture_core.modules.elastic.discover import (
    DetectedSecret,
    DiscoverEngine,
    DiscoverOptions,
    DiscoverResponse,
    FindingAccumulator,
    FindingLocation,
)
from redposture_core.modules.elastic.search_stream import StreamedSearchPage
from redposture_core.stage_runtime import LineOutputSink


def _jwt(query_length: int) -> str:
    def encode(value: dict[str, str]) -> str:
        raw = json.dumps(value, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    query = "query Search($params:BatchParams!){items{id name value timestamp}} "
    payload = (query * (query_length // len(query) + 1))[:query_length]
    return f"{encode({'alg': 'HS256', 'typ': 'JWT'})}.{encode({'query': payload})}.{'s' * 43}"


def _read_value(line: str) -> str:
    value, _ = json.JSONDecoder().raw_decode(line.split(" Value=", 1)[1])
    assert isinstance(value, str)
    return value


def _check_pipeline(tmp_path: Path, token: str, *, bearer: bool, capsys: Any) -> None:
    live_lines: list[str] = []
    live_file = tmp_path / "live.txt"
    live_sink = LineOutputSink(str(live_file), live_lines.append)

    def no_request(_request: Any) -> Any:
        pytest.fail("processing a supplied search hit must not fetch another document")

    def on_finding(finding: Any) -> None:
        if isinstance(finding.value, DiskBackedText):
            live_sink.emit_discovery_value(
                "ELASTIC",
                "127.0.0.1",
                9200,
                finding_type=finding.secret_type,
                value=finding.value,
                place=actions._elastic_discovery_place(finding.to_dict()),
            )
        else:
            live_sink.emit_many([actions._format_elastic_discovery_finding("127.0.0.1", 9200, finding.to_dict())])

    engine = DiscoverEngine(no_request, on_finding=on_finding)
    source_value = f"Authorization: Bearer {token}" if bearer else token
    try:
        engine._process_hit(
            "robot-logs",
            {"_index": "robot-logs", "_id": "doc-1", "_source": {"event": {"original": source_value}}},
            candidate=True,
            payload_complete=True,
        )
    finally:
        live_sink.close()

    findings = [finding.to_dict() for finding in engine.accumulator.findings()]
    assert findings
    assert all(
        (
            "".join(finding["value"].iter_text_chunks())
            if isinstance(finding["value"], DiskBackedText)
            else finding["value"]
        )
        == token
        for finding in findings
    )
    assert not engine.coverage.truncated_reasons
    for finding in findings:
        assert finding["locations"] == [
            {
                "source_kind": "document",
                "object": "robot-logs/doc-1",
                "path": "/event/original",
                "index": "robot-logs",
                "id": "doc-1",
            }
        ]

    # Both the early callback and the final output go through the real file sink.
    record = {
        "host": "127.0.0.1",
        "port": 9200,
        "status": "open_no_auth",
        "discover": True,
        "discover_schema_version": 2,
        "discover_findings": findings,
        "discover_coverage": engine.coverage.to_dict(),
    }
    final_lines: list[str] = []
    output = tmp_path / "final.txt"
    sink = LineOutputSink(str(output), final_lines.append)
    try:
        for finding in findings:
            if isinstance(finding["value"], DiskBackedText):
                sink.emit_discovery_value(
                    "ELASTIC",
                    "127.0.0.1",
                    9200,
                    finding_type=finding["secret_type"],
                    value=finding["value"],
                    place=actions._elastic_discovery_place(finding),
                )
        sink.emit_many(actions._format_detail_records(record, "txt"))
    finally:
        sink.close()
    json_output = tmp_path / "final.jsonl"
    sink = LineOutputSink(str(json_output), lambda _line: None)
    try:
        if any(isinstance(finding["value"], DiskBackedText) for finding in findings):
            sink.emit_json_chunks(iter_json_chunks({"findings": findings}))
        else:
            sink.emit_many(actions._format_detail_records(record, "json"))
    finally:
        sink.close()

    for lines in (live_file.read_text().splitlines(), output.read_text().splitlines()):
        values = [_read_value(line) for line in lines if " Value=" in line]
        assert values == [token] * len(findings)
    disk_count = sum(isinstance(finding["value"], DiskBackedText) for finding in findings)
    for lines in (live_lines, final_lines):
        assert [_read_value(line) for line in lines if " Value=" in line] == [token] * (len(findings) - disk_count)
    streamed_stdout = capsys.readouterr().out
    assert [_read_value(line) for line in streamed_stdout.splitlines() if " Value=" in line] == [token] * (
        2 * disk_count
    )
    assert "\x1b[" not in streamed_stdout and "DiskBackedText object at" not in streamed_stdout
    exported = json.loads(json_output.read_text())
    assert [finding["value"] for finding in exported["findings"]] == [token] * len(findings)
    assert all("\x1b[" not in file.read_text() for file in (live_file, output, json_output))


@pytest.mark.parametrize("query_length", [128, 1024, 16_384, 65_536])
@pytest.mark.parametrize("bearer", [False, True], ids=["jwt", "bearer"])
def test_long_tokens_survive_discovery_live_output_and_saved_txt_json(
    tmp_path: Path, query_length: int, bearer: bool, capsys: Any
) -> None:
    _check_pipeline(tmp_path, _jwt(query_length), bearer=bearer, capsys=capsys)


@pytest.mark.parametrize("source_length", [150, 512])
def test_ellipsis_already_in_source_is_preserved_without_restoring_missing_token(
    tmp_path: Path, source_length: int, capsys: Any
) -> None:
    source_token = _jwt(4096)[: source_length - 3] + "..."
    assert len(source_token) == source_length
    _check_pipeline(tmp_path, source_token, bearer=True, capsys=capsys)


def test_materialized_long_scalar_reports_the_whole_token() -> None:
    token = _jwt(4096)
    source = f"Authorization: Bearer {token}"
    engine = DiscoverEngine(
        lambda _request: pytest.fail("unexpected request"), options=DiscoverOptions(max_scalar_bytes=96)
    )
    engine._process_hit(
        "robot-logs",
        {"_index": "robot-logs", "_id": "doc-1", "_source": {"event": {"original": source}}},
        candidate=True,
        payload_complete=True,
    )
    assert engine.coverage.truncated is False
    assert "document:max_scalar_bytes" not in engine.coverage.truncated_reasons
    findings = engine.accumulator.findings()
    assert findings
    assert all(finding.value == token for finding in findings)


def test_elastic_accumulator_spools_full_disk_value_and_deduplicates() -> None:
    token = "secret-" + "abcdefgh" * 150_000
    value = DiskBackedText()
    for offset in range(0, len(token), 65_536):
        value.append_text(token[offset : offset + 65_536])
    value.finish()
    location = FindingLocation(source_kind="document", object="logs/one", path="/api_token")
    accumulator = FindingAccumulator()
    assert accumulator.add(DetectedSecret(value, "token", 85, ("sensitive_field",)), location)
    finding = next(iter(accumulator.findings()))
    assert finding.value is value
    assert len(accumulator.findings().to_dict_spool()) == 1
    assert accumulator.fingerprint("token", token) == finding.fingerprint
    value.close()


def test_streamed_elastic_hit_keeps_full_indivisible_secret_on_disk(tmp_path: Path) -> None:
    token = "token-" + "abcdefghi" * 150_000
    payload = {
        "hits": {
            "total": {"value": 1, "relation": "eq"},
            "hits": [{"_index": "logs", "_id": "one", "_source": {"api_token": token}}],
        }
    }
    stream = StreamedSearchPage(io.BytesIO(json.dumps(payload).encode()), inline_limit=128)
    parsed = stream.summary()
    engine = DiscoverEngine(lambda _request: pytest.fail("unexpected request"))
    engine._consume_search_page(
        "logs",
        DiscoverResponse(200, b"", streamed_search=stream),
        parsed,
        candidate=True,
        payload_complete=True,
    )
    findings = engine.accumulator.findings()
    assert len(findings) == 1
    finding = findings[0]
    assert isinstance(finding.value, DiskBackedText)
    assert "".join(finding.value.iter_text_chunks()) == token
    assert not engine.coverage.truncated_reasons
    output = tmp_path / "findings.json"
    output.write_text("".join(iter_json_chunks(engine._finalize().to_dict())))
    assert json.loads(output.read_text())["discover_findings"][0]["value"] == token
    assert "\x1b[" not in output.read_text()
    finding.value.close()


def test_streamed_elastic_bearer_field_keeps_token_without_header() -> None:
    token = "eyJ" + "Ab0" * 400_000
    payload = {
        "hits": {
            "total": {"value": 1, "relation": "eq"},
            "hits": [
                {
                    "_index": "logs",
                    "_id": "one",
                    "_source": {"event": {"original": f"Authorization: Bearer {token}"}},
                }
            ],
        }
    }
    stream = StreamedSearchPage(io.BytesIO(json.dumps(payload).encode()), inline_limit=128)
    parsed = stream.summary()
    engine = DiscoverEngine(lambda _request: pytest.fail("unexpected request"))
    engine._consume_search_page(
        "logs",
        DiscoverResponse(200, b"", streamed_search=stream),
        parsed,
        candidate=True,
        payload_complete=True,
    )
    findings = engine.accumulator.findings()
    assert len(findings) == 1
    finding = findings[0]
    assert finding.secret_type == "bearer_token"
    assert isinstance(finding.value, DiskBackedText)
    assert "".join(finding.value.iter_text_chunks()) == token
    assert not engine.coverage.truncated_reasons
    finding.value.close()


def test_streamed_elastic_weak_bearer_is_fully_inspected_without_cut_findings() -> None:
    payload = {
        "hits": {
            "total": {"value": 1, "relation": "eq"},
            "hits": [
                {
                    "_index": "logs",
                    "_id": "one",
                    "_source": {"event": {"original": "Authorization: Bearer " + "Ab0" * 1000 + "\nother log data"}},
                }
            ],
        }
    }
    stream = StreamedSearchPage(io.BytesIO(json.dumps(payload).encode()), inline_limit=128)
    parsed = stream.summary()
    engine = DiscoverEngine(lambda _request: pytest.fail("unexpected request"))
    engine._consume_search_page(
        "logs",
        DiscoverResponse(200, b"", streamed_search=stream),
        parsed,
        candidate=True,
        payload_complete=True,
    )
    assert not engine.accumulator.findings()
    assert not engine.coverage.truncated_reasons


@pytest.mark.parametrize("placeholder", ["x", "*", "-"])
def test_streamed_elastic_placeholder_is_not_a_finding(placeholder: str) -> None:
    payload = {
        "hits": {
            "total": {"value": 1, "relation": "eq"},
            "hits": [{"_index": "logs", "_id": "one", "_source": {"api_token": placeholder * 5000}}],
        }
    }
    stream = StreamedSearchPage(io.BytesIO(json.dumps(payload).encode()), inline_limit=128)
    parsed = stream.summary()
    engine = DiscoverEngine(lambda _request: pytest.fail("unexpected request"))
    engine._consume_search_page(
        "logs",
        DiscoverResponse(200, b"", streamed_search=stream),
        parsed,
        candidate=True,
        payload_complete=True,
    )
    assert not engine.accumulator.findings()
    assert not engine.coverage.truncated_reasons
