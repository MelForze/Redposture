from __future__ import annotations

from redposture_core.modules.minio import render


def _record(**over):
    base = {
        "host": "10.0.0.5",
        "port": 19000,
        "detection_status": "confirmed",
        "auth_required": True,
    }
    base.update(over)
    return base


class _Console:
    def __init__(self):
        self.lines = []

    def _paint(self, text, color, _s):
        return f"<{color}>{text}</{color}>"

    def plain(self, line):
        self.lines.append(line)


def test_detect_record_is_minimal_house_style():
    line = render._format_detect_record(_record(), "txt")
    assert line == "MINIO\t10.0.0.5\t19000\t [*] MinIO (auth required:True)"
    # no detection/api/anonymous clutter
    assert "detection:" not in line and "api:" not in line and "anonymous:" not in line


def test_detect_record_auth_required_false_when_anonymous():
    line = render._format_detect_record(_record(auth_required=False), "txt")
    assert "(auth required:False)" in line


def test_detect_and_records_emit_nothing_for_json():
    assert render._format_detect_record(_record(), "json") == ""
    assert render._format_record(_record(credential_state="valid"), "json") == ""
    assert render._format_minio_detail_records(_record(), "json") == []


def test_not_minio_suppressed():
    assert render._format_detect_record(_record(detection_status="not_minio"), "txt") == ""
    assert render._format_minio_detail_records(_record(detection_status="transport_failure"), "txt") == []


def test_record_line_admin_boolean_no_credential_identity_or_defcreds():
    rec = _record(
        credential_state="valid",
        credential_results=[{"access_key": "minioadmin", "state": "valid"}],
        admin_capability="confirmed",
        identity_kind="delegated_admin",
        default_credentials=True,
    )
    line = render._format_record(rec, "txt")
    assert line == "MINIO\t10.0.0.5\t19000\t [+] minioadmin (admin:True)"
    # `[+]` already means the credential is valid -> no redundant (credential:...)
    assert "(credential:" not in line
    # identity is questionable/non-standard in the summary; kept only in JSON
    assert "(identity:" not in line
    # the default-creds fact stays in JSON only; the TXT line does not repeat it
    assert "(default creds:" not in line


def test_record_line_appends_bucket_and_object_counts():
    rec = _record(
        credential_state="valid",
        credential_results=[{"access_key": "minioadmin", "state": "valid"}],
        admin_capability="not_confirmed",
        buckets=[{"name": "a"}, {"name": "b"}, {"name": "c"}],
        objects_streamed=True,
        objects_count=2,  # objects are streamed; the count comes from the stream, not a list
    )
    line = render._format_record(rec, "txt")
    assert line == "MINIO\t10.0.0.5\t19000\t [+] minioadmin (admin:False) (buckets:3) (objects:2)"


def test_record_line_counts_absent_without_enumeration():
    rec = _record(
        credential_state="valid",
        credential_results=[{"access_key": "minioadmin", "state": "valid"}],
        admin_capability="confirmed",
    )
    line = render._format_record(rec, "txt")
    assert "(buckets:" not in line and "(objects:" not in line


def test_record_line_admin_boolean_mapping():
    def _admin(cap):
        rec = _record(
            credential_state="valid",
            credential_results=[{"access_key": "k", "state": "valid"}],
            admin_capability=cap,
        )
        return render._format_record(rec, "txt")

    assert "(admin:True)" in _admin("confirmed")
    assert "(admin:True)" in _admin("partial")
    assert "(admin:False)" in _admin("not_confirmed")
    assert "(admin:unknown)" in _admin("unknown")


def test_record_line_empty_for_anonymous_or_invalid():
    assert render._format_record(_record(), "txt") == ""
    assert render._format_record(_record(credential_state="invalid"), "txt") == ""


def test_auth_required_colored_green_true_red_false():
    console = _Console()
    render._render_colored_minio_line(console, render._format_detect_record(_record(auth_required=True), "txt"))
    assert "<bright_green>auth required:True</bright_green>" in console.lines[0]
    console = _Console()
    render._render_colored_minio_line(console, render._format_detect_record(_record(auth_required=False), "txt"))
    assert "<true_red>auth required:False</true_red>" in console.lines[0]


def test_record_line_colors_admin_and_counts():
    rec = _record(
        credential_state="valid",
        credential_results=[{"access_key": "minioadmin", "state": "valid"}],
        admin_capability="confirmed",
        buckets=[{"name": "a"}, {"name": "b"}],
        objects_streamed=True,
        objects_count=1,
    )
    console = _Console()
    render._render_colored_minio_line(console, render._format_record(rec, "txt"))
    out = console.lines[0]
    assert "<true_red>admin:True</true_red>" in out
    assert "<true_red>buckets:2</true_red>" in out
    assert "<true_red>objects:1</true_red>" in out


_PFX = "MINIO\t10.0.0.5\t19000\t"


def test_detail_lines_buckets_header_and_streamed_objects_header_only():
    rec = _record(
        buckets=[{"name": "bulk"}, {"name": "public"}],
        objects_streamed=True,
        objects_count=5000,
        secret_findings=[
            {
                "type": "aws_access_key",
                "bucket": "public",
                "key": "creds.env",
                "masked_value": "AKIA...MPLE",
                "object_path": "$",
            }
        ],
        discover_partial_reasons=["object_too_large"],
    )
    lines = render._format_minio_detail_records(rec, "txt")
    body = "\n".join(lines)
    assert f"{_PFX} [*] Show Buckets (Count:2)" in lines
    assert f"{_PFX} bulk" in lines
    assert f"{_PFX} public" in lines
    # objects are streamed by the runtime -> only the header is rendered here
    assert f"{_PFX} [*] Show Objects (Count:5000)" in lines
    assert not any("/" in line.split("\t")[-1] and "size:" in line for line in lines)
    assert "[+] bucket" not in body and "[+] object" not in body
    # clickhouse-style finding line: type, then value=/place= (no "secret" word)
    assert '[+] aws_access_key value="AKIA...MPLE" place="public/creds.env$"' in body
    assert "[+] secret " not in body
    assert "[!] Discover partial: object_too_large" in body


def test_discover_summary_line_clickhouse_style():
    rec = _record(
        discover_requested=True,
        discover_coverage="complete",
        discover_coverage_percent=100.0,
        discover_candidates_count=3,
        discover_objects_scanned=3,
        secret_findings=[
            {
                "type": "aws_access_key",
                "bucket": "creds",
                "key": "app.env",
                "masked_value": "AKIA...MPLE",
                "object_path": "$",
            },
            {
                "type": "password",
                "bucket": "creds",
                "key": "db.yml",
                "masked_value": "p***d",
                "object_path": ".db.pass",
            },
        ],
    )
    lines = render._format_minio_detail_records(rec, "txt")
    assert f"{_PFX} [*] Discover Secrets (status:complete) (coverage:100.00%) (findings:2) (objects:3)" in lines
    assert f'{_PFX} [+] aws_access_key value="AKIA...MPLE" place="creds/app.env$"' in lines
    assert f'{_PFX} [+] password value="p***d" place="creds/db.yml.db.pass"' in lines


def test_discover_summary_partial_with_zero_findings():
    rec = _record(
        discover_requested=True,
        discover_coverage="partial",
        discover_coverage_percent=42.86,
        discover_candidates_count=7,
        discover_objects_scanned=3,
        secret_findings=[],
        discover_partial_reasons=["object_limit"],
    )
    body = "\n".join(render._format_minio_detail_records(rec, "txt"))
    assert "[*] Discover Secrets (status:partial) (coverage:42.86%) (findings:0) (objects:3)" in body
    assert "[!] Discover partial: object_limit" in body


def test_discover_summary_health_coloring():
    rec = _record(
        discover_requested=True,
        discover_coverage="complete",
        discover_coverage_percent=100.0,
        discover_candidates_count=2,
        discover_objects_scanned=2,
        secret_findings=[
            {"type": "aws_access_key", "bucket": "b", "key": "k", "masked_value": "x", "object_path": "$"}
        ],
    )
    summary = next(line for line in render._format_minio_detail_records(rec, "txt") if "Discover Secrets" in line)
    console = _Console()
    assert render._render_colored_minio_line(console, summary) is True
    out = console.lines[0]
    assert "<bright_green>status:complete</bright_green>" in out
    assert "<bright_green>coverage:100.00%</bright_green>" in out
    assert "<true_red>findings:1</true_red>" in out  # any finding is exposure


def test_object_stream_line_txt_and_json():
    obj = {"bucket": "bulk", "key": "a/b.txt", "size": 42}
    assert render.object_stream_line("10.0.0.5", 19000, obj, "txt") == f"{_PFX} bulk/a/b.txt (size:42)"
    js = render.object_stream_line("10.0.0.5", 19000, obj, "json")
    import json as _json

    parsed = _json.loads(js)
    assert parsed == {
        "type": "object",
        "host": "10.0.0.5",
        "port": 19000,
        "bucket": "bulk",
        "key": "a/b.txt",
        "size": 42,
    }


def test_streamed_object_line_is_orange_and_bucket_header_renders():
    rec = _record(buckets=[{"name": "bulk"}], objects_streamed=True, objects_count=3)
    lines = render._format_minio_detail_records(rec, "txt")

    header = next(line for line in lines if "Show Objects" in line)
    console = _Console()
    assert render._render_colored_minio_line(console, header) is True

    # a bare bucket item is orange
    bucket_line = next(line for line in lines if line == f"{_PFX} bulk")
    console = _Console()
    assert render._render_colored_minio_line(console, bucket_line) is True
    assert "<orange>" in console.lines[0]

    # a streamed object line (as emitted from the temp file) is orange too
    obj_line = render.object_stream_line("10.0.0.5", 19000, {"bucket": "bulk", "key": "k.txt", "size": 2}, "txt")
    console = _Console()
    assert render._render_colored_minio_line(console, obj_line) is True
    assert "<orange>" in console.lines[0]


def test_write_probe_status_on_bucket_lines_and_leftover():
    rec = _record(
        buckets=[{"name": "rw"}, {"name": "ro"}],
        write_probe={"rw": {"write": True, "cleanup": "ok"}, "ro": {"write": False}},
        write_probe_leftovers=[{"bucket": "rw", "key": ".redposture-probe-xyz"}],
    )
    lines = render._format_minio_detail_records(rec, "txt")
    assert f"{_PFX} rw (write:True)" in lines
    assert f"{_PFX} ro (write:False)" in lines
    assert f"{_PFX} [!] canary left behind: rw/.redposture-probe-xyz" in lines
    # write:True is colored red (exposure)
    console = _Console()
    render._render_colored_minio_line(console, f"{_PFX} rw (write:True)")
    assert "<true_red>write:True</true_red>" in console.lines[0]


def test_write_probe_section_without_show_buckets():
    rec = _record(write_probe={"rw": {"write": True}})
    lines = render._format_minio_detail_records(rec, "txt")
    assert f"{_PFX} [*] Write Probe (Count:1)" in lines
    assert f"{_PFX} rw (write:True)" in lines


def test_secret_finding_line_still_orange():
    rec = _record(
        secret_findings=[
            {
                "type": "aws_access_key",
                "bucket": "b",
                "key": "creds.env",
                "masked_value": "AKIA...MPLE",
                "object_path": "$",
            }
        ]
    )
    lines = render._format_minio_detail_records(rec, "txt")
    secret_line = next(line for line in lines if " value=" in line and " place=" in line)
    console = _Console()
    assert render._render_colored_minio_line(console, secret_line) is True
    assert "<orange>" in console.lines[0]


def test_detect_record_appends_version_when_known():
    line = render._format_detect_record(_record(version="2025-09-07T16:13:09Z"), "txt")
    assert line == "MINIO\t10.0.0.5\t19000\t [*] MinIO (auth required:True) (version:2025-09-07T16:13:09Z)"


def test_detect_record_omits_version_when_unknown():
    line = render._format_detect_record(_record(), "txt")
    assert "(version:" not in line


def test_credential_attempts_render_rejected_and_skip_winner():
    rec = _record(
        credential_state="valid",
        credential_results=[{"access_key": "minioadmin", "state": "valid"}],
        admin_capability="confirmed",
        attempted_credentials=[
            {"username": "minioadmin", "password": "minioadmin", "credential_state": "valid"},
            {"username": "minio", "password": "minio123", "credential_state": "invalid"},
            {"username": "admin", "password": "", "credential_state": "invalid"},
        ],
    )
    lines = render._format_credential_attempts_records(rec, "txt")
    body = "\n".join(lines)
    # the accepted winner is rendered by _format_record, not here
    assert "minioadmin" not in body
    assert f"{_PFX} [-] minio:minio123" in lines
    assert f"{_PFX} [-] admin:<empty>" in lines


def test_credential_attempts_render_accepted_non_selected():
    rec = _record(
        credential_state="valid",
        credential_results=[{"access_key": "minioadmin", "state": "valid"}],
        attempted_credentials=[
            {"username": "minioadmin", "password": "minioadmin", "credential_state": "valid"},
            {"username": "admin", "password": "admin", "credential_state": "valid"},
        ],
    )
    lines = render._format_credential_attempts_records(rec, "txt")
    assert f"{_PFX} [+] admin" in lines  # a second working default cred is surfaced
    assert not any("minioadmin" in line for line in lines)  # winner skipped (shown by _format_record)


def test_credential_attempts_empty_for_single_or_json():
    assert render._format_credential_attempts_records(_record(), "txt") == []
    single = _record(attempted_credentials=[{"username": "a", "password": "b", "credential_state": "invalid"}])
    assert render._format_credential_attempts_records(single, "txt") == []
    multi = _record(
        attempted_credentials=[
            {"username": "a", "password": "b", "credential_state": "invalid"},
            {"username": "c", "password": "d", "credential_state": "invalid"},
        ]
    )
    assert render._format_credential_attempts_records(multi, "json") == []
