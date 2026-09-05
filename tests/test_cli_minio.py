from __future__ import annotations

import pytest

from redposture_core.cli_args import parse_args
from redposture_core.modules.minio.stage import build_minio_plan


def test_minio_default_ports_include_offsets():
    plan = build_minio_plan(parse_args(["minio", "-t", "127.0.0.1"]))
    assert plan.ports == (9000, 9001, 80, 443, 10080, 10443, 19000, 19001, 20080, 20443, 29000, 29001)


def test_minio_registered_and_parses_bare_host():
    args = parse_args(["minio", "-t", "127.0.0.1"])
    assert args.command == "minio"
    assert args.targets == "127.0.0.1"


def test_minio_credentials_and_session_token_parse():
    args = parse_args(["minio", "-t", "127.0.0.1", "-u", "AKID", "-p", "SECRET", "--session-token", "TOK"])
    assert args.username == "AKID"
    assert args.password == "SECRET"
    assert args.session_token == "TOK"


def test_minio_no_color_flag():
    args = parse_args(["minio", "-t", "127.0.0.1", "--no-color"])
    assert args.no_color is True


def test_minio_output_format_and_file_flags_parse():
    args = parse_args(["minio", "-t", "127.0.0.1", "-f", "json", "-o", "out.json"])
    assert args.output_format == "json"
    assert args.output == "out.json"
    assert parse_args(["minio", "-t", "127.0.0.1"]).output_format == "txt"


@pytest.mark.parametrize("flag", ["--https", "--insecure", "--ca-file"])
def test_minio_transport_flags_removed(flag: str):
    # Transport is auto-detected now (scheme probe + certificates always accepted);
    # the manual transport flags no longer exist.
    with pytest.raises(SystemExit):
        parse_args(["minio", "-t", "127.0.0.1", flag, "x"])


def test_minio_limit_flag_removed():
    # Object listing is now unbounded + streamed (no in-memory materialisation),
    # so the --limit knob is gone.
    with pytest.raises(SystemExit):
        parse_args(["minio", "-t", "127.0.0.1", "--limit", "5"])


def test_minio_probe_write_flag_parses():
    assert parse_args(["minio", "-t", "127.0.0.1", "--probe-write"]).probe_write is True
    assert parse_args(["minio", "-t", "127.0.0.1"]).probe_write is False


def test_minio_object_dump_download_flags_parse():
    args = parse_args(["minio", "-t", "127.0.0.1", "--object", "bulk/creds.env", "--dump", "--download", "/tmp/out"])
    assert args.object == "bulk/creds.env"
    assert args.dump is True
    assert args.download == "/tmp/out"
    base = parse_args(["minio", "-t", "127.0.0.1"])
    assert base.object is None and base.dump is False and base.download is None
