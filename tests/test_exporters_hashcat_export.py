"""Explicit MySQL exporter hash export, independent of human/JSON output."""

from __future__ import annotations

import os

import pytest

from redposture_core import stage_trigger as trigger
from redposture_core.cli_args import parse_args
from redposture_core.logger import AttemptLogger

SALT = "12" * 20
RESPONSE = "ab" * 20
HASH = f"$mysqlna${SALT}*{RESPONSE}"
BASE = ["exporters", "trigger", "-t", "127.0.0.1:19104", "--callback-ip", "127.0.0.1", "-e", "mysql"]


def capture(logger: AttemptLogger) -> None:
    logger.log(
        "mysql",
        ("127.0.0.1", 50000),
        username="exporter",
        auth_plugin="mysql_native_password",
        auth_salt=SALT,
        auth_response=RESPONSE,
        listen_port=13306,
    )


@pytest.fixture
def offline_trigger(monkeypatch):
    def scan(*args, **kwargs):
        return {"detected_exporters": 1, "attempted": 1, "triggered": 1, "failed": 0, "by_host": {}, "by_callback": {}}

    def start(args, logger, console):
        capture(logger)
        capture(logger)
        logger.log(
            "mysql",
            ("127.0.0.1", 50001),
            username="exporter",
            auth_plugin="caching_sha2_password",
            auth_salt=SALT,
            auth_response=RESPONSE,
        )
        return [], None

    def interrupted(seconds):
        raise KeyboardInterrupt

    monkeypatch.setattr(trigger, "scan_exporters_and_trigger", scan)
    monkeypatch.setattr(trigger, "start_listeners_for_trigger", start)
    monkeypatch.setattr(trigger, "stop_started_listeners", lambda *args: None)
    monkeypatch.setattr(trigger.time, "sleep", interrupted)


@pytest.mark.parametrize(
    "export_args,expected",
    [
        ([], None),
        (["--export-hashcat"], "mysql_hashes.hashcat"),
        (["--export-hashcat", "chosen.hashes"], "chosen.hashes"),
    ],
)
def test_export_flag_accepts_default_and_explicit_path(export_args, expected):
    assert parse_args(BASE + export_args).export_hashcat == expected


def test_flag_is_in_mysql_help_group(capsys):
    with pytest.raises(SystemExit):
        parse_args(["exporters", "trigger", "-h"])
    section = capsys.readouterr().out.split("MySQL exporter:", 1)[1].split("JSON exporter:", 1)[0]
    assert "--export-hashcat" in section


@pytest.mark.parametrize("fmt", ["txt", "json"])
def test_export_is_exact_unique_private_and_separate(tmp_path, offline_trigger, fmt):
    hashes = tmp_path / "nested" / "chosen.hashes"
    output = tmp_path / f"trigger.{fmt}"
    args = parse_args(BASE + ["--export-hashcat", str(hashes), "-o", str(output), "-f", fmt, "--no-color"])
    logger = AttemptLogger()
    try:
        assert trigger.run_trigger_stage(args, logger) == 0
    finally:
        logger.close()
    assert hashes.read_text() == HASH + "\n"
    assert os.stat(hashes).st_mode & 0o777 == 0o600
    assert output.exists()
    assert not (tmp_path / "trigger.mysql.hashes.hashcat").exists()
    assert "\x1b" not in hashes.read_text() + output.read_text()


def test_bare_flag_exports_without_regular_output(tmp_path, monkeypatch, offline_trigger):
    monkeypatch.chdir(tmp_path)
    logger = AttemptLogger()
    try:
        assert trigger.run_trigger_stage(parse_args(BASE + ["--export-hashcat"]), logger) == 0
    finally:
        logger.close()
    assert (tmp_path / "mysql_hashes.hashcat").read_text() == HASH + "\n"


@pytest.mark.parametrize(
    "extra,reason",
    [
        (["--no-with-listen"], "requires listeners"),
        (["-e", "redis"], "requires MySQL"),
        (["--export-hashcat", ""], "must not be empty"),
    ],
)
def test_invalid_combinations_fail_before_creating_files(tmp_path, monkeypatch, capsys, extra, reason):
    monkeypatch.chdir(tmp_path)
    assert trigger.run_trigger_stage(parse_args(BASE + ["--export-hashcat"] + extra), AttemptLogger()) == 2
    captured = capsys.readouterr()
    assert reason in captured.out + captured.err
    assert not (tmp_path / "mysql_hashes.hashcat").exists()


@pytest.mark.parametrize("fmt", ["txt", "json"])
def test_hash_path_cannot_overwrite_regular_output(tmp_path, fmt, capsys):
    path = tmp_path / "same.txt"
    path.write_text("preserve\n")
    args = parse_args(BASE + ["--export-hashcat", str(path), "-o", str(path), "-f", fmt])
    assert trigger.run_trigger_stage(args, AttemptLogger()) == 2
    assert path.read_text() == "preserve\n"
    assert "different" in capsys.readouterr().err


def test_unwritable_export_path_is_reported_without_traceback(tmp_path, capsys):
    args = parse_args(BASE + ["--export-hashcat", str(tmp_path)])
    assert trigger.run_trigger_stage(args, AttemptLogger()) == 2
    assert "failed to open MySQL hashcat output" in capsys.readouterr().err


def test_mysql_alias_keeps_existing_automatic_sidecar(tmp_path, offline_trigger):
    output = tmp_path / "trigger.txt"
    logger = AttemptLogger()
    try:
        assert trigger.run_trigger_stage(parse_args(BASE + ["-o", str(output)]), logger) == 0
    finally:
        logger.close()
    assert (tmp_path / "trigger.mysql.hashes.hashcat").read_text() == HASH + "\n"


def test_empty_capture_creates_empty_file(tmp_path, monkeypatch, offline_trigger):
    monkeypatch.setattr(trigger, "start_listeners_for_trigger", lambda *args: ([], None))
    path = tmp_path / "empty.hashes"
    logger = AttemptLogger()
    try:
        assert trigger.run_trigger_stage(parse_args(BASE + ["--export-hashcat", str(path)]), logger) == 0
    finally:
        logger.close()
    assert path.read_bytes() == b""


def test_exact_output_deduplicates_concurrent_callbacks(tmp_path):
    from concurrent.futures import ThreadPoolExecutor

    path = tmp_path / "concurrent.hashes"
    path.write_text("old capture\n")
    path.chmod(0o644)
    logger = AttemptLogger()
    logger.set_mysql_hash_output(str(path), exact_path=True)
    logger.set_trigger_callback_mode(True)
    try:
        with ThreadPoolExecutor(max_workers=8) as workers:
            list(workers.map(lambda _: capture(logger), range(40)))
    finally:
        logger.close()
    assert path.read_text() == HASH + "\n"
    assert os.stat(path).st_mode & 0o777 == 0o600
