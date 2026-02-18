from __future__ import annotations

import pytest

from honeycore.cli_args import COMMAND_LISTEN, parse_args


def test_parse_args_defaults_to_listen() -> None:
    args = parse_args([])
    assert args.command == COMMAND_LISTEN


def test_listen_defaults_have_tls_disabled() -> None:
    args = parse_args(["listen"])
    assert args.postgres_tls is False
    assert args.proxmox_tls is False


def test_scan_flags_are_parsed() -> None:
    args = parse_args([
        "scan",
        "-t",
        "10.0.0.1,10.0.0.2",
        "--timeout",
        "1.5",
        "-w",
        "12",
        "-r",
        "3",
        "--profiles-file",
        "profiles.json",
        "-f",
        "json",
        "-o",
        "scan.jsonl",
        "-m",
        "4096",
    ])
    assert args.command == "scan"
    assert args.targets == "10.0.0.1,10.0.0.2"
    assert args.timeout == 1.5
    assert args.workers == 12
    assert args.retries == 3
    assert args.profiles_file == "profiles.json"
    assert args.output_format == "json"
    assert args.output == "scan.jsonl"
    assert args.max_bytes == 4096


def test_scan_workers_and_retries_defaults() -> None:
    args = parse_args(["scan", "-t", "10.0.0.1"])
    assert args.workers == 10
    assert args.retries == 3


def test_trigger_can_parse_without_callback_values() -> None:
    args = parse_args(["trigger", "-t", "10.0.0.1"])
    assert args.command == "trigger"
    assert args.callback_ip is None
    assert args.callback_dns is None


def test_trigger_with_listen_flag_and_listener_defaults() -> None:
    args = parse_args(["trigger", "-t", "10.0.0.1", "--callback-ip", "10.0.0.2", "--with-listen"])
    assert args.with_listen is True
    assert args.callback_ip == "10.0.0.2"
    assert args.callback_dns is None
    assert args.services == "postgres,redis,proxmox,blackbox"
    assert args.bind == "0.0.0.0"
    assert args.postgres_port == 5432
    assert args.redis_port == 6379
    assert args.proxmox_port == 8006
    assert args.blackbox_port == 9115
    assert args.postgres_tls is False
    assert args.proxmox_tls is False


def test_trigger_workers_and_retries_flags_are_parsed() -> None:
    args = parse_args(["trigger", "-t", "10.0.0.1", "--callback-ip", "10.0.0.2", "-w", "20", "-r", "2"])
    assert args.workers == 20
    assert args.retries == 2


def test_trigger_with_optional_callback_dns_flag() -> None:
    args = parse_args(
        [
            "trigger",
            "-t",
            "10.0.0.1",
            "--callback-ip",
            "10.0.0.2",
            "--callback-dns",
            "honeypot.example.com",
        ]
    )
    assert args.callback_ip == "10.0.0.2"
    assert args.callback_dns == "honeypot.example.com"


def test_version_flag_exits_cleanly() -> None:
    with pytest.raises(SystemExit) as exc:
        parse_args(["--version"])
    assert exc.value.code == 0
