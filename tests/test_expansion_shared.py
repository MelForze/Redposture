"""Behavioral edge cases for shared capture, credential input and spray state."""

from __future__ import annotations

import base64
import json
import socket
from pathlib import Path
from types import SimpleNamespace

import pytest
from hypothesis import given
from hypothesis import strategies as st

from redposture_core import shell_capture as capture
from redposture_core import stage_spray as spray
from redposture_core import utils


class _Console:
    def __init__(self) -> None:
        self.lines: list[tuple[str, str]] = []

    def plain(self, line: str, *, color: str) -> None:
        self.lines.append((line, color))


def _frame(stdout: bytes = b"abc", stderr: bytes = b"error") -> list[str]:
    return [
        "RP:qa:STATUS:7",
        f"RP:qa:STDOUT:{len(stdout)}",
        base64.b64encode(stdout).decode(),
        "RP:qa:ENDSTDOUT",
        f"RP:qa:STDERR:{len(stderr)}",
        base64.b64encode(stderr).decode(),
        "RP:qa:ENDSTDERR",
        "RP:qa:END",
    ]


@pytest.mark.parametrize(
    ("index", "replacement", "error"),
    [
        (0, "RP:other:STATUS:0", "invalid capture response"),
        (0, "RP:qa:STATUS:no", "exit status"),
        (1, "RP:qa:STDERR:3", "incomplete"),
        (1, "RP:qa:STDOUT:no", "byte count"),
        (1, "RP:qa:STDOUT:-1", "byte count"),
        (1, "RP:qa:STDOUT:4", "count mismatch"),
        (3, "RP:qa:MISSING", "incomplete"),
        (4, "RP:qa:STDERR:-1", "byte count"),
        (5, "not_base64!", "base64"),
        (6, "RP:qa:MISSING", "incomplete"),
        (7, "RP:qa:MISSING", "incomplete"),
    ],
)
def test_capture_rejects_corrupt_sections(index: int, replacement: str, error: str) -> None:
    lines = _frame()
    lines[index] = replacement
    with pytest.raises(ValueError, match=error):
        capture.parse_capture_lines(lines, "qa")


def test_capture_rejects_extra_sections_before_final_marker() -> None:
    lines = _frame()
    lines.insert(-1, "RP:qa:EXTRA")
    with pytest.raises(ValueError, match="unexpected"):
        capture.parse_capture_lines(lines, "qa")


@pytest.mark.parametrize("limit", [0, -1, capture.MAX_CAPTURE_BYTES + 1])
def test_capture_rejects_out_of_range_limits(limit: int) -> None:
    with pytest.raises(ValueError, match="out of range"):
        capture.build_capture_command("id", "qa", max_bytes=limit)
    with pytest.raises(ValueError, match="out of range"):
        capture.parse_capture_lines(_frame(), "qa", max_bytes=limit)


@pytest.mark.parametrize("command", ["echo one\necho two", "echo one\recho two"])
def test_capture_rejects_multiline_command(command: str) -> None:
    with pytest.raises(ValueError, match="one line"):
        capture.build_capture_command(command, "qa")


@pytest.mark.parametrize("token", ["", "bad:token", "bad token"])
def test_capture_rejects_invalid_framing_token(token: str) -> None:
    with pytest.raises(ValueError, match="alphanumeric"):
        capture.build_capture_command("id", token)


@given(stdout=st.binary(max_size=512), stderr=st.binary(max_size=512), limit=st.integers(1, 512))
def test_capture_exact_bytes_and_truncation_are_independent_per_stream(
    stdout: bytes, stderr: bytes, limit: int
) -> None:
    lines = _frame(stdout[:limit], stderr[:limit])
    lines[1] = f"RP:qa:STDOUT:{len(stdout)}"
    lines[4] = f"RP:qa:STDERR:{len(stderr)}"
    result = capture.parse_capture_lines(lines, "qa", max_bytes=limit)
    assert result.stdout == stdout[:limit]
    assert result.stderr == stderr[:limit]
    assert result.stdout_total == len(stdout)
    assert result.stderr_total == len(stderr)
    assert result.exit_code == 7
    assert result.truncated == (len(stdout) > limit or len(stderr) > limit)
    assert all("\x1b" not in line for line, _ in capture.format_result(result))


@pytest.mark.parametrize(
    ("command", "message"),
    [
        (':"', "quotation"),
        (":unknown", "Unknown local command"),
        (":limit", "usage"),
        (":limit 51M", "50 MiB"),
        (":limit NaN", "invalid literal"),
        (":hex stdout 0", "preview"),
        (":hex stdout 65537", "preview"),
        (":hex stdout 1 extra", "usage"),
        (":save", "usage"),
    ],
)
def test_local_shell_controls_report_errors_without_forwarding(command: str, message: str) -> None:
    view, console = capture.ShellView(), _Console()
    view.last = capture.CommandResult(stdout=b"abc")
    assert view.handle(command, console) == (True, False)
    assert message.lower() in console.lines[-1][0].lower()
    assert console.lines[-1][1] == "orange"


def test_local_shell_preview_save_and_failure_preserve_original_bytes(tmp_path: Path) -> None:
    view, console = capture.ShellView(), _Console()
    view.last = capture.CommandResult(stdout=b"\x00\xff\r", stderr=b"bad\x00", stdout_total=99)
    assert view.handle(":base64 stderr 2", console) == (True, False)
    assert console.lines[0] == (base64.b64encode(b"ba").decode(), "orange")
    assert "first 2 of 4" in console.lines[1][0]
    destination = tmp_path / "capture.bin"
    assert view.handle(f":save '{destination}'", console) == (True, False)
    assert destination.read_bytes() == b"\x00\xff\r"
    assert "partial" in console.lines[-1][0]
    view.handle(f":save '{destination}'", console)
    assert "Save failed" in console.lines[-1][0]
    assert destination.read_bytes() == b"\x00\xff\r"
    with pytest.raises(ValueError, match="stream"):
        capture.save_result_stream(view.last, tmp_path / "wrong", stream="both")


@pytest.mark.parametrize("operation", [":hex", ":base64", ":save out"])
def test_local_shell_requires_previous_result(operation: str) -> None:
    console = _Console()
    assert capture.ShellView().handle(operation, console) == (True, False)
    assert console.lines == [("[-] No command result yet", "orange")]


def test_capture_text_handles_stderr_carriage_return_and_empty_streams() -> None:
    result = capture.CommandResult(stderr=b"one\rtwo\n", stderr_total=20)
    assert capture.result_text_lines(result) == ["stderr: one\\rtwo", "[output truncated during capture]"]
    assert capture.format_result(capture.CommandResult(error="connection timeout")) == [
        ("[-] connection timeout", "bright_green")
    ]
    assert "exit:unknown" in capture.format_result(capture.CommandResult())[0][0]


@given(
    users=st.lists(st.sampled_from(["alice", "bob", "carol"]), unique=True, max_size=3),
    passwords=st.lists(st.sampled_from(["", "a:b", " spaced "]), unique=True, max_size=3),
    explicit=st.lists(st.tuples(st.sampled_from(["alice", "other"]), st.sampled_from(["", " spaced "])), unique=True),
)
def test_spray_lazy_catalog_matches_independent_ordered_cartesian_model(
    users: list[str], passwords: list[str], explicit: list[tuple[str, str]]
) -> None:
    pairs = tuple(spray.Candidate("pair", u, p) for u, p in explicit)
    catalog = spray.CandidateCatalog(pairs, tuple(users), tuple(passwords), ("token",))
    expected = list(pairs)
    expected.extend(spray.Candidate("pair", u, p) for p in passwords for u in users if (u, p) not in explicit)
    expected.append(spray.Candidate("token", token="token"))
    assert list(catalog) == expected
    assert len(catalog) == len(expected)
    assert [catalog[i] for i in range(len(catalog))] == expected
    assert catalog[::-1] == tuple(reversed(expected))
    assert catalog[-len(catalog)] == expected[0]
    for index in (len(catalog), -len(catalog) - 1):
        with pytest.raises(IndexError):
            _ = catalog[index]


@pytest.mark.parametrize(
    "value",
    [
        [],
        {"redis": []},
        {"not-a-module": {}},
        {"redis": {"tls": "true"}},
        {"redis": {"tls": 1}},
        {"redis": {"nonsense": "x"}},
        {"redis": {"database": ""}},
        {"redis": {"database": 1}},
    ],
)
def test_spray_module_config_rejects_wrong_shapes_and_types(tmp_path: Path, value: object) -> None:
    path = tmp_path / "config.json"
    path.write_text(json.dumps(value))
    with pytest.raises(ValueError, match="module-config"):
        spray._config(str(path), ("redis",))


def test_spray_journal_replay_is_snapshot_bounded_and_target_scoped(tmp_path: Path) -> None:
    journal = spray.AttemptJournal(str(tmp_path / "spray.db"), "fingerprint", False)
    try:
        journal.put("a", "redis", "host", 6379, 0, "invalid", "rejected")
        watermark = journal.last_rowid()
        journal.put("b", "redis", "host", 6379, 1, "valid", "verified")
        journal.put("c", "redis", "other", 6379, 0, "invalid", "rejected")
        assert not journal.target_complete("redis", "host", 6379, 2, max_rowid=watermark)
        assert journal.target_complete("redis", "host", 6379, 2)
        assert [r[3] for r in journal.target_rows("redis", "host", 6379, max_rowid=watermark)] == [0]
        assert [r[3] for r in journal.complete_rows(2)] == [0, 1]
        assert len(list(journal.endpoint_rows("host", 6379))) == 2
        assert journal.claim_target_replay("redis", "host", 6379)
        assert not journal.claim_target_replay("redis", "host", 6379)
    finally:
        journal.close()
    journal.close()
    assert journal.get("a") is None
    assert not journal.job_finished("a")
    journal.finish_job("closed")
    journal.put("closed", "redis", "host", 6379, 0, "valid", "ignored")


def test_spray_journal_refuses_missing_existing_or_changed_checkpoint(tmp_path: Path) -> None:
    path = tmp_path / "spray.db"
    with pytest.raises(ValueError, match="existing"):
        spray.AttemptJournal(str(path), "a", True)
    spray.AttemptJournal(str(path), "a", False).close()
    with pytest.raises(ValueError, match="already exists"):
        spray.AttemptJournal(str(path), "a", False)
    with pytest.raises(ValueError, match="settings changed"):
        spray.AttemptJournal(str(path), "b", True)


def test_spray_cancel_and_lockout_prevent_future_dispatch() -> None:
    gate = spray.RateGate(10, 60)
    gate.stop("a", "captcha")
    assert gate.reserve("a", "alice") == (False, "captcha")
    assert gate.claim("a", "alice") == 0
    assert gate.reserve("b", "alice") == (True, 0)
    gate.cancel()
    assert gate.reserve("b", "alice") == (False, "interrupted")
    assert gate.claim("b", "alice") == 0
    assert not gate.paused(10)


@pytest.mark.parametrize("port", [6379, 6380])
def test_spray_origin_prefers_resolved_surface_and_preserves_ipv6(port: int) -> None:
    from redposture_core.audit_models import AuditRecord

    record = AuditRecord(host="::1", port=port, module="redis", service="redis", status="detected")
    record.extra["api_endpoint"] = "https://[::1]:5540/prefix"
    assert spray._effective_origin(record, SimpleNamespace(scheme=None), "::1", port) == "https://[::1]:5540"


@pytest.mark.parametrize(
    ("attempts", "options", "expected"),
    [
        (None, {}, ""),
        ([], {}, ""),
        ([None, {}, {"username": "-"}], {"skip_username_dash": True}, "attempts=3"),
        (
            [{}, {"username": " alice "}, {"username": "alice"}],
            {"default_username": "user"},
            "attempts=3 users=user,alice",
        ),
        ([{"username": "a"}, {"username": "b"}], {"cap": 1}, "attempts=2 users=a,..."),
    ],
)
def test_credential_summary_counts_attempts_without_duplicate_accounts(
    attempts: object, options: dict, expected: str
) -> None:
    assert utils.format_credential_attempts_suffix({"rows": attempts}, field="rows", **options) == expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (None, (None, None)),
        (" ", (None, None)),
        ("Bearer x", (None, None)),
        ("PVEAPIToken=", (None, None)),
        ("PVEAPIToken a@pve!b=one=two", ("a@pve!b", "one=two")),
        ("PVEAPIToken=a@pve!b", ("a@pve!b", "")),
        ("PVEAPIToken==x", (None, "x")),
    ],
)
def test_proxmox_auth_parser_preserves_secret_equals(value: str | None, expected: tuple) -> None:
    assert utils.parse_proxmox_api_token_auth(value) == expected


def test_credential_file_validation_preserves_password_spaces_and_deduplicates(tmp_path: Path) -> None:
    path = tmp_path / "users"
    path.write_text(" alice : spaced : pass \nalice: spaced : pass \nbob:\n")
    result = utils.parse_username_password_credential_file(str(path), None)
    assert result == [
        utils.UsernamePasswordCredential("alice", " spaced : pass "),
        utils.UsernamePasswordCredential("bob", ""),
    ]
    with pytest.raises(ValueError, match="cannot be combined"):
        utils.parse_username_password_credential_file(str(path), "password")
    path.write_text("alice\nbob\n")
    with pytest.raises(ValueError, match="required"):
        utils.parse_username_password_credential_file(str(path), None)


def test_credential_tcp_prefilter_retains_open_host_order_and_duplicates() -> None:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(8)
        hosts = ["127.0.0.1", "::1", "127.0.0.1"]
        assert utils.filter_open_tcp_hosts_for_credential_file(
            hosts, listener.getsockname()[1], timeout=0.1, workers=2
        ) == ["127.0.0.1", "127.0.0.1"]
        assert utils.filter_open_tcp_hosts_for_credential_file(hosts, 0, timeout=0.1, workers=2, enabled=False) == hosts
        assert utils.filter_open_tcp_hosts_for_credential_file([], 0, timeout=0.1, workers=2) == []


@pytest.mark.parametrize(
    ("message", "allow_positional", "expected"),
    [
        ("", False, False),
        ("got an unexpected keyword argument 'timeout'", False, True),
        ("got an unexpected keyword argument 'other'", False, False),
        ("takes 1 positional argument but 2 were given", True, True),
        ("internal computation failed", True, False),
    ],
)
def test_signature_fallback_only_handles_known_compatibility_mismatches(
    message: str, allow_positional: bool, expected: bool
) -> None:
    assert (
        utils.is_signature_compat_typeerror(
            TypeError(message), expected_keywords={"timeout"}, allow_positional_mismatch=allow_positional
        )
        is expected
    )


@pytest.mark.parametrize(
    ("command", "expected"),
    [
        ([], False),
        (["GET", "/", "HTTP/1.1"], True),
        (["SSH", "/", "HTTP/1.1"], False),
        (["GET", "/", "not-http"], False),
    ],
)
def test_listener_inline_http_requires_both_method_and_version(command: list[str], expected: bool) -> None:
    assert utils.is_http_inline_command(command) is expected


@pytest.mark.parametrize(
    ("users", "passwords", "pairs", "error"),
    [
        ("alice", None, None, "supplied together"),
        (None, None, None, "at least one"),
        (None, None, "missing-colon", "user:password"),
        (None, None, ":secret", "empty username"),
    ],
)
def test_spray_invalid_candidate_sources_fail_before_network_work(
    tmp_path: Path, users: str | None, passwords: str | None, pairs: str | None, error: str
) -> None:
    path = tmp_path / "pairs"
    if pairs is not None:
        path.write_text(pairs)
    with pytest.raises(ValueError, match=error):
        spray.load_candidates(
            SimpleNamespace(
                users=users, passwords=passwords, pairs=str(path) if pairs is not None else None, tokens=None
            )
        )


def test_spray_explicit_empty_literal_password_is_a_candidate() -> None:
    result = spray.load_candidates(SimpleNamespace(users="qa", passwords="", pairs=None, tokens=None))
    assert list(result) == [spray.Candidate("pair", "qa", "")]


@pytest.mark.parametrize("modules", ["", ",", "redis,does-not-exist"])
def test_spray_unknown_or_empty_module_selection_is_rejected(modules: str) -> None:
    with pytest.raises(ValueError, match="modules"):
        spray._modules(modules)


def test_spray_module_selection_normalizes_and_deduplicates() -> None:
    assert spray._modules(" Redis,postgres,REDIS ") == ("redis", "postgres")
    assert spray._modules(" ALL ") == spray.AUDIT_MODULE_NAMES


def test_spray_legacy_checkpoint_recovers_cooldowns_and_lockout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    journal = spray.AttemptJournal(str(tmp_path / "legacy.db"), "input", False)
    try:
        journal.db.execute("DELETE FROM meta WHERE key='pacing_version'")
        journal.db.commit()
    finally:
        journal.close()
    journal = spray.AttemptJournal(str(tmp_path / "legacy.db"), "input", True)
    try:
        assert journal.legacy_pacing
        monkeypatch.setattr(spray, "time", SimpleNamespace(monotonic=lambda: 10.0, time=lambda: 1000.0))
        gate = spray.RateGate(2, 60, journal=journal)
        candidates = [spray.Candidate("pair", "alice", "secret"), spray.Candidate("pair", "bob", "secret")]
        rows = [
            ("redis", "qa", 6379, None, "detected", "", ""),
            ("redis", "qa", 6379, 99, "invalid", "", ""),
            ("redis", "qa", 6379, 1, "unsupported", "", ""),
            ("redis", "qa", 6379, 0, "invalid", "rejected", ""),
        ]
        gate.restore_legacy("tcp://qa:6379", rows, candidates)
        assert gate.reserve("tcp://qa:6379", "alice") == (True, 60)
        restored = spray.RateGate(2, 60, journal=journal)
        assert restored.reserve("tcp://qa:6379", "alice") == (True, 60)
        gate.restore_legacy(
            "tcp://other:6379", [("redis", "other", 6379, 0, "rate_limited", "account locked", "")], candidates
        )
        assert gate.reserve("tcp://other:6379", "bob") == (False, "account locked")
        gate.restore_legacy("tcp://other:6379", rows, candidates)
        assert spray.RateGate(2, 60, journal=journal).reserve("tcp://other:6379", "alice") == (False, "account locked")
    finally:
        journal.close()


def test_local_shell_help_empty_exit_limit_and_hex_controls() -> None:
    view, console = capture.ShellView(), _Console()
    assert view.handle("", console) == (False, False)
    assert view.handle(":", console) == (True, False)
    assert view.handle(":help", console) == (True, False)
    assert "stdout|stderr" in console.lines[0][0]
    assert all(color == "white" for _, color in console.lines)
    assert view.handle(":limit 2K", console) == (True, False)
    assert view.capture_bytes == 2048
    view.last = capture.CommandResult(stdout=b"abcd")
    console.lines.clear()
    assert view.handle(":hex stdout 2", console) == (True, False)
    assert "61 62" in console.lines[0][0] and "63" not in console.lines[0][0]
    assert view.handle(":quit", console) == (True, True)
