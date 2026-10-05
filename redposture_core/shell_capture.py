"""Byte-preserving capture and safe display for explicit remote commands."""

from __future__ import annotations

import base64
import binascii
import importlib
import shlex
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Any

DEFAULT_CAPTURE_BYTES = 8 * 1024 * 1024
MAX_CAPTURE_BYTES = 50 * 1024 * 1024


@dataclass(frozen=True)
class CommandResult:
    stdout: bytes = b""
    stderr: bytes = b""
    exit_code: int | None = None
    duration_ms: int | None = None
    stdout_total: int | None = None
    stderr_total: int | None = None
    error: str | None = None
    outcome_unknown: bool = False

    @property
    def truncated(self) -> bool:
        return (self.stdout_total or 0) > len(self.stdout) or (self.stderr_total or 0) > len(self.stderr)


def build_capture_command(command: str, token: str, *, max_bytes: int = DEFAULT_CAPTURE_BYTES) -> str:
    """Wrap a command in a one-line POSIX shell, returning framed base64 output.

    The wrapper is suitable for PostgreSQL COPY FROM PROGRAM and ClickHouse's
    line-oriented executable() script. Output is capped before it crosses the
    database transport; the reported original sizes make truncation explicit.
    """
    if not token.isalnum():
        raise ValueError("capture token must be alphanumeric")
    if not 1 <= max_bytes <= MAX_CAPTURE_BYTES:
        raise ValueError("capture byte limit is out of range")
    if "\n" in command or "\r" in command:
        raise ValueError("remote command must be one line")
    prefix = f"RP:{token}:"
    return (
        "rp_out=$(mktemp) || exit 125; "
        'rp_err=$(mktemp) || { rm -f "$rp_out"; exit 125; }; '
        'trap \'rm -f "$rp_out" "$rp_err"\' EXIT; '
        f'sh -c {shlex.quote(command)} >"$rp_out" 2>"$rp_err"; rp_rc=$?; '
        f"printf '{prefix}STATUS:%s\\n' \"$rp_rc\"; "
        f"printf '{prefix}STDOUT:%s\\n' \"$(wc -c < \"$rp_out\" | tr -d '[:space:]')\"; "
        f'head -c {max_bytes} "$rp_out" | base64; '
        f"printf '{prefix}ENDSTDOUT\\n'; "
        f"printf '{prefix}STDERR:%s\\n' \"$(wc -c < \"$rp_err\" | tr -d '[:space:]')\"; "
        f'head -c {max_bytes} "$rp_err" | base64; '
        f"printf '{prefix}ENDSTDERR\\n{prefix}END\\n'"
    )


def parse_capture_lines(lines: list[str], token: str, *, max_bytes: int = DEFAULT_CAPTURE_BYTES) -> CommandResult:
    if not 1 <= max_bytes <= MAX_CAPTURE_BYTES:
        raise ValueError("capture byte limit is out of range")
    prefix = f"RP:{token}:"
    if not lines or lines[-1] != prefix + "END":
        raise ValueError("incomplete capture response")
    if len(lines) < 6 or not lines[0].startswith(prefix + "STATUS:"):
        raise ValueError("invalid capture response")
    try:
        exit_code = int(lines[0][len(prefix + "STATUS:") :])
    except ValueError as exc:
        raise ValueError("invalid capture exit status") from exc
    cursor = 1
    streams: dict[str, bytes] = {}
    sizes: dict[str, int] = {}
    for name in ("STDOUT", "STDERR"):
        header = prefix + name + ":"
        if cursor >= len(lines) or not lines[cursor].startswith(header):
            raise ValueError("incomplete capture response")
        try:
            size = int(lines[cursor][len(header) :])
        except ValueError as exc:
            raise ValueError("invalid capture byte count") from exc
        if size < 0:
            raise ValueError("invalid capture byte count")
        sizes[name] = size
        cursor += 1
        end_marker = prefix + "END" + name
        chunks: list[str] = []
        while cursor < len(lines) and lines[cursor] != end_marker:
            chunks.append(lines[cursor])
            cursor += 1
        if cursor >= len(lines):
            raise ValueError("incomplete capture response")
        cursor += 1
        try:
            data = base64.b64decode("".join(chunks), validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ValueError("invalid capture base64") from exc
        if len(data) != min(size, max_bytes):
            raise ValueError("capture byte count mismatch")
        streams[name] = data
    if cursor != len(lines) - 1:
        raise ValueError("unexpected capture data")
    return CommandResult(
        stdout=streams["STDOUT"],
        stderr=streams["STDERR"],
        exit_code=exit_code,
        stdout_total=sizes["STDOUT"],
        stderr_total=sizes["STDERR"],
    )


def is_binary(data: bytes) -> bool:
    try:
        decoded = data.decode("utf-8")
    except UnicodeDecodeError:
        return True
    return any(unicodedata.category(char) in {"Cc", "Cf"} and char not in "\n\r\t" for char in decoded)


def hex_preview(data: bytes, *, limit: int = 32) -> list[str]:
    rows: list[str] = []
    for offset in range(0, min(len(data), limit), 16):
        chunk = data[offset : min(offset + 16, limit)]
        hex_part = " ".join(f"{byte:02x}" for byte in chunk)
        ascii_part = "".join(chr(byte) if 32 <= byte < 127 else "." for byte in chunk)
        rows.append(f"{offset:08x}  {hex_part:<47}  |{ascii_part}|")
    return rows


def result_text_lines(result: CommandResult) -> list[str]:
    """Compact safe output for existing one-shot result renderers."""
    lines: list[str] = []
    for name, data in (("stdout", result.stdout), ("stderr", result.stderr)):
        if not data:
            continue
        if is_binary(data):
            lines.append(f"{name}: [binary {len(data)} B]")
            lines.extend(hex_preview(data))
        else:
            prefix = "stderr: " if name == "stderr" else ""
            lines.extend(prefix + line for line in data.decode("utf-8").replace("\r", "\\r").splitlines())
    if result.truncated:
        lines.append("[output truncated during capture]")
    return lines


def format_result(result: CommandResult, *, preview_bytes: int = 32) -> list[tuple[str, str]]:
    """Return terminal-safe lines and Airflow-style semantic colors."""
    if result.outcome_unknown:
        detail = f" ({result.error})" if result.error else ""
        return [
            (
                f"[!] Connection lost after command submission; outcome unknown{detail}. Command was not retried.",
                "orange",
            )
        ]
    if result.error:
        return [(f"[-] {result.error}", "green")]
    stdout_size = result.stdout_total if result.stdout_total is not None else len(result.stdout)
    stderr_size = result.stderr_total if result.stderr_total is not None else len(result.stderr)
    symbol = "[+]" if result.exit_code == 0 else "[-]"
    status = "unknown" if result.exit_code is None else str(result.exit_code)
    duration = f"  time:{result.duration_ms} ms" if result.duration_ms is not None else ""
    summary = f"{symbol} exit:{status}{duration}  stdout:{stdout_size} B  stderr:{stderr_size} B"
    if result.truncated:
        summary += "  (truncated)"
    lines = [(summary, "red" if result.exit_code == 0 else "green")]
    for name, data in (("stdout", result.stdout), ("stderr", result.stderr)):
        if not data:
            continue
        if is_binary(data):
            lines.append((f"[*] {name} (binary): showing first {min(preview_bytes, len(data))} B", "orange"))
            lines.extend((line, "orange") for line in hex_preview(data, limit=preview_bytes))
        else:
            text = data.decode("utf-8").replace("\r", "\\r")
            lines.extend((f"{name}: {line}" if name == "stderr" else line, "orange") for line in text.splitlines())
    if result.truncated:
        lines.append(("[!] Output truncated during capture; saved data is partial.", "orange"))
    return lines


def save_result_stream(result: CommandResult, path: str | Path, *, stream: str = "stdout") -> int:
    if stream not in {"stdout", "stderr"}:
        raise ValueError("stream must be stdout or stderr")
    data = result.stdout if stream == "stdout" else result.stderr
    with Path(path).open("xb") as output:
        output.write(data)
    return len(data)


class ShellView:
    """Local REPL controls; never forwards colon commands to the target."""

    def __init__(self) -> None:
        self.last: CommandResult | None = None
        self.capture_bytes = DEFAULT_CAPTURE_BYTES

    def show(self, result: CommandResult, console: Any) -> None:
        self.last = result
        for line, color in format_result(result):
            console.plain(line, color=color)

    def remember(self, command: str) -> None:
        """Keep session history in memory only; do not persist shell secrets."""
        try:
            readline = importlib.import_module("readline")
            add_history = getattr(readline, "add_history", None)
            if callable(add_history):
                add_history(command)
        except (ImportError, OSError):
            pass

    def handle(self, command: str, console: Any) -> tuple[bool, bool]:
        if not command.startswith(":"):
            return False, False
        try:
            parts = shlex.split(command[1:])
        except ValueError as exc:
            console.plain(f"[-] {exc}", color="orange")
            return True, False
        if not parts:
            return True, False
        operation = parts[0].lower()
        if operation in {"exit", "quit"}:
            return True, True
        if operation == "help":
            console.plain(":hex [stdout|stderr] [bytes]  :base64 [stdout|stderr] [bytes]", color="white")
            console.plain(":save [stdout|stderr] <local-path>  :limit <bytes|N[K|M]>  :exit", color="white")
            return True, False
        if operation == "limit":
            try:
                if len(parts) != 2:
                    raise ValueError("usage: :limit <bytes|N[K|M]>")
                raw = parts[1].upper()
                multiplier = {"K": 1024, "M": 1024 * 1024}.get(raw[-1], 1)
                size = int(raw[:-1] if multiplier != 1 else raw) * multiplier
                if not 1 <= size <= MAX_CAPTURE_BYTES:
                    raise ValueError("capture limit must be between 1 B and 50 MiB")
                self.capture_bytes = size
                console.plain(f"[*] Capture limit: {size} B per stream", color="white")
            except ValueError as exc:
                console.plain(f"[-] {exc}", color="orange")
            return True, False
        if operation not in {"hex", "base64", "save"}:
            console.plain(f"[-] Unknown local command: :{operation}; use :help", color="orange")
            return True, False
        if self.last is None:
            console.plain("[-] No command result yet", color="orange")
            return True, False
        args = parts[1:]
        stream = "stdout"
        if args and args[0] in {"stdout", "stderr"}:
            stream = args.pop(0)
        data = self.last.stdout if stream == "stdout" else self.last.stderr
        if operation == "save":
            if len(args) != 1:
                console.plain("[-] usage: :save [stdout|stderr] <local-path>", color="orange")
                return True, False
            try:
                written = save_result_stream(self.last, args[0], stream=stream)
            except OSError as exc:
                console.plain(f"[-] Save failed: {exc}", color="orange")
            else:
                console.plain(f"[+] Saved {written} B to {args[0]}", color="red")
                total = self.last.stdout_total if stream == "stdout" else self.last.stderr_total
                if total is not None and total > written:
                    console.plain("[!] Saved data is partial because capture was truncated", color="orange")
            return True, False
        try:
            if len(args) > 1:
                raise ValueError(f"usage: :{operation} [stdout|stderr] [bytes]")
            limit = int(args[0]) if args else (256 if operation == "hex" else 512)
            if not 1 <= limit <= 65536:
                raise ValueError("preview must be between 1 and 65536 bytes")
        except ValueError as exc:
            console.plain(f"[-] {exc}", color="orange")
            return True, False
        if operation == "hex":
            for line in hex_preview(data, limit=limit):
                console.plain(line, color="orange")
        else:
            console.plain(base64.b64encode(data[:limit]).decode("ascii"), color="orange")
        if len(data) > limit:
            console.plain(f"[*] Showing first {limit} of {len(data)} captured bytes", color="white")
        return True, False
