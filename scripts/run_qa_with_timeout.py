"""Run one QA command with a wall-clock limit and stop its process group."""

from __future__ import annotations

import os
import signal
import subprocess
import sys


def main(argv: list[str]) -> int:
    if len(argv) < 3:
        print("usage: run_qa_with_timeout.py SECONDS [--] COMMAND...", file=sys.stderr)
        return 2
    try:
        seconds = float(argv[1])
    except ValueError:
        print("timeout must be a positive number of seconds", file=sys.stderr)
        return 2
    if seconds <= 0:
        print("timeout must be a positive number of seconds", file=sys.stderr)
        return 2
    command = argv[2:]
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        print("a command is required", file=sys.stderr)
        return 2

    try:
        child = subprocess.Popen(command, start_new_session=True)
    except OSError as exc:
        print(f"cannot start QA command: {exc}", file=sys.stderr)
        return 127

    def forward(signum: int, _frame: object) -> None:
        if child.poll() is None:
            os.killpg(child.pid, signum)
        raise SystemExit(128 + signum)

    previous = {sig: signal.signal(sig, forward) for sig in (signal.SIGINT, signal.SIGTERM)}
    try:
        try:
            return child.wait(timeout=seconds)
        except subprocess.TimeoutExpired:
            print(f"[timeout] QA command timed out after {seconds:g} seconds", file=sys.stderr, flush=True)
            os.killpg(child.pid, signal.SIGTERM)
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid, signal.SIGKILL)
                child.wait()
            return 124
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
