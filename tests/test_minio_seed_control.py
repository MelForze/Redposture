"""The committed QA seed must produce a deterministic binary control."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/seed_minio_binary_control.sh"


def test_binary_control_is_deterministic_and_targets_only_the_qa_fixture(tmp_path):
    fake_mc = tmp_path / "mc"
    fake_mc.write_text('#!/bin/sh\nprintf "%s\\n" "$@" > "$QA_MC_ARGS"\ncat > "$QA_MC_BODY"\n')
    fake_mc.chmod(0o755)
    args_path, body_path = tmp_path / "args", tmp_path / "body"
    env = dict(
        os.environ, PATH=f"{tmp_path}:{os.environ['PATH']}", QA_MC_ARGS=str(args_path), QA_MC_BODY=str(body_path)
    )
    for _ in range(3):
        result = subprocess.run(["sh", str(SCRIPT)], env=env, capture_output=True, timeout=5)
        assert result.returncode == 0, result.stderr
        assert args_path.read_text().splitlines() == ["pipe", "local/secrets-corpus/misc/blob.bin"]
        assert body_path.read_bytes() == bytes(4096)


def test_binary_control_does_not_hide_a_seed_upload_failure(tmp_path):
    fake_mc = tmp_path / "mc"
    fake_mc.write_text("#!/bin/sh\ncat >/dev/null\nexit 7\n")
    fake_mc.chmod(0o755)
    result = subprocess.run(
        ["sh", str(SCRIPT)],
        env=dict(os.environ, PATH=f"{tmp_path}:{os.environ['PATH']}"),
        capture_output=True,
        timeout=5,
    )
    assert result.returncode == 7
