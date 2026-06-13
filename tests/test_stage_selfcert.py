from __future__ import annotations

import argparse
import os

from redposture_core.stage_selfcert import run_selfcert_stage


def _args(**overrides: object) -> argparse.Namespace:
    data: dict[str, object] = {
        "debug": False,
        "cert_out": "cert.pem",
        "key_out": "key.pem",
        "force": False,
    }
    data.update(overrides)
    return argparse.Namespace(**data)


def test_stage_selfcert_success(monkeypatch) -> None:
    captured: dict[str, object] = {}

    def fake_write(cert_path: str, key_path: str, *, force: bool) -> tuple[str, str]:
        captured["cert_path"] = cert_path
        captured["key_path"] = key_path
        captured["force"] = force
        return os.path.abspath(cert_path), os.path.abspath(key_path)

    monkeypatch.setattr("redposture_core.stage_selfcert.write_self_signed_cert_files", fake_write)
    rc = run_selfcert_stage(_args(cert_out="tls/cert.pem", key_out="tls/key.pem", force=True))
    assert rc == 0
    assert captured == {"cert_path": "tls/cert.pem", "key_path": "tls/key.pem", "force": True}


def test_stage_selfcert_validation_error(monkeypatch) -> None:
    def fake_write(_cert_path: str, _key_path: str, *, force: bool) -> tuple[str, str]:
        raise ValueError("bad args")

    monkeypatch.setattr("redposture_core.stage_selfcert.write_self_signed_cert_files", fake_write)
    rc = run_selfcert_stage(_args())
    assert rc == 2


def test_stage_selfcert_os_error(monkeypatch) -> None:
    def fake_write(_cert_path: str, _key_path: str, *, force: bool) -> tuple[str, str]:
        raise OSError("disk full")

    monkeypatch.setattr("redposture_core.stage_selfcert.write_self_signed_cert_files", fake_write)
    rc = run_selfcert_stage(_args())
    assert rc == 1


def test_stage_selfcert_debug_emits_staged_markers(monkeypatch, capsys) -> None:
    def fake_write(cert_path: str, key_path: str, *, force: bool) -> tuple[str, str]:
        _ = (force,)
        return cert_path, key_path

    monkeypatch.setattr("redposture_core.stage_selfcert.write_self_signed_cert_files", fake_write)
    rc = run_selfcert_stage(_args(debug=True))
    assert rc == 0
    out = capsys.readouterr().out
    assert "pass=1 detect start total=1" in out
    assert "pass=2 deep start total=1" in out
    assert "stage2_gate=run reason=status=ready" in out
    assert "stage_timing_summary status=ok attempts=1/1" in out


def test_stage_selfcert_debug_validation_error_emits_skip_markers(monkeypatch, capsys) -> None:
    def fake_write(_cert_path: str, _key_path: str, *, force: bool) -> tuple[str, str]:
        _ = force
        raise ValueError("bad args")

    monkeypatch.setattr("redposture_core.stage_selfcert.write_self_signed_cert_files", fake_write)
    rc = run_selfcert_stage(_args(debug=True))
    assert rc == 2
    out = capsys.readouterr().out
    assert "pass=1 detect complete success=0" in out
    assert "stage2_gate=skip reason=error" in out
    assert "stage_timing_summary status=error attempts=1/1" in out
    assert "bad args" in out


def test_stage_selfcert_debug_os_error_emits_skip_markers(monkeypatch, capsys) -> None:
    def fake_write(_cert_path: str, _key_path: str, *, force: bool) -> tuple[str, str]:
        _ = force
        raise OSError("disk full")

    monkeypatch.setattr("redposture_core.stage_selfcert.write_self_signed_cert_files", fake_write)
    rc = run_selfcert_stage(_args(debug=True))
    assert rc == 1
    captured = capsys.readouterr()
    assert "stage_trace stage_name=detect_protocol" in captured.out
    assert "stage2_gate=skip reason=error" in captured.out
    assert "failed to write cert/key files: disk full" in captured.err
