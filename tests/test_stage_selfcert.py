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
