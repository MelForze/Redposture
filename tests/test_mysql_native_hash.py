from __future__ import annotations

import os
from pathlib import Path

from redposture_core.logger import AttemptLogger
from redposture_core.mysql_native_hash import (
    check_mysql_native_weak_password,
    mysql_native_hashcat,
    mysql_native_scramble,
)

SALT = "1c24ab8d0ee94d70ab1f2e814d8f0948a14d10b9"
RESPONSE = "437e93572f18ae44d9e779160c2505271f85821d"


def _capture(**updates: object) -> dict[str, object]:
    return {
        "service": "mysql",
        "auth_plugin": "mysql_native_password",
        "username": "exporter",
        "auth_salt": SALT,
        "auth_response": RESPONSE,
        **updates,
    }


def test_hashcat_reference_vector_and_bounded_check() -> None:
    assert mysql_native_scramble("hashcat", bytes.fromhex(SALT)).hex() == RESPONSE
    assert mysql_native_hashcat(_capture()) == f"$mysqlna${SALT}*{RESPONSE}"
    assert check_mysql_native_weak_password(_capture(), ["wrong", "hashcat"]) == "hashcat"
    assert check_mysql_native_weak_password(_capture(), ["wrong"]) is None


def test_non_native_and_malformed_responses_are_not_exported() -> None:
    for change in (
        {"auth_plugin": "caching_sha2_password"},
        {"auth_response": "zz" * 20},
        {"auth_salt": SALT[:-2]},
        {"service": "postgres"},
    ):
        assert mysql_native_hashcat(_capture(**change)) is None


def test_trigger_hash_sidecar_is_unique_and_private(tmp_path: Path, capsys: object) -> None:
    logger = AttemptLogger()
    logger.set_trigger_callback_mode(True)
    path = logger.set_mysql_hash_output(str(tmp_path / "capture.txt"))
    assert path.name == "capture.mysql.hashes.hashcat"
    for _ in range(2):
        logger.log(
            "mysql", ("127.0.0.1", 50000), listen_port=3306, **{k: v for k, v in _capture().items() if k != "service"}
        )
    logger.log(
        "mysql", ("127.0.0.1", 50001), auth_plugin="caching_sha2_password", auth_salt=SALT, auth_response=RESPONSE
    )
    assert path.read_text() == f"$mysqlna${SALT}*{RESPONSE}\n"
    assert os.stat(path).st_mode & 0o777 == 0o600
    logger.close()


def test_existing_hash_sidecar_is_restricted_again(tmp_path: Path) -> None:
    path = tmp_path / "capture.mysql.hashes.hashcat"
    path.write_text("old\n")
    path.chmod(0o644)
    logger = AttemptLogger()
    logger.set_mysql_hash_output(str(tmp_path / "capture.txt"))
    assert path.read_text() == ""
    assert os.stat(path).st_mode & 0o777 == 0o600
