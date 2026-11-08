"""Public defcreds must retain detection proof instead of repeating bootstrap."""

from __future__ import annotations

import ipaddress

from scripts import profile_module_performance as profile


def test_public_default_catalogue_does_not_repeat_anonymous_mongo_bootstrap(monkeypatch):
    from redposture_core.cli_args import parse_args
    from redposture_core.logger import AttemptLogger
    from redposture_core.modules.mongodb.actions import _MONGODB_DEFAULT_CREDS
    from redposture_core.modules.mongodb.stage import run_mongodb_stage

    monkeypatch.setattr(profile, "BASE_IP", int(ipaddress.IPv4Address("127.0.0.1")))
    fixture = profile.Fixture("mongodb", {0: "positive"}, 0, False, mode="defcreds", bind_host="127.0.0.1")
    records = []
    try:
        args = parse_args(
            [
                "mongodb",
                "-t",
                f"127.0.0.1:{fixture.port}",
                "--defcreds",
                "--workers",
                "1",
                "--timeout",
                "0.5",
                "--retries",
                "0",
                "--no-color",
            ]
        )
        args._async_detect_concurrency = 1
        args._record_callback = records.append
        assert run_mongodb_stage(args, AttemptLogger()) == 0
    finally:
        fixture.close()
    assert len(records) == 1 and records[0]["is_mongodb"] is True
    attempts = records[0]["credential_attempts"]
    assert {(row["username"], row["password"]) for row in attempts} == set(_MONGODB_DEFAULT_CREDS)
    assert all(row["ok"] is False and row["error"] == "authentication failed" for row in attempts)
    assert fixture.stats["command.saslstart"] == len(_MONGODB_DEFAULT_CREDS)
    assert fixture.stats["command.buildinfo"] == 1
    assert fixture.stats["command.listdatabases"] == 1
