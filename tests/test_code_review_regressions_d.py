"""Regression tests for the D-batch (quality/efficiency) code-review fixes.

D1 — Postgres `_pg_try_read_server_file` no longer calls pg_switch_wal.
D2 — MongoDB stage now surfaces `_group_collection_targets` parse errors.
D3 — ZooKeeper: anon=NOAUTH + post-auth=NOAUTH disambiguated via /zookeeper.
D4 — should_use_color caches the default-stream result.
D5 — stage_scan warns when the -t URL path is ignored.
"""

from __future__ import annotations

import argparse

import pytest

# ---------------------------------------------------------------------------
# D1 — Postgres skips `pg_switch_wal` on the read path
# ---------------------------------------------------------------------------


def test_fix_d1_postgres_read_skips_pg_switch_wal(monkeypatch: pytest.MonkeyPatch) -> None:
    """D1: `_pg_try_read_server_file` used to fire `SELECT pg_switch_wal()`
    before every attempt — a superuser-only server side-effect that also
    burns an extra round-trip per audit. The read path must not touch it."""
    from redposture_core.modules.postgres import actions as pg_actions

    seen_sql: list[str] = []

    def _capture(_sock, sql: str):
        seen_sql.append(sql)
        if "pg_read_file" in sql:
            return [], "permission denied"
        if "pg_ls_dir" in sql:
            return [["hostname"]], None
        if "lo_import" in sql:
            return [["42"]], None
        if "lo_get" in sql:
            return [["ok"]], None
        if "lo_unlink" in sql:
            return [["1"]], None
        return [], None

    monkeypatch.setattr(pg_actions, "_pg_query_rows", _capture)

    output, error, method, _attempts = pg_actions._pg_try_read_server_file(object(), "/etc/hostname")
    assert method == "lo_import"
    assert output == ["ok"]
    assert error is None
    assert all("pg_switch_wal" not in sql for sql in seen_sql), (
        "pg_switch_wal must no longer be issued from the read path: " + str(seen_sql)
    )


# ---------------------------------------------------------------------------
# D2 — MongoDB stage surfaces parse errors instead of silently no-op'ing
# ---------------------------------------------------------------------------


def test_fix_d2_mongo_normalize_returns_group_collection_targets_error() -> None:
    """`_normalize_mongodb_action_args` now returns a list of parse errors so
    `run_mongodb_stage` can bail with a non-zero exit code."""
    from redposture_core.modules.mongodb.stage import _normalize_mongodb_action_args

    args = argparse.Namespace(
        collection=["broken."],
        database=None,
        document=None,
        query=None,
        projection=None,
        index=None,
        nosql_cmd=None,
    )
    errors = _normalize_mongodb_action_args(args)
    assert errors, "parse error must be surfaced"
    assert any("--collection" in e for e in errors)


def test_fix_d2_mongo_stage_exits_2_on_parse_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """End-to-end: run_mongodb_stage returns 2 when normalize surfaces an error."""
    from redposture_core.modules.mongodb import stage as mongo_stage

    class _Console:
        def __init__(self):
            self.errors: list[str] = []

        def error(self, msg: str) -> None:
            self.errors.append(msg)

        def info(self, _msg: str) -> None:
            pass

        def warn(self, _msg: str) -> None:
            pass

        def plain(self, _msg: str) -> None:
            pass

        def success(self, _msg: str) -> None:
            pass

    _console = _Console()
    monkeypatch.setattr(mongo_stage, "Console", lambda **_kw: _console)
    monkeypatch.setattr(mongo_stage.policy, "validate_args", lambda *_a, **_kw: None)
    monkeypatch.setattr(mongo_stage, "has_username_password_credential_file", lambda _a: False)

    args = argparse.Namespace(
        collection=["broken."],
        database=None,
        document=None,
        query=None,
        projection=None,
        index=None,
        nosql_cmd=None,
        debug=False,
        target="127.0.0.1",
        port=27017,
        timeout=1.0,
        retries=0,
        workers=1,
        output=None,
        output_format="txt",
        username=None,
        password=None,
        defcreds=False,
        nosql_shell=False,
    )
    rc = mongo_stage.run_mongodb_stage(args, logger=None)
    assert rc == 2
    assert any("--collection" in msg for msg in _console.errors)


# ---------------------------------------------------------------------------
# D3 — Regression test already lives in
# test_code_review_regressions_abc::test_fix_a1d3_zk_*. Keep a stub here so
# the file's structure covers every D-fix by name.
# ---------------------------------------------------------------------------


def test_fix_d3_marker_regression_lives_next_to_a1() -> None:
    """D3 coverage now enforces conservative digest credential verification."""
    from tests import test_code_review_regressions_abc as abc_mod

    assert hasattr(abc_mod, "test_zk_noauth_after_digest_does_not_become_valid_via_control_probe")
    assert hasattr(abc_mod, "test_fix_a1d3_zk_ambiguous_noauth_pair_creds_rejected_when_zookeeper_also_denies")


# ---------------------------------------------------------------------------
# D4 — should_use_color caches the default-stream result
# ---------------------------------------------------------------------------


def test_fix_d4_should_use_color_caches_default_stream_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """D4: the default-stream (`stream is None`) branch is called for every
    log line. Ensure repeated calls don't re-query env + re-invoke isatty."""
    from redposture_core import console

    console._reset_color_cache()
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.delenv("FORCE_COLOR", raising=False)

    isatty_calls = {"n": 0}

    class _FakeStdout:
        def isatty(self):
            isatty_calls["n"] += 1
            return True

    monkeypatch.setattr(console.sys, "stdout", _FakeStdout())

    # 1000 calls on the default path should trigger isatty exactly once.
    for _ in range(1000):
        assert console.should_use_color() is True

    assert isatty_calls["n"] == 1, (
        f"should_use_color did not cache the default path: isatty called {isatty_calls['n']} times"
    )


def test_fix_d4_should_use_color_cache_invalidates_on_env_change(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """D4 negative twin: when NO_COLOR/FORCE_COLOR flip between calls, the
    cache MUST recompute. Otherwise a mid-run env change would be ignored."""
    from redposture_core import console

    console._reset_color_cache()
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.delenv("FORCE_COLOR", raising=False)

    class _Tty:
        def isatty(self):
            return True

    monkeypatch.setattr(console.sys, "stdout", _Tty())
    assert console.should_use_color() is True

    monkeypatch.setenv("NO_COLOR", "1")
    assert console.should_use_color() is False

    monkeypatch.delenv("NO_COLOR")
    monkeypatch.setenv("FORCE_COLOR", "1")
    assert console.should_use_color() is True


# ---------------------------------------------------------------------------
# D5 — stage_scan warns when the -t URL path would be ignored
# ---------------------------------------------------------------------------


def test_fix_d5_stage_scan_warns_when_url_path_is_dropped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """D5: users typing `-t http://host/some/other/metrics` used to get their
    path silently discarded because the probe always hits /metrics. We now
    emit a `[-] ignoring path on N target(s)...` warning."""
    from redposture_core import stage_scan

    warnings: list[str] = []

    class _Console:
        def error(self, _m: str) -> None:
            pass

        def warn(self, m: str) -> None:
            warnings.append(m)

        def info(self, _m: str) -> None:
            pass

        def plain(self, _m: str) -> None:
            pass

        def success(self, _m: str) -> None:
            pass

    _console = _Console()
    monkeypatch.setattr(stage_scan, "Console", lambda **_kw: _console)

    # Stub out everything downstream — we only need to reach the warn branch.
    class _Plan:
        target_count = 1

        def has_scheme(self, _s: str) -> bool:
            return False

        def iter_specs(self):
            return [
                argparse.Namespace(host="host.example.com", path="/api/metrics"),
                argparse.Namespace(host="another.example.com", path="/metrics"),
                argparse.Namespace(host="third.example.com", path="/"),
            ]

    monkeypatch.setattr(stage_scan, "stream_scan_target_specs", lambda *_a, **_kw: _Plan())
    # After the warn branch, force an early clean return by making the code
    # bail on "scan requires -t/--targets" (target_specs will be empty).
    monkeypatch.setattr(stage_scan, "collect_scan_target_specs", lambda _t: [])
    monkeypatch.setattr(stage_scan, "collect_scan_ports", lambda _p: [])
    monkeypatch.setattr(stage_scan, "load_profiles", lambda _p: {})

    args = argparse.Namespace(
        targets="http://host.example.com/api/metrics",
        hosts=None,
        hosts_file=None,
        ports=None,
        profiles_file=None,
        output=None,
        output_format="txt",
        workers=1,
        debug=False,
        timeout=1.0,
        retries=0,
    )

    # Actual exit code isn't the point — we only care the warn fired.
    try:
        stage_scan.run_scan_stage(args, logger=None)
    except Exception:
        pass  # downstream noise from the stub is fine

    assert any("ignoring path" in m for m in warnings), f"expected 'ignoring path' warning, got {warnings!r}"
    ignored = warnings[0]
    assert "host.example.com/api/metrics" in ignored
    # `/metrics` and `/` must NOT be flagged (they aren't dropped).
    assert "another.example.com/metrics" not in ignored
    assert "third.example.com/" not in ignored
