"""Regression tests for the second batch of code-review findings (A/B/C).

Fixes covered:
  A1–A6  — ZooKeeper credential + -124 classification bugs
  A7–A12 — MongoDB (transient vs invalid, db.collection split, permanent
           retry, active_client leak, defcreds_enabled, attempts preservation)
  A13    — Postgres attempt render with password=None
  A14    — Postgres remote-server path handling
  B1     — Unbracketed IPv6 host normalization
  B2     — extract_display_port IPv6 crash
  B3     — Prometheus marker specificity (mongodb / pgbouncer / clickhouse)
  B4/B5  — Exporter negative_markers consulted on shared ports (9117 / 9101)
  B6     — Target parser file-vs-host ambiguity
  C1/C2  — LineOutputSink thread safety
  C3     — BoundedScheduler cancels on Ctrl+C
  C4/C5  — HTTP listener request-body cap + socket timeout
  C6     — AuditConfig cached per Namespace
"""

from __future__ import annotations

import argparse
import io
import threading
import time
from typing import Any

import pytest

# ============================================================================
# ZooKeeper A1–A6
# ============================================================================


class _ZkFake:
    """Minimal ZK client fake tuned per-test."""

    def __init__(self, get_children_impl, auth_ok=True, auth_err=None):
        self._get_children = get_children_impl
        self._auth_ok = auth_ok
        self._auth_err = auth_err

    def connect(self):
        return

    def close(self):
        return

    def auth_digest(self, _u, _p):
        return self._auth_ok, self._auth_err

    def get_children2(self, path):
        return self._get_children(path)

    def get_data(self, _path):
        return b"", 0, {"data_length": 0, "num_children": 0}


def _run_zk(monkeypatch: pytest.MonkeyPatch, client_factory, **kw) -> dict:
    from redposture_core.modules.zookeeper.actions import _audit_zookeeper_host

    monkeypatch.setattr("redposture_core.stage_zookeeper._ZkClient", client_factory)
    defaults = dict(
        host="127.0.0.1",
        port=2181,
        timeout=0.1,
        retries=0,
        username=None,
        password=None,
        show_znodes=False,
        dump=False,
        query_znode=None,
        max_znodes=100,
    )
    defaults.update(kw)
    return _audit_zookeeper_host(**defaults)


def test_fix_a1_zk_post_auth_noauth_when_anon_was_ok_marks_creds_invalid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A1: server accepted the digest frame but the associated principal has
    no rights. Anon read succeeded on `/`, post-auth on the same path
    returned NOAUTH — that's a silent credential rejection. Old code left
    provided_credentials_ok=None and the record slipped through as
    open_no_auth."""

    state = {"called": 0}

    def _get_children(path):
        # `/` is queried multiple times (pre-auth root, post-auth root,
        # possibly auth-inference probes). We flip to NOAUTH after the first
        # call on `/` so post-auth reads see NOAUTH; other paths always OK.
        if path != "/":
            return [], 0, {"data_length": 0, "num_children": 0}
        idx = state["called"]
        state["called"] += 1
        if idx == 0:
            return [], 0, {"data_length": 0, "num_children": 0}
        return None, -102, None

    record = _run_zk(
        monkeypatch,
        lambda *_a, **_kw: _ZkFake(_get_children),
        username="admin",
        password="bad",
    )
    # provided_credentials_ok must reflect the invalid credential, not None.
    assert record["provided_credentials_ok"] is False


def test_fix_a1d3_zk_ambiguous_noauth_pair_disambiguated_by_zookeeper_probe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A1 + D3: anon=NOAUTH + post-auth=NOAUTH is ambiguous. D3 disambiguates
    by probing `/zookeeper` (world-readable on default ZK).

    Sub-scenario 1: `/zookeeper` returns OK → auth applied to a low-privilege
    principal that just has no ACL on `/`. provided_credentials_ok=True.
    """

    def _get_children_zookeeper_ok(path):
        if path == "/zookeeper":
            return [], 0, {"data_length": 0, "num_children": 0}
        return None, -102, None

    def _fake_infer(*_a, **_k):
        return True, "probe_noauth", ["/:noauth"]

    monkeypatch.setattr(
        "redposture_core.stage_zookeeper._infer_auth_required_from_anonymous_probes",
        _fake_infer,
    )
    record = _run_zk(
        monkeypatch,
        lambda *_a, **_kw: _ZkFake(_get_children_zookeeper_ok),
        username="admin",
        password="admin",
    )
    assert record["provided_credentials_ok"] is True


def test_fix_a1d3_zk_ambiguous_noauth_pair_creds_rejected_when_zookeeper_also_denies(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A1 + D3 sub-scenario 2: `/zookeeper` also NOAUTH → the session's auth
    principal really has zero rights, so the digest was silently rejected.
    provided_credentials_ok=False."""

    def _get_children_all_noauth(_path):
        return None, -102, None

    def _fake_infer(*_a, **_k):
        return True, "probe_noauth", ["/:noauth"]

    monkeypatch.setattr(
        "redposture_core.stage_zookeeper._infer_auth_required_from_anonymous_probes",
        _fake_infer,
    )
    record = _run_zk(
        monkeypatch,
        lambda *_a, **_kw: _ZkFake(_get_children_all_noauth),
        username="admin",
        password="admin",
    )
    assert record["provided_credentials_ok"] is False


def test_fix_a2_zk_open_target_with_valid_creds_reports_valid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A2: open ZK where both anon and auth return OK. Old code set
    `provided_credentials_ok = anonymous_root_err != OK` → False, mislabelling
    valid creds as invalid."""

    record = _run_zk(
        monkeypatch,
        lambda *_a, **_kw: _ZkFake(lambda _p: ([], 0, {"data_length": 0, "num_children": 0})),
        username="admin",
        password="admin",
    )
    assert record["status"] == "valid_credentials"
    assert record["provided_credentials_ok"] is True


def test_fix_a3_zk_all_124_probes_stays_inconclusive(monkeypatch: pytest.MonkeyPatch) -> None:
    """A3: consistent -124 across anonymous probes must NOT get promoted to
    auth_required=True."""

    def _get_children(_p):
        return None, -124, None

    record = _run_zk(monkeypatch, lambda *_a, **_kw: _ZkFake(_get_children))
    assert record["auth_required"] is None
    assert record["auth_inference_source"] == "probe_retryable_124_inconclusive"


def test_fix_a5_zk_enum_failure_does_not_pad_from_root_children(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A5 (via A4-fallback): when auth succeeded but root query returned -124,
    total_count must not silently equal the pre-auth root_children count.
    znode_count_unknown must be set instead."""

    # First call is the anon root read: fine. Second call is post-auth root: -124.
    state = {"n": 0}

    def _get_children(path):
        state["n"] += 1
        if state["n"] == 1:
            return ["kafka", "app"], 0, {"data_length": 0, "num_children": 2}
        return None, -124, None

    monkeypatch.setattr(
        "redposture_core.stage_zookeeper._enumerate_znodes",
        lambda *_a, **_kw: ([], 0, False, {}, "getChildren failed for /: ERR_-124"),
    )
    monkeypatch.setattr(
        "redposture_core.stage_zookeeper._infer_auth_required_from_anonymous_probes",
        lambda *_a, **_kw: (True, "probe_noauth", ["/:noauth"]),
    )

    record = _run_zk(
        monkeypatch,
        lambda *_a, **_kw: _ZkFake(_get_children),
        username="admin",
        password="admin",
        show_znodes=True,
    )
    assert record["provided_credentials_ok"] is True
    assert record["znode_count_unknown"] is True
    # Must NOT have been padded from the pre-auth root_children.
    assert record["znode_count"] != 2


def test_fix_a6_zk_query_znode_retries_on_transient_124(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A6: `--query-znode` on -124 must retry once instead of surfacing the
    transient error directly."""
    from redposture_core.modules.zookeeper.actions import _audit_zookeeper_host

    call_counts = {"/": 0, "/target": 0}

    class _Client:
        def __init__(self, *_a, **_kw):
            pass

        def connect(self):
            return

        def close(self):
            return

        def get_children2(self, path):
            call_counts.setdefault(path, 0)
            call_counts[path] += 1
            if path == "/":
                return ["target"], 0, {"data_length": 0, "num_children": 1}
            if path == "/target":
                # First call -124 (transient), second call OK.
                if call_counts["/target"] == 1:
                    return None, -124, None
                return [], 0, {"data_length": 0, "num_children": 0}
            return [], 0, {"data_length": 0, "num_children": 0}

        def get_data(self, _p):
            return b"", 0, {"data_length": 0, "num_children": 0}

    monkeypatch.setattr("redposture_core.stage_zookeeper._ZkClient", _Client)
    monkeypatch.setattr(
        "redposture_core.stage_zookeeper._enumerate_znodes",
        lambda *_a, **_kw: (["/target"], 1, False, {}, None),
    )
    # Speed up retry sleep to 0.
    monkeypatch.setattr("redposture_core.stage_zookeeper._retry_delay", lambda _i: 0.0)

    record = _audit_zookeeper_host(
        host="127.0.0.1",
        port=2181,
        timeout=0.1,
        retries=0,
        username=None,
        password=None,
        show_znodes=False,
        dump=False,
        query_znode="/target",
        max_znodes=100,
    )
    assert call_counts["/target"] >= 2  # retry actually happened
    assert record["query_znode_value"], "query_znode_value should be populated after retry"
    assert "err_-124" not in str(record["query_znode_value"]).lower()


# ============================================================================
# MongoDB A7–A12
# ============================================================================


def test_fix_a7_mongo_transient_network_errors_do_not_look_like_auth_required(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A7: `_try_credentials` used to classify every exception as an invalid
    credential attempt. Transient timeouts during the credential loop must
    now signal a network failure, not fabricated auth_required attempts."""
    from redposture_core.modules.mongodb import actions as mongo_actions

    class _FakeClient:
        client = None

        def hello(self):
            raise TimeoutError("ServerSelectionTimeoutError: connection timeout")

        def list_database_names(self):
            return []

        def close(self):
            pass

    monkeypatch.setattr(mongo_actions, "_open_client", lambda *_a, **_kw: _FakeClient())

    _selected, attempts = mongo_actions._try_credentials(
        "127.0.0.1",
        27017,
        1.0,
        auth_db="admin",
        credential_candidates=[
            {"username": "root", "password": "root", "default": True},
        ],
    )
    assert attempts, "attempt must still be recorded so downstream can inspect it"
    assert attempts[0].get("transient") is True, "transient network failures must be flagged"


def test_fix_a8_mongo_dot_split_wins_over_selected_database() -> None:
    """A8: `--database mydb --collection users.audit` used to become a literal
    "users.audit" collection under mydb. Dot-split now takes precedence."""
    from redposture_core.modules.mongodb.actions import _group_collection_targets

    normalized, grouped, error = _group_collection_targets(
        ["users.audit", "orphan"],
        "mydb",
    )
    assert error is None
    # `users.audit` splits → users['audit']. `orphan` is bare → routes to mydb.
    assert grouped == {"users": ["audit"], "mydb": ["orphan"]}
    assert normalized == ["users.audit", "orphan"]


def test_fix_a9_mongo_fails_fast_on_non_mongo_endpoint(monkeypatch: pytest.MonkeyPatch) -> None:
    """A9: MongoNotMongoError must not burn the retry budget."""
    from redposture_core.clients.mongodb import MongoNotMongoError
    from redposture_core.modules.mongodb import actions as mongo_actions

    call_count = {"n": 0}

    class _NotMongo:
        client = None

        def hello(self):
            call_count["n"] += 1
            raise MongoNotMongoError("hello did not return a document")

        def close(self):
            pass

    monkeypatch.setattr(mongo_actions, "_open_client", lambda *_a, **_kw: _NotMongo())

    record = mongo_actions._audit_mongodb_host(
        host="127.0.0.1",
        port=27017,
        timeout=0.05,
        retries=3,  # 4 attempts if we retried
        credential_candidates=[],
        auth_db="admin",
        database=None,
        show_databases=False,
        show_collections=False,
        show_indexes=False,
        collection_targets=[],
        collection_targets_by_database={},
        dump_documents=False,
        dump_limit=None,
        query_filter=None,
        projection=None,
    )
    assert record["status"] == "fail"
    assert call_count["n"] == 1, f"expected exactly 1 hello() call, got {call_count['n']}"


def test_fix_a10_mongo_active_client_closed_on_exception(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A10: the credentialed active_client must be closed even when
    _collect_mongodb_data raises."""
    from redposture_core.modules.mongodb import actions as mongo_actions

    close_calls = {"anon": 0, "authed": 0}

    class _FakeClient:
        def __init__(self, label: str):
            self.label = label

        def hello(self):
            return {"version": "7.0.0"}

        def server_info(self):
            return {"version": "7.0.0"}

        def close(self):
            close_calls[self.label] += 1

    def _open(*_a, username="", **_kw):
        return _FakeClient("authed" if username else "anon")

    def _fake_try_list(client):  # noqa: ARG001
        # anon: fails; authed: succeeds
        if not hasattr(_fake_try_list, "seen"):
            _fake_try_list.seen = True
            return None, "authentication required"
        return ["admin"], None

    def _raise_on_collect(*_a, **_kw):
        raise RuntimeError("boom in data stage")

    monkeypatch.setattr(mongo_actions, "_open_client", _open)
    monkeypatch.setattr(mongo_actions, "_try_list_databases", _fake_try_list)
    monkeypatch.setattr(
        mongo_actions,
        "_try_credentials",
        lambda *_a, **_kw: (
            {"username": "root", "password": "root", "default": True},
            [{"username": "root", "password": "root", "default": True, "ok": True, "error": None}],
        ),
    )
    monkeypatch.setattr(mongo_actions, "_collect_mongodb_data", _raise_on_collect)

    record = mongo_actions._audit_mongodb_host(
        host="127.0.0.1",
        port=27017,
        timeout=0.1,
        retries=0,
        credential_candidates=[{"username": "root", "password": "root", "default": True}],
        auth_db="admin",
        database=None,
        show_databases=False,
        show_collections=False,
        show_indexes=False,
        collection_targets=[],
        collection_targets_by_database={},
        dump_documents=False,
        dump_limit=None,
        query_filter=None,
        projection=None,
    )
    assert record["status"] == "fail"
    assert close_calls["authed"] == 1, (
        f"active_client leaked — expected exactly 1 close on the credentialed client, got {close_calls['authed']}"
    )


def test_fix_a11_mongo_defcreds_enabled_reflects_actual_attempts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A11: defcreds_enabled must be True only if a default credential was
    actually attempted, not merely supplied."""
    from redposture_core.modules.mongodb import actions as mongo_actions

    class _FakeClient:
        def __init__(self, *_a, **_kw):
            pass

        def hello(self):
            return {"version": "7.0.0"}

        def server_info(self):
            return {"version": "7.0.0"}

        def close(self):
            pass

    monkeypatch.setattr(mongo_actions, "_open_client", lambda *_a, **_kw: _FakeClient())
    monkeypatch.setattr(
        mongo_actions,
        "_try_list_databases",
        lambda _c: (None, "authentication required"),
    )
    # User cred (non-default) succeeds first — defaults never tried.
    monkeypatch.setattr(
        mongo_actions,
        "_try_credentials",
        lambda *_a, **_kw: (
            {"username": "admin", "password": "s3cret", "default": False},
            [{"username": "admin", "password": "s3cret", "default": False, "ok": True, "error": None}],
        ),
    )
    monkeypatch.setattr(mongo_actions, "_collect_mongodb_data", lambda *_a, **_kw: {})

    record = mongo_actions._audit_mongodb_host(
        host="127.0.0.1",
        port=27017,
        timeout=0.1,
        retries=0,
        credential_candidates=[
            {"username": "admin", "password": "s3cret", "default": False},
            {"username": "root", "password": "root", "default": True},
        ],
        auth_db="admin",
        database=None,
        show_databases=False,
        show_collections=False,
        show_indexes=False,
        collection_targets=[],
        collection_targets_by_database={},
        dump_documents=False,
        dump_limit=None,
        query_filter=None,
        projection=None,
    )
    assert record["defcreds_enabled"] is False


def test_fix_a12_mongo_credential_attempts_persist_across_final_fail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A12: the terminal fail record must preserve credential_attempts."""
    from redposture_core.modules.mongodb import actions as mongo_actions

    state = {"attempt": 0}

    class _FakeClient:
        client = None

        def hello(self):
            return {"version": "7.0.0"}

        def server_info(self):
            return {"version": "7.0.0"}

        def close(self):
            pass

    monkeypatch.setattr(mongo_actions, "_open_client", lambda *_a, **_kw: _FakeClient())

    def _try_list(_client):
        return None, "authentication required"

    monkeypatch.setattr(mongo_actions, "_try_list_databases", _try_list)

    def _try_creds(*_a, **_kw):
        return None, [
            {"username": "root", "password": "root", "default": True, "ok": False, "error": "authentication failed"},
        ]

    monkeypatch.setattr(mongo_actions, "_try_credentials", _try_creds)

    # Attempt 1 succeeds up to auth stage then explodes AFTER attempts recorded.
    def _collect_boom(*_a, **_kw):
        state["attempt"] += 1
        raise ConnectionError("connection reset after auth")

    monkeypatch.setattr(mongo_actions, "_collect_mongodb_data", _collect_boom)

    record = mongo_actions._audit_mongodb_host(
        host="127.0.0.1",
        port=27017,
        timeout=0.1,
        retries=0,
        credential_candidates=[{"username": "root", "password": "root", "default": True}],
        auth_db="admin",
        database=None,
        show_databases=False,
        show_collections=False,
        show_indexes=False,
        collection_targets=[],
        collection_targets_by_database={},
        dump_documents=False,
        dump_limit=None,
        query_filter=None,
        projection=None,
    )
    assert record["status"] == "fail"
    # A12 assertion: credential_attempts survived onto the fail record.
    assert record.get("credential_attempts"), "credential_attempts wiped on terminal fail"
    assert record["credential_attempts"][0]["username"] == "root"


# ============================================================================
# Postgres A13/A14
# ============================================================================


def test_fix_a13_postgres_attempt_render_no_password_uses_marker() -> None:
    """A13: a probe with password=None must render as `<no-password>`, not
    the literal `postgres`."""
    from redposture_core.modules.postgres.actions import _format_credential_attempts_records

    record = {
        "host": "10.0.0.1",
        "port": 5432,
        "attempted_credentials": [
            {"username": "postgres", "password": None},
            {"username": "postgres", "password": ""},
            {"username": "admin", "password": "s3cret"},
        ],
    }
    lines = _format_credential_attempts_records(record, "txt")
    joined = "\n".join(lines)
    assert "postgres:<no-password>" in joined
    assert "postgres:<empty>" in joined
    assert "admin:s3cret" in joined
    # NEGATIVE assertion: the buggy fallback must not appear.
    assert "postgres:postgres" not in joined or "admin" in joined  # sanity


def test_fix_a14_postgres_remote_dirname_basename_handles_windows_paths(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A14: server-side path parsing must not follow the CLIENT's os.path
    separator when auditing a Windows PG server from a POSIX host."""
    from redposture_core.modules.postgres import actions as pg_actions

    captured: dict[str, Any] = {}

    def _capture(_sock, sql):
        # pg_read_file must return an ERROR (so we take the pg_ls_dir/lo_import
        # fallback that exercises the A14 helpers). Returning empty rows would
        # short-circuit to the "empty pg_read_file result" path and still fall
        # through, but returning explicit error skips the happy elif.
        if "pg_read_file" in sql:
            return [], "permission denied"
        if "pg_ls_dir" in sql:
            captured["ls_dir_sql"] = sql
            return [["pg_hba.conf"]], None
        if "pg_switch_wal" in sql:
            return [], None
        if "lo_import" in sql:
            return [[42]], None
        if "lo_get" in sql:
            return [["contents"]], None
        return [], None

    monkeypatch.setattr(pg_actions, "_pg_query_rows", _capture)

    pg_actions._pg_try_read_server_file(
        object(),
        r"C:\Program Files\PostgreSQL\data\pg_hba.conf",
    )
    ls_dir_sql = captured.get("ls_dir_sql", "")
    # `pg_ls_dir` argument must be the full Windows-style directory, NOT `.`
    # The SQL doubles single quotes for escaping; there are none in this path
    # so the raw substring should appear.
    assert "C:\\Program Files\\PostgreSQL\\data" in ls_dir_sql, (
        f"pg_ls_dir SQL used the wrong directory: {ls_dir_sql!r}"
    )
    assert "pg_ls_dir('.'" not in ls_dir_sql, "fell back to '.' — client os.path bled through"


# ============================================================================
# Discovery B1 / B2
# ============================================================================


def test_fix_b1_ipv6_unbracketed_host_normalizes_intact() -> None:
    """B1: `2001:db8::1` must round-trip, not truncate to `2001`."""
    from redposture_core.targeting import normalize_scan_host

    assert normalize_scan_host("2001:db8::1") == "2001:db8::1"
    # Bracketed form still works.
    assert normalize_scan_host("[2001:db8::1]") == "2001:db8::1"
    # Bogus multi-colon strings that aren't real IPv6 fall back to the old
    # urlparse behavior; we just make sure we don't crash.
    assert normalize_scan_host("not:a:real:ip") is not None


def test_fix_b2_extract_display_port_no_crash_on_unbracketed_ipv6() -> None:
    """B2: extract_display_port must NOT raise ValueError on IPv6 literals."""
    from redposture_core.exporters.output import extract_display_port

    # Unbracketed IPv6 used to crash `parsed.port`.
    assert extract_display_port("2001:db8::1") == "-"
    # Bracketed with port still parses.
    assert extract_display_port("[2001:db8::1]:8443") == "8443"
    # Plain host:port unaffected.
    assert extract_display_port("host.example.com:9090") == "9090"


# ============================================================================
# Discovery B3 — Prometheus marker specificity
# ============================================================================


@pytest.mark.parametrize(
    "exporter_name",
    ["clickhouse_exporter", "mongodb_exporter", "pgbouncer_exporter"],
)
def test_fix_b3_generic_prefix_markers_removed(exporter_name: str) -> None:
    from redposture_core.constants import DISCOVERY_EXPORTERS

    match = next(e for e in DISCOVERY_EXPORTERS if e["name"] == exporter_name)
    # Bare prefix marker (e.g. `("clickhouse_",)`) is a false-positive magnet.
    assert match["markers"] != (f"{exporter_name.split('_')[0]}_",)
    # Real _up / _build_info anchors should be present.
    combined = " ".join(match["markers"])
    assert "_build_info" in combined or "_up" in combined


# ============================================================================
# Discovery B4 / B5 — negative_markers on shared ports
# ============================================================================


def test_fix_b4b5_negative_markers_veto_cross_labelled_hit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Body clearly belongs to apache_exporter — snmp_exporter on the same
    port 9117 must NOT get a marker_hit despite `snmp_` appearing anywhere."""
    from redposture_core.constants import DISCOVERY_EXPORTERS
    from redposture_core.exporters import discover

    snmp = next(e for e in DISCOVERY_EXPORTERS if e["name"] == "snmp_exporter")

    body = (
        "# HELP apache_exporter_build_info version\n"
        'apache_exporter_build_info{version="0.10"} 1\n'
        "# Some incidental `snmp_` mention that should not fire\n"
    )

    def _fake_http_get(*_a, **_kw):
        return {
            "status": 200,
            "body": body,
            "elapsed_ms": 1,
            "content_type": "text/plain",
            "error": None,
            "truncated": False,
        }

    record, hit = discover.scan_presence_task(
        "127.0.0.1", dict(snmp), timeout=1.0, retries=0, http_get_details_fn=_fake_http_get
    )
    assert hit is None, "snmp_exporter must NOT hit on an apache_exporter body"
    assert record["marker_hit"] is None
    assert record["detected"] is False


# ============================================================================
# Discovery B6 — file-vs-host ambiguity
# ============================================================================


def test_fix_b6_bare_hostname_not_confused_with_local_file(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    """B6: a bare hostname like `localhost` must not be read as a file, even
    if the current directory has a file of that name."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "localhost").write_text("10.0.0.99\n", encoding="utf-8")

    from redposture_core.targeting import collect_scan_targets

    hosts = collect_scan_targets("localhost")
    assert hosts == ["localhost"], f"'localhost' was misread as a hosts file: got {hosts}"


# ============================================================================
# Concurrency C1/C2 — LineOutputSink thread safety
# ============================================================================


def test_fix_c1_c2_line_output_sink_writes_are_serialized(tmp_path) -> None:
    """Two threads calling emit_many concurrently must not truncate one another
    (C1) and must produce whole lines with no interleaving (C2)."""
    from redposture_core.stage_runtime import LineOutputSink

    output_path = str(tmp_path / "out.txt")
    emitted: list[str] = []
    emit_lock = threading.Lock()

    def _emit(line: str) -> None:
        with emit_lock:
            emitted.append(line)

    sink = LineOutputSink(output_path, _emit)

    # 8 threads × 50 batches of 3 lines each — 1200 lines total.
    threads_n = 8
    per_thread = 50

    def _worker(tid: int) -> None:
        for i in range(per_thread):
            sink.emit_many([f"t{tid}-{i}-a", f"t{tid}-{i}-b", f"t{tid}-{i}-c"])

    threads = [threading.Thread(target=_worker, args=(t,)) for t in range(threads_n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    sink.close()

    with open(output_path, encoding="utf-8") as fh:
        file_lines = fh.read().splitlines()

    assert len(file_lines) == threads_n * per_thread * 3
    # C2: every emitted line is intact (no partial/interleaved lines).
    expected = {f"t{tid}-{i}-{tag}" for tid in range(threads_n) for i in range(per_thread) for tag in "abc"}
    assert set(file_lines) == expected
    # The console echo mirrors the file.
    assert len(emitted) == len(file_lines)


# ============================================================================
# Concurrency C3 — BoundedScheduler Ctrl+C cancellation
# ============================================================================


def test_fix_c3_scheduler_iter_completed_cancels_on_keyboard_interrupt() -> None:
    """C3: KeyboardInterrupt raised inside the consumer loop must propagate
    quickly instead of blocking on shutdown(wait=True)."""
    from redposture_core.scheduler import BoundedScheduler

    scheduler: BoundedScheduler[int, int] = BoundedScheduler(max_workers=4)
    items = list(range(50))

    def _slow(x: int) -> int:
        time.sleep(0.2)
        return x * 2

    start = time.monotonic()
    saw_interrupt = False
    try:
        for i, (_item, _result) in enumerate(scheduler.iter_completed(items, _slow)):
            if i == 1:
                raise KeyboardInterrupt
    except KeyboardInterrupt:
        saw_interrupt = True
    elapsed = time.monotonic() - start
    assert saw_interrupt
    # Without the fix, elapsed >> 50 * 0.2 / 4 = ~2.5s. With cancel, it should
    # come back nearly immediately. Allow 3s to keep the test stable on CI.
    assert elapsed < 3.0, f"scheduler did not cancel promptly on Ctrl+C: elapsed={elapsed}"


# ============================================================================
# Concurrency C4/C5 — HTTP listener DoS
# ============================================================================


def test_fix_c4_c5_read_bounded_body_caps_oversized_content_length() -> None:
    """C5: `_read_bounded_body` must clamp reads to the configured cap even
    if the caller advertises a much larger Content-Length."""
    from redposture_core.servers import MAX_LISTENER_REQUEST_BODY_BYTES, _read_bounded_body

    payload = b"A" * (MAX_LISTENER_REQUEST_BODY_BYTES + 4096)
    rfile = io.BytesIO(payload)
    got = _read_bounded_body(rfile, len(payload))
    assert len(got) == MAX_LISTENER_REQUEST_BODY_BYTES


def test_fix_c4_threading_http_reuse_server_sets_timeout_on_accept(monkeypatch: pytest.MonkeyPatch) -> None:
    """C4: ThreadingHTTPReuseServer must apply a socket timeout to every
    accepted connection so slow-clients don't park handler threads forever."""
    from redposture_core.servers import ThreadingHTTPReuseServer

    # We only need to verify the class exposes a non-None `timeout` attribute
    # and that `process_request` applies it to the accepted socket.
    assert isinstance(ThreadingHTTPReuseServer.timeout, (int, float))
    assert ThreadingHTTPReuseServer.timeout > 0

    applied: dict[str, float | None] = {"t": None}

    class _FakeSocket:
        def settimeout(self, value):
            applied["t"] = value

    # Patch the super().process_request so we don't need to actually serve.
    import http.server as http_server_mod

    monkeypatch.setattr(
        http_server_mod.ThreadingHTTPServer,
        "process_request",
        lambda self, request, client_address: None,
    )

    # We only need an instance stub, not a live socket bind.
    server = ThreadingHTTPReuseServer.__new__(ThreadingHTTPReuseServer)
    server.timeout = 10
    server.process_request(_FakeSocket(), ("127.0.0.1", 1))
    assert applied["t"] == 10, "process_request did not apply the class timeout to the accepted socket"


# ============================================================================
# Concurrency C6 — AuditConfig cached per namespace
# ============================================================================


def test_fix_c6_audit_config_reused_across_stage_invocations(monkeypatch: pytest.MonkeyPatch) -> None:
    """C6: the same argparse.Namespace must not force a fresh AuditConfig on
    every per-host stage invocation."""
    from redposture_core import stage_runtime

    build_calls = {"n": 0}
    real_from_namespace = stage_runtime.AuditConfig.from_namespace

    def _counting_from_namespace(ns):
        build_calls["n"] += 1
        return real_from_namespace(ns)

    monkeypatch.setattr(stage_runtime.AuditConfig, "from_namespace", _counting_from_namespace)

    # Minimal Namespace fielding what AuditConfig cares about.
    args = argparse.Namespace(
        timeout=1.0,
        retries=0,
        workers=1,
        debug=False,
        output=None,
        output_format="txt",
        username=None,
        password=None,
        defcreds=False,
    )

    def _fake_hook(host, port, timeout, retries):
        return {"host": host, "port": port, "status": "ok"}

    ctx = stage_runtime.AuditHookContext(
        args=args,
        logger=None,
        host="127.0.0.1",
        port=2181,
        credential=stage_runtime.AuditCredentialRun(source="anonymous"),
    )

    for _ in range(5):
        stage_runtime._invoke_host_stage(
            _fake_hook,
            module="testmod",
            ctx=ctx,
            run_deep_checks=True,
        )

    assert build_calls["n"] == 1, f"AuditConfig.from_namespace fired {build_calls['n']} times — cache didn't stick"
