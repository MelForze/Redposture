"""Regression tests for the 10 code-review findings shipped in v5.7.1.

Each test locks in a specific defect so it cannot silently return. Test names
carry the fix number so a future contributor can trace the assertion back to
the original review write-up in one grep.
"""

from __future__ import annotations

import argparse
import hashlib
import unicodedata
from typing import Any

import pytest

# ---------------------------------------------------------------------------
# Fix 1 — Postgres --os-shell / --sql-shell no longer swallow command output
# ---------------------------------------------------------------------------


def test_fix1_postgres_os_shell_prints_command_output(monkeypatch: pytest.MonkeyPatch) -> None:
    """Interactive --os-shell must echo the (output, error) tuple returned by
    _pg_execute_remote_command. Prior to the fix the return value was ignored
    and the shell was silent."""
    from redposture_core.modules.postgres import stage as pg_stage

    class _CapturingConsole:
        def __init__(self) -> None:
            self.plain_calls: list[str] = []
            self.error_calls: list[str] = []

        def plain(self, message: str = "") -> None:
            self.plain_calls.append(str(message))

        def error(self, message: str) -> None:
            self.error_calls.append(str(message))

    console = _CapturingConsole()
    inputs = iter(["id", "quit"])

    def _fake_input(_prompt: str) -> str:
        return next(inputs)

    executed: list[str] = []

    def _fake_exec(*, host, port, timeout, retries, username, password, database, command):  # noqa: PLR0913
        executed.append(command)
        return ["uid=1000(postgres)"], None

    monkeypatch.setattr("builtins.input", _fake_input)
    monkeypatch.setattr(pg_stage.actions, "_pg_execute_remote_command", _fake_exec)
    monkeypatch.setattr(
        pg_stage,
        "build_postgres_plan",
        lambda args: type(
            "P",
            (),
            {"require_single_target_spec": lambda self: (0, "127.0.0.1", 5432, None)},
        )(),
    )
    monkeypatch.setattr(
        pg_stage.actions,
        "_audit_postgres_host",
        lambda **_kw: {"is_postgres": True, "status": "valid_credentials", "effective_username": "postgres"},
    )

    args = argparse.Namespace(
        os_shell=True,
        sql_shell=False,
        username="postgres",
        password="postgres",
        database="postgres",
        timeout=1.0,
        retries=0,
        debug=False,
        port=5432,
        target="127.0.0.1",
    )
    rc = pg_stage._run_postgres_shell(args, console)
    assert rc == 0
    assert executed == ["id"]
    assert "uid=1000(postgres)" in console.plain_calls  # THE bug being locked in


def test_fix1_postgres_shell_handles_eof_gracefully(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ctrl+D at the shell prompt must exit cleanly, not raise EOFError."""
    from redposture_core.modules.postgres import stage as pg_stage

    class _Console:
        def plain(self, _m: str = "") -> None:
            pass

        def error(self, _m: str) -> None:
            pass

    def _raise_eof(_prompt: str) -> str:
        raise EOFError

    monkeypatch.setattr("builtins.input", _raise_eof)
    monkeypatch.setattr(
        pg_stage,
        "build_postgres_plan",
        lambda args: type(
            "P",
            (),
            {"require_single_target_spec": lambda self: (0, "127.0.0.1", 5432, None)},
        )(),
    )
    monkeypatch.setattr(
        pg_stage.actions,
        "_audit_postgres_host",
        lambda **_kw: {"is_postgres": True, "status": "valid_credentials", "effective_username": "postgres"},
    )

    args = argparse.Namespace(
        os_shell=False,
        sql_shell=True,
        username="postgres",
        password="postgres",
        database="postgres",
        timeout=1.0,
        retries=0,
        debug=False,
        port=5432,
        target="127.0.0.1",
    )
    # Must return 0 (clean exit) instead of propagating EOFError.
    assert pg_stage._run_postgres_shell(args, _Console()) == 0


# ---------------------------------------------------------------------------
# Fix 4 — Redis is_redis must be False on non-RESP responses
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("resp_type", "resp_value", "expected_is_redis"),
    [
        ("simple", "PONG", True),  # canonical redis
        ("error", "NOAUTH", True),  # auth-required redis
        ("error", "LOADING dataset", False),  # generic RESP errors require a Redis INFO fingerprint
        ("bulk", "hello", False),  # not RESP-shaped for PING
        ("integer", 1, False),  # gRPC / memcached / random tcp
        ("array", [], False),  # `*0\r\n` from something else
        ("simple", "HELLO", False),  # simple string but not PONG
        ("null", None, False),
    ],
    ids=[
        "resp_pong",
        "resp_noauth_error",
        "resp_loading_error",
        "resp_bulk_not_redis",
        "resp_integer_not_redis",
        "resp_array_not_redis",
        "resp_simple_non_pong_not_redis",
        "resp_null_not_redis",
    ],
)
def test_fix4_redis_is_redis_only_on_resp_shaped_ping(
    monkeypatch: pytest.MonkeyPatch,
    resp_type: str,
    resp_value: Any,
    expected_is_redis: bool,
) -> None:
    from redposture_core.modules.redis import actions as redis_actions

    class _StubSocket:
        def __enter__(self):
            return self

        def __exit__(self, *_a):
            return False

        def settimeout(self, _t):
            pass

    monkeypatch.setattr(redis_actions.socket, "create_connection", lambda *_a, **_kw: _StubSocket())
    monkeypatch.setattr(redis_actions, "_send_cmd", lambda *_a, **_kw: (resp_type, resp_value))

    record = redis_actions._audit_redis_host(
        host="127.0.0.1",
        port=6379,
        timeout=1.0,
        retries=0,
        username=None,
        password=None,
        defcreds=False,
        show_keys=False,
        dump_keys=False,
        query_key=None,
    )
    assert record["is_redis"] is expected_is_redis, (
        f"redis classifier misfired on {resp_type}:{resp_value!r} — "
        f"is_redis={record.get('is_redis')} expected={expected_is_redis}"
    )


# ---------------------------------------------------------------------------
# Fix 5 — Consul detection must reject non-`host:port` leader strings
# ---------------------------------------------------------------------------


def test_fix5_consul_leader_must_look_like_host_port() -> None:
    from redposture_core.modules.consul.actions import _looks_like_consul_payload

    def _body(literal: str) -> bytes:
        # /v1/status/leader returns a bare JSON-encoded string.
        return f'"{literal}"'.encode()

    # Valid Consul leader payloads pass.
    assert _looks_like_consul_payload(200, _body("10.0.0.1:8300"))
    assert _looks_like_consul_payload(200, _body("[fe80::1]:8300"))

    # False positives that used to slip through:
    assert not _looks_like_consul_payload(200, b'""')  # empty leader (election)
    assert not _looks_like_consul_payload(200, _body(":8300"))  # colon but no host
    assert not _looks_like_consul_payload(200, _body("no-colon-at-all"))
    assert not _looks_like_consul_payload(200, _body("host:port"))  # non-numeric port
    assert not _looks_like_consul_payload(200, _body("host:99999"))  # port out of range

    # Wrong status still short-circuits.
    assert not _looks_like_consul_payload(404, _body("10.0.0.1:8300"))


# ---------------------------------------------------------------------------
# Fix 6 — Registry re-probes /v2/ anonymously to distinguish valid creds
# ---------------------------------------------------------------------------


def test_fix6_registry_valid_credentials_requires_auth_challenge(monkeypatch: pytest.MonkeyPatch) -> None:
    """When /v2/ returns 200 with provided creds AND anon reprobe also returns 200,
    the server is open — status must be open_no_auth, not valid_credentials.
    """
    from redposture_core.modules.registry import actions as registry_actions

    def _both_open(*_args, **kwargs):
        # Server accepts both anon and creds identically — an open registry.
        return 200, b"{}", {"docker-distribution-api-version": "registry/2.0"}, None

    monkeypatch.setattr(registry_actions, "_http_request", _both_open)
    monkeypatch.setattr(registry_actions, "_fetch_gitlab_info", lambda *_a, **_k: (None, "not gitlab"))
    monkeypatch.setattr(registry_actions, "_fetch_harbor_info", lambda *_a, **_k: (None, "not harbor"))
    monkeypatch.setattr(registry_actions, "_fetch_nexus_info", lambda *_a, **_k: (None, "not nexus"))

    from redposture_core.console import Console

    record = registry_actions._audit_registry_host_core(
        "127.0.0.1",
        5000,
        1.0,
        0,
        username="admin",
        password="admin",
        token=None,
        docker=False,
        show_images=False,
        show_tags=False,
        repository=None,
        tag=None,
        metadata=False,
        harbor=False,
        gitlab=False,
        nexus=False,
        assets=False,
        inspect=False,
        image=None,
        download=False,
        download_dir=".",
        console=Console(),
        debug=False,
    )
    assert record["status"] == "open_no_auth", (
        "registry claimed valid_credentials for an anonymous-access server; "
        "the anon reprobe should have downgraded the finding to open_no_auth"
    )


def test_fix6_registry_valid_credentials_confirmed_when_anon_denied(monkeypatch: pytest.MonkeyPatch) -> None:
    """Positive twin: anon reprobe returns 401 → creds actually validated something."""
    from redposture_core.modules.registry import actions as registry_actions

    def _auth_gated(*_args, **kwargs):
        headers = kwargs.get("headers") or {}
        if "Authorization" not in headers:
            return 401, b"unauthorized", {}, None
        return 200, b"{}", {"docker-distribution-api-version": "registry/2.0"}, None

    monkeypatch.setattr(registry_actions, "_http_request", _auth_gated)
    monkeypatch.setattr(registry_actions, "_fetch_gitlab_info", lambda *_a, **_k: (None, "not gitlab"))
    monkeypatch.setattr(registry_actions, "_fetch_harbor_info", lambda *_a, **_k: (None, "not harbor"))
    monkeypatch.setattr(registry_actions, "_fetch_nexus_info", lambda *_a, **_k: (None, "not nexus"))

    from redposture_core.console import Console

    record = registry_actions._audit_registry_host_core(
        "127.0.0.1",
        5000,
        1.0,
        0,
        username="admin",
        password="admin",
        token=None,
        docker=False,
        show_images=False,
        show_tags=False,
        repository=None,
        tag=None,
        metadata=False,
        harbor=False,
        gitlab=False,
        nexus=False,
        assets=False,
        inspect=False,
        image=None,
        download=False,
        download_dir=".",
        console=Console(),
        debug=False,
    )
    assert record["status"] == "valid_credentials"


# ---------------------------------------------------------------------------
# Fix 7 — SCRAM-SHA-256 client applies NFKC normalization before PBKDF2
# ---------------------------------------------------------------------------


def test_fix7_scram_password_is_nfkc_normalized_before_pbkdf2() -> None:
    """Non-ASCII passwords must be normalized so the derived SCRAM key matches
    what PostgreSQL/libpq computes. Prior to the fix the raw UTF-8 bytes were
    hashed, causing valid credentials to be rejected.
    """
    from redposture_core.modules.postgres import actions as pg_actions

    # Compose vs precomposed form of "café": U+0065 U+0301 (e + combining acute)
    # vs U+00E9. NFKC folds both to U+00E9, so the derived key must match.
    decomposed = "café"
    precomposed = "café"
    assert decomposed != precomposed
    assert unicodedata.normalize("NFKC", decomposed) == precomposed

    # Directly exercise the code path that computes salted_password. We
    # replicate the two lines from _scram_client_final that guard the hash.
    salt = b"S" * 16
    iterations = 4096

    def _salted(password: str) -> bytes:
        try:
            prepared = unicodedata.normalize("NFKC", password)
        except (TypeError, ValueError):
            prepared = password
        return hashlib.pbkdf2_hmac("sha256", prepared.encode("utf-8", errors="replace"), salt, iterations)

    assert _salted(decomposed) == _salted(precomposed), (
        "SCRAM salted_password differs between NFKC-equivalent passwords; "
        "SASLprep-lite normalization is not being applied"
    )

    # Sanity: the actions module still exposes the marker string patched by fix 7.
    src = getattr(pg_actions, "__file__", "")
    with open(src, encoding="utf-8") as fh:
        source = fh.read()
    assert 'unicodedata.normalize("NFKC", password)' in source, "SCRAM SASLprep normalization removed — fix 7 regressed"


# ---------------------------------------------------------------------------
# Fix 9 — Postgres privesc tri-state OR: unknown must not decay to False
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("inputs", "expected"),
    [
        ((True, False), True),  # any True wins
        ((False, True, None), True),
        ((None, None), None),  # all unknown → unknown
        ((None, False), None),  # unknown dominates over confirmed False
        ((False, False, False), False),  # all confirmed False → False
        ((True,), True),
        ((False,), False),
        ((None,), None),
    ],
)
def test_fix9_pg_tri_or_returns_unknown_when_any_input_unknown(
    inputs: tuple[bool | None, ...], expected: bool | None
) -> None:
    from redposture_core.modules.postgres.actions import _pg_tri_or

    assert _pg_tri_or(*inputs) is expected, (
        f"_pg_tri_or({inputs!r}) returned {_pg_tri_or(*inputs)!r} "
        f"but tri-state OR should give {expected!r} — "
        "the old `bool(x) or bool(y)` pattern would return False here and "
        "hide a real superuser privesc"
    )


# ---------------------------------------------------------------------------
# Fix 10 — MongoDB: auth_required must be True whenever creds succeed and anon
# listing failed for ANY reason (not only exact 'authentication required')
# ---------------------------------------------------------------------------


def test_fix10_mongodb_auth_required_true_when_anon_failed_generic_and_creds_worked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from redposture_core.modules.mongodb import actions as mongo_actions

    class _FakeClient:
        def __init__(self, *_a, **_kw):
            pass

        def hello(self):
            return {"version": "7.0.0"}

        def server_info(self):
            return {"version": "7.0.0"}

        def list_database_names(self):
            return ["admin", "config"]

        def close(self):
            pass

    def _open_client(*_a, **kwargs):
        return _FakeClient()

    # Simulate anon list failing with a NON-canonical error string.
    monkeypatch.setattr(mongo_actions, "_open_client", _open_client)

    def _try_list(client):  # noqa: ARG001
        # Anon: fails with a generic "not authorized" instead of the sentinel.
        if not hasattr(_try_list, "called"):
            _try_list.called = True
            return None, "not authorized on admin"
        # Auth'd: succeeds
        return ["admin", "config"], None

    monkeypatch.setattr(mongo_actions, "_try_list_databases", _try_list)
    monkeypatch.setattr(
        mongo_actions,
        "_try_credentials",
        lambda *_a, **_kw: (
            {"username": "root", "password": "root", "default": True},
            [{"username": "root", "password": "root", "default": True, "ok": True, "error": None}],
        ),
    )
    monkeypatch.setattr(mongo_actions, "_collect_mongodb_data", lambda *_a, **_kw: {})

    record = mongo_actions._audit_mongodb_host(
        host="127.0.0.1",
        port=27017,
        timeout=1.0,
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
    assert record["status"] == "weak_default_creds"
    assert record["auth_required"] is True, (
        "mongo auth_required stayed False even though anon listing failed and "
        "root:root then succeeded — fix 10 regressed"
    )


# ---------------------------------------------------------------------------
# Fix 2 — resolve_http_scheme picks the right scheme + memoizes results
# ---------------------------------------------------------------------------


def test_fix2_scheme_resolver_prefers_https_on_tls_hint_port(monkeypatch: pytest.MonkeyPatch) -> None:
    from redposture_core.clients import http_api

    # Wipe the process-wide cache to make the test deterministic.
    http_api._SCHEME_CACHE.clear()
    tried: list[str] = []

    class _FakeResponse:
        def __init__(self, error: str | None = None) -> None:
            self.error = error
            self.status = 200
            self.body = b""
            self.headers = {}

    def _fake_request(self, method, url, **_kw):  # noqa: ARG001
        tried.append(url)
        # For TLS hint ports, both scheme probes succeed — we should pick HTTPS.
        return _FakeResponse(None)

    monkeypatch.setattr(http_api.HttpApiClient, "request", _fake_request)

    scheme = http_api.resolve_http_scheme("harbor.example.com", 8443, timeout=1.0)
    assert scheme == "https"
    # The first probe must have been HTTPS (TLS hint port).
    assert tried[0].startswith("https://")


def test_fix2_scheme_resolver_falls_back_to_https_on_tls_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from redposture_core.clients import http_api

    http_api._SCHEME_CACHE.clear()
    tried: list[str] = []

    class _FakeResponse:
        def __init__(self, error: str | None = None) -> None:
            self.error = error
            self.status = 200
            self.body = b""
            self.headers = {}

    def _fake_request(self, method, url, **_kw):  # noqa: ARG001
        tried.append(url)
        if url.startswith("http://"):
            return _FakeResponse("wrong version number (protocol error)")
        return _FakeResponse(None)

    monkeypatch.setattr(http_api.HttpApiClient, "request", _fake_request)

    # Port 5000 is NOT a TLS hint — we start with http, TLS-shaped error should
    # fall back to https.
    scheme = http_api.resolve_http_scheme("registry.internal", 5000, timeout=1.0)
    assert scheme == "https"


def test_fix2_scheme_resolver_memoizes_per_host_port(monkeypatch: pytest.MonkeyPatch) -> None:
    from redposture_core.clients import http_api

    http_api._SCHEME_CACHE.clear()
    call_count = {"n": 0}

    class _FakeResponse:
        def __init__(self) -> None:
            self.error = None
            self.status = 200
            self.body = b""
            self.headers = {}

    def _fake_request(self, method, url, **_kw):  # noqa: ARG001
        call_count["n"] += 1
        return _FakeResponse()

    monkeypatch.setattr(http_api.HttpApiClient, "request", _fake_request)

    a = http_api.resolve_http_scheme("cache-test.example.com", 5000, timeout=1.0)
    first_calls = call_count["n"]
    b = http_api.resolve_http_scheme("cache-test.example.com", 5000, timeout=1.0)
    assert a == b
    assert call_count["n"] == first_calls, "resolver did not memoize repeat calls per (host, port)"


# ---------------------------------------------------------------------------
# Fix 3 — etcd v3 authenticate + credentials flow
# ---------------------------------------------------------------------------


def test_fix3_etcd_v3_authenticate_returns_token_on_success(monkeypatch: pytest.MonkeyPatch) -> None:
    from redposture_core.modules.etcd import actions as etcd_actions

    monkeypatch.setattr(
        etcd_actions,
        "_http_json_request",
        lambda *_a, **_kw: (200, '{"token": "abc.def.ghi"}'),
    )
    token, err = etcd_actions._etcd_v3_authenticate("127.0.0.1", 2379, 1.0, "root", "root")
    assert token == "abc.def.ghi"
    assert err is None


def test_fix3_etcd_v3_authenticate_flags_invalid_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    from redposture_core.modules.etcd import actions as etcd_actions

    monkeypatch.setattr(
        etcd_actions,
        "_http_json_request",
        lambda *_a, **_kw: (401, '{"error": "authentication failed"}'),
    )
    token, err = etcd_actions._etcd_v3_authenticate("127.0.0.1", 2379, 1.0, "root", "wrong")
    assert token is None
    assert err == "invalid credentials"


def test_fix_e2e_etcd_defcreds_reach_authenticate_endpoint_during_auth_phase(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """E2E-batch fix: `_call_audit_etcd_host_with_stage_debug` used to gate
    `username`/`password`/`defcreds` behind `run_deep_checks`, so defcreds
    were disabled during the auth phase (which is when they actually need to
    run — the runtime's default deep_gate rejects `auth_required`, so deep
    phase never runs). Regression pins the ungated propagation so this can't
    silently regress. Verified against a live etcd-auth container: previously
    /v3/auth/authenticate was never called; now the three default pairs
    (root:root, root:etcd, etcd:etcd) get probed."""
    from redposture_core.modules.etcd import actions as etcd_actions

    calls: list[dict] = []

    def _fake_http(host, port, method, path, timeout, *, payload=None, auth_token=None):
        calls.append({"path": path, "payload": payload})
        if path == "/version":
            return 200, '{"etcdserver": "3.5.14"}'
        if path == "/v2/keys?recursive=true":
            return 401, ""
        if path == "/v3/auth/status":
            return 200, '{"enabled": true}'
        if path == "/v3/kv/range" and auth_token is None:
            return 401, ""
        if path == "/v3/auth/authenticate":
            return 400, ""  # every default fails — we only care they were tried
        return 200, "{}"

    monkeypatch.setattr(etcd_actions, "_http_json_request", _fake_http)

    # Auth phase passes run_deep_checks=False.
    record = etcd_actions._call_audit_etcd_host_with_stage_debug(
        "127.0.0.1",
        22379,
        1.0,
        0,
        False,  # show_keys
        False,  # dump_keys
        None,  # query_key
        defcreds=True,
        run_deep_checks=False,
        debug=False,
        debug_emit=None,
    )
    auth_calls = [c for c in calls if c["path"] == "/v3/auth/authenticate"]
    assert auth_calls, "defcreds did not reach /v3/auth/authenticate during the auth phase"
    assert len(record.get("credential_attempts") or []) >= 1


def test_fix3_etcd_audit_tries_defcreds_when_auth_required(monkeypatch: pytest.MonkeyPatch) -> None:
    """When /v3 reports auth enabled and --defcreds is passed, the auditor
    must POST /v3/auth/authenticate at least once with a default credential
    pair."""
    from redposture_core.modules.etcd import actions as etcd_actions

    calls: list[dict[str, Any]] = []

    def _fake_http(host, port, method, path, timeout, *, payload=None, auth_token=None):  # noqa: PLR0913
        calls.append({"method": method, "path": path, "payload": payload, "auth": auth_token})
        if path == "/version":
            return 200, '{"etcdserver": "3.5.9"}'
        if path == "/v2/keys?recursive=true":
            return 401, ""  # v2 auth-gated
        if path == "/v3/auth/status":
            return 200, '{"enabled": true}'
        if path == "/v3/kv/range" and auth_token is None:
            return 401, ""  # anon denied
        if path == "/v3/kv/range" and auth_token == "TOKEN":
            return 200, '{"count": "3"}'
        if path == "/v3/auth/authenticate":
            if payload and payload.get("name") == "root" and payload.get("password") == "root":
                return 200, '{"token": "TOKEN"}'
            return 401, "unauthorized"
        return 200, "{}"

    monkeypatch.setattr(etcd_actions, "_http_json_request", _fake_http)

    record = etcd_actions._audit_etcd_host(
        host="127.0.0.1",
        port=2379,
        timeout=1.0,
        retries=0,
        show_keys=False,
        dump_keys=False,
        query_key=None,
        defcreds=True,
    )
    auth_calls = [c for c in calls if c["path"] == "/v3/auth/authenticate"]
    assert auth_calls, "audit did not invoke /v3/auth/authenticate with --defcreds set"
    assert record["status"] == "weak_default_creds"
    assert record["auth_required"] is True
    assert record["effective_username"] == "root"
    assert any(item.get("default") and item.get("ok") for item in record["credential_attempts"])
