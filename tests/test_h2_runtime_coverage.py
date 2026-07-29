from __future__ import annotations

import time
from types import SimpleNamespace

import pytest

from redposture_core.audit_models import AuditRecord
from redposture_core.modules.redis import actions as redis
from redposture_core.stage_runtime import AuditCredentialRun


class _Socket:
    def __init__(self) -> None:
        self.closed = False

    def close(self) -> None:
        self.closed = True


def _state(**overrides: object) -> redis.RedisAuditLifecycleState:
    values: dict[str, object] = {
        "host": "redis.internal",
        "port": 6379,
        "timeout": 1.0,
        "retries": 0,
        "debug": False,
        "debug_emit": None,
        "started": time.monotonic(),
    }
    values.update(overrides)
    return redis.RedisAuditLifecycleState(**values)


def _ctx(
    state: object,
    *,
    credential: AuditCredentialRun | None = None,
    **args: object,
) -> SimpleNamespace:
    defaults: dict[str, object] = {
        "show_keys": False,
        "dump": False,
        "key": None,
        "query_key": None,
        "dump_batch": 10000,
        "dump_delay": 20,
    }
    defaults.update(args)
    return SimpleNamespace(
        lifecycle_state=state,
        credential=credential or AuditCredentialRun(source="anonymous"),
        args=SimpleNamespace(**defaults),
    )


def _record(status: str = "auth_required") -> AuditRecord:
    return AuditRecord(
        host="redis.internal",
        port=6379,
        module="redis",
        service="redis",
        status=status,
    )


def test_redis_detect_covers_open_unexpected_and_retry_exhaustion(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(redis, "_open_redis_lifecycle_socket", lambda state: setattr(state, "sock", _Socket()))

    open_state = _state()
    monkeypatch.setattr(redis, "_send_cmd", lambda *_args: ("simple", "PONG"))
    open_record = redis.redis_detect_hook(_ctx(open_state))
    assert open_record.status == "open_no_auth"
    assert open_state.auth_required is False

    unexpected_state = _state()
    monkeypatch.setattr(redis, "_send_cmd", lambda *_args: ("bulk", "not redis"))
    unexpected_record = redis.redis_detect_hook(_ctx(unexpected_state))
    assert unexpected_record.status == "fail"
    assert unexpected_state.sock is None

    attempts = 0

    def fail_open(state: redis.RedisAuditLifecycleState) -> None:
        nonlocal attempts
        attempts += 1
        state.sock = _Socket()
        raise TimeoutError("connect timed out")

    failed_state = _state(retries=1)
    monkeypatch.setattr(redis, "_open_redis_lifecycle_socket", fail_open)
    monkeypatch.setattr(redis.time, "sleep", lambda _delay: None)
    failed_record = redis.redis_detect_hook(_ctx(failed_state))
    assert attempts == 2
    assert failed_record.status == "fail"
    assert failed_record.extra["is_redis"] is False
    assert failed_record.extra["error"] == "connect timed out"


def test_redis_auth_covers_shortcuts_default_failure_and_transient_exhaustion(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prior = _record()

    failed_state = _state(is_redis=False, status="fail", error="not redis")
    assert redis.redis_auth_hook(_ctx(failed_state), prior).status == "fail"

    open_state = _state(is_redis=True, auth_required=False, status="open_no_auth", sock=_Socket())
    open_record = redis.redis_auth_hook(_ctx(open_state), prior)
    assert open_record.status == "open_no_auth"
    assert open_state.active_source == "anonymous"

    required_state = _state(is_redis=True, auth_required=True, status="auth_required", sock=_Socket())
    required_record = redis.redis_auth_hook(_ctx(required_state), prior)
    assert required_record.status == "auth_required"

    default_state = _state(is_redis=True, auth_required=True, status="auth_required", sock=_Socket())
    monkeypatch.setattr(redis, "_check_default_credentials", lambda _sock, **_kwargs: (False, "WRONGPASS"))
    default_record = redis.redis_auth_hook(
        _ctx(
            default_state,
            credential=AuditCredentialRun(username="redis", password="redis", source="default"),
        ),
        prior,
    )
    assert default_record.status == "auth_required"
    assert default_state.default_credentials_attempted is True
    assert default_state.error == "WRONGPASS"

    attempts = 0

    def fail_auth(*_args: object, **_kwargs: object) -> tuple[bool | None, str | None]:
        nonlocal attempts
        attempts += 1
        raise ConnectionError("socket reset")

    exhausted_state = _state(
        retries=1,
        is_redis=True,
        auth_required=True,
        status="auth_required",
        sock=_Socket(),
    )
    monkeypatch.setattr(redis, "_check_provided_credentials", fail_auth)
    monkeypatch.setattr(redis, "_open_redis_lifecycle_socket", lambda state: setattr(state, "sock", _Socket()))
    monkeypatch.setattr(redis.time, "sleep", lambda _delay: None)
    exhausted_record = redis.redis_auth_hook(
        _ctx(
            exhausted_state,
            credential=AuditCredentialRun(username="app", password="secret", source="provided"),
        ),
        prior,
    )
    assert attempts == 2
    assert exhausted_record.status == "fail"
    assert exhausted_state.error == "socket reset"


def test_redis_collect_data_covers_dump_show_and_query_error_paths(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dump_state = _state(dump_keys=True, query_key="selected", sock=_Socket())
    monkeypatch.setattr(redis, "_count_redis_keys", lambda _sock: (None, "DBSIZE unavailable"))
    monkeypatch.setattr(
        redis,
        "_stream_dump_redis_keys",
        lambda *_args, **_kwargs: ([{"key": "a", "value": "1", "error": None}], "partial dump"),
    )
    monkeypatch.setattr(redis, "_dump_redis_key_value", lambda *_args: ("<error>", "GET failed"))
    redis._redis_collect_lifecycle_data_once(dump_state, dump_batch=10, dump_delay=0)
    assert dump_state.key_count == 1
    assert dump_state.keys == ["a"]
    assert dump_state.error == "DBSIZE unavailable; partial dump; GET failed"

    show_state = _state(show_keys=True, query_key="selected", sock=_Socket())
    monkeypatch.setattr(redis, "_count_redis_keys", lambda _sock: (None, None))
    monkeypatch.setattr(redis, "_scan_redis_keys", lambda *_args, **_kwargs: (["a", "b"], "SCAN partial"))
    monkeypatch.setattr(redis, "_dump_redis_key_value", lambda *_args: ("value", None))
    redis._redis_collect_lifecycle_data_once(show_state, dump_batch=10, dump_delay=0)
    assert show_state.key_count == 2
    assert show_state.error == "SCAN partial"
    assert show_state.query_key_entry == {"key": "selected", "value": "value", "error": None}


def test_redis_reauthentication_and_data_failure_paths(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    anonymous = _state(active_source="anonymous")
    redis._redis_reauthenticate_lifecycle_state(anonymous)

    default_state = _state(active_source="default", sock=_Socket())
    monkeypatch.setattr(redis, "_check_default_credentials", lambda _sock: (True, None))
    redis._redis_reauthenticate_lifecycle_state(default_state)

    rejected_state = _state(
        active_source="provided",
        active_username="app",
        active_password="secret",
        sock=_Socket(),
    )
    monkeypatch.setattr(redis, "_check_provided_credentials", lambda *_args: (False, "WRONGPASS"))
    with pytest.raises(redis._RedisAuthenticationRejected, match="WRONGPASS"):
        redis._redis_reauthenticate_lifecycle_state(rejected_state)

    shallow_state = _state(status="auth_required")
    shallow = redis.redis_data_hook(_ctx(shallow_state), _record())
    assert shallow.status == "auth_required"

    retry_state = _state(
        retries=1,
        is_redis=True,
        auth_required=True,
        status="valid_credentials",
        active_source="provided",
        active_username="app",
        active_password="secret",
        sock=None,
    )
    monkeypatch.setattr(redis, "_open_redis_lifecycle_socket", lambda state: setattr(state, "sock", _Socket()))
    monkeypatch.setattr(
        redis,
        "_redis_reauthenticate_lifecycle_state",
        lambda _state: (_ for _ in ()).throw(redis._RedisAuthenticationRejected("credentials revoked")),
    )
    rejected = redis.redis_data_hook(_ctx(retry_state), _record("valid_credentials"))
    assert rejected.status == "auth_required"
    assert rejected.extra["error"] == "credentials revoked"

    exhausted_state = _state(
        retries=1,
        is_redis=True,
        auth_required=False,
        status="open_no_auth",
        active_source="anonymous",
        sock=_Socket(),
    )
    calls = 0

    def fail_data(*_args: object, **_kwargs: object) -> None:
        nonlocal calls
        calls += 1
        raise ConnectionError("read reset")

    monkeypatch.setattr(redis, "_redis_collect_lifecycle_data_once", fail_data)
    monkeypatch.setattr(redis, "_open_redis_lifecycle_socket", lambda state: setattr(state, "sock", _Socket()))
    monkeypatch.setattr(redis, "_redis_reauthenticate_lifecycle_state", lambda _state: None)
    monkeypatch.setattr(redis.time, "sleep", lambda _delay: None)
    exhausted = redis.redis_data_hook(_ctx(exhausted_state), _record("open_no_auth"))
    assert calls == 2
    assert exhausted.status == "fail"
    assert exhausted.extra["error"] == "read reset"


def test_redis_lifecycle_contract_rejects_missing_state_and_tolerates_close_error() -> None:
    ctx = _ctx(object())
    with pytest.raises(TypeError, match="lifecycle state"):
        redis.redis_detect_hook(ctx)
    with pytest.raises(TypeError, match="lifecycle state"):
        redis.redis_auth_hook(ctx, _record())
    with pytest.raises(TypeError, match="lifecycle state"):
        redis.redis_data_hook(ctx, _record())

    class BrokenSocket:
        def close(self) -> None:
            raise OSError("close failed")

    state = _state(sock=BrokenSocket())
    redis.close_redis_lifecycle_state(state)
    assert state.sock is None
