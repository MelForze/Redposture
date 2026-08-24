from __future__ import annotations

import threading
from contextlib import nullcontext
from types import SimpleNamespace

import pytest

from redposture_core.audit_models import AuditRecord
from redposture_core.cli_args import build_parser
from redposture_core.modules.postgres import actions, policy
from redposture_core.modules.postgres import stage as postgres_stage


def _record(*, sqlstate: str | None = None, error: str | None = None) -> AuditRecord:
    return AuditRecord.from_mapping(
        {
            "host": "127.0.0.1",
            "port": 6432,
            "service": "postgres",
            "module": "postgres",
            "status": "unknown_auth",
            "is_postgres": True,
            "sqlstate": sqlstate,
            "error": error,
        },
        module="postgres",
        service="postgres",
    )


def test_postgres_credential_coordinator_serializes_same_host_across_ports() -> None:
    coordinator = postgres_stage._PostgresCredentialCoordinator(sleep=lambda _seconds: None, uniform=lambda *_: 0.1)
    first_entered = threading.Event()
    second_entered = threading.Event()
    release_first = threading.Event()

    def first() -> None:
        with coordinator.slot("10.0.0.1"):
            first_entered.set()
            assert release_first.wait(1.0)

    def second() -> None:
        with coordinator.slot("10.0.0.1"):
            second_entered.set()

    first_thread = threading.Thread(target=first)
    second_thread = threading.Thread(target=second)
    first_thread.start()
    assert first_entered.wait(1.0)
    second_thread.start()
    assert not second_entered.wait(0.05)
    release_first.set()
    first_thread.join(1.0)
    second_thread.join(1.0)
    assert second_entered.is_set()
    assert not first_thread.is_alive()
    assert not second_thread.is_alive()


def test_postgres_credential_coordinator_keeps_different_hosts_parallel() -> None:
    coordinator = postgres_stage._PostgresCredentialCoordinator(sleep=lambda _seconds: None, uniform=lambda *_: 0.1)
    first_entered = threading.Event()
    second_entered = threading.Event()
    release = threading.Event()

    def worker(host: str, entered: threading.Event) -> None:
        with coordinator.slot(host):
            entered.set()
            assert release.wait(1.0)

    first_thread = threading.Thread(target=worker, args=("10.0.0.1", first_entered))
    second_thread = threading.Thread(target=worker, args=("10.0.0.2", second_entered))
    first_thread.start()
    second_thread.start()
    assert first_entered.wait(1.0)
    assert second_entered.wait(1.0)
    release.set()
    first_thread.join(1.0)
    second_thread.join(1.0)
    assert not first_thread.is_alive()
    assert not second_thread.is_alive()


def test_postgres_credential_pacing_and_overload_cooldown_are_bounded() -> None:
    now = [0.0]
    sleeps: list[float] = []

    def sleep(seconds: float) -> None:
        sleeps.append(seconds)
        now[0] += seconds

    coordinator = postgres_stage._PostgresCredentialCoordinator(
        monotonic=lambda: now[0],
        sleep=sleep,
        uniform=lambda low, high: low,
    )
    with coordinator.slot("db.example"):
        pass
    with coordinator.slot("DB.EXAMPLE."):
        pass
    assert sleeps == pytest.approx([0.10])

    with coordinator.slot("db.example"):
        assert coordinator.observe("db.example", _record(sqlstate="53300")) == pytest.approx(0.50)
    with coordinator.slot("db.example"):
        pass
    assert sleeps[-1] == pytest.approx(0.50)


@pytest.mark.parametrize(
    ("sqlstate", "error"),
    [
        ("53300", "too many clients"),
        ("57P03", "cannot connect now"),
        (None, "PgBouncer max_client_conn reached"),
        (None, "server login has been failing, cached error"),
    ],
)
def test_postgres_transient_overload_classification(sqlstate: str | None, error: str) -> None:
    assert postgres_stage._postgres_is_transient_overload(_record(sqlstate=sqlstate, error=error)) is True


def test_postgres_unknown_startup_is_verification_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(actions, "_pg_open_socket", lambda *_args, **_kwargs: nullcontext(object()))
    monkeypatch.setattr(actions, "_pg_send_terminate", lambda _sock: None)

    def reject_startup(*_args, **_kwargs):
        raise actions._PgAuditError(
            'database "postgres" does not exist',
            detected=True,
            auth_required=None,
            sqlstate="3D000",
            failure_phase="startup",
            error_kind="startup_rejected",
        )

    monkeypatch.setattr(actions, "_pg_startup_and_auth", reject_startup)
    ctx = SimpleNamespace(
        host="127.0.0.1",
        port=6432,
        credential=SimpleNamespace(username="postgres", password="postgres", source="default"),
        args=SimpleNamespace(
            timeout=1.0,
            retries=0,
            sslmode="disable",
            ssl_ca=None,
            ssl_cert=None,
            ssl_key=None,
            ssl_server_name=None,
        ),
    )
    record = postgres_stage._postgres_probe_credential(ctx)
    assert record.status == "unknown_auth"
    assert record.extra["credential_verified"] is None
    assert record.extra["credential_verification"] == "unavailable"


def test_postgres_unavailable_attempt_is_not_rendered_as_rejected() -> None:
    lines = actions._format_credential_attempts_records(
        {
            "host": "127.0.0.1",
            "port": 6432,
            "attempted_credentials": [
                {
                    "username": "postgres",
                    "password": "postgres",
                    "status": "unknown_auth",
                    "credential_verification": "unavailable",
                },
                {
                    "username": "admin",
                    "password": "admin",
                    "status": "auth_required",
                    "credential_verification": "rejected",
                },
            ],
        },
        "txt",
    )
    assert "[!] postgres:postgres (verification unavailable)" in lines[0]
    assert "[-] postgres:postgres" not in lines[0]
    assert "[-] admin:admin" in lines[1]


def test_postgres_cli_accepts_stop_on_success_with_defcreds() -> None:
    args = build_parser().parse_args(["postgres", "-t", "127.0.0.1", "--defcreds", "--stop-on-success"])
    assert args.defcreds is True
    assert args.stop_on_success is True
    assert postgres_stage.build_postgres_spec(args).continue_after_credential_success is False


def test_postgres_stop_on_success_requires_defcreds() -> None:
    args = build_parser().parse_args(["postgres", "-t", "127.0.0.1", "--stop-on-success"])
    errors: list[str] = []
    console = SimpleNamespace(error=errors.append)
    assert policy.validate_args(args, console) == 2
    assert errors == ["--stop-on-success requires --defcreds"]
