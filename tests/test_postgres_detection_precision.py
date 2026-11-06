"""Only startup decisions confirm PostgreSQL wire, not incidental metadata."""

import pytest

from redposture_core.modules.postgres import actions
from tests.test_postgres_startup_evidence import Socket, error, frame


@pytest.mark.parametrize(
    "message",
    [
        frame(b"S", b"server_version\x0016.4\0"),
        frame(b"K", bytes(8)),
        frame(b"N", b"SNOTICE\0C00000\0Mhello\0\0"),
        frame(b"R", (8).to_bytes(4, "big") + b"opaque"),
        frame(b"R", (11).to_bytes(4, "big") + b"r=nonce,s=c2FsdA==,i=4096"),
        frame(b"R", (12).to_bytes(4, "big") + b"v=c2ln"),
    ],
)
def test_incidental_or_out_of_order_message_is_not_protocol_proof(message):
    with pytest.raises((actions._PgAuditError, ConnectionError)) as caught:
        actions._pg_startup_and_auth(Socket(message), "qa", "candidate", "app")
    assert getattr(caught.value, "detected", False) is False
    assert getattr(caught.value, "credential_verified", None) is None


def test_notice_before_authentication_is_allowed_without_being_proof_itself():
    notice = frame(b"N", b"SNOTICE\0C00000\0Mproxy notice\0\0")
    with pytest.raises(actions._PgAuditError) as caught:
        actions._pg_startup_and_auth(Socket(notice + error("08P01", "no such user")), "qa", "candidate", "app")
    assert caught.value.detected is True
    assert caught.value.auth_required is None
    assert caught.value.credential_verified is None


def test_complete_startup_confirms_protocol_without_claiming_exact_product():
    response = (
        frame(b"R", bytes(4)) + frame(b"S", b"server_version\x0016.4\0") + frame(b"K", bytes(8)) + frame(b"Z", b"I")
    )
    record = actions._pg_startup_record_fields(actions._pg_startup_and_auth(Socket(response), "qa", None, "app"))
    assert record["protocol_evidence"] == "postgresql_wire"
    assert record["service_identity"] == "postgresql_compatible"
    assert record["startup_complete"] is True
