from __future__ import annotations

from redposture_core.clients.minio_api import MinioResponse, S3Error
from redposture_core.modules.minio import actions


class _StubClient:
    def __init__(self, *, account=None, users=None, policies=None):
        self._account, self._users, self._policies = account, users, policies

    def account_info(self, *, signed=True):
        return self._account

    def list_users(self, *, signed=True):
        return self._users

    def list_canned_policies(self, *, signed=True):
        return self._policies


def _ok(body=b"{}"):
    return MinioResponse(http_status=200, headers={}, body=body, error=None)


def _denied():
    return MinioResponse(http_status=403, headers={}, body=b"", error=S3Error(403, "AccessDenied", ""))


def _boom():
    return MinioResponse(http_status=0, headers={}, body=b"", transport_error="timeout")


def test_confirmed_when_admin_reads_succeed():
    cap = actions.classify_admin_capability(_StubClient(account=_ok(), users=_ok(), policies=_ok()))
    assert cap.capability == "confirmed"


def test_partial_when_some_admin_reads_denied():
    cap = actions.classify_admin_capability(_StubClient(account=_ok(), users=_ok(), policies=_denied()))
    assert cap.capability == "partial"


def test_not_confirmed_when_all_admin_reads_denied():
    cap = actions.classify_admin_capability(_StubClient(account=_denied(), users=_denied(), policies=_denied()))
    assert cap.capability == "not_confirmed"


def test_unknown_when_admin_plane_unreachable():
    cap = actions.classify_admin_capability(_StubClient(account=_boom(), users=_boom(), policies=_boom()))
    assert cap.capability == "unknown"


def test_identity_root_from_console_admin_accountinfo():
    account = _ok(
        b'{"AccountName":"minioadmin","Policy":{"Statement":[{"Effect":"Allow","Action":["admin:*"],"Resource":["arn:aws:s3:::*"]}]}}'
    )
    cap = actions.classify_admin_capability(_StubClient(account=account, users=_ok(), policies=_ok()))
    assert cap.identity_kind == "delegated_admin"


def test_capabilities_record_populates_admin_and_permissions(monkeypatch):
    from redposture_core.modules.minio import actions as _a
    from redposture_core.modules.minio.types import AdminCapability

    monkeypatch.setattr(
        _a,
        "classify_admin_capability",
        lambda client: AdminCapability(capability="confirmed", identity_kind="root", evidence={}),
    )
    from redposture_core.clients.minio_api import MinioResponse

    class _FakeClient:
        def admin_info(self, *, signed: bool = True) -> MinioResponse:
            return MinioResponse(http_status=403, headers={}, body=b"")

    monkeypatch.setattr(_a, "_client_for", lambda ctx, cred: _FakeClient())

    class _Ctx:
        class args:
            session_token = None

        host, port = "h", 9000
        lifecycle_state = None

        class credential:
            username, password, source = "AK", "SK", "provided"

    rec = _a.capabilities_record(_Ctx(), {"credential_state": "valid"})
    assert rec["admin_capability"] == "confirmed"
    assert rec["identity_kind"] == "root"
    assert rec["permissions"]["write_objects"] == "unknown"
    assert rec["permissions"]["admin_plane"] == "ok"


def test_capabilities_record_skips_when_no_valid_credential():
    from redposture_core.modules.minio import actions as _a

    rec = _a.capabilities_record(object(), {"credential_state": "invalid"})
    assert "admin_capability" not in rec


def test_admin_equivalent_is_delegated_admin_not_over_claimed_root():
    from redposture_core.modules.minio import actions as _a

    class _C:
        access_key = "minioadmin"

        def account_info(self, *, signed=True):
            return _ok(b'{"AccountName":"minioadmin","Policy":{"Statement":[{"Action":["admin:*"]}]}}')

        def list_users(self, *, signed=True):
            return _ok()

        def list_canned_policies(self, *, signed=True):
            return _ok()

    # Admin-equivalent identity is reported delegated_admin; root is never
    # over-claimed from accountinfo (needs Phase-4 lab calibration).
    assert _a.classify_admin_capability(_C()).identity_kind == "delegated_admin"
