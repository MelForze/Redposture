from __future__ import annotations

from redposture_core.clients.airflow_api import AirflowResponse
from redposture_core.modules.airflow import actions


class _FakeClient:
    def __init__(self, get_status=200, get_body=b'{"dags":[],"total_entries":0}', post=None):
        self._get_status = get_status
        self._get_body = get_body
        self._post = post

    def get(self, path, *, authed=True):
        return AirflowResponse(http_status=self._get_status, headers={}, body=self._get_body)

    def post_json(self, path, payload, *, authed=False):
        status, body = self._post
        return AirflowResponse(http_status=status, headers={}, body=body)


def test_v1_basic_valid():
    r = actions.verify_credential(lambda **k: _FakeClient(get_status=200), "v1", "airflow", "airflow")
    assert r.state == "valid"


def test_v1_basic_invalid_on_401():
    body = b'{"status":401,"title":"Unauthorized","detail":"Authentication required"}'
    r = actions.verify_credential(lambda **k: _FakeClient(get_status=401, get_body=body), "v1", "admin", "admin")
    assert r.state == "invalid"


def test_v1_basic_restricted_on_403():
    body = b'{"status":403,"title":"Forbidden","detail":"Permission denied"}'
    r = actions.verify_credential(lambda **k: _FakeClient(get_status=403, get_body=body), "v1", "u", "p")
    assert r.state == "valid_but_restricted"


def test_v2_token_valid_keeps_bearer():
    def factory(**k):
        return _FakeClient(post=(200, b'{"access_token":"JWT","token_type":"Bearer"}'))

    r = actions.verify_credential(factory, "v2", "airflow", "airflow")
    assert r.state == "valid" and r.bearer_token == "JWT"


def test_v2_token_invalid_on_401():
    def factory(**k):
        return _FakeClient(post=(401, b'{"detail":"bad"}'))

    r = actions.verify_credential(factory, "v2", "admin", "admin")
    assert r.state == "invalid"
