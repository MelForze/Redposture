"""Asyncio's refused-connect wording must remain operational, not a proven negative."""

import pytest

from redposture_core.audit_models import AuditRecord
from redposture_core.stage_runtime import is_pre_detect_network_noise, is_pre_detect_operational_failure


@pytest.mark.parametrize("errno", [61, 111])
@pytest.mark.parametrize("typed", [False, True])
def test_async_refusal_is_not_a_conclusive_service_negative(errno, typed):
    payload = {
        "host": "127.0.0.1",
        "port": 6379,
        "module": "redis",
        "service": "redis",
        "status": "fail",
        "is_redis": False,
        "error": f"[Errno {errno}] Connect call failed ('127.0.0.1', 6379)",
    }
    record = AuditRecord.from_mapping(payload, module="redis", service="redis") if typed else payload
    assert is_pre_detect_operational_failure(record)
    assert is_pre_detect_network_noise(record)


def test_confirmed_service_cannot_be_hidden_as_pre_detect_noise():
    record = {
        "module": "redis",
        "status": "auth_required",
        "is_redis": True,
        "error": "[Errno 111] Connect call failed",
    }
    assert not is_pre_detect_operational_failure(record)
    assert not is_pre_detect_network_noise(record)
