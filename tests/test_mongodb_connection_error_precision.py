from __future__ import annotations

import pytest
from pymongo.errors import OperationFailure, ServerSelectionTimeoutError

from redposture_core.clients.mongodb import normalize_mongodb_error


@pytest.mark.parametrize("code", [61, 111])
def test_refused_connection_is_not_timeout_because_driver_lists_timeout_configuration(code):
    error = ServerSelectionTimeoutError(
        f"127.0.0.1:27017: [Errno {code}] Connect call failed ('127.0.0.1', 27017) "
        "(configured timeouts: socketTimeoutMS: 500.0ms, connectTimeoutMS: 500.0ms), Timeout: 0.5s"
    )
    assert normalize_mongodb_error(error) == "connection refused (service is not listening on target port)"


@pytest.mark.parametrize("code", [8, -2])
def test_numeric_dns_errno_takes_precedence_over_configuration_footer(code):
    error = ServerSelectionTimeoutError(f"[Errno {code}] lookup failed (configured timeouts: connectTimeoutMS: 500)")
    assert normalize_mongodb_error(error) == "dns lookup failed"


def test_mixed_refused_and_actual_timed_out_addresses_are_not_all_called_refused():
    error = ServerSelectionTimeoutError("[Errno 111] Connect call failed; [Errno 110] timed out; Timeout: 0.5s")
    assert normalize_mongodb_error(error) == "connection timeout"


@pytest.mark.parametrize(("code", "expected"), [(18, "authentication failed"), (13, "authorization denied")])
def test_structured_server_auth_error_is_not_overridden_by_timeout_text(code, expected):
    assert normalize_mongodb_error(OperationFailure("user timeout test, error [Errno 111]", code=code)) == expected
