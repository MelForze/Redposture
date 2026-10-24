"""MongoDB's authorization code 13 is distinct from invalid credentials (18)."""

import pytest

from redposture_core.clients.mongodb import normalize_mongodb_error


@pytest.mark.parametrize(
    "message", ["not authorized on denied to execute command", "Unauthorized", "not authorized code 13"]
)
def test_authorization_denial_is_never_renamed_authentication_failed(message: str) -> None:
    assert normalize_mongodb_error(RuntimeError(message)) == "authorization denied"


def test_real_server_authentication_failure_remains_an_identity_rejection() -> None:
    assert normalize_mongodb_error(RuntimeError("Authentication failed")) == "authentication failed"
