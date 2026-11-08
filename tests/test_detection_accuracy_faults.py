"""Read failures and generic ACL errors cannot confirm an HTTP product."""

from __future__ import annotations

import pytest

from scripts.detection_accuracy import detect, response_peer
from tests.test_network_fingerprint_matrix import HTTP_PRODUCTS


@pytest.mark.parametrize("module", HTTP_PRODUCTS)
@pytest.mark.parametrize("mode", ["sync", "async"])
def test_generic_denied_api_is_not_product_identity(module, mode):
    with response_peer(
        {"*": (403, b'{"error":"permission denied","code":403}', {"Content-Type": "application/json"})}
    ) as (port, requests):
        result = detect(module, port, mode)
    assert requests
    assert result["detected"] is False, result
