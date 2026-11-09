"""A completed scalar spilled by a small portion retains its provider rules."""

import pytest

from scripts.discovery_accuracy import expected_rows, load_holdout, measure, scan


@pytest.mark.parametrize("route", ["common", "disk-json", "stream-json", "elastic", "minio"])
@pytest.mark.parametrize("portion", [7, 37, 128, 65536])
def test_completed_webhook_matches_independent_label(route, portion):
    case = next(c for c in load_holdout()["cases"] if c["id"] == "provider-17-slack_webhook")
    actual, status = scan(route, case["body"], portion=portion)
    result = measure(expected_rows(case, route), actual)
    assert status == "complete"
    assert result["tp"] == 1 and result["fp"] == result["fn"] == result["duplicates"] == 0
