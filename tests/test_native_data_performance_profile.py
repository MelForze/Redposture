"""Data adapters use independent known values; network/SDK internals are not fabricated."""

import pytest

from scripts.profile_native_data_performance import MODULES, native_data


@pytest.mark.parametrize("module", MODULES)
def test_native_data_profile_has_exact_rows_and_explicit_boundary(module):
    actual, expected, scope = native_data(module, 4)
    assert actual == expected
    assert "excludes" in scope
