"""Seeded foreign-schema fuzzing and required-field mutation regressions."""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from redposture_core.modules.spark import actions as spark
from redposture_core.modules.yarn import actions as yarn
from redposture_core.web_panels import _portainer_inventory_item

JSON = st.recursive(
    st.none() | st.booleans() | st.integers(min_value=-(2**128), max_value=2**128) | st.text(max_size=128),
    lambda child: (
        st.lists(child, max_size=8)
        | st.dictionaries(
            st.sampled_from(("unrelated", "status", "version", "error", "message", "items")), child, max_size=6
        )
    ),
    max_leaves=40,
)


@settings(max_examples=1000, derandomize=True, deadline=None)
@given(JSON)
def test_arbitrary_json_never_crashes_or_invents_a_cluster_product(value):
    assert spark._master(value) is False
    assert spark._status(value) is False
    assert yarn._info(value) is None


@settings(max_examples=1000, derandomize=True, deadline=None)
@given(JSON)
def test_arbitrary_inventory_wrappers_do_not_invent_allowed_rows(value):
    for name in ("apps", "nodes"):
        rows = yarn._rows(value, name)
        assert rows is None  # random JSON has no documented outer product key
    for name in ("containers", "images", "networks", "volumes"):
        assert _portainer_inventory_item(name, value) is False


@settings(max_examples=500, derandomize=True, deadline=None)
@given(st.sampled_from(("url", "workers", "cores", "activeapps")), JSON)
def test_mutating_spark_required_fields_can_only_preserve_a_real_schema(key, value):
    body = {"url": "spark://qa:7077", "workers": [], "cores": 0, "activeapps": []}
    body[key] = value
    confirmed = spark._master(body)
    if confirmed:
        assert isinstance(body["url"], str) and body["url"].startswith("spark://")
        assert type(body["cores"]) is int and body["cores"] >= 0
        assert isinstance(body["workers"], list) and isinstance(body["activeapps"], list)
