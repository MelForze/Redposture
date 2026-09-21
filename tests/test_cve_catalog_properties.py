"""Catalog-wide version-range properties, evaluated for every shipped range."""

from __future__ import annotations

import pytest

from redposture_core.cve import load_catalog, normalize_version, version_in_range


def _catalog_ranges() -> list[tuple[str, str, dict[str, str]]]:
    return [
        (str(entry["id"]), str(entry["product"]), dict(affected))
        for entry in load_catalog().entries
        for affected in entry["affected"]
    ]


@pytest.mark.parametrize(("cve_id", "product", "affected"), _catalog_ranges())
def test_every_catalog_range_accepts_inclusive_boundaries_and_rejects_fixed_boundary(
    cve_id: str,
    product: str,
    affected: dict[str, str],
) -> None:
    del cve_id, product
    if introduced := affected.get("introduced"):
        assert version_in_range(introduced, affected) is True
    if last_affected := affected.get("last_affected"):
        assert version_in_range(last_affected, affected) is True
    if fixed := affected.get("fixed"):
        assert version_in_range(fixed, affected) is False


@pytest.mark.parametrize(("cve_id", "product", "affected"), _catalog_ranges())
def test_every_catalog_boundary_normalizes_deterministically(
    cve_id: str,
    product: str,
    affected: dict[str, str],
) -> None:
    del cve_id, product
    scheme = affected.get("scheme", "numeric")
    for field in ("introduced", "fixed", "last_affected"):
        value = affected.get(field)
        if value is None:
            continue
        first = normalize_version(value, scheme)
        second = normalize_version(value.strip(), scheme)
        assert first is not None
        assert second == first


@pytest.mark.parametrize(
    ("version", "affected", "expected"),
    [
        ("8.2.7-rc1", {"introduced": "8.2.0", "fixed": "8.2.7", "scheme": "numeric"}, True),
        ("8.2.7+vendor.9", {"introduced": "8.2.0", "fixed": "8.2.7", "scheme": "numeric"}, False),
        ("v1.27.5", {"introduced": "1.27.0", "last_affected": "1.27.5", "scheme": "numeric"}, True),
        ("13.10.2-ee", {"introduced": "13.10.0", "fixed": "13.10.3", "scheme": "numeric"}, True),
        (
            "RELEASE.2023-03-20T20-16-18Z",
            {"fixed": "2023-03-20t20-16-18z", "scheme": "minio_release"},
            False,
        ),
        ("18c", {"introduced": "18.0.0.0.0", "last_affected": "18.0.0.0.0", "scheme": "oracle"}, True),
    ],
)
def test_version_range_representation_invariants(
    version: str,
    affected: dict[str, str],
    expected: bool,
) -> None:
    assert version_in_range(version, affected) is expected
