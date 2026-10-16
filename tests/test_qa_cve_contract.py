from __future__ import annotations

import pytest

from scripts.qa_cve_contract import assert_cve_rendering


@pytest.mark.parametrize(
    ("enumeration", "output"),
    [
        ({"status": "unsupported", "findings": []}, "REDIS [*] Redis Service"),
        (
            {"status": "version_unknown", "findings": [{"id": "CVE-2026-12345"}]},
            "REDIS [*] CVE's Enumeration\nREDIS [!] Possibly CVE-2026-12345 may affect this service",
        ),
        (
            {"status": "matched", "findings": [{"id": "CVE-2026-12345"}]},
            "REDIS [*] CVE's Enumeration\nREDIS [!] CVE-2026-12345 potentially affected",
        ),
    ],
)
def test_cve_rendering_contract_accepts_current_output(enumeration: dict, output: str) -> None:
    assert_cve_rendering(enumeration, output)


@pytest.mark.parametrize(
    ("enumeration", "output"),
    [
        ({"status": "unsupported", "findings": []}, "REDIS [*] CVE's Enumeration"),
        ({"status": "version_unknown", "findings": [{"id": "CVE-2026-12345"}]}, "CVE's Enumeration"),
        ({"status": "matched", "findings": [{"id": "CVE-2026-12345"}]}, "CVE's Enumeration"),
    ],
)
def test_cve_rendering_contract_rejects_missing_or_empty_output(enumeration: dict, output: str) -> None:
    with pytest.raises(AssertionError):
        assert_cve_rendering(enumeration, output)
