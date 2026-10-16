"""GitLab Docker QA must follow the current unknown-version CVE policy."""

from __future__ import annotations

import pytest

from scripts.verify_gitlab_lab import verify_rendered_findings, verify_unknown_version_findings


def test_unknown_version_accepts_recent_unauthenticated_speculative_findings() -> None:
    verify_unknown_version_findings(
        {
            "status": "version_unknown",
            "findings": [
                {
                    "product": "gitlab",
                    "detected_version": None,
                    "version_assessment": "unknown",
                    "privileges_required": "N",
                    "access_basis": "network",
                }
            ],
        }
    )
    verify_unknown_version_findings({"status": "version_unknown", "findings": []})


@pytest.mark.parametrize(
    "change",
    [
        {"product": "jenkins"},
        {"detected_version": "17.7.1"},
        {"version_assessment": "affected"},
        {"privileges_required": "L"},
        {"access_basis": "credentials"},
    ],
)
def test_unknown_version_rejects_cross_product_or_privileged_findings(change: dict[str, str]) -> None:
    finding = {
        "product": "gitlab",
        "detected_version": None,
        "version_assessment": "unknown",
        "privileges_required": "N",
        "access_basis": "network",
        **change,
    }
    with pytest.raises(AssertionError):
        verify_unknown_version_findings({"status": "version_unknown", "findings": [finding]})


def test_rendered_unknown_version_cve_uses_possibly_wording() -> None:
    enumeration: dict[str, object] = {"status": "version_unknown", "findings": [{"id": "CVE-2026-85706"}]}
    verify_rendered_findings(enumeration, "[!] Possibly CVE-2026-85706 may affect this service")
    with pytest.raises(AssertionError):
        verify_rendered_findings(enumeration, "[!] CVE-2026-85706 potentially affected")


def test_rendered_known_version_cve_matches_identifier() -> None:
    verify_rendered_findings(
        {"status": "matched", "findings": [{"id": "CVE-2026-85706"}]},
        "[!] CVE-2026-85706 potentially affected",
    )
