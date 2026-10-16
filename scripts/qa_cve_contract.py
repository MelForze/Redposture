"""Check that QA text output represents the CVE findings in its JSON record."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


def assert_cve_rendering(enumeration: Mapping[str, Any], output: str) -> None:
    findings = enumeration.get("findings")
    assert isinstance(findings, list), "CVE findings missing"
    assert ("CVE's Enumeration" in output) is bool(findings), "CVE heading/findings mismatch"
    for finding in findings:
        assert isinstance(finding, dict), "invalid CVE finding"
        identifier = finding.get("id")
        assert isinstance(identifier, str), "CVE identifier missing"
        expected = f"Possibly {identifier}" if enumeration.get("status") == "version_unknown" else identifier
        assert expected in output, f"CVE finding not rendered: {identifier}"
