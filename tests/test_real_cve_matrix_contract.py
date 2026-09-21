from __future__ import annotations

import runpy
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_real_cve_matrix_has_vulnerable_and_fixed_vendor_versions() -> None:
    namespace = runpy.run_path(
        str(ROOT / "scripts/verify_real_cve_matrix.py"),
        run_name="redposture_real_cve_matrix",
    )
    cases = namespace["CASES"]
    compose = (ROOT / "tests/fixtures/cve_version_matrix/docker-compose.yml").read_text(encoding="utf-8")

    by_module: dict[str, list[object]] = {}
    for case in cases:
        by_module.setdefault(case.module, []).append(case)
        assert f":{case.version}" in compose
    assert set(by_module) == {"redis", "grafana"}
    for module_cases in by_module.values():
        assert {case.affected for case in module_cases} == {False, True}
        assert len({case.cve for case in module_cases}) == 1
