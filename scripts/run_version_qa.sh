#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"
export REDPOSTURE_QA_PROJECT_PREFIX="${REDPOSTURE_QA_PROJECT_PREFIX:-redpostureqa$$}"
ARTIFACT_DIR="${1:-/tmp/redposture_versions_$(date -u +%Y%m%d_%H%M%S)}"
if [ -d "${ARTIFACT_DIR}" ] && [ -n "$(ls -A "${ARTIFACT_DIR}")" ]; then
  echo "[error] version QA output directory is not empty: ${ARTIFACT_DIR}" >&2
  exit 2
fi
mkdir -p "${ARTIFACT_DIR}"
PYTHON_BIN="${PYTHON_BIN:-${ROOT_DIR}/.venv/bin/python}"
if [ ! -x "${PYTHON_BIN}" ]; then
  PYTHON_BIN=python3
fi

echo "== Redis, Grafana and PostgreSQL CVE boundaries =="
set +e
PYTHON="${PYTHON_BIN}" ./scripts/run_real_cve_matrix.sh 2>&1 | tee "${ARTIFACT_DIR}/cve-boundaries.log"
boundary_rc=${PIPESTATUS[0]}
echo "== Airflow and Elasticsearch release detection =="
"${PYTHON_BIN}" scripts/run_extended_version_matrix.py "${ARTIFACT_DIR}/extended" 2>&1 | tee "${ARTIFACT_DIR}/extended.log"
extended_rc=${PIPESTATUS[0]}
echo "== Other real-service release pairs and module actions =="
"${PYTHON_BIN}" scripts/run_service_version_matrix.py "${ARTIFACT_DIR}/compatibility" 2>&1 | tee "${ARTIFACT_DIR}/compatibility.log"
compatibility_rc=${PIPESTATUS[0]}
set -e

"${PYTHON_BIN}" - "${ARTIFACT_DIR}" "${boundary_rc}" "${extended_rc}" "${compatibility_rc}" <<'PY'
import json
import sys
from pathlib import Path

root = Path(sys.argv[1]).resolve()
checkout = Path.cwd()
boundary_rc, extended_rc, compatibility_rc = map(int, sys.argv[2:])
extended_path = root / "extended" / "results.json"
extended = json.loads(extended_path.read_text()) if extended_path.exists() else []
compatibility_path = root / "compatibility" / "report.json"
compatibility = json.loads(compatibility_path.read_text()) if compatibility_path.exists() else {}
compatibility_cases = json.loads((checkout / "lab/services/version_matrix.json").read_text())["cases"]
if len(extended) != 5 or any(item["status"] != "passed" for item in extended):
    extended_rc = extended_rc or 1
if (len(compatibility.get("results", [])) != len(compatibility_cases)
        or compatibility.get("interrupted")
        or any(item["status"] != "passed" for item in compatibility.get("results", []))):
    compatibility_rc = compatibility_rc or 1
coverage = json.loads((checkout / "lab/services/coverage.json").read_text())
tested_releases = {
    "airflow": ["2.9.2", "2.9.3", "2.10.5"],
    "elastic": ["Elasticsearch 8.13.4", "Elasticsearch 8.15.0"],
    "grafana": ["11.0.0", "11.0.5", "11.1.5", "11.1.6"],
    "postgres": ["16.4", "16.5"],
    "redis": ["7.0.3", "7.0.4", "7.0.5"],
}
for result in compatibility.get("results", []):
    case = result["case"]
    tested_releases.setdefault(case["module"], []).append({
        "release": case["expected_version"], "fixture": case["fixture"], "status": result["status"],
    })
remaining_modules = sorted(
    module for module, info in coverage["modules"].items()
    if info["fidelity"] in {"real", "mixed"} and module not in tested_releases
)
report = {
    "status": "passed" if boundary_rc == extended_rc == compatibility_rc == 0 else "failed",
    "cve_boundary_exit_code": boundary_rc,
    "extended_exit_code": extended_rc,
    "compatibility_exit_code": compatibility_rc,
    "cve_boundary_cases": 10,
    "extended_cases": len(extended),
    "extended_results": extended,
    "compatibility_results": compatibility,
    "tested_releases": tested_releases,
    "remaining_real_or_mixed_modules": remaining_modules,
    "release_boundary_cases": sum(item["case"].get("validation_kind") == "cve_boundary" for item in compatibility.get("results", [])),
    "total_cases": 10 + len(extended) + len(compatibility.get("results", [])),
}
(root / "report.json").write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
lines = [
    "# Real-version QA",
    "",
    f"Status: **{report['status']}**",
    "",
    f"- Redis/Grafana/PostgreSQL CVE boundaries: {boundary_rc=}, ten cases; see `cve-boundaries.log`.",
    f"- Airflow/Elasticsearch version and CVE checks: {extended_rc=}, {len(extended)} cases; see `extended/report.md`.",
    f"- Other release checks: {compatibility_rc=}, {len(compatibility_cases)} cases; see `compatibility/report.md`.",
    "- Boundary assertions are saved per case; release compatibility alone is not proof of an affected/fixed transition.",
    "- Artifacts use only local targets. Each lab stack is stopped after its cases.",
    "- Real/mixed modules still missing multi-release coverage:",
    "  " + ", ".join(remaining_modules) + ".",
]
(root / "report.md").write_text("\n".join(lines) + "\n")
print(root / "report.md")
raise SystemExit(0 if report["status"] == "passed" else 1)
PY

if [ "${boundary_rc}" -ne 0 ] || [ "${extended_rc}" -ne 0 ] || [ "${compatibility_rc}" -ne 0 ]; then
  exit 1
fi
