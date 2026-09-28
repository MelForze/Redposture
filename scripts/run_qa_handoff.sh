#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"
MODE="${1:-}"
case "${MODE}" in
  full|versions) ;;
  *) echo "usage: $0 full|versions [new_artifact_dir]" >&2; exit 2 ;;
esac
ARTIFACT_DIR="${2:-/tmp/redposture_qa_${MODE}_$(date -u +%Y%m%d_%H%M%S)}"
if [ -d "${ARTIFACT_DIR}" ] && [ -n "$(ls -A "${ARTIFACT_DIR}")" ]; then
  echo "[error] QA output directory is not empty: ${ARTIFACT_DIR}" >&2
  exit 2
fi
mkdir -p "${ARTIFACT_DIR}"

started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
set +e
if [ "${MODE}" = "full" ]; then
  ./scripts/run_full_local_qa.sh "${ARTIFACT_DIR}/full" 2>&1 | tee "${ARTIFACT_DIR}/console.log"
else
  ./scripts/run_version_qa.sh "${ARTIFACT_DIR}/versions" 2>&1 | tee "${ARTIFACT_DIR}/console.log"
fi
run_rc=${PIPESTATUS[0]}
set -e
finished_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

{
  echo "mode=${MODE}"
  echo "exit_code=${run_rc}"
  echo "started_utc=${started_at}"
  echo "finished_utc=${finished_at}"
  echo "git_head=$(git rev-parse --short HEAD)"
  echo "artifact_dir=${ARTIFACT_DIR}"
  echo "console_log=${ARTIFACT_DIR}/console.log"
  if [ "${MODE}" = "full" ]; then
    echo "matrix_status=${ARTIFACT_DIR}/full/service-matrix/matrix-status.tsv"
    echo "optional_real_report=${ARTIFACT_DIR}/full/optional-real/report.md"
    echo "hypothesis_seed=20260928"
    echo "hypothesis_junit=${ARTIFACT_DIR}/full/hypothesis.xml"
    echo "local_output_load_junit=${ARTIFACT_DIR}/full/local-output-load.xml"
    if [ -f "${ARTIFACT_DIR}/full/service-matrix/matrix-status.tsv" ]; then
      awk -F '\t' 'NR > 1 {total++; if ($3 == $4) matched++} END {printf "matrix_expected_exits=%d/%d\n", matched, total}' \
        "${ARTIFACT_DIR}/full/service-matrix/matrix-status.tsv"
    fi
    if [ -f "${ARTIFACT_DIR}/full/service-matrix/postrun_checks/summary.json" ]; then
      echo "postrun=completed"
    else
      echo "postrun=not_completed; inspect the tail of console.log"
    fi
  else
    echo "version_report=${ARTIFACT_DIR}/versions/report.md"
    if [ -f "${ARTIFACT_DIR}/versions/report.json" ]; then
      grep -m1 '"status"' "${ARTIFACT_DIR}/versions/report.json" | tr -d ' ,"'
    fi
  fi
  if [ "${run_rc}" -ne 0 ]; then
    echo "last_console_lines:"
    tail -n 20 "${ARTIFACT_DIR}/console.log"
  fi
} | tee "${ARTIFACT_DIR}/summary.txt"

echo "Send me summary.txt and this artifact directory path; on failure also send the relevant .log file."
exit "${run_rc}"
