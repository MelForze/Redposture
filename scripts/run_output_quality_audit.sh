#!/usr/bin/env bash
set -uo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

if [ -x "${ROOT_DIR}/.venv/bin/python" ]; then
  PYTHON_BIN="${PYTHON_BIN:-${ROOT_DIR}/.venv/bin/python}"
else
  PYTHON_BIN="${PYTHON_BIN:-python3}"
fi

ARTIFACT_DIR="${1:-/tmp/redposture_output_qa_$(date +%Y%m%d_%H%M%S)}"
exec "${PYTHON_BIN}" "${ROOT_DIR}/scripts/run_output_quality_audit.py" "${ARTIFACT_DIR}"
