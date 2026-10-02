#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"
PYTHON_BIN="${PYTHON_BIN:-${ROOT_DIR}/.venv/bin/python}"
exec "${PYTHON_BIN}" "${ROOT_DIR}/scripts/run_http_detection_qa.py" "${1:-${ROOT_DIR}/.redposture/qa/http-detection-$(date +%Y%m%d-%H%M%S)}"
