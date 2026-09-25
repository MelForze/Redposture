#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

if [ -x "${ROOT_DIR}/.venv/bin/python" ]; then
  PYTHON_BIN="${PYTHON_BIN:-${ROOT_DIR}/.venv/bin/python}"
else
  PYTHON_BIN="${PYTHON_BIN:-python3}"
fi
ARTIFACT_DIR="${1:-/tmp/redposture_full_qa_$(date +%Y%m%d_%H%M%S)}"
mkdir -p "${ARTIFACT_DIR}"

command -v docker >/dev/null
docker compose version >/dev/null

echo "== deterministic suite =="
"${PYTHON_BIN}" -m pytest -q
"${PYTHON_BIN}" scripts/run_mutation_smoke.py
REDPOSTURE_CLI_PARAM_FUZZ=1 "${PYTHON_BIN}" -m pytest tests/test_cli_param_fuzz.py -q

echo "== focused real-service matrices =="
PYTHON="${PYTHON_BIN}" ./scripts/run_minio_kubeapi_lab.sh
PYTHON="${PYTHON_BIN}" ./scripts/run_auth_service_matrix.sh
PYTHON="${PYTHON_BIN}" ./scripts/run_real_cve_matrix.sh

echo "== proxy QA =="
"${PYTHON_BIN}" -m pytest tests/test_proxy_end_to_end.py -q

echo "== complete Docker service matrix =="
REDPOSTURE_MATRIX_PROFILE=extended PYTHON_BIN="${PYTHON_BIN}" \
  ./scripts/run_lab_matrix_sequential.sh "${ARTIFACT_DIR}/service-matrix"

echo "full local QA passed; artifacts: ${ARTIFACT_DIR}"
