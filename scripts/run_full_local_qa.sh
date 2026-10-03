#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"
export REDPOSTURE_QA_PROJECT_PREFIX="${REDPOSTURE_QA_PROJECT_PREFIX:-redpostureqa$$}"
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-${REDPOSTURE_QA_PROJECT_PREFIX}-matrix}"

if [ -x "${ROOT_DIR}/.venv/bin/python" ]; then
  PYTHON_BIN="${PYTHON_BIN:-${ROOT_DIR}/.venv/bin/python}"
else
  PYTHON_BIN="${PYTHON_BIN:-python3}"
fi
ARTIFACT_DIR="${1:-/tmp/redposture_full_qa_$(date +%Y%m%d_%H%M%S)}"
mkdir -p "${ARTIFACT_DIR}"

command -v docker >/dev/null
docker compose version >/dev/null
for project in "${COMPOSE_PROJECT_NAME}" \
  "${REDPOSTURE_QA_PROJECT_PREFIX}-auth-matrix" \
  "${REDPOSTURE_QA_PROJECT_PREFIX}-minio-kubeapi" \
  "${REDPOSTURE_QA_PROJECT_PREFIX}-cve-matrix"; do
  if [[ -n "$(docker ps -aq --filter "label=com.docker.compose.project=$project")" ]] ||
     [[ -n "$(docker volume ls -q --filter "label=com.docker.compose.project=$project")" ]]; then
    echo "[error] QA Compose project already exists: $project" >&2
    exit 2
  fi
done

echo "== service fixture fidelity =="
"${PYTHON_BIN}" lab/services/coverage.py "${ARTIFACT_DIR}/service-coverage"

echo "== deterministic suite =="
"${PYTHON_BIN}" -m pytest -q --junitxml="${ARTIFACT_DIR}/deterministic.xml"
"${PYTHON_BIN}" scripts/run_mutation_smoke.py
REDPOSTURE_CLI_PARAM_FUZZ=1 "${PYTHON_BIN}" -m pytest tests/test_cli_param_fuzz.py -q

echo "== 10000-example deterministic property fuzzing =="
REDPOSTURE_HYPOTHESIS_PROFILE=redposture-local "${PYTHON_BIN}" -m pytest \
  tests/test_detection_cve_hypothesis.py tests/test_registry_nexus_detection.py \
  tests/test_quality_discovery_properties.py tests/test_quality_discovery_stateful.py \
  tests/test_quality_exporters_matrix.py tests/test_quality_registry_matrix.py \
  tests/test_quality_kafka_fuzz.py tests/test_quality_proxmox_discovery.py \
  --hypothesis-seed=20260928 -q --junitxml="${ARTIFACT_DIR}/hypothesis.xml"
echo "== local output, load, SIGINT and FD/thread soak =="
"${PYTHON_BIN}" -m pytest -q -m local_output_audit \
  tests/test_local_output_audit.py tests/test_concurrency_stress.py \
  tests/test_sigint_runtime.py tests/test_soak_qa.py \
  --junitxml="${ARTIFACT_DIR}/local-output-load.xml"

echo "== focused real-service matrices =="
PYTHON="${PYTHON_BIN}" ./scripts/run_minio_kubeapi_lab.sh
PYTHON="${PYTHON_BIN}" ./scripts/run_auth_service_matrix.sh
PYTHON="${PYTHON_BIN}" ./scripts/run_real_cve_matrix.sh

echo "== proxy QA =="
"${PYTHON_BIN}" -m pytest tests/test_proxy_end_to_end.py -q

echo "== complete Docker service matrix =="
REDPOSTURE_MATRIX_PROFILE=extended PYTHON_BIN="${PYTHON_BIN}" \
  ./scripts/run_lab_matrix_sequential.sh "${ARTIFACT_DIR}/service-matrix"

echo "== optional real-product fixtures =="
"${PYTHON_BIN}" lab/services/run_optional_real_qa.py "${ARTIFACT_DIR}/optional-real" proxmox-real

echo "full local QA matrix passed; inspect optional-real/report.json for unavailable vendor fixtures"
echo "artifacts: ${ARTIFACT_DIR}"
