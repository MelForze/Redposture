#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

SECTIONS=(fixtures pytest mutation cli-fuzz hypothesis stress focused-services proxy docker-matrix optional-real)
REQUESTED=()
ARTIFACT_DIR=""
LIST_ONLY=0
PLAN_ONLY=0

usage() {
  cat <<'EOF'
Usage: scripts/run_full_local_qa.sh [artifact_dir] [--section NAME[,NAME...]] [--plan]
       scripts/run_full_local_qa.sh --list

Without --section, run every QA section. Repeat --section or separate names with
commas to run only changed areas. Use a fresh artifact directory for each run;
each section writes its own log and summary entry.
EOF
}

list_sections() {
  cat <<'EOF'
fixtures          Service fixture fidelity
pytest            Full deterministic pytest suite
mutation          Mutation smoke
cli-fuzz          CLI parameter fuzz
hypothesis        10,000-example property fuzzing
stress            Output, load, SIGINT, and FD/thread soak
focused-services  MinIO/KubeAPI, auth, and CVE Docker matrices
proxy             Proxy end-to-end tests
docker-matrix     Complete extended Docker service matrix
optional-real     Optional real-product fixtures
EOF
}

section_known() {
  local item="$1"
  local candidate
  for candidate in "${SECTIONS[@]}"; do
    [[ "$candidate" == "$item" ]] && return 0
  done
  return 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --section)
      if [[ $# -lt 2 || -z "$2" ]]; then
        echo "[error] --section requires a name" >&2
        exit 2
      fi
      IFS=',' read -r -a names <<< "$2"
      REQUESTED+=("${names[@]}")
      shift 2
      ;;
    --list)
      LIST_ONLY=1
      shift
      ;;
    --plan)
      PLAN_ONLY=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    -*)
      echo "[error] unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
    *)
      if [[ -n "$ARTIFACT_DIR" ]]; then
        echo "[error] only one artifact directory may be supplied" >&2
        exit 2
      fi
      ARTIFACT_DIR="$1"
      shift
      ;;
  esac
done

if [[ "$LIST_ONLY" -eq 1 ]]; then
  list_sections
  exit 0
fi

ARTIFACT_DIR="${ARTIFACT_DIR:-/tmp/redposture_full_qa_$(date +%Y%m%d_%H%M%S)}"
if [[ ${#REQUESTED[@]} -eq 0 ]]; then
  REQUESTED=("${SECTIONS[@]}")
fi
SELECTED=()
for section in "${REQUESTED[@]}"; do
  if ! section_known "$section"; then
    echo "[error] unknown QA section: $section" >&2
    list_sections >&2
    exit 2
  fi
  if [[ ! " ${SELECTED[*]} " =~ " ${section} " ]]; then
    SELECTED+=("$section")
  fi
done

if [[ "$PLAN_ONLY" -eq 1 ]]; then
  echo "artifact directory: ${ARTIFACT_DIR}"
  printf 'section: %s\n' "${SELECTED[@]}"
  exit 0
fi

export REDPOSTURE_QA_PROJECT_PREFIX="${REDPOSTURE_QA_PROJECT_PREFIX:-redpostureqa$$}"
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-${REDPOSTURE_QA_PROJECT_PREFIX}-matrix}"
if [[ -x "${ROOT_DIR}/.venv/bin/python" ]]; then
  PYTHON_BIN="${PYTHON_BIN:-${ROOT_DIR}/.venv/bin/python}"
else
  PYTHON_BIN="${PYTHON_BIN:-python3}"
fi

DOCKER_PROJECTS=()
for section in "${SELECTED[@]}"; do
  case "$section" in
    focused-services)
      DOCKER_PROJECTS+=("${REDPOSTURE_QA_PROJECT_PREFIX}-auth-matrix"
        "${REDPOSTURE_QA_PROJECT_PREFIX}-minio-kubeapi" "${REDPOSTURE_QA_PROJECT_PREFIX}-cve-matrix")
      ;;
    docker-matrix) DOCKER_PROJECTS+=("${COMPOSE_PROJECT_NAME}") ;;
    optional-real) DOCKER_PROJECTS+=("${REDPOSTURE_QA_PROJECT_PREFIX}-optional-real") ;;
  esac
done
if [[ ${#DOCKER_PROJECTS[@]} -gt 0 ]]; then
  command -v docker >/dev/null
  docker compose version >/dev/null
  for project in "${DOCKER_PROJECTS[@]}"; do
    if [[ -n "$(docker ps -aq --filter "label=com.docker.compose.project=$project")" ]] ||
       [[ -n "$(docker volume ls -q --filter "label=com.docker.compose.project=$project")" ]]; then
      echo "[error] QA Compose project already exists: $project" >&2
      exit 2
    fi
  done
fi

mkdir -p "${ARTIFACT_DIR}/sections"
SUMMARY="${ARTIFACT_DIR}/sections/summary.tsv"
if [[ ! -e "$SUMMARY" ]]; then
  printf 'section\tstatus\texit_code\tduration_seconds\tlog\n' > "$SUMMARY"
fi

execute_section() {
  case "$1" in
    fixtures)
      "${PYTHON_BIN}" lab/services/coverage.py "${ARTIFACT_DIR}/service-coverage"
      ;;
    pytest)
      "${PYTHON_BIN}" -m pytest -q --junitxml="${ARTIFACT_DIR}/deterministic.xml"
      ;;
    mutation)
      "${PYTHON_BIN}" scripts/run_mutation_smoke.py
      ;;
    cli-fuzz)
      REDPOSTURE_CLI_PARAM_FUZZ=1 "${PYTHON_BIN}" -m pytest tests/test_cli_param_fuzz.py -q \
        --junitxml="${ARTIFACT_DIR}/cli-fuzz.xml"
      ;;
    hypothesis)
      REDPOSTURE_HYPOTHESIS_PROFILE=redposture-local "${PYTHON_BIN}" -m pytest \
        tests/test_detection_cve_hypothesis.py tests/test_registry_nexus_detection.py \
        tests/test_quality_discovery_properties.py tests/test_quality_discovery_stateful.py \
        tests/test_quality_exporters_matrix.py tests/test_quality_registry_matrix.py \
        tests/test_quality_kafka_fuzz.py tests/test_quality_proxmox_discovery.py \
        --hypothesis-seed=20260928 -q --junitxml="${ARTIFACT_DIR}/hypothesis.xml"
      ;;
    stress)
      "${PYTHON_BIN}" -m pytest -q -m local_output_audit \
        tests/test_local_output_audit.py tests/test_concurrency_stress.py \
        tests/test_sigint_runtime.py tests/test_soak_qa.py \
        --junitxml="${ARTIFACT_DIR}/local-output-load.xml"
      ;;
    focused-services)
      PYTHON="${PYTHON_BIN}" ./scripts/run_minio_kubeapi_lab.sh
      PYTHON="${PYTHON_BIN}" ./scripts/run_auth_service_matrix.sh
      PYTHON="${PYTHON_BIN}" ./scripts/run_real_cve_matrix.sh
      ;;
    proxy)
      "${PYTHON_BIN}" -m pytest tests/test_proxy_end_to_end.py -q \
        --junitxml="${ARTIFACT_DIR}/proxy.xml"
      ;;
    docker-matrix)
      REDPOSTURE_MATRIX_PROFILE=extended PYTHON_BIN="${PYTHON_BIN}" \
        ./scripts/run_lab_matrix_sequential.sh "${ARTIFACT_DIR}/service-matrix"
      ;;
    optional-real)
      "${PYTHON_BIN}" lab/services/run_optional_real_qa.py "${ARTIFACT_DIR}/optional-real" proxmox-real
      ;;
  esac
}

for section in "${SELECTED[@]}"; do
  log="${ARTIFACT_DIR}/sections/${section}.log"
  if [[ -e "$log" ]]; then
    echo "[error] QA section already has a log: $log; use a fresh artifact directory" >&2
    exit 2
  fi
  echo "== ${section} =="
  started="$(date +%s)"
  set +e
  ( set -e; execute_section "$section" ) 2>&1 | tee "$log"
  rc=${PIPESTATUS[0]}
  set -e
  elapsed=$(( $(date +%s) - started ))
  status=passed
  [[ "$rc" -eq 0 ]] || status=failed
  printf '%s\t%s\t%d\t%d\t%s\n' "$section" "$status" "$rc" "$elapsed" "$log" >> "$SUMMARY"
  if [[ "$rc" -ne 0 ]]; then
    echo "[error] ${section} failed; inspect $log" >&2
    exit "$rc"
  fi
done

echo "selected local QA sections passed; summary: ${SUMMARY}"
