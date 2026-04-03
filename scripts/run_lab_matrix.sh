#!/usr/bin/env bash
set -u

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR" || exit 1

OUT_DIR="${1:-/tmp/redposture_lab_matrix_$(date +%Y%m%d_%H%M%S)}"
STATUS_FILE="${OUT_DIR}/matrix-status.tsv"
VERIFY_SCRIPT="${ROOT_DIR}/scripts/verify_postrun.py"
COMPOSE_FILE="${ROOT_DIR}/docker-compose.lab.yml"
if [ -n "${PYTHON_BIN:-}" ]; then
  PYTHON_BIN="${PYTHON_BIN}"
elif [ -x "${ROOT_DIR}/.venv/bin/python" ]; then
  PYTHON_BIN="${ROOT_DIR}/.venv/bin/python"
else
  PYTHON_BIN="python3"
fi

EXPORTER_PORTS="7777,9100,9102,9104,9113,9114,9116,9117,9119,9121,9127,9128,9131,9150,9182,9187,9216,9221,9256,9290,9308,9342,9349,9399,9419,9427,19101,19119,17777,19100,19102,19104,19113,19114,19115,19117,19121,19128,19131,19150,19182,19187,19219,19221,19290,19308,19399,19419"

mkdir -p "${OUT_DIR}"
mkdir -p "${OUT_DIR}/logs"
mkdir -p "${OUT_DIR}/json"

compose() {
  docker compose -f "${COMPOSE_FILE}" "$@"
}

wait_nonempty_file() {
  local path="$1"
  local timeout="${2:-120}"
  local elapsed=0
  while [ "${elapsed}" -lt "${timeout}" ]; do
    if [ -s "${path}" ]; then
      return 0
    fi
    sleep 1
    elapsed=$((elapsed + 1))
  done
  echo "[error] timed out waiting for file: ${path}" >&2
  return 1
}

wait_healthy_compose() {
  local timeout="${1:-180}"
  local elapsed=0
  while [ "${elapsed}" -lt "${timeout}" ]; do
    local ps_output
    ps_output="$(compose ps || true)"
    local unhealthy
    unhealthy="$(printf "%s" "${ps_output}" | grep -E "Restarting|unhealthy" || true)"
    if [ -z "${unhealthy}" ]; then
      return 0
    fi
    local blocking
    blocking="$(printf "%s" "${unhealthy}" | grep -Ev 'redposture-lab-consul-acl|redposture-lab-consul-seed' || true)"
    if [ -z "${blocking}" ]; then
      echo "[warn] continuing with degraded consul lab branch" >&2
      printf "%s\n" "${unhealthy}" >&2
      return 0
    fi
    sleep 2
    elapsed=$((elapsed + 2))
  done
  echo "[error] compose health gate failed" >&2
  compose ps >&2 || true
  return 1
}

run_case() {
  local module="$1"
  local label="$2"
  shift 2

  local json_path="${OUT_DIR}/json/${label}.json"
  local log_path="${OUT_DIR}/logs/${label}.log"

  echo "== ${label} =="
  set +e
  "${PYTHON_BIN}" redposture.py "$@" --format json --output "${json_path}" >"${log_path}" 2>&1
  local rc=$?
  set -e

  printf "%s\t%s\t%s\t%s\t%s\n" "${module}" "${label}" "${rc}" "${json_path}" "${log_path}" >> "${STATUS_FILE}"
  if [ "${rc}" -ne 0 ]; then
    echo "[warn] ${label} failed (rc=${rc})" >&2
  fi
  return 0
}

run_text_case() {
  local module="$1"
  local label="$2"
  shift 2

  local text_path="${OUT_DIR}/logs/${label}.txt"
  local log_path="${OUT_DIR}/logs/${label}.log"

  echo "== ${label} =="
  set +e
  "${PYTHON_BIN}" redposture.py "$@" --output "${text_path}" >"${log_path}" 2>&1
  local rc=$?
  set -e

  printf "%s\t%s\t%s\t%s\t%s\n" "${module}" "${label}" "${rc}" "-" "${log_path}" >> "${STATUS_FILE}"
  if [ "${rc}" -ne 0 ]; then
    echo "[warn] ${label} failed (rc=${rc})" >&2
  fi
  return 0
}

set -e
printf "module\tlabel\texit_code\tjson_path\tlog_path\n" > "${STATUS_FILE}"

set +e
compose up -d --build --wait --wait-timeout 120
compose_rc=$?
set -e
if [ "${compose_rc}" -ne 0 ]; then
  echo "[warn] compose up returned ${compose_rc}; continuing with explicit health gate" >&2
fi
wait_healthy_compose
HAS_KUBE_TOKENS=1
HAS_CONSUL_TOKENS=1
wait_nonempty_file "${ROOT_DIR}/docker/kubeapi/output/kubeapi_tokens.env" || HAS_KUBE_TOKENS=0
wait_nonempty_file "${ROOT_DIR}/docker/consul/output/consul_acl_tokens.env" || HAS_CONSUL_TOKENS=0

CONSUL_READ_TOKEN=""
CONSUL_MGMT_TOKEN=""
KUBE_AUDITOR_TOKEN=""
KUBE_ADMIN_TOKEN=""
if [ "${HAS_CONSUL_TOKENS}" -eq 1 ]; then
  CONSUL_READ_TOKEN="$(grep '^CONSUL_ACL_READ_TOKEN=' docker/consul/output/consul_acl_tokens.env | cut -d= -f2-)"
  CONSUL_MGMT_TOKEN="$(grep '^CONSUL_ACL_MANAGEMENT_TOKEN=' docker/consul/output/consul_acl_tokens.env | cut -d= -f2-)"
else
  echo "[warn] consul ACL tokens are unavailable; auth consul runs will be skipped" >&2
fi
if [ "${HAS_KUBE_TOKENS}" -eq 1 ]; then
  KUBE_AUDITOR_TOKEN="$(grep '^KUBEAPI_AUDITOR_TOKEN=' docker/kubeapi/output/kubeapi_tokens.env | cut -d= -f2-)"
  KUBE_ADMIN_TOKEN="$(grep '^KUBEAPI_ADMIN_TOKEN=' docker/kubeapi/output/kubeapi_tokens.env | cut -d= -f2-)"
else
  echo "[warn] kubeapi tokens are unavailable; token kubeapi runs will be skipped" >&2
fi

run_case exporters exporters_scan exporters scan -t 127.0.0.1 -p "${EXPORTER_PORTS}"
run_case exporters exporters_collect exporters collect -t 127.0.0.1 -p "${EXPORTER_PORTS}" --deep --save-responses-dir "${OUT_DIR}/collect_raw"
run_case exporters exporters_trigger exporters trigger -t 127.0.0.1 --callback-dns host.docker.internal -p "19121,19308" --with-listen --listen-seconds 8 \
  --postgres-port 15432 --redis-port 16379 --proxmox-port 28006 --blackbox-port 29115

run_case registry registry_open registry -t 127.0.0.1 --port 15000 --docker --images
run_case registry registry_auth registry -t 127.0.0.1 --port 15001 -u admin -p admin --docker --images
run_case registry registry_harbor registry -t 127.0.0.1 --port 15002 --harbor --images
run_case registry registry_gitlab registry -t 127.0.0.1 --port 15003 --gitlab --images
run_case registry registry_nexus registry -t 127.0.0.1 --port 15004 --nexus --assets

run_case grafana grafana_default grafana -t 127.0.0.1 --defcreds --show-datasources

run_case gitlab gitlab_public gitlab -t 127.0.0.1 --port 18080
run_case gitlab gitlab_analyst gitlab -t 127.0.0.1 --port 18080 --token glpat-redposture-lab-analyst-2026

run_case consul consul_open consul -t 127.0.0.1 --port 8500 --dump
if [ -n "${CONSUL_READ_TOKEN}" ]; then
  run_case consul consul_acl_read consul -t 127.0.0.1 --port 18500 --token "${CONSUL_READ_TOKEN}" --dump
fi
if [ -n "${CONSUL_MGMT_TOKEN}" ]; then
  run_case consul consul_acl_mgmt consul -t 127.0.0.1 --port 18500 --token "${CONSUL_MGMT_TOKEN}" --dump
fi

run_case kubeapi kubeapi_open kubeapi -t 127.0.0.1 --port 26443 --namespaces --pods
if [ -n "${KUBE_AUDITOR_TOKEN}" ]; then
  run_case kubeapi kubeapi_auditor kubeapi -t 127.0.0.1 --port 16443 --insecure --token "${KUBE_AUDITOR_TOKEN}" --namespaces --pods
fi
if [ -n "${KUBE_ADMIN_TOKEN}" ]; then
  run_case kubeapi kubeapi_admin kubeapi -t 127.0.0.1 --port 16443 --insecure --token "${KUBE_ADMIN_TOKEN}" --secrets
fi

run_case postgres postgres_default postgres -t 127.0.0.1 -u postgres -p postgres --show-databases --show-tables --dump 20

run_case clickhouse clickhouse_native_open clickhouse -t 127.0.0.1 --show-databases --show-tables --dump
run_case clickhouse clickhouse_http_open clickhouse -t 127.0.0.1 --http --port 8123 --show-databases --show-tables --dump
run_case clickhouse clickhouse_native_auth clickhouse -t 127.0.0.1 --port 19000 -u default -p default --show-databases --show-tables --dump
run_case clickhouse clickhouse_http_auth clickhouse -t 127.0.0.1 --http --port 18123 -u default -p default --show-databases --show-tables --dump

run_case redis redis_default redis -t 127.0.0.1 -u redis -p redis --show-keys --dump

run_case etcd etcd_open etcd -t 127.0.0.1 --port 2379 --show-keys --dump
run_case etcd etcd_auth etcd -t 127.0.0.1 --port 22379 --show-keys --dump

run_case qdrant qdrant_default qdrant -t 127.0.0.1 --collections --dump

run_case elastic elastic_open elastic -t 127.0.0.1 --port 19200 --endpoints --cluster --discover
run_case elastic elastic_auth elastic -t 127.0.0.1 --port 19201 --apitoken "ZXM6bGFiLXRva2Vu" --endpoints --cluster --user --discover

run_case kafka kafka_open kafka -t 127.0.0.1 --port 9092 --show-topics --dump --max-messages 50
run_case kafka kafka_auth kafka -t 127.0.0.1 --port 29092 -u metrics -p metricspass --show-topics --dump --max-messages 50

run_case zookeeper zookeeper_default zookeeper -t 127.0.0.1 --show-znodes --dump

run_case proxmox proxmox_audit proxmox -t 127.0.0.1 --port 18006 --insecure --pveapitoken "audit@pve!redposture=pve-redposture-token-2026" --nodes --users
run_case proxmox proxmox_admin proxmox -t 127.0.0.1 --port 18006 --insecure --pveapitoken "admin@pve!root=pve-redposture-admin-2026" --discover-creds --nodes --users

"${PYTHON_BIN}" "${VERIFY_SCRIPT}" --status-file "${STATUS_FILE}" --out-dir "${OUT_DIR}"

echo
echo "Matrix complete."
echo "OUT_DIR=${OUT_DIR}"
