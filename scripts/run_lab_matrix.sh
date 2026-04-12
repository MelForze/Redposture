#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR" || exit 1
# Use engine socket context by default for local/CI consistency.
export DOCKER_CONTEXT="${DOCKER_CONTEXT:-default}"

OUT_DIR="${1:-/tmp/redposture_lab_matrix_$(date +%Y%m%d_%H%M%S)}"
STATUS_FILE="${OUT_DIR}/matrix-status.tsv"
VERIFY_SCRIPT="${ROOT_DIR}/scripts/verify_postrun.py"
COMPOSE_FILE="${ROOT_DIR}/lab/full/docker-compose.yml"
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
    blocking="$(printf "%s" "${unhealthy}" | grep -Ev 'redposture-lab-consul-acl|redposture-lab-consul-seed|redposture-lab-elastic-auth' || true)"
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
  local expected_exit="$3"
  shift 3

  local json_path="${OUT_DIR}/json/${label}.json"
  local log_path="${OUT_DIR}/logs/${label}.log"

  echo "== ${label} =="
  set +e
  "${PYTHON_BIN}" redposture.py "$@" --format json --output "${json_path}" >"${log_path}" 2>&1
  local rc=$?
  set -e

  printf "%s\t%s\t%s\t%s\t%s\t%s\n" \
    "${module}" "${label}" "${expected_exit}" "${rc}" "${json_path}" "${log_path}" >> "${STATUS_FILE}"
  if [ "${rc}" -ne "${expected_exit}" ]; then
    echo "[error] ${label} exit mismatch: expected=${expected_exit} actual=${rc}" >&2
    echo "[error] log: ${log_path}" >&2
    return 1
  fi
  if [ "${rc}" -ne 0 ]; then
    echo "[warn] ${label} expected failure matched (rc=${rc})" >&2
  fi
  return 0
}

run_text_case() {
  local module="$1"
  local label="$2"
  local expected_exit="$3"
  shift 3

  local text_path="${OUT_DIR}/logs/${label}.txt"
  local log_path="${OUT_DIR}/logs/${label}.log"

  echo "== ${label} =="
  set +e
  "${PYTHON_BIN}" redposture.py "$@" --output "${text_path}" >"${log_path}" 2>&1
  local rc=$?
  set -e

  printf "%s\t%s\t%s\t%s\t%s\t%s\n" \
    "${module}" "${label}" "${expected_exit}" "${rc}" "-" "${log_path}" >> "${STATUS_FILE}"
  if [ "${rc}" -ne "${expected_exit}" ]; then
    echo "[error] ${label} exit mismatch: expected=${expected_exit} actual=${rc}" >&2
    echo "[error] log: ${log_path}" >&2
    return 1
  fi
  if [ "${rc}" -ne 0 ]; then
    echo "[warn] ${label} expected failure matched (rc=${rc})" >&2
  fi
  return 0
}

set -e
printf "module\tlabel\texpected_exit\texit_code\tjson_path\tlog_path\n" > "${STATUS_FILE}"

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
  echo "[error] consul ACL tokens are unavailable; strict matrix cannot continue" >&2
  exit 1
fi
if [ "${HAS_KUBE_TOKENS}" -eq 1 ]; then
  KUBE_AUDITOR_TOKEN="$(grep '^KUBEAPI_AUDITOR_TOKEN=' docker/kubeapi/output/kubeapi_tokens.env | cut -d= -f2-)"
  KUBE_ADMIN_TOKEN="$(grep '^KUBEAPI_ADMIN_TOKEN=' docker/kubeapi/output/kubeapi_tokens.env | cut -d= -f2-)"
else
  echo "[error] kubeapi tokens are unavailable; strict matrix cannot continue" >&2
  exit 1
fi

if [ -z "${CONSUL_READ_TOKEN}" ] || [ -z "${CONSUL_MGMT_TOKEN}" ]; then
  echo "[error] consul ACL tokens are empty; strict matrix cannot continue" >&2
  exit 1
fi
if [ -z "${KUBE_AUDITOR_TOKEN}" ] || [ -z "${KUBE_ADMIN_TOKEN}" ]; then
  echo "[error] kubeapi tokens are empty; strict matrix cannot continue" >&2
  exit 1
fi

run_case exporters exporters_scan 0 exporters scan -t 127.0.0.1 -p "${EXPORTER_PORTS}"
run_case exporters exporters_collect 0 exporters collect -t 127.0.0.1 -p "${EXPORTER_PORTS}" --deep --save-responses-dir "${OUT_DIR}/collect_raw"
run_case exporters exporters_trigger 0 exporters trigger -t 127.0.0.1 --callback-dns host.docker.internal -p "19121,19308" --with-listen --listen-seconds 8 \
  --postgres-port 15432 --redis-port 16379 --proxmox-port 28006 --blackbox-port 29115
run_case exporters exporters_scan_url_http 0 exporters scan -t "http://127.0.0.1:19100/metrics?from=matrix"
run_case exporters exporters_scan_url_https_reject 2 exporters scan -t "https://127.0.0.1:19100/metrics"
run_case exporters exporters_collect_url_http 0 exporters collect -t "http://127.0.0.1:19100/debug/vars" --exporters node --save-responses-dir "${OUT_DIR}/collect_raw_url"
run_case exporters exporters_collect_url_https_reject 2 exporters collect -t "https://127.0.0.1:19100/debug/vars"
run_case exporters exporters_trigger_url_http 0 exporters trigger -t "http://127.0.0.1:19121/scrape?target=redis://127.0.0.1:6379" --callback-dns host.docker.internal --no-with-listen
run_case exporters exporters_trigger_url_https_reject 2 exporters trigger -t "https://127.0.0.1:19121/scrape" --callback-dns host.docker.internal --no-with-listen

run_case registry registry_open 0 registry -t 127.0.0.1 --port 15000 --docker --images
run_case registry registry_auth 0 registry -t 127.0.0.1 --port 15001 -u admin -p admin --docker --images
run_case registry registry_harbor 0 registry -t 127.0.0.1 --port 15002 --harbor --images
run_case registry registry_gitlab 0 registry -t 127.0.0.1 --port 15003 --gitlab --images
run_case registry registry_nexus 0 registry -t 127.0.0.1 --port 15004 --nexus --assets
run_case registry registry_url_http 0 registry -t "http://127.0.0.1:15000/v2/_catalog?n=1000" --docker --images
run_case registry registry_url_https_reject 2 registry -t "https://127.0.0.1:15000/v2/_catalog" --docker --images
run_case registry registry_multi_instance_urls 0 registry -t "http://127.0.0.1:15000/v2/_catalog,http://127.0.0.1:15010/v2/_catalog,http://127.0.0.1:15011/v2/_catalog,http://127.0.0.1:15012/v2/_catalog,http://127.0.0.1:15013/v2/_catalog" --docker --images

run_case grafana grafana_default 0 grafana -t 127.0.0.1 --defcreds --show-datasources
run_case grafana grafana_url_http 0 grafana -t "http://127.0.0.1:3000/login?next=%2F" --defcreds --show-datasources
run_case grafana grafana_url_https_reject 2 grafana -t "https://127.0.0.1:3000/login"
run_case grafana grafana_ssrf_edge 0 grafana -t 127.0.0.1 --defcreds --ssrf-target "http://127.0.0.1:19115/probe?module=http_2xx" --show-datasources
run_case grafana grafana_multi_instance_urls 0 grafana -t "http://127.0.0.1:3000/login,http://127.0.0.1:13001/login,http://127.0.0.1:13002/login,http://127.0.0.1:13003/login,http://127.0.0.1:13004/login" --defcreds

run_case gitlab gitlab_public 0 gitlab -t 127.0.0.1 --port 18080
run_case gitlab gitlab_analyst 0 gitlab -t 127.0.0.1 --port 18080 --token glpat-redposture-lab-analyst-2026
run_case gitlab gitlab_url_override_http 0 gitlab -t "http://127.0.0.1:18080/users/sign_in?ref=matrix" --https
run_case gitlab gitlab_multi_instance_urls 0 gitlab -t "http://127.0.0.1:18080/users/sign_in,http://127.0.0.1:18081/users/sign_in,http://127.0.0.1:18082/users/sign_in,http://127.0.0.1:18083/users/sign_in,http://127.0.0.1:18084/users/sign_in"

run_case consul consul_open 0 consul -t 127.0.0.1 --port 8500 --dump
run_case consul consul_acl_read 0 consul -t 127.0.0.1 --port 18500 --token "${CONSUL_READ_TOKEN}" --dump
run_case consul consul_acl_mgmt 0 consul -t 127.0.0.1 --port 18500 --token "${CONSUL_MGMT_TOKEN}" --dump
run_case consul consul_url_hint_http 0 consul -t "http://127.0.0.1:8500/v1/status/leader" --dump
run_case consul consul_multi_instance_urls 0 consul -t "http://127.0.0.1:8500/v1/status/leader,http://127.0.0.1:8501/v1/status/leader,http://127.0.0.1:8502/v1/status/leader,http://127.0.0.1:8503/v1/status/leader,http://127.0.0.1:8504/v1/status/leader" --dump

run_case kubeapi kubeapi_open 0 kubeapi -t 127.0.0.1 --port 26443 --namespaces --pods
run_case kubeapi kubeapi_auditor 0 kubeapi -t 127.0.0.1 --port 16443 --insecure --token "${KUBE_AUDITOR_TOKEN}" --namespaces --pods
run_case kubeapi kubeapi_admin 0 kubeapi -t 127.0.0.1 --port 16443 --insecure --token "${KUBE_ADMIN_TOKEN}" --secrets
run_case kubeapi kubeapi_url_override_https 0 kubeapi -t "https://127.0.0.1:26443/api?from=matrix" --no-https --namespaces
run_case kubeapi kubeapi_multi_instance_urls 0 kubeapi -t "https://127.0.0.1:26443/version,https://127.0.0.1:26444/version,https://127.0.0.1:26445/version,https://127.0.0.1:26446/version,https://127.0.0.1:26447/version" --namespaces

run_case postgres postgres_default 0 postgres -t 127.0.0.1 -u postgres -p postgres --show-databases --show-tables --dump 20
run_case postgres postgres_multi_ports 0 postgres -t 127.0.0.1 -u postgres -p postgres --ports "5432,25432,25433,25434,25435" --show-databases

run_case clickhouse clickhouse_native_open 0 clickhouse -t 127.0.0.1 --show-databases --show-tables --dump
run_case clickhouse clickhouse_http_open 0 clickhouse -t 127.0.0.1 --http --port 8123 --show-databases --show-tables --dump
run_case clickhouse clickhouse_native_auth 0 clickhouse -t 127.0.0.1 --port 19000 -u default -p default --show-databases --show-tables --dump
run_case clickhouse clickhouse_http_auth 0 clickhouse -t 127.0.0.1 --http --port 18123 -u default -p default --show-databases --show-tables --dump
run_case clickhouse clickhouse_multi_ports 0 clickhouse -t 127.0.0.1 --ports "9000,29001,29002,29003,29004" --show-databases

run_case redis redis_default 0 redis -t 127.0.0.1 -u redis -p redis --show-keys --dump
run_case redis redis_multi_ports 0 redis -t 127.0.0.1 -u redis -p redis --ports "6379,26380,26381,26382,26383" --show-keys

run_case etcd etcd_open 0 etcd -t 127.0.0.1 --port 2379 --show-keys --dump
run_case etcd etcd_auth 0 etcd -t 127.0.0.1 --port 22379 --show-keys --dump
run_case etcd etcd_url_http 0 etcd -t "http://127.0.0.1:2379/v2/keys?recursive=true" --show-keys --dump
run_case etcd etcd_url_https_reject 2 etcd -t "https://127.0.0.1:2379/v2/keys?recursive=true" --show-keys
run_case etcd etcd_multi_instance_urls 0 etcd -t "http://127.0.0.1:2379/v2/keys,http://127.0.0.1:23790/v2/keys,http://127.0.0.1:23791/v2/keys,http://127.0.0.1:23792/v2/keys,http://127.0.0.1:23793/v2/keys" --show-keys

run_case qdrant qdrant_default 0 qdrant -t 127.0.0.1 --collections --dump
run_case qdrant qdrant_url_http 0 qdrant -t "http://127.0.0.1:6333/collections?from=matrix" --collections --dump
run_case qdrant qdrant_url_https_reject 2 qdrant -t "https://127.0.0.1:6333/collections" --collections
run_case qdrant qdrant_multi_instance_urls 0 qdrant -t "http://127.0.0.1:6333/collections,http://127.0.0.1:26333/collections,http://127.0.0.1:26334/collections,http://127.0.0.1:26335/collections,http://127.0.0.1:26336/collections" --collections

run_case elastic elastic_open 0 elastic -t 127.0.0.1 --port 19200 --endpoints --cluster --discover
run_case elastic elastic_auth 0 elastic -t 127.0.0.1 --port 19201 --apitoken "ZXM6bGFiLXRva2Vu" --endpoints --cluster --user --discover
run_case elastic elastic_url_hint_https 0 elastic -t "https://127.0.0.1:19201/" --apitoken "ZXM6bGFiLXRva2Vu" --endpoints
run_case elastic elastic_plugins_edge 0 elastic -t 127.0.0.1 --port 19201 --apitoken "ZXM6bGFiLXRva2Vu" --plugins
run_case elastic elastic_multi_instance_urls 0 elastic -t "http://127.0.0.1:19200/,http://127.0.0.1:19202/,http://127.0.0.1:19203/,http://127.0.0.1:19204/,http://127.0.0.1:19205/" --endpoints

run_case kafka kafka_open 0 kafka -t 127.0.0.1 --port 9092 --show-topics --dump --max-messages 50
run_case kafka kafka_auth 0 kafka -t 127.0.0.1 --port 29092 -u metrics -p metricspass --show-topics --dump --max-messages 50
run_case kafka kafka_multi_ports 0 kafka -t 127.0.0.1 --ports "9092,39092,39093,39094,39095" --show-topics

run_case zookeeper zookeeper_default 0 zookeeper -t 127.0.0.1 --show-znodes --dump
run_case zookeeper zookeeper_multi_ports 0 zookeeper -t 127.0.0.1 --ports "2181,22181,22182,22183,22184" --show-znodes

run_case proxmox proxmox_audit 0 proxmox -t 127.0.0.1 --port 18006 --insecure --pveapitoken "audit@pve!redposture=pve-redposture-token-2026" --nodes --users
run_case proxmox proxmox_admin 0 proxmox -t 127.0.0.1 --port 18006 --insecure --pveapitoken "admin@pve!root=pve-redposture-admin-2026" --discover-creds --nodes --users
run_case proxmox proxmox_url_override_https 0 proxmox -t "https://127.0.0.1:18006/api2/json/access/ticket" --no-https --insecure --pveapitoken "audit@pve!redposture=pve-redposture-token-2026" --nodes
run_case proxmox proxmox_multi_instance_urls 0 proxmox -t "https://127.0.0.1:18006/api2/json/access/ticket,https://127.0.0.1:18061/api2/json/access/ticket,https://127.0.0.1:18062/api2/json/access/ticket,https://127.0.0.1:18063/api2/json/access/ticket,https://127.0.0.1:18064/api2/json/access/ticket" --insecure --pveapitoken "audit@pve!redposture=pve-redposture-token-2026" --nodes

"${PYTHON_BIN}" "${VERIFY_SCRIPT}" --status-file "${STATUS_FILE}" --out-dir "${OUT_DIR}"

echo
echo "Matrix complete."
echo "OUT_DIR=${OUT_DIR}"
