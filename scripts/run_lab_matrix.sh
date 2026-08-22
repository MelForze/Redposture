#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR" || exit 1
# Use engine socket context by default for local/CI consistency.
export DOCKER_CONTEXT="${DOCKER_CONTEXT:-default}"

OUT_DIR="${1:-/tmp/redposture_lab_matrix_$(date +%Y%m%d_%H%M%S)}"
STATUS_FILE="${OUT_DIR}/matrix-status.tsv"
VERIFY_SCRIPT="${ROOT_DIR}/scripts/verify_postrun.py"
LAB_DIR="${REDPOSTURE_LAB_DIR:-${ROOT_DIR}/lab}"
LAB_DOCKER_DIR="${REDPOSTURE_LAB_DOCKER_DIR:-${LAB_DIR}/full/docker}"
if [ ! -d "${LAB_DOCKER_DIR}" ] && [ -d "${LAB_DIR}/docker" ]; then
  LAB_DOCKER_DIR="${LAB_DIR}/docker"
fi
COMPOSE_FILE="${LAB_DIR}/full/docker-compose.yml"
ZOOKEEPER_AUTH_COMPOSE_FILE="${ROOT_DIR}/lab/services/zookeeper-auth/docker-compose.yml"
if [ -n "${PYTHON_BIN:-}" ]; then
  PYTHON_BIN="${PYTHON_BIN}"
elif [ -x "${ROOT_DIR}/.venv/bin/python" ]; then
  PYTHON_BIN="${ROOT_DIR}/.venv/bin/python"
else
  PYTHON_BIN="python3"
fi

EXPORTER_PORTS="7777,9100,9102,9104,9113,9114,9116,9117,9119,9121,9127,9128,9131,9150,9182,9187,9216,9221,9256,9290,9308,9342,9349,9399,9419,9427,9854,19101,19119,19854,29854,17777,19100,19102,19104,19113,19114,19115,19117,19121,19128,19131,19150,19182,19187,19219,19221,19290,19308,19399,19419"

mkdir -p "${OUT_DIR}"
mkdir -p "${OUT_DIR}/logs"
mkdir -p "${OUT_DIR}/json"

if [ ! -f "${COMPOSE_FILE}" ]; then
  echo "[error] local lab compose not found: ${COMPOSE_FILE}" >&2
  echo "[error] set REDPOSTURE_LAB_DIR to your local lab directory" >&2
  exit 2
fi

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
docker compose -f "${ZOOKEEPER_AUTH_COMPOSE_FILE}" up -d --wait --wait-timeout 120
HAS_KUBE_TOKENS=1
HAS_CONSUL_TOKENS=1
wait_nonempty_file "${LAB_DOCKER_DIR}/kubeapi/output/kubeapi_tokens.env" || HAS_KUBE_TOKENS=0
wait_nonempty_file "${LAB_DOCKER_DIR}/consul/output/consul_acl_tokens.env" || HAS_CONSUL_TOKENS=0

CONSUL_READ_TOKEN=""
CONSUL_MGMT_TOKEN=""
KUBE_AUDITOR_TOKEN=""
KUBE_ADMIN_TOKEN=""
if [ "${HAS_CONSUL_TOKENS}" -eq 1 ]; then
  CONSUL_READ_TOKEN="$(grep '^CONSUL_ACL_READ_TOKEN=' "${LAB_DOCKER_DIR}/consul/output/consul_acl_tokens.env" | cut -d= -f2-)"
  CONSUL_MGMT_TOKEN="$(grep '^CONSUL_ACL_MANAGEMENT_TOKEN=' "${LAB_DOCKER_DIR}/consul/output/consul_acl_tokens.env" | cut -d= -f2-)"
else
  echo "[error] consul ACL tokens are unavailable; strict matrix cannot continue" >&2
  exit 1
fi
if [ "${HAS_KUBE_TOKENS}" -eq 1 ]; then
  KUBE_AUDITOR_TOKEN="$(grep '^KUBEAPI_AUDITOR_TOKEN=' "${LAB_DOCKER_DIR}/kubeapi/output/kubeapi_tokens.env" | cut -d= -f2-)"
  KUBE_ADMIN_TOKEN="$(grep '^KUBEAPI_ADMIN_TOKEN=' "${LAB_DOCKER_DIR}/kubeapi/output/kubeapi_tokens.env" | cut -d= -f2-)"
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
run_case exporters exporters_scan_url_https_transport_fail 1 exporters scan -t "https://127.0.0.1:19100/metrics"
run_case exporters exporters_collect_url_http 0 exporters collect -t "http://127.0.0.1:19100/debug/vars" --exporters node --save-responses-dir "${OUT_DIR}/collect_raw_url"
run_case exporters exporters_collect_url_https_transport_fail 1 exporters collect -t "https://127.0.0.1:19100/debug/vars"
run_case exporters exporters_trigger_url_http 0 exporters trigger -t "http://127.0.0.1:19121/scrape?target=redis://127.0.0.1:6379" --callback-dns host.docker.internal --no-with-listen
run_case exporters exporters_trigger_url_https_transport_mismatch 0 exporters trigger -t "https://127.0.0.1:19121/scrape" --callback-dns host.docker.internal --no-with-listen

run_case registry registry_open 0 registry -t 127.0.0.1 --port 15000 --docker --images
run_case registry registry_auth 0 registry -t 127.0.0.1 --port 15001 -u admin -p admin --docker --images
run_case registry registry_harbor 0 registry -t 127.0.0.1 --port 15002 --harbor --images
run_case registry registry_gitlab 0 registry -t 127.0.0.1 --port 15003 --token glrt-lab-token --gitlab --images
run_case registry registry_nexus 0 registry -t 127.0.0.1 --port 15004 --nexus --assets
run_case registry registry_url_http 0 registry -t "http://127.0.0.1:15000/v2/_catalog?n=1000" --docker --images
run_case registry registry_url_https_transport_fail 1 registry -t "https://127.0.0.1:15000/v2/_catalog" --docker --images
run_case registry registry_multi_instance_urls 0 registry -t "http://127.0.0.1:15000/v2/_catalog,http://127.0.0.1:15010/v2/_catalog,http://127.0.0.1:15011/v2/_catalog,http://127.0.0.1:15012/v2/_catalog,http://127.0.0.1:15013/v2/_catalog" --docker --images

run_case grafana grafana_default 0 grafana -t 127.0.0.1 --defcreds --show-datasources
run_case grafana grafana_url_http 0 grafana -t "http://127.0.0.1:3000/login?next=%2F" --defcreds --show-datasources
run_case grafana grafana_url_https_transport_fail 1 grafana -t "https://127.0.0.1:3000/login"
run_case grafana grafana_ssrf_edge 0 grafana -t 127.0.0.1 --defcreds --ssrf-target "http://grafana-2:3000/api/health" --show-datasources
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
run_case mongodb mongodb_open 0 mongodb -t 127.0.0.1 --port 27017 --show-databases --show-collections --show-indexes --dump 20
run_case mongodb mongodb_auth 0 mongodb -t 127.0.0.1 --port 27018 -u root -p root --show-databases --show-collections --dump 20
run_case mongodb mongodb_defcreds 0 mongodb -t 127.0.0.1 --port 27018 --defcreds --show-databases --show-collections
run_case mongodb mongodb_multi_ports 0 mongodb -t 127.0.0.1 --ports "27017,37017,37018,37019,37020" --show-databases
run_case mongodb mongodb_query_dump 0 mongodb -t 127.0.0.1 --port 27017 --database redposture --collection demo_accounts --query '{"role":"admin"}' --dump 10
run_text_case mongodb mongodb_debug_smoke 0 mongodb -t 127.0.0.1 --port 27017 --debug
run_case oracle oracle_listener 0 oracle --timeout 5 -t 127.0.0.1 --port 1521 --service FREEPDB1
run_case oracle oracle_sid_service_enum 0 oracle --timeout 5 -t 127.0.0.1 --port 1521 --service-list FREEPDB1,FREE --sid-list FREE,ORCLCDB
run_case oracle oracle_auth 0 oracle --timeout 5 -t 127.0.0.1 --port 1521 --service FREEPDB1 -u redposture -p "OracleLab!2026" --show-pdbs --show-users
run_case oracle oracle_defcreds 0 oracle --timeout 5 -t 127.0.0.1 --port 1521 --service FREEPDB1 --defcreds --show-users
ORACLE_COMBO="${OUT_DIR}/oracle_combo.txt"
printf "bad:bad\nredposture:OracleLab!2026\n" > "${ORACLE_COMBO}"
run_case oracle oracle_combo_file 0 oracle --timeout 5 -t 127.0.0.1 --port 1521 --service FREEPDB1 --combo-list "${ORACLE_COMBO}" --show-users
ORACLE_USERS="${OUT_DIR}/oracle_users.txt"
ORACLE_PASSWORDS="${OUT_DIR}/oracle_passwords.txt"
printf "redposture\nlimited\n" > "${ORACLE_USERS}"
printf "wrong\nOracleLab!2026\n" > "${ORACLE_PASSWORDS}"
run_case oracle oracle_spray 0 oracle --timeout 5 -t 127.0.0.1 --port 1521 --service FREEPDB1 --user-list "${ORACLE_USERS}" --pass-list "${ORACLE_PASSWORDS}" --spray-passwords
run_case oracle oracle_multi_ports 0 oracle --timeout 5 -t 127.0.0.1 --ports "1521,31521,31522,31523,31524" --service FREEPDB1 -u redposture -p "OracleLab!2026" --show-pdbs
run_case oracle oracle_pdb_cdb 0 oracle --timeout 5 -t 127.0.0.1 --port 1521 --service FREEPDB1 -u redposture -p "OracleLab!2026" --show-pdbs
run_case oracle oracle_privesc_check 0 oracle --timeout 5 -t 127.0.0.1 --port 1521 --service FREEPDB1 -u redposture -p "OracleLab!2026" --privesc-check
run_case oracle oracle_privesc_chain 0 oracle --timeout 5 -t 127.0.0.1 --port 1521 --service FREEPDB1 -u redposture -p "OracleLab!2026" --privesc-chain
run_case oracle oracle_nne_check 0 oracle --timeout 5 -t 127.0.0.1 --port 1521 --service FREEPDB1 -u redposture -p "OracleLab!2026" --nne-check
run_case oracle oracle_listener_dump 0 oracle --timeout 5 -t 127.0.0.1 --port 1521 --service FREEPDB1 --listener-dump
run_text_case oracle oracle_listener_protected 0 oracle --timeout 5 -t 127.0.0.1 --port 31525 --listener-dump
run_case oracle oracle_query_dump 0 oracle --timeout 5 -t 127.0.0.1 --port 1521 --service FREEPDB1 -u redposture -p "OracleLab!2026" --schema REDPOSTURE --table ACCOUNTS --show-tables --dump 10 --query "select username, role from accounts fetch first 2 rows only"
run_case oracle oracle_rce_scheduler 0 oracle --timeout 5 -t 127.0.0.1 --port 1521 --service FREEPDB1 -u redposture -p "OracleLab!2026" --exec-cmd "id"
run_case oracle oracle_external_table_rce 0 oracle --timeout 5 -t 127.0.0.1 --port 1521 --service FREEPDB1 -u redposture -p "OracleLab!2026" --exec-cmd "echo ext-rce-ok" --exec-method external-table
run_case oracle oracle_dbms_cloud_capability 0 oracle --timeout 5 -t 127.0.0.1 --port 1521 --service FREEPDB1 -u redposture -p "OracleLab!2026" --exec-cmd "id" --exec-method dbms-cloud
run_case oracle oracle_privesc_chain_execute 0 oracle --timeout 5 -t 127.0.0.1 --port 1521 --service FREEPDB1 -u redposture -p "OracleLab!2026" --privesc-check --privesc-chain
run_case oracle oracle_file_read 0 oracle --timeout 5 -t 127.0.0.1 --port 1521 --service FREEPDB1 -u redposture -p "OracleLab!2026" --os-read redposture_wallet_hint.txt
run_case oracle oracle_wallet_search 0 oracle --timeout 5 -t 127.0.0.1 --port 1521 --service FREEPDB1 -u redposture -p "OracleLab!2026" --wallet-search
run_case oracle oracle_wallet_extract 0 oracle --timeout 5 -t 127.0.0.1 --port 1521 --service FREEPDB1 -u redposture -p "OracleLab!2026" --wallet-search -o "${OUT_DIR}/oracle_wallet_extract.txt"
run_case oracle oracle_large_file_resume 0 oracle --timeout 5 -t 127.0.0.1 --port 1521 --service FREEPDB1 -u redposture -p "OracleLab!2026" --download "redposture_large_file.txt:${OUT_DIR}/oracle_large_file_download.txt"
run_case oracle oracle_arbitrary_fs 0 oracle --timeout 5 -t 127.0.0.1 --port 1521 --service FREEPDB1 -u redposture -p "OracleLab!2026" --os-read /etc/hostname --fs-mode scheduler
run_case oracle oracle_hashes 0 oracle --timeout 5 -t 127.0.0.1 --port 1521 --service FREEPDB1 -u redposture -p "OracleLab!2026" --hashes
run_case oracle oracle_dblink 0 oracle --timeout 5 -t 127.0.0.1 --port 1521 --service FREEPDB1 -u redposture -p "OracleLab!2026" --dblink-check
run_text_case oracle oracle_debug_smoke 0 oracle --timeout 5 -t 127.0.0.1 --port 1521 --service FREEPDB1 -u redposture -p "OracleLab!2026" --debug
run_case oracle oracle_json_smoke 0 oracle --timeout 5 -t 127.0.0.1 --port 1521 --service FREEPDB1 -u redposture -p "OracleLab!2026" --show-pdbs
run_case docker docker_open 0 docker -t 127.0.0.1 --port 2375 --containers --images --networks --volumes --system
run_case docker docker_tls 0 docker -t 127.0.0.1 --port 2376 --insecure --system
run_case docker docker_multi_ports 0 docker -t 127.0.0.1 --ports "2375,2376,24243,24244,24245" --insecure --containers
run_case docker docker_inventory 0 docker -t 127.0.0.1 --port 2375 --containers --images --networks --volumes --system
run_case docker docker_exec 0 docker -t 127.0.0.1 --port 2375 --container redposture-web --exec-cmd "id"
run_text_case docker docker_debug_smoke 0 docker -t 127.0.0.1 --port 2375 --debug

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
run_case etcd etcd_url_https_transport_fail 1 etcd -t "https://127.0.0.1:2379/v2/keys?recursive=true" --show-keys
run_case etcd etcd_multi_instance_urls 0 etcd -t "http://127.0.0.1:2379/v2/keys,http://127.0.0.1:23790/v2/keys,http://127.0.0.1:23791/v2/keys,http://127.0.0.1:23792/v2/keys,http://127.0.0.1:23793/v2/keys" --show-keys

run_case qdrant qdrant_default 0 qdrant -t 127.0.0.1 --collections --dump
run_case qdrant qdrant_url_http 0 qdrant -t "http://127.0.0.1:6333/collections?from=matrix" --collections --dump
run_case qdrant qdrant_url_https_transport_fail 1 qdrant -t "https://127.0.0.1:6333/collections" --collections
run_case qdrant qdrant_multi_instance_urls 0 qdrant -t "http://127.0.0.1:6333/collections,http://127.0.0.1:26333/collections,http://127.0.0.1:26334/collections,http://127.0.0.1:26335/collections,http://127.0.0.1:26336/collections" --collections --dump

run_case elastic elastic_open 0 elastic -t 127.0.0.1 --port 19200 --endpoints --cluster --discover
run_case elastic elastic_auth 0 elastic -t 127.0.0.1 --port 19201 -u elastic -p changeme --endpoints --cluster --user --discover
run_case elastic elastic_url_hint_https 0 elastic -t "http://127.0.0.1:19201/" -u elastic -p changeme --endpoints
run_case elastic elastic_plugins_edge 0 elastic -t 127.0.0.1 --port 19201 -u elastic -p changeme --plugins
run_case elastic elastic_multi_instance_urls 0 elastic -t "http://127.0.0.1:19200/,http://127.0.0.1:19202/,http://127.0.0.1:19203/,http://127.0.0.1:19204/,http://127.0.0.1:19205/" --endpoints

run_case grpc grpc_open 0 grpc -t 127.0.0.1 --port 50051 --plaintext --analyze
run_case grpc grpc_auth_token 0 grpc -t 127.0.0.1 --port 50061 --token "grpc-lab-token-2026" --analyze
run_case grpc grpc_auth_defcreds 0 grpc -t 127.0.0.1 --port 50061 --defcreds --analyze
run_case grpc grpc_multi_ports 0 grpc -t 127.0.0.1 --ports "50051,25052,25053,25054,25055" --analyze
run_text_case grpc grpc_debug_smoke 0 grpc -t 127.0.0.1 --port 50051 --debug
GRPC_PROTOSET="${OUT_DIR}/grpc_health.protoset"
"${PYTHON_BIN}" -c 'import sys; from google.protobuf import descriptor_pb2; from redposture_core.proto import grpc_health_pb2; ds=descriptor_pb2.FileDescriptorSet(); fd=ds.file.add(); fd.ParseFromString(grpc_health_pb2.DESCRIPTOR.serialized_pb); open(sys.argv[1], "wb").write(ds.SerializeToString())' "${GRPC_PROTOSET}"
run_case grpc grpc_invoke_health 0 grpc -t 127.0.0.1 --port 50051 --invoke /grpc.health.v1.Health/Check --data '{"service":""}'
run_case grpc grpc_proto_invoke 0 grpc -t 127.0.0.1 --port 50051 --proto redposture_core/proto/grpc_health.proto --proto-path redposture_core/proto --invoke /grpc.health.v1.Health/Check --data '{"service":""}'
run_case grpc grpc_protoset_invoke 0 grpc -t 127.0.0.1 --port 50051 --protoset "${GRPC_PROTOSET}" --invoke /grpc.health.v1.Health/Check --data '{"service":""}'
run_case grpc grpc_openapi_export 0 grpc -t 127.0.0.1 --port 50051 --openapi "${OUT_DIR}/json/grpc_openapi.json"
run_case grpc grpc_web_detect 0 grpc -t 127.0.0.1 --port 50071 --plaintext

run_case kafka kafka_open 0 kafka -t 127.0.0.1 --port 9092 --show-topics --dump --max-messages 50
run_case kafka kafka_auth 0 kafka -t 127.0.0.1 --port 29092 -u metrics -p metricspass --show-topics --dump --max-messages 50
run_case kafka kafka_multi_ports 0 kafka -t 127.0.0.1 --ports "9092,39092,39093,39094,39095" --show-topics --dump --max-messages 10
run_case kafka kafka_tls_defcreds 0 kafka -t 127.0.0.1 --port 29093 --tls --insecure --tls-server-name kafka-tls --defcreds --show-topics --dump --max-messages 5
run_case kafka kafka_tls_explicit_user 0 kafka -t 127.0.0.1 --port 29093 --tls --insecure -u admin -p admin --show-topics --dump --max-messages 5

run_case zookeeper zookeeper_default 0 zookeeper -t 127.0.0.1 --show-znodes --dump
run_case zookeeper zookeeper_multi_ports 0 zookeeper -t 127.0.0.1 --ports "2181,22181,22182,22183,22184" --show-znodes --dump
run_case zookeeper zookeeper_auth_defcreds 0 zookeeper -t 127.0.0.1 --port 22185 --defcreds --znode /redposture-auth --dump --probe-write

run_case proxmox proxmox_audit 0 proxmox -t 127.0.0.1 --port 18006 --insecure --pveapitoken "audit@pve!redposture=pve-redposture-token-2026" --nodes --users
run_case proxmox proxmox_admin 0 proxmox -t 127.0.0.1 --port 18006 --insecure --pveapitoken "admin@pve!root=pve-redposture-admin-2026" --discover-creds --nodes --users
run_case proxmox proxmox_url_override_https 0 proxmox -t "https://127.0.0.1:18006/api2/json/access/ticket" --no-https --insecure --pveapitoken "audit@pve!redposture=pve-redposture-token-2026" --nodes
run_case proxmox proxmox_multi_instance_urls 0 proxmox -t "https://127.0.0.1:18006/api2/json/access/ticket,https://127.0.0.1:18061/api2/json/access/ticket,https://127.0.0.1:18062/api2/json/access/ticket,https://127.0.0.1:18063/api2/json/access/ticket,https://127.0.0.1:18064/api2/json/access/ticket" --insecure --pveapitoken "audit@pve!redposture=pve-redposture-token-2026" --nodes

"${PYTHON_BIN}" "${VERIFY_SCRIPT}" --status-file "${STATUS_FILE}" --out-dir "${OUT_DIR}"

echo
echo "Matrix complete."
echo "OUT_DIR=${OUT_DIR}"
