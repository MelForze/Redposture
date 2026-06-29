#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}" || exit 1
# Use engine socket context by default for local/CI consistency.
export DOCKER_CONTEXT="${DOCKER_CONTEXT:-default}"

OUT_DIR="${1:-/tmp/redposture_lab_matrix_seq_$(date +%Y%m%d_%H%M%S)}"
STATUS_FILE="${OUT_DIR}/matrix-status.tsv"
VERIFY_SCRIPT="${ROOT_DIR}/scripts/verify_postrun.py"
MATRIX_PROFILE="${REDPOSTURE_MATRIX_PROFILE:-balanced}"
LAB_DIR="${REDPOSTURE_LAB_DIR:-${ROOT_DIR}/lab}"
LAB_DOCKER_DIR="${REDPOSTURE_LAB_DOCKER_DIR:-${LAB_DIR}/full/docker}"
if [ ! -d "${LAB_DOCKER_DIR}" ] && [ -d "${LAB_DIR}/docker" ]; then
  LAB_DOCKER_DIR="${LAB_DIR}/docker"
fi
case "${MATRIX_PROFILE}" in
  balanced|extended)
    ;;
  *)
    echo "[error] unsupported REDPOSTURE_MATRIX_PROFILE=${MATRIX_PROFILE}; expected balanced or extended" >&2
    exit 2
    ;;
esac
if [ -n "${PYTHON_BIN:-}" ]; then
  PYTHON_BIN="${PYTHON_BIN}"
elif [ -x "${ROOT_DIR}/.venv/bin/python" ]; then
  PYTHON_BIN="${ROOT_DIR}/.venv/bin/python"
else
  PYTHON_BIN="python3"
fi

EXPORTER_PORTS="7777,9100,9102,9104,9113,9114,9116,9117,9119,9121,9127,9128,9131,9150,9182,9187,9216,9221,9256,9290,9308,9342,9349,9399,9419,9427,19101,19119,17777,19100,19102,19104,19113,19114,19115,19117,19121,19128,19131,19150,19182,19187,19219,19221,19290,19308,19399,19419"

mkdir -p "${OUT_DIR}/logs" "${OUT_DIR}/json"

if [ ! -d "${LAB_DIR}/services" ]; then
  echo "[error] local lab services directory not found: ${LAB_DIR}/services" >&2
  echo "[error] set REDPOSTURE_LAB_DIR to your local lab directory" >&2
  exit 2
fi

# P3-G: pre-run port cleanup. Stops any docker container or host process occupying a lab
# port before the matrix starts. Without this, a leftover container/process (e.g. user-side
# `grafana` on :3000 from another project) silently makes the lab service refuse to bind,
# and the matrix audits whatever was already on that port -- producing confusing "service
# is not <module>" failures that look like a regression in the audit code.
LAB_PORTS=(
  3000 5432 6379 9000 9090 9100 9115 9121 9187 9216 9290 9308
  15000 15432 15433 16379 17777 18123 19000 19090 19100 19102 19104 19113 19114 19115
  19117 19121 19128 19131 19150 19182 19187 19219 19221 19290 19308 19399 19419
  19121 22379 22380 23790 23791 23792 23793 25432 25433 25434 25435 25439 26380 26381
  26382 26383 26380 26443 26444 26445 26446 26447 27017 27018 28006 29115 31521 31522
  31523 31524 8123 8500 8501 8502 8503 8504 2379 5672 9092 9200 1521 6443 22181 22182
  22183 22184 9876 9877 9878 9879
)
echo "== pre-run: ensuring lab ports are free =="
freed=0
for port in $(printf "%s\n" "${LAB_PORTS[@]}" | sort -un); do
  # Stop any docker container publishing that port (most common cause)
  cids=$(docker ps -q --filter "publish=${port}" 2>/dev/null || true)
  if [ -n "${cids}" ]; then
    for cid in ${cids}; do
      name=$(docker inspect -f '{{.Name}}' "${cid}" 2>/dev/null | sed 's|^/||')
      # Don't touch redposture lab containers themselves (they get started/stopped per service block)
      case "${name}" in
        redposture-lab-*) continue ;;
      esac
      echo "  port ${port}: stopping container ${name} (cid=${cid:0:12})"
      docker rm -f "${cid}" >/dev/null 2>&1 || true
      freed=$((freed + 1))
    done
  fi
done
echo "== pre-run: freed ${freed} occupant(s) =="

is_extended_matrix() {
  [ "${MATRIX_PROFILE}" = "extended" ]
}

CURRENT_SERVICE=""
compose_service() {
  local service="$1"
  shift
  local compose_file="${LAB_DIR}/services/${service}/docker-compose.yml"
  if [ ! -f "${compose_file}" ]; then
    echo "[error] local lab service compose not found: ${compose_file}" >&2
    return 2
  fi
  docker compose -f "${compose_file}" "$@"
}

cleanup_current_service() {
  if [ -n "${CURRENT_SERVICE}" ]; then
    compose_service "${CURRENT_SERVICE}" down -v >/dev/null 2>&1 || true
    CURRENT_SERVICE=""
  fi
}
trap cleanup_current_service EXIT

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

wait_healthy_service() {
  local service="$1"
  local timeout="${2:-180}"
  local elapsed=0
  while [ "${elapsed}" -lt "${timeout}" ]; do
    local ps_output
    set +e
    ps_output="$(compose_service "${service}" ps 2>&1)"
    local ps_rc=$?
    set -e
    if [ "${ps_rc}" -ne 0 ]; then
      if printf "%s" "${ps_output}" | grep -qi "failed to connect to the docker API"; then
        echo "[error] docker daemon is unavailable while checking service ${service}" >&2
        printf "%s\n" "${ps_output}" >&2
        return 1
      fi
      sleep 2
      elapsed=$((elapsed + 2))
      continue
    fi
    local unhealthy
    unhealthy="$(printf "%s" "${ps_output}" | grep -E "Restarting|unhealthy" || true)"
    if [ -z "${unhealthy}" ]; then
      return 0
    fi
    local blocking
    blocking="$(printf "%s" "${unhealthy}" | grep -Ev 'redposture-lab-consul-acl|redposture-lab-consul-seed|redposture-lab-elastic-auth' || true)"
    if [ -z "${blocking}" ]; then
      echo "[warn] continuing with degraded non-blocking services for ${service}" >&2
      printf "%s\n" "${unhealthy}" >&2
      return 0
    fi
    sleep 2
    elapsed=$((elapsed + 2))
  done
  echo "[error] compose health gate failed for ${service}" >&2
  compose_service "${service}" ps >&2 || true
  return 1
}

start_service() {
  local service="$1"
  echo
  echo "== service:${service} up =="
  CURRENT_SERVICE="${service}"
  set +e
  compose_service "${service}" up -d --build --wait --wait-timeout 120
  local compose_rc=$?
  set -e
  if [ "${compose_rc}" -ne 0 ]; then
    echo "[warn] compose up for ${service} returned ${compose_rc}; continuing with health gate" >&2
  fi
  wait_healthy_service "${service}"
}

stop_service() {
  local service="$1"
  echo "== service:${service} down =="
  compose_service "${service}" down -v
  if [ "${CURRENT_SERVICE}" = "${service}" ]; then
    CURRENT_SERVICE=""
  fi
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
}

run_raw_case() {
  local module="$1"
  local label="$2"
  local expected_exit="$3"
  shift 3

  local log_path="${OUT_DIR}/logs/${label}.log"
  echo "== ${label} =="
  set +e
  "${PYTHON_BIN}" redposture.py "$@" >"${log_path}" 2>&1
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
}

run_negative_cli_cases() {
  run_raw_case exporters fuzz_exporters_scan_missing_targets 2 exporters scan -p 9100
  run_raw_case exporters fuzz_exporters_scan_invalid_ports 2 exporters scan -t 127.0.0.1 -p bad
  run_raw_case exporters fuzz_exporters_scan_zero_timeout 2 exporters scan -t 127.0.0.1 --timeout 0
  run_raw_case exporters fuzz_exporters_collect_zero_max_inflight 2 exporters collect -t 127.0.0.1 --max-inflight 0
  run_raw_case exporters fuzz_exporters_trigger_missing_callback 2 exporters trigger -t 127.0.0.1 --no-with-listen
  run_raw_case exporters fuzz_exporters_trigger_bad_callback_ip 2 exporters trigger -t 127.0.0.1 --callback-ip 999.999.999.999 --no-with-listen
  run_raw_case exporters fuzz_exporters_trigger_check_without_listen 2 exporters trigger -t 127.0.0.1 --callback-ip 127.0.0.1 --no-with-listen --check-credentials
  run_raw_case exporters fuzz_exporters_trigger_json_listen_without_output 2 exporters trigger -t 127.0.0.1 --callback-ip 127.0.0.1 --with-listen --format json
  run_raw_case exporters fuzz_exporters_trigger_negative_listen_seconds 2 exporters trigger -t 127.0.0.1 --callback-ip 127.0.0.1 --with-listen --listen-seconds -1

  run_raw_case registry fuzz_registry_missing_targets 2 registry --docker --images
  run_raw_case grafana fuzz_grafana_missing_targets 2 grafana --defcreds
  run_raw_case gitlab fuzz_gitlab_missing_targets 2 gitlab
  run_raw_case consul fuzz_consul_missing_targets 2 consul --keys
  run_raw_case kubeapi fuzz_kubeapi_missing_targets 2 kubeapi --namespaces
  run_raw_case postgres fuzz_postgres_missing_targets 2 postgres --show-databases
  run_raw_case mongodb fuzz_mongodb_missing_targets 2 mongodb --show-databases
  run_raw_case oracle fuzz_oracle_missing_targets 2 oracle --service FREEPDB1
  run_raw_case docker fuzz_docker_missing_targets 2 docker --containers
  run_raw_case clickhouse fuzz_clickhouse_missing_targets 2 clickhouse --show-databases
  run_raw_case redis fuzz_redis_missing_targets 2 redis --show-keys
  run_raw_case etcd fuzz_etcd_missing_targets 2 etcd --show-keys
  run_raw_case qdrant fuzz_qdrant_missing_targets 2 qdrant --collections
  run_raw_case elastic fuzz_elastic_missing_targets 2 elastic --endpoints
  run_raw_case grpc fuzz_grpc_missing_targets 2 grpc
  run_raw_case kafka fuzz_kafka_missing_targets 2 kafka --show-topics
  run_raw_case zookeeper fuzz_zookeeper_missing_targets 2 zookeeper --show-znodes
  run_raw_case proxmox fuzz_proxmox_missing_targets 2 proxmox --pveapitoken "monitor@pve!audit=token"

  run_raw_case registry fuzz_registry_username_without_password 2 registry -t 127.0.0.1 -u admin --docker --images
  run_raw_case registry fuzz_registry_token_basic_conflict 2 registry -t 127.0.0.1 --token token -u admin -p admin --docker --images
  run_raw_case registry fuzz_registry_show_tags_without_repository 2 registry -t 127.0.0.1 --docker --show-tags
  run_raw_case registry fuzz_registry_metadata_without_tag 2 registry -t 127.0.0.1 --docker --repository redposture/demo-api --metadata
  run_raw_case registry fuzz_registry_assets_without_nexus 2 registry -t 127.0.0.1 --assets
  run_raw_case registry fuzz_registry_download_without_image 2 registry -t 127.0.0.1 --docker --download

  run_raw_case grafana fuzz_grafana_username_without_password 2 grafana -t 127.0.0.1 -u admin --show-datasource
  run_raw_case kubeapi fuzz_kubeapi_username_without_password 2 kubeapi -t 127.0.0.1 -u audit --namespaces
  run_raw_case elastic fuzz_elastic_username_without_password 2 elastic -t 127.0.0.1 -u elastic --endpoints
  run_raw_case grpc fuzz_grpc_username_without_password 2 grpc -t 127.0.0.1 -u grpcuser
  run_raw_case kafka fuzz_kafka_username_without_password 2 kafka -t 127.0.0.1 -u metrics --show-topics
  run_raw_case zookeeper fuzz_zookeeper_username_without_password 2 zookeeper -t 127.0.0.1 -u zkuser --show-znodes
  run_raw_case proxmox fuzz_proxmox_username_without_password 2 proxmox -t 127.0.0.1 -u root@pam --nodes
  run_raw_case redis fuzz_redis_username_without_password 2 redis -t 127.0.0.1 -u redis --show-keys

  run_raw_case consul fuzz_consul_username_without_password 2 consul -t 127.0.0.1 -u matrix --keys
  run_raw_case consul fuzz_consul_key_without_dump 2 consul -t 127.0.0.1 --key redposture/kafka/sasl_password
  run_raw_case consul fuzz_consul_service_without_dump 2 consul -t 127.0.0.1 --service svc-redposture-api
  run_raw_case consul fuzz_consul_agent_without_dump 2 consul -t 127.0.0.1 --agent redposture-lab-consul
  run_raw_case consul fuzz_consul_node_without_dump 2 consul -t 127.0.0.1 --node redposture-lab-consul
  run_raw_case consul fuzz_consul_ssrf_port_without_target 2 consul -t 127.0.0.1 --ssrf-port 19100
  run_raw_case consul fuzz_consul_delete_without_revshell 2 consul -t 127.0.0.1 --delete
  run_raw_case consul fuzz_consul_listen_without_revshell 2 consul -t 127.0.0.1 --listen
  run_raw_case consul fuzz_consul_revshell_missing_lhost 2 consul -t 127.0.0.1 --revshell
  run_raw_case consul fuzz_consul_revshell_bad_lhost 2 consul -t 127.0.0.1 --revshell --lhost "http://bad" --lport 4444
  run_raw_case consul fuzz_consul_revshell_listen_missing_lport 2 consul -t 127.0.0.1 --revshell --listen --lhost 127.0.0.1

  run_raw_case qdrant fuzz_qdrant_listen_without_ssrf_target 2 qdrant -t 127.0.0.1 --collection demo_vectors --listen
  run_raw_case qdrant fuzz_qdrant_ssrf_without_collection 2 qdrant -t 127.0.0.1 --ssrf-target http://127.0.0.1:19115/probe
  run_raw_case qdrant fuzz_qdrant_bad_ssrf_port 2 qdrant -t 127.0.0.1 --collection demo_vectors --ssrf-target 127.0.0.1 --ssrf-port bad

  run_raw_case postgres fuzz_postgres_username_without_password 2 postgres -t 127.0.0.1 -u postgres --show-databases
  run_raw_case postgres fuzz_postgres_show_columns_without_table 2 postgres -t 127.0.0.1 --show-columns
  run_raw_case postgres fuzz_postgres_column_without_table 2 postgres -t 127.0.0.1 --column username
  run_raw_case postgres fuzz_postgres_execute_sql_conflict 2 postgres -t 127.0.0.1 --execute id --sql-cmd "select 1"
  run_raw_case postgres fuzz_postgres_execute_os_read_conflict 2 postgres -t 127.0.0.1 --execute id --os-read /etc/hostname
  run_raw_case postgres fuzz_postgres_os_shell_sql_shell_conflict 2 postgres -t 127.0.0.1 --os-shell --sql-shell

  run_raw_case mongodb fuzz_mongodb_username_without_password 2 mongodb -t 127.0.0.1 -u root --show-databases
  run_raw_case mongodb fuzz_mongodb_invalid_query_json 2 mongodb -t 127.0.0.1 --collection demo_accounts --query "{bad"
  run_raw_case mongodb fuzz_mongodb_query_without_collection 2 mongodb -t 127.0.0.1 --query '{"role":"admin"}'
  run_raw_case mongodb fuzz_mongodb_document_without_collection 2 mongodb -t 127.0.0.1 --document 1
  run_raw_case mongodb fuzz_mongodb_document_query_conflict 2 mongodb -t 127.0.0.1 --collection demo_accounts --document 1 --query '{"role":"admin"}'
  run_raw_case mongodb fuzz_mongodb_invalid_projection_json 2 mongodb -t 127.0.0.1 --collection demo_accounts --projection "{bad"
  run_raw_case mongodb fuzz_mongodb_invalid_nosql_cmd_json 2 mongodb -t 127.0.0.1 --nosql-cmd "{bad"
  run_raw_case mongodb fuzz_mongodb_nosql_cmd_shell_conflict 2 mongodb -t 127.0.0.1 --nosql-cmd '{"dbStats":1}' --nosql-shell

  run_raw_case oracle fuzz_oracle_username_without_password 2 oracle -t 127.0.0.1 --service FREEPDB1 -u redposture
  run_raw_case oracle fuzz_oracle_service_sid_conflict 2 oracle -t 127.0.0.1 --service FREEPDB1 --sid FREE
  run_raw_case oracle fuzz_oracle_non_select_query 2 oracle -t 127.0.0.1 --service FREEPDB1 --query "delete from accounts"
  run_raw_case oracle fuzz_oracle_os_write_bad_syntax 2 oracle -t 127.0.0.1 --service FREEPDB1 --os-write /tmp/file
  run_raw_case oracle fuzz_oracle_download_bad_syntax 2 oracle -t 127.0.0.1 --service FREEPDB1 --download redposture_wallet_hint.txt

  run_raw_case docker fuzz_docker_container_without_exec 2 docker -t 127.0.0.1 --container redposture-web
  run_raw_case docker fuzz_docker_exec_without_container 2 docker -t 127.0.0.1 --exec-cmd id
  run_raw_case docker fuzz_docker_tls_cert_without_key 2 docker -t 127.0.0.1 --tls-cert cert.pem
  run_raw_case docker fuzz_docker_tls_key_without_cert 2 docker -t 127.0.0.1 --tls-key key.pem

  run_raw_case clickhouse fuzz_clickhouse_username_without_password 2 clickhouse -t 127.0.0.1 -u default --show-databases
  run_raw_case clickhouse fuzz_clickhouse_show_columns_without_table 2 clickhouse -t 127.0.0.1 --show-columns
  run_raw_case clickhouse fuzz_clickhouse_column_without_table 2 clickhouse -t 127.0.0.1 --column owner
  run_raw_case clickhouse fuzz_clickhouse_execute_sql_conflict 2 clickhouse -t 127.0.0.1 --execute id --sql-cmd "select 1"
  run_raw_case clickhouse fuzz_clickhouse_os_shell_sql_shell_conflict 2 clickhouse -t 127.0.0.1 --os-shell --sql-shell
  run_raw_case clickhouse fuzz_clickhouse_os_shell_execute_conflict 2 clickhouse -t 127.0.0.1 --os-shell --execute id

  run_raw_case zookeeper fuzz_zookeeper_zero_max_znodes 2 zookeeper -t 127.0.0.1 --max-znodes 0
  run_raw_case zookeeper fuzz_zookeeper_zero_enum_workers 2 zookeeper -t 127.0.0.1 --enum-workers 0
}

run_exporters_cases() {
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
  run_text_case exporters exporters_debug_smoke 0 exporters scan -t 127.0.0.1 -p "19100,19121" --debug
  if is_extended_matrix; then
    local collect_checkpoint="${OUT_DIR}/exporters_collect_extended.checkpoint"
    run_case exporters exporters_scan_extended_controls 0 exporters scan -t 127.0.0.1 -p "19100,19121" --timeout 2 -w 4 -r 1
    run_case exporters exporters_collect_extended_controls 0 exporters collect -t 127.0.0.1 -p "19100,19121" --exporters node,blackbox --deep --no-adaptive-collect --max-inflight 4 --pprof-seconds 1 --trace-seconds 1 --checkpoint-file "${collect_checkpoint}" --save-responses-dir "${OUT_DIR}/collect_extended"
    run_case exporters exporters_collect_resume_checkpoint 0 exporters collect -t 127.0.0.1 -p "19100,19121" --exporters node --resume --checkpoint-file "${collect_checkpoint}" --save-responses-dir "${OUT_DIR}/collect_extended_resume"
    run_text_case exporters exporters_collect_debug_smoke 0 exporters collect -t 127.0.0.1 -p "19100" --exporters node --debug
    run_case exporters exporters_trigger_extended_controls 0 exporters trigger -t 127.0.0.1 --callback-ip 127.0.0.1 -p "19121,19187" --no-with-listen --exporters blackbox,postgres --services blackbox --blackbox-port 29115 --postgres-auth-module stage --no-postgres-tls --no-proxmox-tls
    run_text_case exporters exporters_trigger_debug_smoke 0 exporters trigger -t 127.0.0.1 --callback-ip 127.0.0.1 -p "19121" --no-with-listen --exporters blackbox --debug
  fi
}

run_registry_cases() {
  run_case registry registry_open 0 registry -t 127.0.0.1 --port 15000 --docker --images
  run_case registry registry_auth 0 registry -t 127.0.0.1 --port 15001 -u admin -p admin --docker --images
  run_case registry registry_harbor 0 registry -t 127.0.0.1 --port 15002 --harbor --images
  run_case registry registry_gitlab 0 registry -t 127.0.0.1 --port 15003 --token glrt-lab-token --gitlab --images
  run_case registry registry_nexus 0 registry -t 127.0.0.1 --port 15004 --nexus --assets
  run_case registry registry_url_http 0 registry -t "http://127.0.0.1:15000/v2/_catalog?n=1000" --docker --images
  run_case registry registry_url_https_reject 2 registry -t "https://127.0.0.1:15000/v2/_catalog" --docker --images
  run_case registry registry_multi_instance_urls 0 registry -t "http://127.0.0.1:15000/v2/_catalog,http://127.0.0.1:15010/v2/_catalog,http://127.0.0.1:15011/v2/_catalog,http://127.0.0.1:15012/v2/_catalog,http://127.0.0.1:15013/v2/_catalog" --docker --images
  run_text_case registry registry_debug_smoke 0 registry -t 127.0.0.1 --port 15000 --docker --images --debug
  if is_extended_matrix; then
    run_case registry registry_extended_tags_metadata 0 registry -t 127.0.0.1 --port 15000 --docker --repository redposture/demo-api --show-tags --tag latest --metadata --inspect --image redposture/demo-api:latest --download --download-dir "${OUT_DIR}/registry_downloads"
    run_case registry registry_extended_ports_flag 0 registry -t 127.0.0.1 --ports 15000 --docker --images
    run_case registry fuzz_registry_malformed_target 2 registry -t "http://[invalid:url" --docker --images
    run_case registry fuzz_registry_invalid_port 2 registry -t 127.0.0.1 --port -1 --docker --images
  fi
}

run_grafana_cases() {
  run_case grafana grafana_default 0 grafana -t 127.0.0.1 --defcreds --show-datasources
  run_case grafana grafana_url_http 0 grafana -t "http://127.0.0.1:3000/login?next=%2F" --defcreds --show-datasources
  run_case grafana grafana_url_https_reject 2 grafana -t "https://127.0.0.1:3000/login"
  run_case grafana grafana_ssrf_edge 0 grafana -t 127.0.0.1 --defcreds --ssrf-target "http://127.0.0.1:19115/probe?module=http_2xx" --show-datasources
  run_case grafana grafana_multi_instance_urls 0 grafana -t "http://127.0.0.1:3000/login,http://127.0.0.1:13001/login,http://127.0.0.1:13002/login,http://127.0.0.1:13003/login,http://127.0.0.1:13004/login" --defcreds
  run_text_case grafana grafana_debug_smoke 0 grafana -t 127.0.0.1 --defcreds --debug
  if is_extended_matrix; then
    run_case grafana grafana_extended_auth_ssrf_controls 0 grafana -t 127.0.0.1 --port 3000 -u admin -p prom-operator --show-datasource --ssrf-target 127.0.0.1 --ssrf-port 19115 --ssrf-path /probe?module=http_2xx
    run_case grafana grafana_extended_ports_flag 0 grafana -t 127.0.0.1 --ports 3000 --defcreds
    run_case grafana fuzz_grafana_invalid_target 2 grafana -t "not://valid" --show-datasource
    run_case grafana fuzz_grafana_huge_port 2 grafana -t 127.0.0.1 --port 99999 --defcreds
  fi
}

run_gitlab_cases() {
  run_case gitlab gitlab_public 0 gitlab -t 127.0.0.1 --port 18080
  run_case gitlab gitlab_analyst 0 gitlab -t 127.0.0.1 --port 18080 --token glpat-redposture-lab-analyst-2026
  run_case gitlab gitlab_url_override_http 0 gitlab -t "http://127.0.0.1:18080/users/sign_in?ref=matrix" --https
  run_case gitlab gitlab_multi_instance_urls 0 gitlab -t "http://127.0.0.1:18080/users/sign_in,http://127.0.0.1:18081/users/sign_in,http://127.0.0.1:18082/users/sign_in,http://127.0.0.1:18083/users/sign_in,http://127.0.0.1:18084/users/sign_in"
  run_text_case gitlab gitlab_debug_smoke 0 gitlab -t 127.0.0.1 --port 18080 --debug
  if is_extended_matrix; then
    run_case gitlab gitlab_extended_token_project_clone 0 gitlab -t 127.0.0.1 --port 18080 --https --token glpat-redposture-lab-analyst-2026 --project redposture-lab/public-api --clone --clone-dir "${OUT_DIR}/gitlab_clones"
    run_case gitlab gitlab_extended_ports_flag 0 gitlab -t 127.0.0.1 --ports 18080
    run_case gitlab fuzz_gitlab_invalid_port 2 gitlab -t 127.0.0.1 --port 99999
    run_case gitlab fuzz_gitlab_zero_timeout 2 gitlab -t 127.0.0.1 --timeout 0
  fi
}

run_consul_cases() {
  wait_nonempty_file "${LAB_DOCKER_DIR}/consul/output/consul_acl_tokens.env"
  local consul_read_token
  local consul_mgmt_token
  consul_read_token="$(grep '^CONSUL_ACL_READ_TOKEN=' "${LAB_DOCKER_DIR}/consul/output/consul_acl_tokens.env" | cut -d= -f2-)"
  consul_mgmt_token="$(grep '^CONSUL_ACL_MANAGEMENT_TOKEN=' "${LAB_DOCKER_DIR}/consul/output/consul_acl_tokens.env" | cut -d= -f2-)"
  if [ -z "${consul_read_token}" ] || [ -z "${consul_mgmt_token}" ]; then
    echo "[error] consul tokens are empty" >&2
    return 1
  fi
  run_case consul consul_open 0 consul -t 127.0.0.1 --port 8500 --dump
  run_case consul consul_acl_read 0 consul -t 127.0.0.1 --port 18500 --token "${consul_read_token}" --dump
  run_case consul consul_acl_mgmt 0 consul -t 127.0.0.1 --port 18500 --token "${consul_mgmt_token}" --dump
  run_case consul consul_url_hint_http 0 consul -t "http://127.0.0.1:8500/v1/status/leader" --dump
  run_case consul consul_multi_instance_urls 0 consul -t "http://127.0.0.1:8500/v1/status/leader,http://127.0.0.1:8501/v1/status/leader,http://127.0.0.1:8502/v1/status/leader,http://127.0.0.1:8503/v1/status/leader,http://127.0.0.1:8504/v1/status/leader" --dump
  run_text_case consul consul_debug_smoke 0 consul -t 127.0.0.1 --port 8500 --debug
  if is_extended_matrix; then
    run_case consul consul_extended_ports_basic_auth 0 consul -t 127.0.0.1 --ports 8500 -u matrix -p "" --keys
    run_case consul consul_extended_inventory_filters 0 consul -t 127.0.0.1 --port 8500 --keys --services --agents --checks --nodes --key redposture/kafka/sasl_password --service svc-redposture-api --agent redposture-lab-consul --node redposture-lab-consul --dump 3
    run_case consul consul_extended_ssrf_probe 0 consul -t 127.0.0.1 --port 8500 --ssrf-target 127.0.0.1 --ssrf-port 19100 --ssrf-path /metrics --checks
    run_case consul fuzz_consul_zero_workers 2 consul -t 127.0.0.1 --workers 0 --keys
    run_case consul fuzz_consul_negative_dump 2 consul -t 127.0.0.1 --port 8500 --keys --dump -1
  fi
}

run_kubeapi_cases() {
  wait_nonempty_file "${LAB_DOCKER_DIR}/kubeapi/output/kubeapi_tokens.env"
  local kube_auditor_token
  local kube_admin_token
  kube_auditor_token="$(grep '^KUBEAPI_AUDITOR_TOKEN=' "${LAB_DOCKER_DIR}/kubeapi/output/kubeapi_tokens.env" | cut -d= -f2-)"
  kube_admin_token="$(grep '^KUBEAPI_ADMIN_TOKEN=' "${LAB_DOCKER_DIR}/kubeapi/output/kubeapi_tokens.env" | cut -d= -f2-)"
  if [ -z "${kube_auditor_token}" ] || [ -z "${kube_admin_token}" ]; then
    echo "[error] kubeapi tokens are empty" >&2
    return 1
  fi
  run_case kubeapi kubeapi_open 0 kubeapi -t 127.0.0.1 --port 26443 --namespaces --pods
  run_case kubeapi kubeapi_auditor 0 kubeapi -t 127.0.0.1 --port 16443 --insecure --token "${kube_auditor_token}" --namespaces --pods
  run_case kubeapi kubeapi_admin 0 kubeapi -t 127.0.0.1 --port 16443 --insecure --token "${kube_admin_token}" --secrets
  run_case kubeapi kubeapi_url_override_https 0 kubeapi -t "https://127.0.0.1:26443/api?from=matrix" --no-https --namespaces
  run_case kubeapi kubeapi_multi_instance_urls 0 kubeapi -t "https://127.0.0.1:26443/version,https://127.0.0.1:26444/version,https://127.0.0.1:26445/version,https://127.0.0.1:26446/version,https://127.0.0.1:26447/version" --namespaces
  run_text_case kubeapi kubeapi_debug_smoke 0 kubeapi -t 127.0.0.1 --port 26443 --debug
  if is_extended_matrix; then
    run_case kubeapi kubeapi_extended_ports_flag 0 kubeapi -t 127.0.0.1 --ports 26443 --namespaces
    run_case kubeapi kubeapi_extended_selectors_basic_auth 0 kubeapi -t 127.0.0.1 --port 26443 --namespace default --namespaces --pods --pod redposture-api --username audit --password ""
    run_case kubeapi fuzz_kubeapi_zero_timeout 2 kubeapi -t 127.0.0.1 --timeout 0
    run_case kubeapi fuzz_kubeapi_huge_port 2 kubeapi -t 127.0.0.1 --port 99999 --namespaces
  fi
}

run_postgres_cases() {
  run_case postgres postgres_default 0 postgres -t 127.0.0.1 -u postgres -p postgres --show-databases --show-tables --dump 20
  run_case postgres postgres_multi_ports 0 postgres -t 127.0.0.1 -u postgres -p postgres --ports "5432,25432,25433,25434,25435" --show-databases
  run_text_case postgres postgres_debug_smoke 0 postgres -t 127.0.0.1 -u postgres -p postgres --debug
  if is_extended_matrix; then
    run_case postgres postgres_extended_defcreds 0 postgres -t 127.0.0.1 --port 5432 --defcreds --show-databases
    run_case postgres postgres_extended_query_privs 0 postgres -t 127.0.0.1 --port 5432 -u postgres -p postgres --database postgres --table redposture.demo_accounts --show-columns 5 --column username,password --rows --dump 5 --sql-cmd "select username, role from redposture.demo_accounts order by id limit 2" --privesc-check
    run_case postgres postgres_extended_execute 0 postgres -t 127.0.0.1 --port 5432 -u postgres -p postgres --execute "id"
    run_case postgres postgres_extended_os_read 0 postgres -t 127.0.0.1 --port 5432 -u postgres -p postgres --os-read /etc/hostname
    # postgres-alt accepts neither postgres:postgres nor pgbouncer:pgbouncer -- exercises
    # the 5.5.1 path that surfaces ALL attempted defaults in the output (previously only
    # unit-test covered). Runtime attaches `attempted_credentials`; postgres render
    # produces one `[-] user:pass` line per attempt.
    run_case postgres postgres_extended_defcreds_both_fail 0 postgres -t 127.0.0.1 --port 25439 --defcreds
    # P4-D idempotency twin of postgres_default.
    run_case postgres postgres_idempotency 0 postgres -t 127.0.0.1 -u postgres -p postgres --show-databases --show-tables --dump 20
    # P4-E fuzz: empty credentials must be rejected at parse time.
    run_case postgres fuzz_postgres_empty_credentials 2 postgres -t 127.0.0.1 -u "" -p "" --show-databases
  fi
}

run_mongodb_cases() {
  run_case mongodb mongodb_open 0 mongodb -t 127.0.0.1 --port 27017 --show-databases --show-collections --show-indexes --dump 20
  run_case mongodb mongodb_auth 0 mongodb -t 127.0.0.1 --port 27018 -u root -p root --show-databases --show-collections --dump 20
  run_case mongodb mongodb_defcreds 0 mongodb -t 127.0.0.1 --port 27018 --defcreds --show-databases --show-collections
  run_case mongodb mongodb_multi_ports 0 mongodb -t 127.0.0.1 --ports "27017,37017,37018,37019,37020" --show-databases
  run_case mongodb mongodb_query_dump 0 mongodb -t 127.0.0.1 --port 27017 --database redposture --collection demo_accounts --query '{"role":"admin"}' --dump 10
  run_text_case mongodb mongodb_debug_smoke 0 mongodb -t 127.0.0.1 --port 27017 --debug
  if is_extended_matrix; then
    run_case mongodb mongodb_extended_document_index_cmd 0 mongodb -t 127.0.0.1 --port 27017 --auth-db admin --database redposture --collection demo_accounts --document 1 --projection '{"username":1,"role":1}' --show-indexes 5 --index username_1 --nosql-cmd '{"dbStats":1}'
    run_case mongodb mongodb_extended_invalid_document_query 2 mongodb -t 127.0.0.1 --port 27017 --database redposture --collection demo_accounts --document 1 --query '{"role":"admin"}'
    # P4-D idempotency twin of mongodb_auth (the cleaner of the two mongo bases).
    run_case mongodb mongodb_idempotency 0 mongodb -t 127.0.0.1 --port 27018 -u root -p root --show-databases --show-collections --dump 20
    # P4-E fuzz: zero timeout must be rejected at parse.
    run_case mongodb fuzz_mongodb_zero_timeout 2 mongodb -t 127.0.0.1 --timeout 0 --show-databases
    run_case mongodb fuzz_mongodb_invalid_workers 2 mongodb -t 127.0.0.1 --workers abc --show-databases
    run_case mongodb fuzz_mongodb_negative_retries 2 mongodb -t 127.0.0.1 --retries -2 --show-databases
  fi
}

run_oracle_cases() {
  run_case oracle oracle_listener 0 oracle --timeout 5 -t 127.0.0.1 --port 1521 --service FREEPDB1
  run_case oracle oracle_sid_service_enum 0 oracle --timeout 5 -t 127.0.0.1 --port 1521 --service-list FREEPDB1,FREE --sid-list FREE,ORCLCDB
  run_case oracle oracle_auth 0 oracle --timeout 5 -t 127.0.0.1 --port 1521 --service FREEPDB1 -u redposture -p "OracleLab!2026" --show-pdbs --show-users
  run_case oracle oracle_defcreds 0 oracle --timeout 5 -t 127.0.0.1 --port 1521 --service FREEPDB1 --defcreds --show-users
  local oracle_combo="${OUT_DIR}/oracle_combo.txt"
  printf "bad:bad\nredposture:OracleLab!2026\n" > "${oracle_combo}"
  run_case oracle oracle_combo_file 0 oracle --timeout 5 -t 127.0.0.1 --port 1521 --service FREEPDB1 --combo-list "${oracle_combo}" --show-users
  local oracle_users="${OUT_DIR}/oracle_users.txt"
  local oracle_passwords="${OUT_DIR}/oracle_passwords.txt"
  printf "redposture\nlimited\n" > "${oracle_users}"
  printf "wrong\nOracleLab!2026\n" > "${oracle_passwords}"
  run_case oracle oracle_spray 0 oracle --timeout 5 -t 127.0.0.1 --port 1521 --service FREEPDB1 --user-list "${oracle_users}" --pass-list "${oracle_passwords}" --spray-passwords
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
  if is_extended_matrix; then
    run_case oracle oracle_extended_schema_sensitive_protocol 0 oracle --timeout 5 -t 127.0.0.1 --port 1521 --protocol tcp --insecure --service FREEPDB1 -u redposture -p "OracleLab!2026" --schema REDPOSTURE --table ACCOUNTS --show-roles --show-privs --show-schemas --show-tables --dump 2 --sensitive-scan
    run_case oracle fuzz_oracle_invalid_port 2 oracle -t 127.0.0.1 --port -1 --service FREEPDB1
    run_case oracle fuzz_oracle_zero_timeout 2 oracle -t 127.0.0.1 --timeout 0 --service FREEPDB1
  fi
}

run_docker_cases() {
  run_case docker docker_open 0 docker -t 127.0.0.1 --port 2375 --containers --images --networks --volumes --system
  run_case docker docker_tls 0 docker -t 127.0.0.1 --port 2376 --insecure --system
  run_case docker docker_multi_ports 0 docker -t 127.0.0.1 --ports "2375,2376,24243,24244,24245" --insecure --containers
  run_case docker docker_inventory 0 docker -t 127.0.0.1 --port 2375 --containers --images --networks --volumes --system
  run_case docker docker_exec 0 docker -t 127.0.0.1 --port 2375 --container redposture-web --exec-cmd "id"
  run_text_case docker docker_debug_smoke 0 docker -t 127.0.0.1 --port 2375 --debug
  if is_extended_matrix; then
    run_case docker docker_extended_tls_files_pairing_error 2 docker -t 127.0.0.1 --port 2376 --tls-cert "${LAB_DIR}/services/proxy-isolated/certs/proxy-cert.pem"
    run_case docker docker_extended_exec_worker 0 docker -t 127.0.0.1 --port 2375 --container redposture-worker --exec-cmd "hostname && whoami"
    run_case docker fuzz_docker_invalid_port 2 docker -t 127.0.0.1 --port abc --containers
    run_case docker fuzz_docker_zero_timeout 2 docker -t 127.0.0.1 --timeout 0 --containers
  fi
}

run_clickhouse_cases() {
  run_case clickhouse clickhouse_native_open 0 clickhouse -t 127.0.0.1 --show-databases --show-tables --dump
  run_case clickhouse clickhouse_http_open 0 clickhouse -t 127.0.0.1 --http --port 8123 --show-databases --show-tables --dump
  run_case clickhouse clickhouse_native_auth 0 clickhouse -t 127.0.0.1 --port 19000 -u default -p default --show-databases --show-tables --dump
  run_case clickhouse clickhouse_http_auth 0 clickhouse -t 127.0.0.1 --http --port 18123 -u default -p default --show-databases --show-tables --dump
  run_case clickhouse clickhouse_multi_ports 0 clickhouse -t 127.0.0.1 --ports "9000,29001,29002,29003,29004" --show-databases
  run_text_case clickhouse clickhouse_debug_smoke 0 clickhouse -t 127.0.0.1 --debug
  if is_extended_matrix; then
    run_case clickhouse clickhouse_extended_defcreds 0 clickhouse -t 127.0.0.1 --port 9000 --defcreds --show-databases
    run_case clickhouse clickhouse_extended_query_columns 0 clickhouse -t 127.0.0.1 --port 19000 -u default -p default --database secure --show-databases 5 --show-tables 5 --table secure.secrets_inventory --show-columns 5 --column owner,value_hint --dump 5 --sql-cmd "select secret_name, owner from secure.secrets_inventory limit 2"
    run_case clickhouse clickhouse_extended_execute 0 clickhouse -t 127.0.0.1 --port 19000 -u default -p default --execute "id"
    run_case clickhouse fuzz_clickhouse_negative_timeout 2 clickhouse -t 127.0.0.1 --timeout -1 --show-databases
    run_case clickhouse fuzz_clickhouse_invalid_port 2 clickhouse -t 127.0.0.1 --port -1 --show-databases
  fi
}

run_redis_cases() {
  run_case redis redis_default 0 redis -t 127.0.0.1 -u redis -p redis --show-keys --dump
  run_case redis redis_multi_ports 0 redis -t 127.0.0.1 -u redis -p redis --ports "6379,26380,26381,26382,26383" --show-keys
  run_text_case redis redis_debug_smoke 0 redis -t 127.0.0.1 -u redis -p redis --debug
  if is_extended_matrix; then
    run_case redis redis_extended_key_dump_count 0 redis -t 127.0.0.1 --port 6379 -u redis -p redis --key offlineStocks:city_4949:552400 --show-keys 5 --dump 3 --dump-batch 2 --dump-delay 0
    run_case redis redis_extended_defcreds 0 redis -t 127.0.0.1 --port 6379 --defcreds --show-keys 3
    # Force-paged dump (batch=1 -> one page per key). Exercises the SCAN-cursor streaming
    # loop end-to-end on a seeded keyspace and verifies that all keys still surface.
    run_case redis redis_extended_paged_dump 0 redis -t 127.0.0.1 --port 6379 -u redis -p redis --dump --dump-batch 1 --dump-delay 0
    # P4-D idempotency twin of redis_default. Must produce identical normalized output.
    run_case redis redis_idempotency 0 redis -t 127.0.0.1 -u redis -p redis --show-keys --dump
    # P4-C mutate-config: same case with different --show-keys values. Each must produce
    # exactly its N entries (or fewer when keyspace is smaller).
    run_case redis redis_mutate_show_keys_3 0 redis -t 127.0.0.1 -u redis -p redis --show-keys 3
    run_case redis redis_mutate_show_keys_100 0 redis -t 127.0.0.1 -u redis -p redis --show-keys 100
    # P4-E fuzz cases. CLI must reject these with exit=2 without crashing.
    run_case redis fuzz_redis_invalid_port_negative 2 redis -t 127.0.0.1 --port -1 --show-keys
    run_case redis fuzz_redis_invalid_port_huge 2 redis -t 127.0.0.1 --port 99999 --show-keys
    run_case redis fuzz_redis_zero_dump 2 redis -t 127.0.0.1 --dump 0
    run_case redis fuzz_redis_negative_show_keys 2 redis -t 127.0.0.1 --show-keys -1
    run_case redis fuzz_redis_invalid_dump_batch 2 redis -t 127.0.0.1 -u redis -p redis --dump --dump-batch -3
    run_case redis fuzz_redis_negative_dump_delay 2 redis -t 127.0.0.1 -u redis -p redis --dump --dump-delay -1
  fi
}

run_etcd_cases() {
  run_case etcd etcd_open 0 etcd -t 127.0.0.1 --port 2379 --show-keys --dump
  run_case etcd etcd_auth 0 etcd -t 127.0.0.1 --port 22379 --show-keys --dump
  run_case etcd etcd_url_http 0 etcd -t "http://127.0.0.1:2379/v2/keys?recursive=true" --show-keys --dump
  run_case etcd etcd_url_https_reject 2 etcd -t "https://127.0.0.1:2379/v2/keys?recursive=true" --show-keys
  run_case etcd etcd_multi_instance_urls 0 etcd -t "http://127.0.0.1:2379/v2/keys,http://127.0.0.1:23790/v2/keys,http://127.0.0.1:23791/v2/keys,http://127.0.0.1:23792/v2/keys,http://127.0.0.1:23793/v2/keys" --show-keys
  run_text_case etcd etcd_debug_smoke 0 etcd -t 127.0.0.1 --port 2379 --debug
  if is_extended_matrix; then
    run_case etcd etcd_extended_key_dump_count 0 etcd -t 127.0.0.1 --port 2379 --key /offlineStocks:city_4949:552400 --show-keys 5 --dump 3 --dump-batch 2 --dump-delay 0
    run_case etcd etcd_extended_ports_flag 0 etcd -t 127.0.0.1 --ports 2379 --show-keys 3
    # Force multi-page continuation (batch=2 -> ~6 pages for 11 seeded keys). Exercises
    # the `last_key + \0` continuation cursor and guarantees the full keyspace is dumped.
    run_case etcd etcd_extended_paged_dump 0 etcd -t 127.0.0.1 --port 2379 --dump --dump-batch 2 --dump-delay 0
    # P4-D idempotency twin of etcd_open.
    run_case etcd etcd_idempotency 0 etcd -t 127.0.0.1 --port 2379 --show-keys --dump
    # P4-E fuzz: garbage target URL must be rejected at parse.
    run_case etcd fuzz_etcd_garbage_target 2 etcd -t "not_a_real_url://[invalid]"
    run_case etcd fuzz_etcd_invalid_dump_batch 2 etcd -t 127.0.0.1 --port 2379 --dump --dump-batch -2
    run_case etcd fuzz_etcd_negative_show_keys 2 etcd -t 127.0.0.1 --port 2379 --show-keys -1
  fi
}

run_qdrant_cases() {
  run_case qdrant qdrant_default 0 qdrant -t 127.0.0.1 --collections --dump
  run_case qdrant qdrant_url_http 0 qdrant -t "http://127.0.0.1:6333/collections?from=matrix" --collections --dump
  run_case qdrant qdrant_url_https_reject 2 qdrant -t "https://127.0.0.1:6333/collections" --collections
  run_case qdrant qdrant_multi_instance_urls 0 qdrant -t "http://127.0.0.1:6333/collections,http://127.0.0.1:26333/collections,http://127.0.0.1:26334/collections,http://127.0.0.1:26335/collections,http://127.0.0.1:26336/collections" --collections --dump
  run_text_case qdrant qdrant_debug_smoke 0 qdrant -t 127.0.0.1 --collections --debug
  if is_extended_matrix; then
    run_case qdrant qdrant_extended_collection_dump_count 0 qdrant -t 127.0.0.1 --port 6333 --api-key matrix-key --collection demo_vectors --collections --dump 3
    run_case qdrant qdrant_extended_ports_flag 0 qdrant -t 127.0.0.1 --ports 6333 --collections
    run_case qdrant qdrant_extended_ssrf_probe 0 qdrant -t 127.0.0.1 --port 6333 --collection demo_vectors --listen --ssrf-target http://127.0.0.1:19115/probe --ssrf-port 19115 --ssrf-path /probe?module=http_2xx
    run_case qdrant fuzz_qdrant_zero_timeout 2 qdrant -t 127.0.0.1 --timeout 0 --collections
    run_case qdrant fuzz_qdrant_invalid_port 2 qdrant -t 127.0.0.1 --port -1 --collections
  fi
}

run_elastic_cases() {
  run_case elastic elastic_open 0 elastic -t 127.0.0.1 --port 19200 --endpoints --cluster --discover
  run_case elastic elastic_auth 0 elastic -t 127.0.0.1 --port 19201 -u elastic -p changeme --endpoints --cluster --user --discover
  run_case elastic elastic_url_hint_https 0 elastic -t "http://127.0.0.1:19201/" -u elastic -p changeme --endpoints
  run_case elastic elastic_plugins_edge 0 elastic -t 127.0.0.1 --port 19201 -u elastic -p changeme --plugins
  run_case elastic elastic_multi_instance_urls 0 elastic -t "http://127.0.0.1:19200/,http://127.0.0.1:19202/,http://127.0.0.1:19203/,http://127.0.0.1:19204/,http://127.0.0.1:19205/" --endpoints
  run_text_case elastic elastic_debug_smoke 0 elastic -t 127.0.0.1 --port 19200 --debug
  if is_extended_matrix; then
    run_case elastic elastic_extended_ports_defcreds 0 elastic -t 127.0.0.1 --ports 19201 --defcreds --endpoints
    run_case elastic elastic_extended_all_actions 0 elastic -t 127.0.0.1 --port 19201 -u elastic -p changeme --endpoints --cluster --user --plugins --discover
    run_case elastic elastic_extended_apitoken_invalid 0 elastic -t 127.0.0.1 --port 19201 --apitoken invalid-token --endpoints
    run_case elastic fuzz_elastic_negative_retries 2 elastic -t 127.0.0.1 --retries -3 --endpoints
    run_case elastic fuzz_elastic_invalid_port 2 elastic -t 127.0.0.1 --port abc --endpoints
  fi
}

run_grpc_cases() {
  run_case grpc grpc_open 0 grpc -t 127.0.0.1 --port 50051
  run_case grpc grpc_auth_token 0 grpc -t 127.0.0.1 --port 50061 --token "grpc-lab-token-2026"
  run_case grpc grpc_auth_defcreds 0 grpc -t 127.0.0.1 --port 50061 --defcreds
  run_case grpc grpc_multi_ports 0 grpc -t 127.0.0.1 --ports "50051,25052,25053,25054,25055"
  run_text_case grpc grpc_debug_smoke 0 grpc -t 127.0.0.1 --port 50051 --debug
  local grpc_protoset="${OUT_DIR}/grpc_health.protoset"
  "${PYTHON_BIN}" -c 'import sys; from google.protobuf import descriptor_pb2; from redposture_core.proto import grpc_health_pb2; ds=descriptor_pb2.FileDescriptorSet(); fd=ds.file.add(); fd.ParseFromString(grpc_health_pb2.DESCRIPTOR.serialized_pb); open(sys.argv[1], "wb").write(ds.SerializeToString())' "${grpc_protoset}"
  run_case grpc grpc_invoke_health 0 grpc -t 127.0.0.1 --port 50051 --invoke /grpc.health.v1.Health/Check --data '{"service":""}'
  run_case grpc grpc_proto_invoke 0 grpc -t 127.0.0.1 --port 50051 --proto redposture_core/proto/grpc_health.proto --proto-path redposture_core/proto --invoke /grpc.health.v1.Health/Check --data '{"service":""}'
  run_case grpc grpc_protoset_invoke 0 grpc -t 127.0.0.1 --port 50051 --protoset "${grpc_protoset}" --invoke /grpc.health.v1.Health/Check --data '{"service":""}'
  run_case grpc grpc_openapi_export 0 grpc -t 127.0.0.1 --port 50051 --openapi "${OUT_DIR}/json/grpc_openapi.json"
  run_case grpc grpc_web_detect 0 grpc -t 127.0.0.1 --port 50071
  if is_extended_matrix; then
    run_case grpc grpc_extended_metadata_invoke 0 grpc -t 127.0.0.1 --port 50051 --meta "x-redposture-matrix: extended" --invoke /grpc.health.v1.Health/Check --data '{"service":""}'
    run_case grpc grpc_extended_basic_empty_password 0 grpc -t 127.0.0.1 --port 50061 -u grpcuser -p "" --invoke /grpc.health.v1.Health/Check --data '{"service":""}'
    run_case grpc fuzz_grpc_invalid_port 2 grpc -t 127.0.0.1 --port -1 --invoke /grpc.health.v1.Health/Check
    run_case grpc fuzz_grpc_zero_workers 2 grpc -t 127.0.0.1 --workers 0
  fi
}

run_kafka_cases() {
  run_case kafka kafka_open 0 kafka -t 127.0.0.1 --port 9092 --show-topics --dump --max-messages 50
  run_case kafka kafka_auth 0 kafka -t 127.0.0.1 --port 29092 -u metrics -p metricspass --show-topics --dump --max-messages 50
  run_case kafka kafka_multi_ports 0 kafka -t 127.0.0.1 --ports "9092,39092,39093,39094,39095" --show-topics --dump --max-messages 10
  run_text_case kafka kafka_debug_smoke 0 kafka -t 127.0.0.1 --port 9092 --debug
  if is_extended_matrix; then
    run_case kafka kafka_extended_topic_dump_count 0 kafka -t 127.0.0.1 --port 9092 --topic orders --show-topics --dump 3
    run_case kafka kafka_extended_dump_max_conflict 2 kafka -t 127.0.0.1 --port 9092 --dump 3 --max-messages 4
    run_case kafka kafka_extended_defcreds 0 kafka -t 127.0.0.1 --port 9092 --defcreds --show-topics
    run_case kafka kafka_extended_empty_password 0 kafka -t 127.0.0.1 --port 29092 -u metrics -p "" --show-topics
    # P4-D idempotency twin of kafka_open (must match base CLI exactly).
    run_case kafka kafka_idempotency 0 kafka -t 127.0.0.1 --port 9092 --show-topics --dump --max-messages 50
    # P4-E fuzz: negative workers must be rejected at parse.
    run_case kafka fuzz_kafka_negative_workers 2 kafka -t 127.0.0.1 --workers -5 --show-topics
    run_case kafka fuzz_kafka_zero_max_messages 2 kafka -t 127.0.0.1 --max-messages 0 --show-topics
    run_case kafka fuzz_kafka_invalid_port 2 kafka -t 127.0.0.1 --port abc --show-topics
  fi
}

run_zookeeper_cases() {
  run_case zookeeper zookeeper_default 0 zookeeper -t 127.0.0.1 --show-znodes --dump
  run_case zookeeper zookeeper_multi_ports 0 zookeeper -t 127.0.0.1 --ports "2181,22181,22182,22183,22184" --show-znodes --dump
  run_text_case zookeeper zookeeper_debug_smoke 0 zookeeper -t 127.0.0.1 --debug
  if is_extended_matrix; then
    run_case zookeeper zookeeper_extended_znode_limits 0 zookeeper -t 127.0.0.1 --port 2181 --znode /redposture/app/api_key --show-znodes 5 --dump 3 --max-znodes 10 --enum-workers 2
    run_case zookeeper zookeeper_extended_empty_password 0 zookeeper -t 127.0.0.1 --port 2181 -u zkuser -p "" --show-znodes 1
    run_case zookeeper fuzz_zookeeper_invalid_port 2 zookeeper -t 127.0.0.1 --port abc --show-znodes
    run_case zookeeper fuzz_zookeeper_zero_workers 2 zookeeper -t 127.0.0.1 --workers 0 --show-znodes
  fi
}

run_proxmox_cases() {
  run_case proxmox proxmox_audit 0 proxmox -t 127.0.0.1 --port 18006 --insecure --pveapitoken "audit@pve!redposture=pve-redposture-token-2026" --nodes --users
  run_case proxmox proxmox_admin 0 proxmox -t 127.0.0.1 --port 18006 --insecure --pveapitoken "admin@pve!root=pve-redposture-admin-2026" --discover-creds --nodes --users
  run_case proxmox proxmox_url_override_https 0 proxmox -t "https://127.0.0.1:18006/api2/json/access/ticket" --no-https --insecure --pveapitoken "audit@pve!redposture=pve-redposture-token-2026" --nodes
  run_case proxmox proxmox_multi_instance_urls 0 proxmox -t "https://127.0.0.1:18006/api2/json/access/ticket,https://127.0.0.1:18061/api2/json/access/ticket,https://127.0.0.1:18062/api2/json/access/ticket,https://127.0.0.1:18063/api2/json/access/ticket,https://127.0.0.1:18064/api2/json/access/ticket" --insecure --pveapitoken "audit@pve!redposture=pve-redposture-token-2026" --nodes
  run_text_case proxmox proxmox_debug_smoke 0 proxmox -t 127.0.0.1 --port 18006 --insecure --pveapitoken "audit@pve!redposture=pve-redposture-token-2026" --debug
  if is_extended_matrix; then
    run_case proxmox proxmox_extended_ports_flag 0 proxmox -t 127.0.0.1 --ports 18006 --insecure --pveapitoken "audit@pve!redposture=pve-redposture-token-2026" --nodes
    run_case proxmox proxmox_extended_defcreds 0 proxmox -t 127.0.0.1 --port 18006 --insecure --defcreds --nodes
    run_case proxmox proxmox_extended_defcreds_empty_password 0 proxmox -t 127.0.0.1 --port 18006 --insecure --no-https -u root@pam -p "" --nodes --users
    run_case proxmox proxmox_extended_add_user_mock 0 proxmox -t 127.0.0.1 --port 18006 --insecure --pveapitoken "admin@pve!root=pve-redposture-admin-2026" --add-user rp-matrix@pve --users
    run_case proxmox fuzz_proxmox_negative_workers 2 proxmox -t 127.0.0.1 --workers -1 --insecure --pveapitoken "audit@pve!redposture=pve-redposture-token-2026" --nodes
    run_case proxmox fuzz_proxmox_invalid_port 2 proxmox -t 127.0.0.1 --port -1 --insecure --pveapitoken "audit@pve!redposture=pve-redposture-token-2026" --nodes
  fi
}

run_proxy_isolated_cases() {
  run_case exporters proxy_exporters_socks4a 0 exporters scan -t proxy-node-exporter -p 9100 --proxy socks4a://127.0.0.1:11080
  run_case exporters proxy_exporters_socks5h 0 exporters scan -t proxy-node-exporter -p 9100 --proxy socks5h://127.0.0.1:11081
  run_case exporters proxy_exporters_http 0 exporters scan -t proxy-node-exporter -p 9100 --proxy http://127.0.0.1:18080
  SSL_CERT_FILE="${LAB_DIR}/services/proxy-isolated/certs/proxy-ca.pem" \
    run_case exporters proxy_exporters_https 0 exporters scan -t proxy-node-exporter -p 9100 --proxy https://127.0.0.1:18443
  run_case redis proxy_redis_socks4a 0 redis -t proxy-redis --port 6379 --proxy socks4a://127.0.0.1:11080 --show-keys 3
  run_case redis proxy_redis_socks5h 0 redis -t proxy-redis --port 6379 --proxy socks5h://127.0.0.1:11081 --show-keys 3
  run_case redis proxy_redis_http 0 redis -t proxy-redis --port 6379 --proxy http://127.0.0.1:18080 --show-keys 3
  SSL_CERT_FILE="${LAB_DIR}/services/proxy-isolated/certs/proxy-ca.pem" \
    run_case redis proxy_redis_https 0 redis -t proxy-redis --port 6379 --proxy https://127.0.0.1:18443 --show-keys 3
}

run_service_block() {
  local service="$1"
  local fn="$2"
  start_service "${service}"
  "${fn}"
  stop_service "${service}"
}

set -e
printf "module\tlabel\texpected_exit\texit_code\tjson_path\tlog_path\n" > "${STATUS_FILE}"

if is_extended_matrix; then
  run_negative_cli_cases
fi

run_service_block exporters run_exporters_cases
run_service_block registry run_registry_cases
run_service_block grafana run_grafana_cases
run_service_block gitlab run_gitlab_cases
run_service_block consul run_consul_cases
run_service_block kubeapi run_kubeapi_cases
run_service_block postgres run_postgres_cases
run_service_block mongodb run_mongodb_cases
run_service_block oracle run_oracle_cases
run_service_block docker run_docker_cases
run_service_block clickhouse run_clickhouse_cases
run_service_block redis run_redis_cases
run_service_block etcd run_etcd_cases
run_service_block qdrant run_qdrant_cases
run_service_block elastic run_elastic_cases
run_service_block grpc run_grpc_cases
run_service_block kafka run_kafka_cases
run_service_block zookeeper run_zookeeper_cases
run_service_block proxmox run_proxmox_cases
if is_extended_matrix; then
  run_service_block proxy-isolated run_proxy_isolated_cases
fi

"${PYTHON_BIN}" "${VERIFY_SCRIPT}" --status-file "${STATUS_FILE}" --out-dir "${OUT_DIR}" --profile "${MATRIX_PROFILE}"
if is_extended_matrix; then
  "${PYTHON_BIN}" "${ROOT_DIR}/scripts/matrix_flag_coverage.py" \
    --matrix-script "${ROOT_DIR}/scripts/run_lab_matrix_sequential.sh" \
    --status-file "${STATUS_FILE}" \
    --out "${OUT_DIR}/postrun_checks/flag-coverage.json"
fi

echo
echo "Sequential matrix complete (${MATRIX_PROFILE})."
echo "OUT_DIR=${OUT_DIR}"
