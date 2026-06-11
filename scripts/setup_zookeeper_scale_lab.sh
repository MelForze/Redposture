#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LAB_DIR="${REDPOSTURE_LAB_DIR:-${ROOT_DIR}/lab}"
COMPOSE_FILE="${LAB_DIR}/services/zookeeper-scale/docker-compose.yml"
PROJECT_NAME="${ZK_SCALE_PROJECT:-redposture-zk-scale}"
ZK_SCALE_PORT="${ZK_SCALE_PORT:-32181}"
CHUNK_SIZE="${ZK_SCALE_CHUNK_SIZE:-5000}"
RESET_VOLUME=1

usage() {
  cat <<'EOF'
Usage:
  scripts/setup_zookeeper_scale_lab.sh <100k|500k|1000k> [--keep-data]

Examples:
  scripts/setup_zookeeper_scale_lab.sh 100k
  scripts/setup_zookeeper_scale_lab.sh 500k
  scripts/setup_zookeeper_scale_lab.sh 1000k
  ZK_SCALE_PORT=42181 scripts/setup_zookeeper_scale_lab.sh 1000k

Env:
  ZK_SCALE_PORT         Host port for ZooKeeper (default: 32181)
  ZK_SCALE_PROJECT      Docker compose project name (default: redposture-zk-scale)
  ZK_SCALE_CHUNK_SIZE   Nodes per seed batch (default: 5000)
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" || $# -lt 1 ]]; then
  usage
  exit 0
fi

PROFILE="${1:-}"
shift || true

case "${PROFILE}" in
  100k) ZNODE_COUNT=100000 ;;
  500k) ZNODE_COUNT=500000 ;;
  1000k|1m|1000000) ZNODE_COUNT=1000000 ;;
  *)
    echo "[error] unsupported profile: ${PROFILE}" >&2
    usage
    exit 2
    ;;
esac

while (($#)); do
  case "$1" in
    --keep-data)
      RESET_VOLUME=0
      ;;
    *)
      echo "[error] unknown option: $1" >&2
      usage
      exit 2
      ;;
  esac
  shift
done

if ! [[ "${CHUNK_SIZE}" =~ ^[0-9]+$ ]] || [[ "${CHUNK_SIZE}" -le 0 ]]; then
  echo "[error] ZK_SCALE_CHUNK_SIZE must be a positive integer" >&2
  exit 2
fi

compose() {
  ZK_SCALE_PORT="${ZK_SCALE_PORT}" docker compose -p "${PROJECT_NAME}" -f "${COMPOSE_FILE}" "$@"
}

if ! command -v docker >/dev/null 2>&1; then
  echo "[error] docker is required" >&2
  exit 2
fi

if [[ ! -f "${COMPOSE_FILE}" ]]; then
  echo "[error] local zookeeper-scale compose not found: ${COMPOSE_FILE}" >&2
  echo "[error] set REDPOSTURE_LAB_DIR to your local lab directory" >&2
  exit 2
fi

if [[ "${RESET_VOLUME}" -eq 1 ]]; then
  echo "[*] resetting previous zookeeper-scale data volume (project=${PROJECT_NAME})"
  compose down -v --remove-orphans >/dev/null 2>&1 || true
fi

echo "[*] starting zookeeper-scale on 127.0.0.1:${ZK_SCALE_PORT}"
compose up -d --wait

CONTAINER_ID="$(compose ps -q zookeeper-scale | tr -d '[:space:]')"
if [[ -z "${CONTAINER_ID}" ]]; then
  echo "[error] zookeeper-scale container is not running" >&2
  exit 1
fi

SEED_PATH="/redposture/scale_${ZNODE_COUNT}"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

run_zkcli_script() {
  local src_file="$1"
  local remote_file="$2"
  docker cp "${src_file}" "${CONTAINER_ID}:${remote_file}" >/dev/null
  docker exec "${CONTAINER_ID}" bash -lc '
    set -euo pipefail
    if command -v zkCli.sh >/dev/null 2>&1; then
      ZKCLI="zkCli.sh"
    else
      ZKCLI="$(echo /apache-zookeeper-*/bin/zkCli.sh)"
    fi
    "$ZKCLI" -server 127.0.0.1:2181 < "'"${remote_file}"'" >/tmp/rp_zk_seed.log 2>&1 || true
  '
}

echo "[*] preparing seed namespace: ${SEED_PATH}"
INIT_FILE="${TMP_DIR}/init.zk"
cat >"${INIT_FILE}" <<EOF
create /redposture "env=lab"
create ${SEED_PATH} "dataset=zookeeper-scale,count=${ZNODE_COUNT}"
set ${SEED_PATH} "dataset=zookeeper-scale,count=${ZNODE_COUNT}"
quit
EOF
run_zkcli_script "${INIT_FILE}" "/tmp/rp_zk_init.zk"

echo "[*] seeding ${ZNODE_COUNT} znodes (chunk_size=${CHUNK_SIZE})"
START_TS="$(date +%s)"
created_total=0
chunk_idx=0

for ((start = 1; start <= ZNODE_COUNT; start += CHUNK_SIZE)); do
  end=$((start + CHUNK_SIZE - 1))
  if ((end > ZNODE_COUNT)); then
    end="${ZNODE_COUNT}"
  fi
  chunk_idx=$((chunk_idx + 1))
  chunk_file="${TMP_DIR}/seed_${chunk_idx}.zk"
  : >"${chunk_file}"
  for ((i = start; i <= end; i++)); do
    printf 'create %s/item_%07d "index=%d,owner=seed,profile=%s"\n' "${SEED_PATH}" "${i}" "${i}" "${PROFILE}" >>"${chunk_file}"
  done
  echo "quit" >>"${chunk_file}"
  run_zkcli_script "${chunk_file}" "/tmp/rp_zk_seed_chunk.zk"
  created_total="${end}"
  now_ts="$(date +%s)"
  elapsed=$((now_ts - START_TS))
  echo "[*] chunk=${chunk_idx} seeded=${created_total}/${ZNODE_COUNT} elapsed=${elapsed}s"
done

LAST_NODE="$(printf '%s/item_%07d' "${SEED_PATH}" "${ZNODE_COUNT}")"
VERIFY_FILE="${TMP_DIR}/verify.zk"
cat >"${VERIFY_FILE}" <<EOF
get ${LAST_NODE}
quit
EOF
run_zkcli_script "${VERIFY_FILE}" "/tmp/rp_zk_verify.zk"

TOTAL_TS="$(date +%s)"
echo
echo "[+] zookeeper-scale is ready"
echo "    profile:        ${PROFILE}"
echo "    target_count:   ${ZNODE_COUNT}"
echo "    host:           127.0.0.1"
echo "    port:           ${ZK_SCALE_PORT}"
echo "    seed_path:      ${SEED_PATH}"
echo "    elapsed:        $((TOTAL_TS - START_TS))s"
echo
echo "Smoke:"
echo "  python3 redposture.py zookeeper -t 127.0.0.1 --port ${ZK_SCALE_PORT}"
echo "  python3 redposture.py zookeeper -t 127.0.0.1 --port ${ZK_SCALE_PORT} --show-znodes"
