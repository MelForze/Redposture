#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LAB_DIR="${ROOT_DIR}/.redposture/qa/exporter-auth-profile-lab"
CONFIG_FILE="${LAB_DIR}/elasticsearch-exporter.yml"
CONTAINER_NAME="redposture-elastic-auth-profile-lab"
IMAGE="quay.io/prometheuscommunity/elasticsearch-exporter:latest"

case "${1:-}" in
  up)
    mkdir -p "${LAB_DIR}"
    cat > "${CONFIG_FILE}" <<'YAML'
auth_modules:
  basic:
    type: userpass
    userpass:
      username: lab_reader
      password: LabPass-2026!
  apikey:
    type: apikey
    apikey: bGFiLWlkOkxhYktleS0yMDI2IQ==
YAML
    docker run --rm -d --name "${CONTAINER_NAME}" \
      -p 127.0.0.1:19114:9114 \
      --mount "type=bind,source=${CONFIG_FILE},target=/auth.yml,readonly" \
      "${IMAGE}" --config.file=/auth.yml
    for _ in $(seq 1 60); do
      if curl -fsS --max-time 2 http://127.0.0.1:19114/metrics >/dev/null 2>&1; then
        printf 'Elasticsearch exporter is ready at http://127.0.0.1:19114\n'
        exit 0
      fi
      sleep 1
    done
    docker logs "${CONTAINER_NAME}" >&2 || true
    exit 1
    ;;
  down)
    docker stop "${CONTAINER_NAME}" >/dev/null
    rm -f "${CONFIG_FILE}"
    printf 'Elasticsearch exporter stopped\n'
    ;;
  *)
    printf 'Usage: %s up|down\n' "$0" >&2
    exit 2
    ;;
esac
