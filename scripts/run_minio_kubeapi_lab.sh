#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="$ROOT_DIR/tests/fixtures/minio_kubeapi_lab/docker-compose.yml"
PROJECT="redposture-minio-kubeapi"
PYTHON_BIN="${PYTHON:-}"
if [[ -z "$PYTHON_BIN" ]]; then
  if [[ -x "$ROOT_DIR/.venv/bin/python" ]]; then
    PYTHON_BIN="$ROOT_DIR/.venv/bin/python"
  else
    PYTHON_BIN="python3"
  fi
fi
CERTS_DIR="${TMPDIR:-/tmp}/redposture-minio-certs"
export MINIO_CERTS_DIR="$CERTS_DIR"

cleanup() {
  docker compose --project-name "$PROJECT" --file "$COMPOSE_FILE" down --volumes --remove-orphans
  rm -rf "$CERTS_DIR"
}
trap cleanup EXIT

rm -rf "$CERTS_DIR"
mkdir -p "$CERTS_DIR"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
  -keyout "$CERTS_DIR/private.key" \
  -out "$CERTS_DIR/public.crt" >/dev/null 2>&1

docker compose --project-name "$PROJECT" --file "$COMPOSE_FILE" up --detach
"$PYTHON_BIN" "$ROOT_DIR/scripts/verify_minio_kubeapi_lab.py"
