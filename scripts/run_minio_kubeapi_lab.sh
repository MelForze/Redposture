#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="$ROOT_DIR/tests/fixtures/minio_kubeapi_lab/docker-compose.yml"
PROJECT="${REDPOSTURE_QA_PROJECT_PREFIX:-redpostureqa$$}-minio-kubeapi"
PYTHON_BIN="${PYTHON:-}"
if [[ -z "$PYTHON_BIN" ]]; then
  if [[ -x "$ROOT_DIR/.venv/bin/python" ]]; then
    PYTHON_BIN="$ROOT_DIR/.venv/bin/python"
  else
    PYTHON_BIN="python3"
  fi
fi
CERTS_DIR="$(mktemp -d "${TMPDIR:-/tmp}/redposture-minio-certs.XXXXXX")"
export MINIO_CERTS_DIR="$CERTS_DIR"

QA_IMAGE_SNAPSHOT=""
cleanup() {
  local rc=0
  docker compose --project-name "$PROJECT" --file "$COMPOSE_FILE" down --volumes --remove-orphans || rc=$?
  if [[ -n "$QA_IMAGE_SNAPSHOT" ]]; then
    if "$PYTHON_BIN" "$ROOT_DIR/scripts/qa_owned_images.py" cleanup "$QA_IMAGE_SNAPSHOT"; then
      rm -f "$QA_IMAGE_SNAPSHOT"
    else
      rc=1
    fi
  fi
  rm -rf "$CERTS_DIR"
  return "$rc"
}
if [[ -n "$(docker ps -aq --filter "label=com.docker.compose.project=$PROJECT")" ]] ||
   [[ -n "$(docker volume ls -q --filter "label=com.docker.compose.project=$PROJECT")" ]]; then
  echo "[error] Compose project already exists: $PROJECT" >&2
  rmdir "$CERTS_DIR"
  exit 2
fi
trap cleanup EXIT
"$PYTHON_BIN" "$ROOT_DIR/scripts/prepare_minio_qa_image.py"
if [[ "${REDPOSTURE_QA_CLEAN_IMAGES:-0}" == "1" ]]; then
  QA_IMAGE_SNAPSHOT="$(mktemp "${TMPDIR:-/tmp}/redposture-minio-images.XXXXXX")"
  "$PYTHON_BIN" "$ROOT_DIR/scripts/qa_owned_images.py" snapshot "$QA_IMAGE_SNAPSHOT" -- \
    docker compose --project-name "$PROJECT" --file "$COMPOSE_FILE"
fi
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
  -keyout "$CERTS_DIR/private.key" \
  -out "$CERTS_DIR/public.crt" >/dev/null 2>&1

docker compose --project-name "$PROJECT" --file "$COMPOSE_FILE" up --detach
"$PYTHON_BIN" "$ROOT_DIR/scripts/verify_minio_kubeapi_lab.py"
