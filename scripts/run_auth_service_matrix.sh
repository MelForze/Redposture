#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="$ROOT_DIR/tests/fixtures/auth_service_matrix/docker-compose.yml"
PROJECT="${REDPOSTURE_QA_PROJECT_PREFIX:-redpostureqa$$}-auth-matrix"
PYTHON_BIN="${PYTHON:-}"
if [[ -z "$PYTHON_BIN" ]]; then
  if [[ -x "$ROOT_DIR/.venv/bin/python" ]]; then
    PYTHON_BIN="$ROOT_DIR/.venv/bin/python"
  else
    PYTHON_BIN="python3"
  fi
fi

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
  return "$rc"
}
if [[ -n "$(docker ps -aq --filter "label=com.docker.compose.project=$PROJECT")" ]] ||
   [[ -n "$(docker volume ls -q --filter "label=com.docker.compose.project=$PROJECT")" ]]; then
  echo "[error] Compose project already exists: $PROJECT" >&2
  exit 2
fi
trap cleanup EXIT
if [[ "${REDPOSTURE_QA_CLEAN_IMAGES:-0}" == "1" ]]; then
  QA_IMAGE_SNAPSHOT="$(mktemp "${TMPDIR:-/tmp}/redposture-auth-images.XXXXXX")"
  "$PYTHON_BIN" "$ROOT_DIR/scripts/qa_owned_images.py" snapshot "$QA_IMAGE_SNAPSHOT" -- \
    docker compose --project-name "$PROJECT" --file "$COMPOSE_FILE"
fi

docker compose --project-name "$PROJECT" --file "$COMPOSE_FILE" up --detach
"$PYTHON_BIN" "$ROOT_DIR/scripts/verify_auth_service_matrix.py"
