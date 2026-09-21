#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="$ROOT_DIR/tests/fixtures/cve_version_matrix/docker-compose.yml"
PROJECT="redposture-cve-matrix"
PYTHON_BIN="${PYTHON:-}"
if [[ -z "$PYTHON_BIN" ]]; then
  if [[ -x "$ROOT_DIR/.venv/bin/python" ]]; then
    PYTHON_BIN="$ROOT_DIR/.venv/bin/python"
  else
    PYTHON_BIN="python3"
  fi
fi

cleanup() {
  docker compose --project-name "$PROJECT" --file "$COMPOSE_FILE" down --volumes --remove-orphans
}
trap cleanup EXIT

docker compose --project-name "$PROJECT" --file "$COMPOSE_FILE" up --detach
"$PYTHON_BIN" "$ROOT_DIR/scripts/verify_real_cve_matrix.py"
