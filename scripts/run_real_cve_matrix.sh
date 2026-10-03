#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="$ROOT_DIR/tests/fixtures/cve_version_matrix/docker-compose.yml"
PROJECT="${REDPOSTURE_QA_PROJECT_PREFIX:-redpostureqa$$}-cve-matrix"
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
if [[ -n "$(docker ps -aq --filter "label=com.docker.compose.project=$PROJECT")" ]] ||
   [[ -n "$(docker volume ls -q --filter "label=com.docker.compose.project=$PROJECT")" ]]; then
  echo "[error] Compose project already exists: $PROJECT" >&2
  exit 2
fi
trap cleanup EXIT

for image in $(docker compose --project-name "$PROJECT" --file "$COMPOSE_FILE" config --images | sort -u); do
  if docker image inspect "$image" >/dev/null 2>&1; then
    continue
  fi
  pulled=0
  for attempt in 1 2 3; do
    echo "[pull] ${image} (attempt ${attempt}/3)"
    if docker pull --quiet "$image"; then
      pulled=1
      break
    fi
    sleep $((attempt * 5))
  done
  if [ "$pulled" -ne 1 ]; then
    echo "[error] could not pull ${image} after three attempts" >&2
    exit 1
  fi
done

docker compose --project-name "$PROJECT" --file "$COMPOSE_FILE" up --detach --wait --wait-timeout 240
"$PYTHON_BIN" "$ROOT_DIR/scripts/verify_real_cve_matrix.py"
