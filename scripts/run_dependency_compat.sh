#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROFILE="${1:-}"
if [ "${PROFILE}" != "min" ] && [ "${PROFILE}" != "max" ]; then
  echo "Usage: scripts/run_dependency_compat.sh <min|max>" >&2
  exit 2
fi

VENV_DIR="$(mktemp -d "${TMPDIR:-/tmp}/redposture-deps-${PROFILE}.XXXXXX")"
cleanup() {
  rm -rf "${VENV_DIR}"
}
trap cleanup EXIT

PYTHON_BOOTSTRAP="${PYTHON_BOOTSTRAP:-python3}"
"${PYTHON_BOOTSTRAP}" -m venv "${VENV_DIR}"
PYTHON_BIN="${VENV_DIR}/bin/python"
"${PYTHON_BIN}" -m pip install --upgrade pip

if [ "${PROFILE}" = "min" ]; then
  "${PYTHON_BIN}" -m pip install \
    'clickhouse-connect==0.8.0' \
    'clickhouse-driver==0.2.9' \
    'h2==4.1.0' \
    'grpcio-tools==1.74.0' \
    'pymongo==4.7' \
    'oracledb==2.4' \
    'protobuf==6.31.1'
  "${PYTHON_BIN}" -m pip install \
    'pytest==8.3.0' \
    'pytest-socket==0.8.1' \
    'hatchling==1.24.0' \
    'tomlkit==0.13.2'
  "${PYTHON_BIN}" -m pip install --no-deps --no-build-isolation "${ROOT_DIR}"
else
  "${PYTHON_BIN}" -m pip install --upgrade --upgrade-strategy eager "${ROOT_DIR}[dev,kafka-codecs]"
fi

cd "${ROOT_DIR}"
"${PYTHON_BIN}" -m pip check
"${PYTHON_BIN}" -m pytest -q
"${VENV_DIR}/bin/redposture" --version
