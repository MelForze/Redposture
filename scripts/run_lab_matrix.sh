#!/usr/bin/env bash
# Compatibility entrypoint: keep one maintained matrix and postrun contract.
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec bash "${ROOT_DIR}/scripts/run_lab_matrix_sequential.sh" "$@"
