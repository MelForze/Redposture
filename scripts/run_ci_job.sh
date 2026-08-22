#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  echo "Usage: scripts/run_ci_job.sh <lint|test>" >&2
}

case "${1:-}" in
  lint)
    ruff check .
    ruff format --check .
    mypy
    python redposture.py --help >/dev/null
    ;;
  test)
    python_tag="$(python -c 'import sys; print(f"py{sys.version_info.major}{sys.version_info.minor}")')"
    coverage_dir="${REDPOSTURE_COVERAGE_DIR:-$ROOT_DIR/.ci-venvs/coverage/$python_tag}"
    mkdir -p "$coverage_dir"
    export COVERAGE_FILE="$coverage_dir/.coverage"
    coverage_json="$coverage_dir/coverage.json"

    python -m coverage erase
    python -m py_compile redposture.py
    python -m compileall -q redposture_core tests
    python -m pytest -q --cov=redposture_core --cov-report=term-missing --cov-report="json:$coverage_json"
    python scripts/check_coverage_per_file.py "$coverage_json" --min 70
    redposture --version
    ;;
  *)
    usage
    exit 2
    ;;
esac
