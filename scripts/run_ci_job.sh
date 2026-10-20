#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  echo "Usage: scripts/run_ci_job.sh <lint|test>" >&2
}

case "${1:-}" in
  lint)
    echo "== lint: Ruff checks =="
    ruff check .
    echo "== lint: Ruff format =="
    ruff format --check .
    echo "== lint: mypy =="
    mypy
    echo "== lint: CLI smoke =="
    python redposture.py --help >/dev/null
    ;;
  test)
    python_tag="$(python -c 'import sys; print(f"py{sys.version_info.major}{sys.version_info.minor}")')"
    coverage_dir="${REDPOSTURE_COVERAGE_DIR:-$ROOT_DIR/.ci-venvs/coverage/$python_tag}"
    mkdir -p "$coverage_dir"
    export COVERAGE_FILE="$coverage_dir/.coverage"
    coverage_json="$coverage_dir/coverage.json"

    echo "== ${python_tag}: compile =="
    python -m coverage erase
    python -m py_compile redposture.py
    python -m compileall -q redposture_core tests
    echo "== ${python_tag}: pytest and branch coverage =="
    # Keep the active test visible and fail with thread stacks instead of
    # leaving a CI worker blocked indefinitely on a deadlocked test.
    python -u -m pytest -vv -o faulthandler_timeout=180 -o faulthandler_exit_on_timeout=true \
      --cov=redposture_core --cov-report=term-missing --cov-report="json:$coverage_json"
    echo "== ${python_tag}: per-file coverage gate =="
    python scripts/check_coverage_per_file.py "$coverage_json" --min 70
    echo "== ${python_tag}: focused coverage gate =="
    python scripts/check_quality_coverage.py "$coverage_json"
    echo "== ${python_tag}: version smoke =="
    redposture --version
    ;;
  *)
    usage
    exit 2
    ;;
esac
