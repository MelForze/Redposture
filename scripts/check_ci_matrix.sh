#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

PYTHONS=(python3.10 python3.11 python3.12 python3.13)
VENV_ROOT="${REDPOSTURE_CI_VENV_ROOT:-$ROOT_DIR/.ci-venvs}"
ALLOW_MISSING=0
SKIP_INSTALL=0
USE_WORKTREE=0
ALLOW_DIRTY=0
TMP_ROOT=""

cleanup() {
  if [[ -n "$TMP_ROOT" && -d "$TMP_ROOT" ]]; then
    rm -rf "$TMP_ROOT"
  fi
}
trap cleanup EXIT

usage() {
  cat <<'EOF'
Usage: scripts/check_ci_matrix.sh [--allow-missing] [--skip-install] [--worktree] [--allow-dirty]

Runs the local pre-push CI gate:
  - install exact locked project + dev deps into per-version venvs
  - by default, test a clean tracked HEAD archive, matching GitHub checkout
  - run the same blocking lint job as GitHub on Python 3.12
  - run the same syntax, pytest/coverage, per-file floor and CLI smoke on Python 3.10-3.13

Options:
  --allow-missing   Skip missing Python interpreters instead of failing.
  --skip-install    Reuse existing .ci-venvs without reinstalling dependencies.
  --worktree        Test the current working tree instead of clean tracked HEAD.
  --allow-dirty     Allow uncommitted changes when testing clean tracked HEAD.

Environment:
  REDPOSTURE_CI_VENV_ROOT   Override venv directory. Default: .ci-venvs
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --allow-missing)
      ALLOW_MISSING=1
      shift
      ;;
    --skip-install)
      SKIP_INSTALL=1
      shift
      ;;
    --worktree)
      USE_WORKTREE=1
      shift
      ;;
    --allow-dirty)
      ALLOW_DIRTY=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "[!] unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

mkdir -p "$VENV_ROOT"

if [[ "$USE_WORKTREE" -ne 1 ]]; then
  if [[ "$ALLOW_DIRTY" -ne 1 ]] && ! git diff --quiet HEAD --; then
    echo "[!] working tree has uncommitted changes; clean tracked HEAD would not include them" >&2
    echo "[!] commit/stash changes, or rerun with --worktree for a partial pre-commit check" >&2
    exit 2
  fi
  TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/redposture-ci-head.XXXXXX")"
  git archive HEAD | tar -xf - -C "$TMP_ROOT"
  cd "$TMP_ROOT"
  echo "== source: clean tracked HEAD archive =="
else
  echo "== source: current working tree =="
fi

declare -a AVAILABLE=()
declare -a MISSING=()

for py in "${PYTHONS[@]}"; do
  if command -v "$py" >/dev/null 2>&1; then
    AVAILABLE+=("$py")
  else
    MISSING+=("$py")
  fi
done

if [[ ${#MISSING[@]} -gt 0 && "$ALLOW_MISSING" -ne 1 ]]; then
  echo "[!] missing required Python interpreters: ${MISSING[*]}" >&2
  echo "[!] install them or rerun with --allow-missing for a partial local check" >&2
  exit 2
fi

if [[ ${#AVAILABLE[@]} -eq 0 ]]; then
  echo "[!] no Python interpreters available from: ${PYTHONS[*]}" >&2
  exit 2
fi

venv_for() {
  local py="$1"
  echo "$VENV_ROOT/${py/python/py}"
}

run_in_venv() {
  local py="$1"
  shift
  local venv
  venv="$(venv_for "$py")"
  "$venv/bin/$1" "${@:2}"
}

lock_for() {
  local py="$1"
  local minor="${py#python3.}"
  echo "$PWD/requirements/ci-py3${minor}.txt"
}

for py in "${AVAILABLE[@]}"; do
  venv="$(venv_for "$py")"
  echo "== prepare ${py} =="
  if [[ ! -x "$venv/bin/python" ]]; then
    "$py" -m venv "$venv"
  fi
  if [[ "$SKIP_INSTALL" -ne 1 ]]; then
    lock_file="$(lock_for "$py")"
    "$venv/bin/python" -m pip install --upgrade --requirement "$lock_file"
    "$venv/bin/python" -m pip install --no-deps --no-build-isolation -e .
  fi
done

QUALITY_PY=""
if command -v python3.12 >/dev/null 2>&1; then
  QUALITY_PY="python3.12"
else
  QUALITY_PY="${AVAILABLE[0]}"
fi
QUALITY_VENV="$(venv_for "$QUALITY_PY")"

echo "== lint (${QUALITY_PY}) =="
PATH="$QUALITY_VENV/bin:$PATH" bash scripts/run_ci_job.sh lint

for py in "${AVAILABLE[@]}"; do
  venv="$(venv_for "$py")"
  echo "== tests ${py} =="
  PATH="$venv/bin:$PATH" bash scripts/run_ci_job.sh test
done

if [[ ${#MISSING[@]} -gt 0 ]]; then
  echo "[!] skipped missing Python interpreters: ${MISSING[*]}" >&2
fi

echo "== local CI matrix complete =="
