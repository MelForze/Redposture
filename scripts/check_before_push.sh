#!/usr/bin/env bash
set -uo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR" || exit 2

OUT_DIR=""
REUSE_VENVS=0
ALLOW_MISSING=0

usage() {
  cat <<'EOF'
Usage: bash scripts/check_before_push.sh [--reuse-venvs] [--allow-missing] [--out DIR]

Check the current uncommitted tree before your own commit/push. Runs
git diff --check and the same lint/test jobs as GitHub CI on Python 3.12–3.14.
Logs and a short report are saved under .redposture/qa/ by default.

  --reuse-venvs   Reuse installed .ci-venvs (faster; dependencies are not refreshed).
  --allow-missing Report a partial check if a Python version is unavailable.
  --out DIR       Choose the report directory.

Does not commit, tag, push, or start Docker QA.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --reuse-venvs) REUSE_VENVS=1; shift ;;
    --allow-missing) ALLOW_MISSING=1; shift ;;
    --out)
      if [[ $# -lt 2 || -z "$2" ]]; then
        echo "--out requires a directory" >&2
        exit 2
      fi
      OUT_DIR="$2"
      shift 2
      ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ -z "$OUT_DIR" ]]; then
  OUT_DIR="$ROOT_DIR/.redposture/qa/prepush-$(date +%Y%m%d-%H%M%S)"
fi
mkdir -p "$OUT_DIR" || exit 2
OUT_DIR="$(cd "$OUT_DIR" && pwd)"
REPORT="$OUT_DIR/report.md"

{
  echo "# Local pre-push check"
  echo
  echo "- Source: current working tree (including staged and unstaged changes)"
  echo "- Git HEAD: $(git rev-parse --short HEAD)"
  echo "- Started: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo
  echo "| Check | Exit | Seconds | Log |"
  echo "| --- | ---: | ---: | --- |"
} > "$REPORT"
git status --short > "$OUT_DIR/git-status.txt"

run_step() {
  local name="$1"
  shift
  local started result elapsed command_text
  started="$(date +%s)"
  printf -v command_text '%q ' "$@"
  printf '== %s ==\n%s\n' "$name" "$command_text"
  if "$@" > "$OUT_DIR/$name.log" 2>&1; then
    result=0
  else
    result=$?
  fi
  elapsed=$(( $(date +%s) - started ))
  printf '| %s | %s | %s | [%s.log](%s.log) |\n' "$name" "$result" "$elapsed" "$name" "$name" >> "$REPORT"
  tail -n 8 "$OUT_DIR/$name.log"
  if [[ "$result" -ne 0 ]]; then
    printf 'Stopped at %s. Report: %s\n' "$name" "$REPORT" >&2
    return "$result"
  fi
}

run_step diff-check git diff --check HEAD -- || exit $?
matrix=(bash scripts/check_ci_matrix.sh --worktree)
if [[ "$REUSE_VENVS" -eq 1 ]]; then
  matrix+=(--skip-install)
fi
if [[ "$ALLOW_MISSING" -eq 1 ]]; then
  matrix+=(--allow-missing)
fi
run_step ci-matrix "${matrix[@]}" || exit $?
printf '\nAll requested checks passed. No commit, tag, or push was created.\n' >> "$REPORT"
printf 'Report: %s\n' "$REPORT"
