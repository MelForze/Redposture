# Source from a QA runner after ROOT_DIR and PYTHON_BIN have been initialized.
# Keep the ledger with the run artifacts (or in an explicit temporary directory).
QA_VOLUME_LEDGER_DIR="${QA_VOLUME_LEDGER_DIR:-${OUT_DIR:-${TMPDIR:-/tmp}/redposture-volumes-${PROJECT:-$$}}/volumes}"
docker() {
  if [[ "${1:-}" == "compose" ]]; then
    "${PYTHON_BIN}" "${ROOT_DIR}/scripts/qa_owned_volumes.py" "${QA_VOLUME_LEDGER_DIR}" docker "$@"
  else
    command docker "$@"
  fi
}
