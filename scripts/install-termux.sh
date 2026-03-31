#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"

if [[ -z "${PREFIX:-}" ]]; then
	echo "This installer is intended for Termux and expects \$PREFIX to be set."
	echo "Run it from a Termux shell."
	exit 1
fi

if ! command -v pkg >/dev/null 2>&1; then
	echo "Termux package manager 'pkg' was not found."
	echo "Run this script from a Termux environment."
	exit 1
fi

APP_NAME="${APP_NAME:-nmaper}"
TERMUX_BIN_DIR="${TERMUX_BIN_DIR:-${PREFIX}/bin}"
TERMUX_LIBEXEC_DIR="${TERMUX_LIBEXEC_DIR:-${PREFIX}/lib/${APP_NAME}}"
TERMUX_DATA_DIR="${TERMUX_DATA_DIR:-${HOME}/.local/share/${APP_NAME}}"
TERMUX_DB_PATH="${TERMUX_DB_PATH:-${TERMUX_DATA_DIR}/${APP_NAME}.db}"
TERMUX_XML_DIR="${TERMUX_XML_DIR:-${TERMUX_DATA_DIR}/scans}"
TERMUX_GOCACHE="${TERMUX_GOCACHE:-${HOME}/.cache/go-build/${APP_NAME}}"

mkdir -p "${TERMUX_BIN_DIR}" "${TERMUX_LIBEXEC_DIR}" "${TERMUX_DATA_DIR}" "${TERMUX_XML_DIR}" "${TERMUX_GOCACHE}"

echo "Installing Termux dependencies..."
pkg install -y golang nmap

echo "Installing ${APP_NAME} for Termux..."
(
	cd "${REPO_ROOT}"
	BIN_DIR="${TERMUX_BIN_DIR}" \
	LIBEXEC_DIR="${TERMUX_LIBEXEC_DIR}" \
	DATA_DIR="${TERMUX_DATA_DIR}" \
	DB_PATH="${TERMUX_DB_PATH}" \
	XML_DIR="${TERMUX_XML_DIR}" \
	GOCACHE="${TERMUX_GOCACHE}" \
	./scripts/install.sh
)

echo
echo "Termux install complete."
echo "Command: ${TERMUX_BIN_DIR}/${APP_NAME}"
echo "Database: ${TERMUX_DB_PATH}"
echo "XML artifacts: ${TERMUX_XML_DIR}"
