#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"

APP_NAME="${APP_NAME:-nmaper}"
BIN_DIR="${BIN_DIR:-${HOME}/.local/bin}"
BUILD_DIR="${BUILD_DIR:-${REPO_ROOT}/.build}"
LIBEXEC_DIR="${LIBEXEC_DIR:-${HOME}/.local/lib/${APP_NAME}}"
DATA_DIR="${DATA_DIR:-${XDG_DATA_HOME:-${HOME}/.local/share}/${APP_NAME}}"
PURGE_DATA="${PURGE_DATA:-0}"

INSTALLED_TARGET="${BIN_DIR}/${APP_NAME}"
BUILD_TARGET="${BUILD_DIR}/${APP_NAME}"
LIBEXEC_TARGET="${LIBEXEC_DIR}/${APP_NAME}"

if [[ -e "${INSTALLED_TARGET}" || -L "${INSTALLED_TARGET}" ]]; then
	rm -f "${INSTALLED_TARGET}"
	echo "Removed ${INSTALLED_TARGET}"
else
	echo "Installed binary not found at ${INSTALLED_TARGET}"
fi

if [[ -e "${BUILD_TARGET}" ]]; then
	rm -f "${BUILD_TARGET}"
	echo "Removed build artifact ${BUILD_TARGET}"
fi

if [[ -e "${LIBEXEC_TARGET}" ]]; then
	rm -f "${LIBEXEC_TARGET}"
	echo "Removed installed binary payload ${LIBEXEC_TARGET}"
fi

if [[ "${PURGE_DATA}" == "1" ]]; then
	rm -rf "${DATA_DIR}"
	echo "Removed application data ${DATA_DIR}"
else
	echo "Preserved application data at ${DATA_DIR}"
	echo "Set PURGE_DATA=1 to remove the database and saved XML artifacts too."
fi
