#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"

APP_NAME="${APP_NAME:-nmaper}"
BIN_DIR="${BIN_DIR:-${HOME}/.local/bin}"
BUILD_DIR="${BUILD_DIR:-${REPO_ROOT}/.build}"

INSTALLED_TARGET="${BIN_DIR}/${APP_NAME}"
BUILD_TARGET="${BUILD_DIR}/${APP_NAME}"

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
