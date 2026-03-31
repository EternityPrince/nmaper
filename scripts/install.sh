#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"

APP_NAME="${APP_NAME:-nmaper}"
GO_CMD="${GO_CMD:-go}"
BIN_DIR="${BIN_DIR:-${HOME}/.local/bin}"
BUILD_DIR="${BUILD_DIR:-${REPO_ROOT}/.build}"
BUILD_TARGET="${BUILD_DIR}/${APP_NAME}"

mkdir -p "${BUILD_DIR}" "${BIN_DIR}"
export GOCACHE="${GOCACHE:-/tmp/nmaper-gocache}"

echo "Building ${APP_NAME}..."
(
	cd "${REPO_ROOT}"
	"${GO_CMD}" build -o "${BUILD_TARGET}" ./cmd/nmaper
)

cp "${BUILD_TARGET}" "${BIN_DIR}/${APP_NAME}"
chmod 755 "${BIN_DIR}/${APP_NAME}"

echo "Installed ${APP_NAME} to ${BIN_DIR}/${APP_NAME}"

if [[ ":${PATH}:" != *":${BIN_DIR}:"* ]]; then
	echo "Add ${BIN_DIR} to PATH to run '${APP_NAME}' from any shell."
	echo "Example for zsh: export PATH=\"${BIN_DIR}:\$PATH\""
fi

if command -v "${APP_NAME}" >/dev/null 2>&1; then
	echo "Command available at: $(command -v "${APP_NAME}")"
else
	echo "Open a new shell or reload your profile, then run: ${APP_NAME} --help"
fi
