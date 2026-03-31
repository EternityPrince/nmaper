#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"

APP_NAME="${APP_NAME:-nmaper}"
GO_CMD="${GO_CMD:-go}"
BIN_DIR="${BIN_DIR:-${HOME}/.local/bin}"
BUILD_DIR="${BUILD_DIR:-${REPO_ROOT}/.build}"
BUILD_TARGET="${BUILD_DIR}/${APP_NAME}"
LIBEXEC_DIR="${LIBEXEC_DIR:-${HOME}/.local/lib/${APP_NAME}}"
LIBEXEC_TARGET="${LIBEXEC_DIR}/${APP_NAME}"
DATA_DIR="${DATA_DIR:-${XDG_DATA_HOME:-${HOME}/.local/share}/${APP_NAME}}"
DB_PATH="${DB_PATH:-${DATA_DIR}/${APP_NAME}.db}"
XML_DIR="${XML_DIR:-${DATA_DIR}/scans}"

mkdir -p "${BUILD_DIR}" "${BIN_DIR}" "${LIBEXEC_DIR}" "${DATA_DIR}" "${XML_DIR}"
export GOCACHE="${GOCACHE:-/tmp/nmaper-gocache}"

echo "Building ${APP_NAME}..."
(
	cd "${REPO_ROOT}"
	"${GO_CMD}" build -o "${BUILD_TARGET}" ./cmd/nmaper
)

cp "${BUILD_TARGET}" "${LIBEXEC_TARGET}"
chmod 755 "${LIBEXEC_TARGET}"

if [[ ! -e "${DB_PATH}" ]]; then
	LEGACY_DB="${REPO_ROOT}/${APP_NAME}.db"
	if [[ -f "${LEGACY_DB}" ]]; then
		cp "${LEGACY_DB}" "${DB_PATH}"
		echo "Migrated database from ${LEGACY_DB} to ${DB_PATH}"
	else
		: > "${DB_PATH}"
	fi
fi

cat > "${BIN_DIR}/${APP_NAME}" <<EOF
#!/usr/bin/env bash
set -euo pipefail

DATA_DIR="${DATA_DIR}"
DB_PATH="${DB_PATH}"
XML_DIR="${XML_DIR}"
REAL_BIN="${LIBEXEC_TARGET}"

mkdir -p "\${DATA_DIR}" "\${XML_DIR}"
if [[ ! -e "\${DB_PATH}" ]]; then
	: > "\${DB_PATH}"
fi

exec "\${REAL_BIN}" --db "\${DB_PATH}" -o "\${XML_DIR}" "\$@"
EOF
chmod 755 "${BIN_DIR}/${APP_NAME}"

echo "Installed ${APP_NAME} to ${BIN_DIR}/${APP_NAME}"
echo "Binary payload: ${LIBEXEC_TARGET}"
echo "Data directory: ${DATA_DIR}"
echo "Database path: ${DB_PATH}"
echo "XML artifact directory: ${XML_DIR}"

if [[ ":${PATH}:" != *":${BIN_DIR}:"* ]]; then
	echo "Add ${BIN_DIR} to PATH to run '${APP_NAME}' from any shell."
	echo "Example for zsh: export PATH=\"${BIN_DIR}:\$PATH\""
fi

if command -v "${APP_NAME}" >/dev/null 2>&1; then
	echo "Command available at: $(command -v "${APP_NAME}")"
else
	echo "Open a new shell or reload your profile, then run: ${APP_NAME} --help"
fi
