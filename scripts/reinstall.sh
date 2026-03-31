#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
APP_NAME="${APP_NAME:-nmaper}"
DATA_DIR="${DATA_DIR:-${XDG_DATA_HOME:-${HOME}/.local/share}/${APP_NAME}}"
DB_PATH="${DB_PATH:-${DATA_DIR}/${APP_NAME}.db}"
XML_DIR="${XML_DIR:-${DATA_DIR}/scans}"
MODE="${1:-}"

backup_before_reinstall() {
	local source_dir="$1"
	local backup_dir="$1/backups"

	if [[ ! -d "${source_dir}" ]]; then
		return 0
	fi

	mkdir -p "${backup_dir}"
	local stamp
	stamp="$(date +%Y%m%d-%H%M%S)"
	local target_dir="${backup_dir}/reinstall-${stamp}"

	mkdir -p "${target_dir}"
	if [[ -f "${source_dir}/${APP_NAME}.db" ]]; then
		cp "${source_dir}/${APP_NAME}.db" "${target_dir}/${APP_NAME}.db"
	fi
	if [[ -d "${source_dir}/scans" ]]; then
		cp -R "${source_dir}/scans" "${target_dir}/scans"
	fi
	echo "Backed up existing data to ${target_dir}"
}

safe_remove() {
	local target="$1"
	if [[ ! -e "${target}" && ! -L "${target}" ]]; then
		return 0
	fi

	chmod -R u+w "${target}" 2>/dev/null || true
	rm -rf "${target}"
}

if [[ -n "${MODE}" && "${MODE}" != "backup" ]]; then
	echo "Usage: ./scripts/reinstall.sh [backup]"
	exit 1
fi

if [[ "${MODE}" == "backup" ]]; then
	backup_before_reinstall "${DATA_DIR}"
fi

echo "Removing installed binaries..."
"${SCRIPT_DIR}/uninstall.sh"

echo "Removing active database and XML artifacts..."
safe_remove "${DB_PATH}"
safe_remove "${XML_DIR}"

"${SCRIPT_DIR}/install.sh"
