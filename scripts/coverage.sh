#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"

export GOCACHE="${GOCACHE:-/tmp/nmaper-gocache}"
export GOPROXY="${GOPROXY:-off}"
export GOSUMDB="${GOSUMDB:-off}"

cd "${REPO_ROOT}"
go test -coverprofile=coverage.out ./...
go tool cover -func=coverage.out
