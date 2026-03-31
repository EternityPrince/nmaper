# nmaper

`nmaper` is a snapshot-first CLI for running `nmap`, persisting scan history in SQLite, and exploring network changes from the terminal.

## Features

- Two-phase scanning: discovery plus parallel detail scans
- SQLite-backed history with sessions, devices, services, OS guesses, scripts, and traces
- Read-only analytics: sessions, session detail, diff, global dynamics, devices, device history, timeline
- XML-only mode for artifact generation without database writes
- Clipboard, terminal, Markdown, JSON, and `file:<path>` output modes
- Safe interactive deletion flow for single-session or full-history cleanup

## Build

```bash
GOCACHE=/tmp/nmaper-gocache GOPROXY=off GOSUMDB=off go build ./cmd/nmaper
```

## Install

```bash
./scripts/install.sh
nmaper --help
```

Default install target is `~/.local/bin/nmaper`. You can override it, for example:

```bash
BIN_DIR=/usr/local/bin ./scripts/install.sh
BIN_DIR=/usr/local/bin ./scripts/uninstall.sh
BIN_DIR=/usr/local/bin ./scripts/reinstall.sh
```

## Test

```bash
GOCACHE=/tmp/nmaper-gocache GOPROXY=off GOSUMDB=off go test ./...
./scripts/test.sh
./scripts/coverage.sh
```

## Examples

```bash
./nmaper 192.168.0.0/24 --sudo
./nmaper 192.168.0.0/24 -p 22,80,443 --service-version --save db
./nmaper 192.168.0.0/24 --save xml -o ./scans
./nmaper --sessions
./nmaper --session 12
./nmaper --diff 12 18 --out json
./nmaper --diff-global --limit 20
./nmaper --devices --vendor tp
./nmaper --device tp --vendor tp --out md
./nmaper --timeline
./nmaper --session --del 12
./nmaper --check
```

## Layout

- `cmd/nmaper`: executable entrypoint
- `internal/cli`: CLI parsing and validation
- `internal/scanner`: `nmap` command building and scan orchestration
- `internal/parser`: XML parsing into typed Go models
- `internal/storage`: SQLite schema, persistence, and deletion logic
- `internal/history`: read-only history and analytics
- `internal/output`: terminal / markdown / json rendering and sinks
- `internal/preflight`: formatting and test preflight
- `tests`: end-to-end CLI scenario
