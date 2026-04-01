# nmaper

`nmaper` is a snapshot-first CLI for running `nmap`, persisting scan history in SQLite, and exploring network changes from the terminal.

## Features

- Two-phase scanning: discovery plus parallel detail scans
- Adaptive detail scans: safe NSE profiles are attached by discovered service ports, with traceroute and targeted UDP enrichment when scanning with `--sudo`
- SQLite-backed history with sessions, devices, services, OS guesses, scripts, and traces
- Structured snapshots for TLS / SSH / HTTP / SMB fingerprints, vulnerability findings, and management surface
- Read-only analytics: sessions, session detail, diff, global dynamics, devices, device history, timeline
- Security posture summary mode with risk-class counters (`--posture`, optional `--vendor` / `--network` filters)
- Identity-aware diffing: hosts are matched by MAC first, then IP, so device moves are visible as moves instead of fake disappear/reappear events
- High-signal alerts in diff/timeline: new management ports, SMB/RDP appearance, TLS cert changes, SSH hostkey rotation, HTTP title changes, and new vulnerability signals
- Optional source MAC spoofing for `nmap` while preserving the real scanner MAC in SQLite metadata
- XML-only mode for artifact generation without database writes
- Clipboard, terminal, Markdown, JSON, and `file:<path>` output modes
- View density for history terminal output: `--view compact|full`
- Safe interactive deletion flow for single-session or full-history cleanup

## Scan Levels

- `low`: fast unprivileged TCP scan, no sudo, no MAC spoofing, lighter NSE profile
- `mid`: default balanced profile with richer TCP fingerprints and traceroute
- `high`: deep privileged profile, enables sudo, turns on random MAC spoofing by default, adds UDP enrichment and deeper service/vulnerability coverage

## Build

```bash
GOCACHE=/tmp/nmaper-gocache GOPROXY=off GOSUMDB=off go build ./cmd/nmaper
```

## Install

```bash
./scripts/install.sh
nmaper --help
```

For Termux on Android, use:

```bash
./scripts/install-termux.sh
nmaper --help
```

Default install target is `~/.local/bin/nmaper`. You can override it, for example:

```bash
BIN_DIR=/usr/local/bin ./scripts/install.sh
BIN_DIR=/usr/local/bin ./scripts/uninstall.sh
BIN_DIR=/usr/local/bin ./scripts/reinstall.sh
BIN_DIR=/usr/local/bin ./scripts/reinstall.sh backup
```

The installed command now uses a stable data home by default:

- database: `~/.local/share/nmaper/nmaper.db`
- XML artifacts: `~/.local/share/nmaper/scans`

So `nmaper` no longer depends on the shell's current working directory for SQLite writes after install or reinstall.

`./scripts/reinstall.sh` now removes previous app data by default. If you want to save the current database and XML artifacts first, use:

```bash
./scripts/reinstall.sh backup
```

Termux defaults:

- binary: `$PREFIX/bin/nmaper`
- database: `~/.local/share/nmaper/nmaper.db`
- XML artifacts: `~/.local/share/nmaper/scans`

## Test

```bash
GOCACHE=/tmp/nmaper-gocache GOPROXY=off GOSUMDB=off go test ./...
./scripts/test.sh
./scripts/coverage.sh
```

## Examples

```bash
./nmaper 192.168.0.0/24 --sudo
./nmaper 192.168.0.0/24 --sudo --spoof-mac random
./nmaper 192.168.0.0/24 -p 22,80,443 --service-version --save db
./nmaper 192.168.0.0/24 --save xml -o ./scans
./nmaper --sessions
./nmaper --session 12
./nmaper --diff 12 18 --out json
./nmaper --diff 12 18 --view compact
./nmaper --diff-global --limit 20
./nmaper --devices --vendor tp
./nmaper --device tp --vendor tp --out md
./nmaper --posture
./nmaper --posture --vendor tp-link
./nmaper --posture --network 192.168.0.0/24
./nmaper --timeline
./nmaper --delete-session 12
./nmaper --delete-all-sessions
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
