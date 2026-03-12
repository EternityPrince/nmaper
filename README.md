# nmaper

`nmaper` is a snapshot-first network reconnaissance CLI: scan with `nmap`, keep the evidence, and explore what changed later without digging through raw output by hand.

It is built for the workflow most people actually want:
- run a fast scan now
- save the result as a durable snapshot
- come back later and ask better questions
- compare sessions, devices, timelines, and drift

## Why It Exists

Raw `nmap` output is excellent for one run and annoying for history.

`nmaper` turns repeated scans into a small local intelligence layer:
- SQLite-backed session history
- human-readable terminal reports
- JSON and Markdown export for notes, tickets, or automation
- device-centric analytics across multiple scans
- timeline and diff views for spotting change instead of rereading walls of text

## What It Does

- Runs two-stage scans:
  - discovery across a target/prefix
  - detailed per-host follow-up on open ports
- Stores parsed scan evidence in SQLite
- Keeps raw XML in the database by default
- Can switch to XML-only artifact mode when needed
- Shows saved sessions and detailed session reports
- Diffs two sessions directly
- Builds a global “what changed lately?” summary
- Tracks recurring devices and unique device identities
- Supports fuzzy search like `tp` matching `TP-Link`
- Copies rich session/device reports to the clipboard by default

## Quick Start

```bash
uv sync
uv run nmaper --help
```

Run a first scan:

```bash
uv run nmaper 192.168.0.0/24 --sudo
```

Scan a tighter port set and keep results in SQLite:

```bash
uv run nmaper 192.168.0.0/24 -p 22,80,443,8000-8100 --service-version --save db
```

Use XML-only mode when you only want artifacts:

```bash
uv run nmaper 192.168.0.0/24 --save xml -o ./scans
```

## Explore Saved History

List sessions:

```bash
uv run nmaper --sessions
uv run nmaper --session
```

Open one session:

```bash
uv run nmaper --session 12
uv run nmaper --session 12 --host 192.168.0.34
uv run nmaper --session 12 --out md
uv run nmaper --session 12 --out json
```

Default behavior for detailed reports:
- print a rich terminal view
- copy the same report to the clipboard

## Diff, Dynamics, and Drift

Compare two snapshots:

```bash
uv run nmaper --diff 12 18
uv run nmaper --diff 12 18 --out json
```

See broader movement across recent sessions:

```bash
uv run nmaper --diff-global
uv run nmaper --diff-global --limit 20 --out md
```

Build a chronological change view:

```bash
uv run nmaper --timeline
uv run nmaper --timeline --status completed
```

## Device Intelligence

See the biggest repeat offenders on your network:

```bash
uv run nmaper --devices
uv run nmaper --devices --vendor tp
uv run nmaper --devices --mac-only
```

Drill into one device by MAC, IP, or fuzzy query:

```bash
uv run nmaper --device AC:15:A2:85:C5:71
uv run nmaper --device 19216801
uv run nmaper --device tp --vendor tp --out md
```

Fuzzy matching is intentionally forgiving:
- `tp` matches `TP-Link`
- `tplnk` matches `TP-Link`
- `19216801` matches `192.168.0.1`

## Safe Cleanup

Delete one session:

```bash
uv run nmaper --session --del 12
```

Wipe everything:

```bash
uv run nmaper --session --del -1
```

Both destructive commands require an interactive `y` confirmation.

## Developer Workflow

Run Ruff + unit tests only:

```bash
uv run nmaper --check
```

Run checks before the actual command:

```bash
uv run nmaper 192.168.0.0/24 --sudo --dev
```

## Typical Terminal Flow

```text
21:03:12 [PHASE] nmaper mission control online
21:03:12 [PHASE] Target locked: 192.168.0.0/24 | save=db | ports=default
21:03:13 [PHASE] Running in database mode
21:03:13 [ OK  ] Database schema is ready
21:03:13 [PHASE] Bootstrapping nmap runtime
21:03:13 [ OK  ] nmap binary located in PATH
21:03:13 [PHASE] Acquiring sudo credentials
21:03:13 [ OK  ] sudo session is warm
21:04:04 [ OK  ] Discovery scan completed: 10 hosts observed, 10 hosts with open ports in 51s
21:05:47 [ OK  ] [3/10] host 192.168.0.34 done in 1m 52s (4 open ports from 4 target ports)
21:06:09 [ OK  ] session=20260312-210313 hosts=10 detailed=10 detail_errors=0 discovery=51s total=2m 56s dir=db-only app_total=2m 56s
```

## Architecture

- `nmap` does the scanning
- XML is the parsing source of truth
- SQLAlchemy models persist normalized history in SQLite
- read-only analytics are built on top of saved sessions

That means you get the reliability of `nmap`, the convenience of SQLite, and the ergonomics of a purpose-built terminal tool instead of a pile of old scan logs.

## Local End-to-End Run

A separate real-run test lives in:

- [`tests/e2e_real_run.py`](/Users/vladimirkasterin/python/nmaper/tests/e2e_real_run.py)

It spins up local HTTP services, runs the actual CLI twice through `uv run nmaper`, writes to a temporary SQLite database, and exercises:
- scanning
- saved session listing
- session detail
- host filtering
- diff
- global diff
- device analytics
- device history
- timeline output

Run it when you want a full real-world sanity check:

```bash
uv run python tests/e2e_real_run.py
```

## Notes

- `--sudo` is recommended for privileged SYN scans
- without `--sudo`, discovery falls back to TCP connect scanning
- use this only on networks you own or are explicitly authorized to inspect

If you want a terminal-first network history tool that feels faster than opening XML dumps and more useful than hoarding screenshots, this is the lane.
