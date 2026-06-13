# Tamandua CTL

`tamandua-ctl` is the command-line control tool for the
[Tamandua EDR](https://github.com/treant-lab) platform. It talks to the agent's
local IPC socket (MessagePack over the same protocol the GUI uses) and to the
server's HTTP/WebSocket APIs for operator tasks.

## Overview

### Local IPC Commands

These commands communicate with the local agent via IPC socket:

- **status** - Show agent health, collector status, and performance metrics
- **events** - List, search, and get statistics on telemetry events
- **alerts** - List, acknowledge, and inspect local alerts
- **config** - View/modify agent configuration and performance profiles
- **scan** - Start on-demand scans, check status, cancel, or view history
- **quarantine** - List, inspect, restore, or delete quarantined files
- **response** - Execute response actions (kill process, isolate host, block IP)

### Remote Server Commands

These commands communicate with the Tamandua server via HTTP/WebSocket:

- **remote login** - Authenticate and store operator credentials
- **remote agents list** - List enrolled agents visible to the operator
- **remote alerts list** - List alerts from the server with filtering
- **remote shell** - Open an interactive live response shell to an agent
- **remote command** - Execute a single command on an agent
- **remote upload** - Upload a local file to an agent

### JSON Output Mode

All commands support `--json` for machine-readable output, useful for scripting
and integration with other tools.

## Example Commands

```bash
# Check agent health and collector status
tamandua-ctl status
tamandua-ctl status --detailed --metrics

# List recent telemetry events
tamandua-ctl events list
tamandua-ctl events list --limit 100 --since 1h --event-type process
tamandua-ctl events search "powershell.exe"

# View and acknowledge alerts
tamandua-ctl alerts list --unacked
tamandua-ctl alerts ack <alert-id> --note "Investigated, benign"

# Start an on-demand scan
tamandua-ctl scan start /path/to/scan --recursive --wait

# Manage quarantine
tamandua-ctl quarantine list
tamandua-ctl quarantine restore <id>

# Response actions
tamandua-ctl response kill 1234 --force
tamandua-ctl response isolate
tamandua-ctl response block-ip 192.168.1.100 --duration 3600

# Remote: authenticate with the server
tamandua-ctl remote login --server https://tamandua.example.com

# Remote: list agents
tamandua-ctl remote agents list --status online

# Remote: open live response shell
tamandua-ctl remote shell --agent-id <uuid>

# Remote: execute single command on agent
tamandua-ctl remote command --agent-id <uuid> -- whoami
tamandua-ctl remote command --agent-id <uuid> -- netstat -an

# Remote: upload file to agent
tamandua-ctl remote upload --agent-id <uuid> ./script.ps1 C:\Temp\script.ps1

# JSON output for scripting
tamandua-ctl --json status | jq '.collectors'
tamandua-ctl --json alerts list | jq '.[] | select(.severity == "critical")'
```

## Build

Requires a stable Rust toolchain (edition 2021).

```bash
cargo build --release
```

The binary is emitted at `target/release/tamandua-ctl`.

## Test

```bash
cargo test
cargo clippy --all-targets
cargo fmt --check
```

## Run

```bash
tamandua-ctl --help
```

Run with `--help` to list subcommands. Token authentication uses an HMAC over the
shared token; see `--help` for the relevant flags and environment variables.

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md). Run `cargo fmt`, `cargo clippy`, and
`cargo test` before opening a PR.

## License

Licensed under the [Apache License, Version 2.0](./LICENSE).
