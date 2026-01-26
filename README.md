# Clauditor - Security Watchdog for Clawdbot

Clauditor is a tamper-resistant audit watchdog that makes it hard for a compromised
Clawdbot agent to operate without leaving a trail. It runs a dedicated `sysaudit`
daemon, captures filesystem activity, appends HMAC-chained JSON logs, and emits
alerts when suspicious patterns are detected.

## Features
- Separate `sysaudit` daemon (stealth service name: `systemd-journaldd`)
- Append-only log writer with HMAC hash chaining
- Rule-based detection for exfiltration, injection, persistence, tamper attempts
- Alerting via Clawdbot wake, syslog, file, or command
- Sentinel integrity checks with heartbeat monitoring
- <3 minute interactive installer (wizard)

## Repository Layout
- `crates/schema`: Event schema and HMAC hash chain
- `crates/collector`: File events (inotify dev mode, fanotify privileged mode)
- `crates/detector`: Detection rules and severity scoring
- `crates/writer`: Append-only log writer with rotation
- `crates/alerter`: Alert dispatch and cooldowns
- `crates/clauditor-cli`: `clauditor` CLI (daemon + digest)
- `dist/systemd`: Hardened systemd unit files
- `wizard/`: Interactive installer

## Requirements
- Linux with systemd
- Rust toolchain for building
- CAP_SYS_ADMIN for privileged fanotify collection (fallback to inotify in dev mode)
- Root access for installation (wizard)

## Installation (Recommended)
Use the interactive wizard:
```bash
sudo bash wizard/wizard.sh
```

Useful flags:
```bash
sudo bash wizard/wizard.sh --dry-run
sudo bash wizard/wizard.sh --uninstall
```

The wizard will:
- Create the `sysaudit` user
- Generate `/etc/sysaudit/key` (HMAC key)
- Install `/usr/local/sbin/systemd-journaldd`
- Install systemd units and timers
- Set up `/var/lib/.sysd/.audit` with append-only log file

## Manual / Dev Run
Build the binary:
```bash
cargo build
```

Create a local config (example below), then run:
```bash
./target/debug/clauditor daemon --config ./config.toml
```

## Configuration
Example `config.toml`:
```toml
# Clauditor configuration

[collector]
watch_paths = ["/home/clawdbot"]
target_uid = 1000

[writer]
log_path = "/var/lib/.sysd/.audit/events.log"
fsync = "periodic"
fsync_interval = 100
max_size_bytes = 104857600  # 100MB

[alerter]
min_severity = "medium"
queue_path = "/var/lib/.sysd/.audit/alerts.queue"

[[alerter.channels]]
type = "clawdbot_wake"

[[alerter.channels]]
type = "syslog"
facility = "local0"
```

Notes:
- `watch_paths` should include the workspaces you want to monitor.
- `target_uid` should match the user being audited (e.g., `clawdbot`).
- `log_path` must be absolute.

## Usage
Run the daemon (default config path is `/etc/sysaudit/config.toml`):
```bash
clauditor daemon --config /etc/sysaudit/config.toml
```

Generate a digest report (verifies HMAC chain when key is provided):
```bash
clauditor digest --log /var/lib/.sysd/.audit/events.log --key /etc/sysaudit/key --format markdown
```

## Alerts
Alert channels supported in `alerter` config:
- `clawdbot_wake`
- `syslog` (facility optional)
- `file` (path required)
- `command` (command + args)

## Systemd Units
Installed by the wizard under stealth names:
- `systemd-journaldd.service` (daemon)
- `systemd-journaldd-alert.service` (OnFailure alert)
- `systemd-journaldd-digest.timer` / `.service` (daily digest)
- `systemd-core-check.timer` / `.service` (sentinel integrity checks)

## Testing
```bash
cargo test
```

## License
No LICENSE file is present yet. Add a LICENSE before distribution.
