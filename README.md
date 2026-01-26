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
- Interactive CLI wizard for guided installation

## Security Model

| Component | Owner | Permissions | Clawdbot Access |
|-----------|-------|-------------|-----------------|
| Daemon | sysaudit | runs as sysaudit user | ❌ Cannot kill |
| HMAC Key | root:sysaudit | 640 | ❌ Cannot read |
| Log Dir | sysaudit:sysaudit | 750 | ❌ Cannot write |
| Logs | sysaudit | 640 | ✅ Can read (tamper-evident) |

**Threat model:** Even if Clawdbot is fully compromised, it cannot:
- Stop the watchdog daemon
- Forge log entries (no key access)
- Delete evidence (no write access to logs)

## Installation

### Option 1: Guided Wizard (Recommended for Clawdbot users)

The CLI wizard guides you through installation step-by-step:

```bash
# Build first
cargo build --release

# Check current status
./target/release/clauditor wizard status

# Get next step (run this, follow instructions, repeat)
./target/release/clauditor wizard next

# Verify a step completed
./target/release/clauditor wizard verify
```

### Option 2: Interactive Script (Power users)

```bash
sudo bash wizard/wizard.sh
```

Dry-run or uninstall:
```bash
sudo bash wizard/wizard.sh --dry-run
sudo bash wizard/wizard.sh --uninstall
```

## Installation Steps (Manual Reference)

1. **Create system user:** `sudo useradd --system --shell /usr/sbin/nologin --no-create-home sysaudit`
2. **Create directories:** `sudo install -d -m 0750 /etc/sysaudit && sudo install -d -m 0750 -o sysaudit -g sysaudit /var/lib/.sysd/.audit`
3. **Generate HMAC key:** `sudo sh -c 'head -c 32 /dev/urandom | base64 > /etc/sysaudit/key && chown root:sysaudit /etc/sysaudit/key && chmod 640 /etc/sysaudit/key'`
4. **Build and install:** `cargo build --release && sudo install -m 0755 target/release/clauditor /usr/local/sbin/systemd-journaldd`
5. **Install config:** `sudo install -m 0640 dist/config/default.toml /etc/sysaudit/config.toml`
6. **Start service:** `sudo cp dist/systemd/*.service dist/systemd/*.timer /etc/systemd/system/ && sudo systemctl daemon-reload && sudo systemctl enable --now systemd-journaldd`

## Usage

### Check daemon status
```bash
systemctl status systemd-journaldd
```

### Generate digest report
```bash
clauditor digest --log /var/lib/.sysd/.audit/events.log --key /etc/sysaudit/key --format markdown
```

### View raw logs
```bash
sudo cat /var/lib/.sysd/.audit/events.log | jq .
```

## Configuration

Default config location: `/etc/sysaudit/config.toml`

```toml
key_path = "/etc/sysaudit/key"

[collector]
watch_paths = ["/home/clawdbot"]  # Directories to monitor
target_uid = 1000                  # User ID to watch

[writer]
log_path = "/var/lib/.sysd/.audit/events.log"
fsync = "periodic"
fsync_interval = 100
max_size_bytes = 104857600  # 100MB

[alerter]
min_severity = "medium"  # low, medium, high, critical
queue_path = "/var/lib/.sysd/.audit/alerts.queue"

[[alerter.channels]]
type = "clawdbot_wake"

[[alerter.channels]]
type = "syslog"
facility = "local0"
```

## Repository Layout
- `crates/schema`: Event schema and HMAC hash chain
- `crates/collector`: File events (inotify dev mode, fanotify privileged mode)
- `crates/detector`: Detection rules and severity scoring
- `crates/writer`: Append-only log writer with rotation
- `crates/alerter`: Alert dispatch and cooldowns
- `crates/clauditor-cli`: CLI (daemon, digest, wizard)
- `dist/config`: Default configuration
- `dist/systemd`: Hardened systemd unit files
- `wizard/`: Interactive installer script

## Requirements
- Linux with systemd
- Rust toolchain for building
- Root access for installation

## Testing
```bash
cargo test
```

## License
MIT (add LICENSE file before distribution)
