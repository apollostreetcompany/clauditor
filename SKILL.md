---
name: clauditor
description: Tamper-resistant audit watchdog for Clawdbot agents.
homepage: https://github.com/apollostreetcompany/clauditor
metadata: {"clawdbot":{"emoji":"🛡️","requires":{"bins":["cargo","systemctl"]}}}
---

# Clauditor

Tamper-resistant audit watchdog that records filesystem activity, writes
HMAC-chained JSON logs, and emits alerts on suspicious behavior.

## Installation (Guided Wizard)

Use the CLI wizard to guide users through installation step-by-step.

### Check status
```bash
cd /path/to/clauditor
./target/debug/clauditor wizard status
```
Returns JSON with `current_step` (1-6) and `complete` (true/false).

### Show next step
```bash
./target/debug/clauditor wizard next
```
Outputs: WHAT it does, WHY it matters, and the exact COMMAND to run.

### Verify last step
```bash
./target/debug/clauditor wizard verify
```
Confirms the last step completed successfully.

### Agent workflow
1. Run `wizard status` to check current state
2. Run `wizard next` to get the next command
3. Show user the command and explanation
4. User runs the sudo command manually
5. Run `wizard verify` to confirm success
6. Repeat until `complete: true`

## Quick Install (Power Users)

For users who want to run everything at once:
```bash
sudo bash wizard/wizard.sh
```

Dry-run or uninstall:
```bash
sudo bash wizard/wizard.sh --dry-run
sudo bash wizard/wizard.sh --uninstall
```

## Build (required before install)

```bash
cargo build --release
```

## After Installation

### Check daemon status
```bash
systemctl status systemd-journaldd
```

### Generate digest report
```bash
clauditor digest --log /var/lib/.sysd/.audit/events.log --key /etc/sysaudit/key --format markdown
```

## Configuration

Default config: `/etc/sysaudit/config.toml`
HMAC key: `/etc/sysaudit/key`
Logs: `/var/lib/.sysd/.audit/events.log`

Edit the config to customize:
- `watch_paths`: directories to monitor
- `target_uid`: user to watch (find with `id -u username`)
- `alerter.min_severity`: low/medium/high/critical
