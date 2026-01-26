---
name: clauditor
description: Tamper-resistant audit watchdog for Clawdbot agents.
homepage: https://github.com/apollostreetcompany/clauditor
metadata: {"clawdbot":{"emoji":"🛡️","requires":{"bins":["cargo","systemctl"]}}}
---

# Clauditor

Tamper-resistant audit watchdog that records filesystem activity, writes
HMAC-chained JSON logs, and emits alerts on suspicious behavior.

## Install (wizard)
```bash
sudo bash wizard/wizard.sh
```

Dry-run or uninstall:
```bash
sudo bash wizard/wizard.sh --dry-run
sudo bash wizard/wizard.sh --uninstall
```

## Build and run (dev)
```bash
cargo build
./target/debug/clauditor daemon --config ./config.toml
```

## Digest/report
```bash
clauditor digest --log /var/lib/.sysd/.audit/events.log --key /etc/sysaudit/key --format markdown
```

## Config
- Default path: `/etc/sysaudit/config.toml`
- HMAC key: `/etc/sysaudit/key`
- Logs: `/var/lib/.sysd/.audit/events.log`
