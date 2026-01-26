# CONTINUITY.md — Clauditor

## Goal (incl. success criteria)
Build a tamper-resistant audit watchdog that makes it *hard* for a compromised `clawdbot` user to operate without leaving a trail or cover tracks.

**Success criteria:**
- Separate `sysaudit` user runs the daemon (can't be killed/manipulated by clawdbot)
- Append-only logs with HMAC hash chains (tamper-evident)
- Alerts on suspicious patterns (exfil, injection, persistence, tamper)
- Sentinel detects if watchdog is killed/deleted
- <3 minute install via wizard

## Constraints/Assumptions
- Attacker controls `clawdbot` account, can run arbitrary commands
- Attacker is NOT root (root scope = add remote log shipping later)
- Linux + systemd environment
- Stealth naming: installed as `systemd-journaldd` to blend with system

## Key Decisions
1. **Rust** for daemon (memory safety, single binary, fast)
2. **HMAC-SHA256** hash chain for tamper evidence (key stored root-owned)
3. **fanotify + eBPF** for privileged capture (inotify fallback for dev mode)
4. **Stealth paths:** `/usr/local/sbin/systemd-journaldd`, `/var/lib/.sysd/.audit/`
5. **Separate user:** `sysaudit` (not `clauditor`) with no login shell

## State

### Done
- [x] **Bead 1:** Schema crate — Event types + HMAC hash chain + 4 tests
- [x] **Bead 2:** Detector crate — Rule-based detection (20+ rules, 4 tests)
- [x] .gitignore added, target artifacts cleaned
- [x] **Bead 3:** Collector (dev mode) — inotify + proc enrichment, Collector with start/stop

### Now
- Bead 4: Collector (privileged) — fanotify + eBPF with UID filtering

### Next
- Bead 5: Append-only writer — O_APPEND + chattr +a integration
- Bead 6: Alerting integration
- Bead 7: Digest/report subcommand
- Bead 8: Systemd hardening
- Bead 9: Sentinel (outside clauditor)
- Bead 10: Wizard

## Open Questions
- None currently

## Working Set
- **Repo:** `/home/clawdbot/clawd/skills/clauditor/`
- **Crates:** `crates/schema/`, `crates/detector/`
- **Plan:** `PLAN.md` (detailed architecture)
- **Build:** `source ~/.cargo/env && cargo build && cargo test`
