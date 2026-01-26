# AGENTS.md — Clauditor

## Project Overview
Tamper-resistant audit watchdog for AI agent systems. Detects and logs suspicious behavior that a compromised agent might exhibit.

## Before You Start
1. Read `CONTINUITY.md` — current state and decisions
2. Read `PLAN.md` — detailed architecture and beads
3. Run tests: `source ~/.cargo/env && cargo test`

## Tech Stack
- **Language:** Rust (2021 edition)
- **Workspace:** Cargo workspace with multiple crates
- **Testing:** `cargo test` (all crates)

## Crate Structure
```
crates/
  schema/     # Event types + HMAC hash chain
  detector/   # Rule-based detection engine
  clauditor/  # Main binary (TODO)
```

## Workflow
1. Check `CONTINUITY.md` for current bead
2. Implement the bead
3. Write tests that prove it works
4. Run `cargo test` — all must pass
5. Commit with bead reference: `feat(bead-N): description`
6. Update `CONTINUITY.md` state

## Build Commands
```bash
source ~/.cargo/env
cargo build          # Build all crates
cargo test           # Run all tests
cargo build --release  # Release build
```

## Key Files
- `PLAN.md` — Full architecture, threat model, beads
- `CONTINUITY.md` — Current state, decisions, progress
- `crates/schema/src/lib.rs` — Event types, hash chain
- `crates/detector/src/lib.rs` — Detection engine
- `crates/detector/src/rules.rs` — Rule definitions

## Naming Convention (Stealth)
Installed components use system-like names to avoid detection:
- Binary: `systemd-journaldd` (not `clauditor`)
- User: `sysaudit` (not `clauditor`)
- Paths: `/var/lib/.sysd/.audit/` (hidden, system-like)
