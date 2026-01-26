# clauditor – PLAN (tamper‑resistant audit watchdog)

Goal: make it *hard* for a compromised `clawdbot` user to (a) operate without leaving a trail and (b) cover tracks, while keeping the system low‑footprint and operationally sane.

Assumptions (from threat model):

- Attacker controls the `clawdbot` account and can run arbitrary commands as that user.
- Attacker is *not* root. (If root is in scope later, add remote log shipping + secure boot/IMA/EVM.)

---

## 1) Architecture (components, data‑flow, low‑visibility techniques)

### Components

1. **Collector Daemon (Rust, systemd service)**
   - Runs as dedicated OS user `clauditor` (no login shell, no home).
   - Captures **exec** + **file** activity for processes owned by `clawdbot`.
   - Writes structured append‑only events to local storage; emits alerts on high‑severity matches.

2. **Capture Backends (kernel‑level first, user‑space fallback)**
   - **Exec**: prefer eBPF tracepoints (e.g., `sched_process_exec`) filtered to `uid=clawdbot`.
   - **File ops**: prefer **fanotify** on the workspace mount(s) (open/write/unlink/rename); fall back to inotify for non‑root/dev mode.
   - Optional: **network** enrichment via eBPF (`connect`/`tcp_connect` tracepoints) to correlate exfil attempts with PIDs.

3. **Append‑Only Log Store (local WORM + tamper‑evidence)**
   - Directory (root-owned, non-world-readable): `/var/lib/clauditor/` (or distro-appropriate `/var/log/clauditor/`).
   - Files owned by `clauditor:clauditor`, mode `0400` (or `0440` with `adm` group if you want read access).
   - **Kernel-enforced append-only**: `chattr +a` on each log file (filesystem must support it; wizard checks).
   - **Tamper-evident chaining**: each event line includes `prev_hash` and `hash = HMAC(key, prev_hash || line)` so edits/deletions are detectable even if someone gains write access later.

4. **Detector (rules + heuristics)**
   - Stateless rules (regex / allowlists) + stateful heuristics (rates, byte counts, unusual destinations).
   - Outputs `Alert{severity, rule_id, pid, uid, argv_snip, paths, remote, evidence}`.

5. **Alert Egress (out-of-band options)**
   - Immediate: `clawdbot gateway wake --mode now` (preferred) and/or local syslog/journal.
   - Resiliency: spool alerts to `/var/lib/clauditor/alerts.queue` and retry on transient failures.

6. **Digest/Report (timer-triggered)**
   - Systemd timer runs daily (or hourly for high-risk environments).
   - Generates a concise markdown report: top alerts, top commands, top touched files, anomaly summary, and integrity verification status.

### Data Flow (high level)

```
eBPF/fanotify → Collector → (normalize/enrich) → append-only log
                                     └→ Detector → alerts (immediate) + report (timer)
```

### Low‑visibility (defensive, not “security by obscurity”)

Low-visibility is achieved by *privilege boundaries*, not deception:

- Run under a different UID (`clauditor`) so `clawdbot` can’t signal/ptrace it.
- Consider `/proc` hardening (`hidepid=2`) so `clawdbot` can’t enumerate other users’ processes.
- Restrict log directory permissions so `clawdbot` can’t read or delete evidence.
- Lock down unit/config readability via filesystem permissions and (optionally) polkit rules for `systemctl` introspection.

---

## 2) Heartbeat + failsafe (detect deletion/killing from *outside* clauditor)

You need **two independent liveness paths**:

1) **In-band liveness** (service health)

- `WatchdogSec=` + `sd_notify("WATCHDOG=1")` from the Collector.
- `Restart=always` + `RestartSec=…` so crashes don’t create blind spots.
- `OnFailure=` hooks an alert action.

2) **Out-of-band sentinel** (integrity & existence checks)

Install a second, independent systemd unit that is *not* implemented by the Collector binary and lives outside the clauditor repo directory. It should detect:

- **Binary missing/changed** (Collector executable path)
- **Unit file missing/changed**
- **Log directory missing** (or unexpectedly empty)
- **Heartbeat stale** (`/run/clauditor.hb` not updated within N seconds)

Recommended systemd pattern (fast + reliable):

- A `*.path` unit watching for changes/deletions:
  - `PathChanged=/usr/local/sbin/clauditor` (or wherever installed)
  - `PathChanged=/etc/systemd/system/clauditor.service`
  - `PathChanged=/var/lib/clauditor`
- A `*.timer` unit as a backstop (e.g., every 60s) to catch missed inotify events and validate heartbeat freshness.
- Both trigger a **oneshot** notifier service that alerts via at least one channel not controlled by `clawdbot` (syslog + gateway wake).

Alert payload should include:

- What disappeared/changed, timestamp, last known heartbeat, and last N log lines’ hashes.
- Command to verify integrity (`sha256sum` of binary + unit + config) and to collect forensic bundle.

Optional “belt and suspenders” (recommended where available):

- **Linux audit** rules to watch the binary/unit/log dir for `unlink`, `rename`, `chmod`, `chattr`, and `kill` attempts; route audit events to the same alerting path.
- Store periodic report digests off-host (email/webhook/S3) so that even log deletion is visible.

---

## 3) File structure (repo + installed footprint)

Repo (this skill/project):

```
skills/clauditor/
  PLAN.md
  README.md
  Cargo.toml              # workspace
  crates/
    clauditor/            # single binary: daemon + digest subcommands
    detector/             # rules + heuristics (pure library)
    schema/               # event types + JSON serialization
  dist/
    systemd/
      clauditor.service
      clauditor-digest.timer
      clauditor-digest.service
      clauditor-sentinel.path
      clauditor-sentinel.timer
      clauditor-alert.service
  rules/
    default.toml
  wizard/
    wizard.sh             # prints commands, then runs after confirmation
```

Installed footprint (outside the repo directory) — STEALTH NAMING:

- Binary: `/usr/local/sbin/systemd-journaldd` (note: double-d, blends with system)
- Config: `/etc/sysaudit/config.toml` (root-owned `0640`)
- Logs: `/var/lib/.sysd/.audit/` (hidden, system-like path)
- Units: `/etc/systemd/system/systemd-journaldd.service`, `systemd-core-check.{path,timer}`
- User: `sysaudit` (not `clauditor`)

All naming chosen to blend with legitimate systemd components. Wizard includes full uninstall script that removes `+a/+i` attrs and all components.

---

## 4) Beads (testable implementation steps)

1. **Define event schema + hashing**
   - Test: feed sample events; verify hash chain continuity and tamper detection.

2. **Implement detector rules (library crate)**
   - Test: unit tests for each rule category (exfil, persistence, tamper).

3. **Collector (dev mode)**
   - Implement inotify + proc enrichment in unprivileged mode.
   - Test: touch/write/unlink files → JSONL events emitted.

4. **Collector (privileged capture)**
   - Add fanotify for file ops and eBPF for exec (uid filter).
   - Test: run `bash -c 'echo hi'` and file writes → both captured with PID correlation.

5. **Append-only writer**
   - Open with `O_APPEND`, fsync policy, rotation strategy, and `chattr +a` integration (wizard applies attributes).
   - Test: as `clawdbot`, attempt truncate/overwrite/delete → fails; append continues.

6. **Alerting integration**
   - Implement immediate alert hook + queued retry.
   - Test: simulate exfil command signature → `clawdbot gateway wake` invoked and logged.

7. **Digest/report subcommand**
   - Test: replay fixture log → deterministic markdown report + integrity check section.

8. **Systemd hardening**
   - Add unit sandboxing, watchdog, OnFailure.
   - Test: kill the daemon (as root) → OnFailure triggers; restart occurs; alert emitted.

9. **Sentinel (outside clauditor)**
   - Add `.path` + `.timer` + notifier unit.
   - Test: delete/move unit file or binary (as root) → immediate alert; timer catches within 60s if missed.

10. **Wizard**
   - Test: on a clean VM, install completes <3 minutes; `systemctl is-active clauditor` OK; log file has `+a`.

---

## 5) Security hardening checklist

**Identity & permissions**
- [ ] `clauditor` is a system user (`useradd --system`) with `/usr/sbin/nologin`
- [ ] Log dir is root-owned; log files are `clauditor` owned; `clawdbot` has no read/write perms
- [ ] `chattr +a` applied to log files (wizard verifies filesystem support)
- [ ] Optional: `chattr +i` on unit files/binary to prevent accidental tampering (wizard includes uninstall escape hatch)

**Service sandboxing (systemd)**
- [ ] `NoNewPrivileges=true`
- [ ] `ProtectSystem=strict`, `ProtectHome=true`, `PrivateTmp=true`, `PrivateDevices=true`
- [ ] `ProtectKernelTunables=true`, `ProtectKernelModules=true`, `ProtectControlGroups=true`
- [ ] `RestrictSUIDSGID=true`, `RestrictNamespaces=true`, `LockPersonality=true`
- [ ] `SystemCallFilter=` baseline allowlist + `SystemCallErrorNumber=EPERM`
- [ ] `CapabilityBoundingSet=` minimal required (fanotify/eBPF needs elevated caps; drop after init if possible)

**Integrity & resilience**
- [ ] Hash chain + HMAC key stored root-owned (`/etc/clauditor/key`, `0440 root:clauditor`)
- [ ] Periodic report includes last hash, detects gaps and rewrites
- [ ] Disk-full behavior: alert on low space; backpressure/rotation policy documented
- [ ] Sentinel `.path` + `.timer` enabled and tested
- [ ] Optional: audit rules for unit/binary/logdir modifications

**Detection coverage**
- [ ] Exfil: `curl/wget/scp/rsync/nc/ssh`, suspicious DNS tools, large outbound connections
- [ ] Injection: `bash -c`, `python -c`, heredocs, base64 decode, `eval`, writing to shell init files
- [ ] Persistence: crontab/systemd unit writes, SSH key modifications, new setuid binaries
- [ ] Tamper: `rm`, `truncate`, `chattr`, `systemctl stop/disable`, log dir probing

---

## 6) Setup wizard flow (3-minute, prints exact commands)

Wizard UX goal: show **exact commands**, ask for confirmation, then run.

Example command sequence (Linux + systemd):

```bash
sudo useradd --system --shell /usr/sbin/nologin --no-create-home clauditor
sudo install -d -m 0750 -o root -g root /var/lib/clauditor
sudo install -d -m 0750 -o root -g root /etc/clauditor

sudo install -m 0755 -o root -g root ./target/release/clauditor /usr/local/sbin/clauditor
sudo install -m 0640 -o root -g root ./dist/systemd/clauditor*.service /etc/systemd/system/
sudo install -m 0640 -o root -g root ./dist/systemd/clauditor*.timer /etc/systemd/system/
sudo install -m 0640 -o root -g root ./dist/systemd/clauditor*.path /etc/systemd/system/

sudo install -m 0440 -o root -g clauditor /dev/stdin /etc/clauditor/key <<'EOF'
<generated-32-bytes-hex-or-base64>
EOF

sudo install -m 0400 -o clauditor -g clauditor /dev/null /var/lib/clauditor/events.log
sudo chattr +a /var/lib/clauditor/events.log

sudo systemctl daemon-reload
sudo systemctl enable --now clauditor.service clauditor-digest.timer clauditor-sentinel.path clauditor-sentinel.timer
sudo systemctl --no-pager status clauditor.service
```

Wizard must also print an **uninstall/recovery** sequence (removes `+a/+i` attrs, disables units, removes files).

---

## 7) ClawdHub submission checklist

- [ ] `PLAN.md` matches current design
- [ ] Public `README.md` avoids sensitive operational details (focus on purpose + safe install/use)
- [ ] `cargo test` passes (unit tests for detector + hash chain)
- [ ] Release build documented (`cargo build --release`)
- [ ] `wizard/wizard.sh` supports `--dry-run` and prints exact commands
- [ ] Systemd units included under `dist/systemd/` and validated (`systemd-analyze verify …`)
- [ ] Rule defaults shipped (`rules/default.toml`) with documented tuning knobs
- [ ] Minimal privileges documented + distro caveats (fanotify/eBPF availability)

---

End of PLAN.
