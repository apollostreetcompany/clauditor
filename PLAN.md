# clauditor – PLAN

## 1. Architecture Overview

Components (→ data-flow):

1. **Watcher (systemd service, Rust binary)**
   • Runs under dedicated `clauditor` UNIX user.  
   • Subscribes to Linux **fanotify + inotify + proc-fs** to capture:
     – File open/write/unlink events inside Clawdbot workspace and sensitive paths.  
     – Process execve() for commands issued by agents (via /proc/PID/cmdline).  
   • Writes raw event JSON lines to append-only log file.

2. **Log Store (append-only, tamper-resistant)**
   • Directory: `/var/lib/.sysd/.audit/` (hidden-ish).  
   • File naming: `YYYY-MM.log`.  
   • `chown clauditor:clauditor`, `chmod 0400`, `chattr +a` after rotation.

3. **Digest Generator (timer-triggered)**
   • systemd **clauditor-digest.timer** fires daily/weekly/monthly.  
   • Companion binary scans last period’s raw log, runs rules → produces markdown report.  
   • Report stored in same dir and (optionally) emailed / pushed to preferred channel via Clawdbot message tool.

4. **Anomaly Detector (library crate reused by Watcher & Digest)**
   • Stateless rule engine (regex + heuristic counters).  
   • Flags red-flags enumerated in requirements.  
   • Emits structured `Alert{severity, rule_id, context}` events.

5. **Failsafe Heartbeat**
   • Watcher emits `sd_notify("WATCHDOG=1")` every 20 s.  
   • systemd service has `WatchdogSec=60s`; if missed → `OnFailure=clauditor-alert@%n.service` sends high-severity alert.

6. **Stealth Layer**
   • Binary installed as `/usr/lib/systemd/systemd-journaldd` (note double *d*).  
   • Service unit named `systemd-journaldd.service` → blends with system units.  
   • Uses `SyslogIdentifier=systemd-journaldd` to avoid custom names.

Data-flow:  
Fanotify → Watcher → raw log (append-only) → Anomaly Detector → on-the-fly Alerts + stored log.  
Digest Timer → Digest Generator → report + Alerts summary.

---

## 2. File / Repo Structure

```
skills/
└─ clauditor/
   ├─ PLAN.md              ← this document
   ├─ README.md            ← public overview (sanitised)
   ├─ wizard.sh            ← interactive installer (runs as root)
   ├─ service/
   │   ├─ systemd-journaldd.service
   │   ├─ claudi_digest.timer
   │   └─ claudi_digest.service
   ├─ src/                 ← Rust workspace
   │   ├─ watcher/
   │   ├─ digest/
   │   └─ detector/
   ├─ Cargo.toml           ← top-level workspace
   ├─ rules.toml           ← default detection rules (regexes, thresholds)
   ├─ tests/
   └─ .clawdhub.yml        ← submission metadata
```

---

## 3. Beads Breakdown (implementation roadmap)

1. **Scaffold repo & Rust workspace**  
   Test: `cargo check` passes.

2. **Implement Rule Engine crate (`detector/`)**  
   – Define `Rule`, `Alert`, load from TOML.  
   Test: unit tests trigger alerts on sample strings.

3. **Watcher prototype**  
   – Inotify on workspace; log events to stdout.  
   Test: create & delete file, event appears.

4. **Integrate Rule Engine into Watcher**  
   – Real-time alert printing.  
   Test: touch `rm logfile` command triggers alert.

5. **Add fanotify / process exec capture**  
   – Requires root capabilities (granted via service).  
   Test: run `curl example.com` ⇒ alert.

6. **Write to append-only log file**  
   – Implement log rotation monthly.  
   – Apply `chattr +a` via `libc::ioctl`.  
   Test: attempt `truncate -s 0` fails for non-root.

7. **Digest generator**  
   – Parse last period log, group by rule, severity.  
   Test: sample log → correct markdown report.

8. **Systemd service & timer units**  
   – Watchdog & OnFailure hook.  
   Test: kill process → OnFailure service runs.

9. **Wizard script**  
   – Creates user, copies binary, installs units, enables timer, verifies status.  
   Test: fresh VM install completes <3-min.

10. **Stealth hardening**  
    – Rename binary/service, hide log dir, strip symbols.  
    Test: `ps aux | grep` doesn’t reveal “clauditor”.

11. **End-to-end integration with Clawdbot alert channel**  
    – Digest & OnFailure send message via skill bus.  
    Test: simulated alert arrives in test chat.

12. **Security audit & fuzz tests**

13. **Documentation & ClawdHub package**

---

## 4. Security Considerations

• **Privilege separation:** only Watcher needs elevated caps (`CAP_SYS_ADMIN, CAP_DAC_READ_SEARCH`). Runs as unprivileged user otherwise.  
• **Tamper-resistance:** `chattr +a`, separate ownership, off-line rotation script retains immutability.  
• **Binary integrity:** stripped, sha256 recorded in unit `Environment=CLAUDITOR_HASH=…`; Digest compares running binary hash.  
• **Resource usage:** epoll-based, <5 MB RSS, wakes only on FS/proc events.  
• **No network access** by default; Digest can invoke Clawdbot message tool through command exec with restrictive env.

---

## 5. Setup Wizard Flow (what user sees)

Run inside `clawd` workspace:
```
bash skills/clauditor/wizard.sh
```
Wizard steps (1-2-3):
1. Detect distro (systemd required) & confirm sudo.  
2. Show the exact commands it *will* run, e.g.:
   ```bash
   sudo useradd -r -s /usr/sbin/nologin clauditor
   sudo mkdir -p /var/lib/.sysd/.audit && sudo chown clauditor /var/lib/.sysd/.audit
   sudo install -Dm755 target/release/systemd-journaldd /usr/lib/systemd/systemd-journaldd
   sudo install -Dm644 service/systemd-journaldd.service /etc/systemd/system/
   sudo install -Dm644 service/claudi_digest.* /etc/systemd/system/
   sudo systemctl daemon-reload
   sudo systemctl enable --now systemd-journaldd.service claudi_digest.timer
   sudo systemctl status systemd-journaldd.service --no-pager
   ```
3. Ask for confirmation → execute.  
4. Print "🚨 COPY THIS RECOVERY COMMAND:" with one-liner to disable immutability & uninstall.

Total time <3 min.

---

## 6. Rust vs Elixir Recommendation

Choose **Rust**:
• Produces single static binary (no BEAM/OTP runtime).  
• Lower memory (<5 MB vs >40 MB).  
• First-class fanotify/eBPF support crates.  
• Easier to strip symbols & obfuscate.  
• Widely adopted for security tooling (Falco, eBPF agents).

Elixir requires Erlang VM (multiple binaries, obvious processes, harder to hide). Performance & startup time worse. Therefore, Rust best matches stealth + simplicity.

---

## 7. ClawdHub Submission Checklist ✅

- [ ] `README.md` (public, no stealth details)
- [ ] `PLAN.md` included
- [ ] `wizard.sh` with non-interactive mode
- [ ] unit + integration tests pass (`cargo test`)
- [ ] CI workflow (`clawdhub.yml`) builds x86_64 & aarch64
- [ ] Version pinning in `Cargo.lock`
- [ ] `LICENSE` (Apache-2.0)
- [ ] Changelog `CHANGELOG.md`
- [ ] Security audit report (cargo audit)
- [ ] Screenshots redacted (optional)
- [ ] Tags: `security`, `watchdog`, `audit`, `rust`
- [ ] Verified digest output sample

---

End of PLAN.
