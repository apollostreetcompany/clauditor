//! Clauditor CLI - Security audit watchdog for Clawdbot
//!
//! Subcommands:
//! - daemon: Run the watchdog daemon
//! - digest: Generate a summary report from logs

use alerter::Alerter;
use chrono::{DateTime, Utc};
use clap::{Parser, Subcommand};
use collector::{CollectorEvent, DevCollector, PrivilegedCollector};
use schema::verify_chain;
use sd_notify::NotifyState;
use serde::{Deserialize, Serialize};
use signal_hook::consts::signal::{SIGINT, SIGTERM};
use std::collections::HashMap;
use std::env;
use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::{Duration, Instant};
use writer::{AppendWriter, FsyncPolicy, WriterConfig};

const DEFAULT_CONFIG_PATH: &str = "/etc/sysaudit/config.toml";
const DEFAULT_KEY_PATH: &str = "/etc/sysaudit/key";
const HEARTBEAT_PATH: &str = "/run/sysaudit.hb";
const HEARTBEAT_INTERVAL_SECS: u64 = 10;

fn default_key_path() -> PathBuf {
    PathBuf::from(DEFAULT_KEY_PATH)
}

#[derive(Debug, Deserialize)]
struct DaemonConfig {
    #[serde(default = "default_key_path")]
    key_path: PathBuf,
    collector: CollectorConfig,
    writer: WriterConfigFile,
    alerter: alerter::AlerterConfig,
}

#[derive(Debug, Deserialize)]
struct CollectorConfig {
    watch_paths: Vec<PathBuf>,
    target_uid: u32,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum FsyncMode {
    None,
    Periodic,
    Every,
}

fn default_fsync_mode() -> FsyncMode {
    FsyncMode::Periodic
}

fn default_fsync_interval() -> u32 {
    100
}

#[derive(Debug, Deserialize)]
struct WriterConfigFile {
    log_path: PathBuf,
    #[serde(default = "default_fsync_mode")]
    fsync: FsyncMode,
    #[serde(default = "default_fsync_interval")]
    fsync_interval: u32,
    #[serde(default)]
    max_size_bytes: u64,
}

impl WriterConfigFile {
    fn to_writer_config(&self) -> WriterConfig {
        let fsync = match self.fsync {
            FsyncMode::None => FsyncPolicy::None,
            FsyncMode::Every => FsyncPolicy::Every,
            FsyncMode::Periodic => FsyncPolicy::Periodic(self.fsync_interval),
        };

        WriterConfig {
            path: self.log_path.clone(),
            fsync,
            max_size_bytes: self.max_size_bytes,
        }
    }
}

#[derive(Parser)]
#[command(name = "clauditor")]
#[command(about = "Security audit watchdog for Clawdbot", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run the clauditor daemon
    Daemon {
        /// Path to the config file
        #[arg(short, long, default_value = DEFAULT_CONFIG_PATH)]
        config: PathBuf,
    },
    /// Generate a digest/report from log files
    Digest {
        /// Path to the log file
        #[arg(short, long)]
        log: PathBuf,

        /// Path to the HMAC key file (for integrity verification)
        #[arg(short, long)]
        key: Option<PathBuf>,

        /// Output format (markdown or json)
        #[arg(short, long, default_value = "markdown")]
        format: String,

        /// Time range start (ISO 8601)
        #[arg(long)]
        since: Option<String>,

        /// Time range end (ISO 8601)
        #[arg(long)]
        until: Option<String>,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Daemon { config } => {
            if let Err(e) = run_daemon(&config) {
                eprintln!("Daemon error: {}", e);
                std::process::exit(1);
            }
        }
        Commands::Digest {
            log,
            key,
            format,
            since,
            until,
        } => {
            if let Err(e) = run_digest(&log, key.as_deref(), &format, since, until) {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        }
    }
}

struct CollectorHandle {
    stop: Arc<AtomicBool>,
    handle: thread::JoinHandle<()>,
}

impl CollectorHandle {
    fn request_stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

fn spawn_collector(
    session_id: String,
    key: Vec<u8>,
    config: &CollectorConfig,
    sender: mpsc::Sender<CollectorEvent>,
) -> io::Result<CollectorHandle> {
    if PrivilegedCollector::is_available() {
        if let Ok(handle) = spawn_privileged_collector(
            session_id.clone(),
            key.clone(),
            config.watch_paths.clone(),
            config.target_uid,
            sender.clone(),
        ) {
            return Ok(handle);
        }
        eprintln!("privileged collector unavailable, falling back to dev collector");
    }

    spawn_dev_collector(session_id, key, config.watch_paths.clone(), sender)
}

fn spawn_dev_collector(
    session_id: String,
    key: Vec<u8>,
    watch_paths: Vec<PathBuf>,
    sender: mpsc::Sender<CollectorEvent>,
) -> io::Result<CollectorHandle> {
    let stop = Arc::new(AtomicBool::new(false));
    let stop_clone = Arc::clone(&stop);

    let handle = thread::spawn(move || {
        let mut collector = match DevCollector::new(session_id, key) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("collector init failed: {e}");
                return;
            }
        };

        for path in &watch_paths {
            if let Err(e) = collector.add_watch(path) {
                eprintln!("watch {path:?} failed: {e}");
            }
        }

        if !watch_paths.is_empty() {
            eprintln!("dev collector active (no uid filtering)");
        }

        while !stop_clone.load(Ordering::Relaxed) {
            match collector.read_available() {
                Ok(events) => {
                    for event in events {
                        if sender.send(event).is_err() {
                            return;
                        }
                    }
                }
                Err(e) => {
                    eprintln!("collector read error: {e}");
                    return;
                }
            }
        }
    });

    Ok(CollectorHandle { stop, handle })
}

fn spawn_privileged_collector(
    session_id: String,
    key: Vec<u8>,
    watch_paths: Vec<PathBuf>,
    target_uid: u32,
    sender: mpsc::Sender<CollectorEvent>,
) -> io::Result<CollectorHandle> {
    let stop = Arc::new(AtomicBool::new(false));
    let stop_clone = Arc::clone(&stop);

    let handle = thread::spawn(move || {
        let mut collector = match PrivilegedCollector::new(session_id, key, target_uid) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("privileged collector init failed: {e}");
                return;
            }
        };

        for path in &watch_paths {
            if let Err(e) = collector.add_watch(path) {
                eprintln!("watch {path:?} failed: {e}");
            }
        }

        while !stop_clone.load(Ordering::Relaxed) {
            match collector.read_available() {
                Ok(events) => {
                    for event in events {
                        if sender.send(event).is_err() {
                            return;
                        }
                    }
                }
                Err(e) => {
                    eprintln!("collector read error: {e}");
                    return;
                }
            }
        }
    });

    Ok(CollectorHandle { stop, handle })
}

fn write_heartbeat(path: &Path) -> io::Result<()> {
    let now = Utc::now().to_rfc3339();
    std::fs::write(path, format!("{now}\n"))
}

fn watchdog_interval_from_env() -> Option<Duration> {
    let usec = env::var("WATCHDOG_USEC").ok()?.parse::<u64>().ok()?;
    if usec == 0 {
        return None;
    }
    Some(Duration::from_micros(usec))
}

fn run_daemon(config_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let config_contents = std::fs::read_to_string(config_path)?;
    let config: DaemonConfig = toml::from_str(&config_contents)?;

    let key = std::fs::read(&config.key_path)?;
    let session_id = format!("sess-{}-{}", Utc::now().timestamp(), std::process::id());

    let (sender, receiver) = mpsc::channel();
    let collector_handle = spawn_collector(session_id, key, &config.collector, sender)?;

    let mut writer = AppendWriter::new(config.writer.to_writer_config())?;
    let alerter = Alerter::new(config.alerter);
    let detector = detector::Detector::new();

    let shutdown = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(SIGTERM, Arc::clone(&shutdown))?;
    signal_hook::flag::register(SIGINT, Arc::clone(&shutdown))?;

    let watchdog_interval = watchdog_interval_from_env();
    let watchdog_tick = watchdog_interval.map(|d| d / 2).filter(|d| *d > Duration::ZERO);
    let mut last_watchdog = Instant::now();

    let _ = sd_notify::notify(false, &[NotifyState::Ready]);

    let heartbeat_interval = Duration::from_secs(HEARTBEAT_INTERVAL_SECS);
    let mut last_heartbeat = Instant::now() - heartbeat_interval;
    if let Err(e) = write_heartbeat(Path::new(HEARTBEAT_PATH)) {
        eprintln!("heartbeat write failed: {e}");
    }

    loop {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }

        match receiver.recv_timeout(Duration::from_millis(500)) {
            Ok(event) => {
                let input = event_to_detector_input(&event);
                let alerts = detector.detect(&input);

                if let Err(e) = writer.write_event(&event) {
                    return Err(Box::new(e));
                }

                if !alerts.is_empty() {
                    if let Err(e) = alerter.process(&event) {
                        eprintln!("alerter error: {e}");
                    }
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }

        let now = Instant::now();
        if now.duration_since(last_heartbeat) >= heartbeat_interval {
            if let Err(e) = write_heartbeat(Path::new(HEARTBEAT_PATH)) {
                eprintln!("heartbeat write failed: {e}");
            }
            last_heartbeat = now;
        }

        if let Some(interval) = watchdog_tick {
            if now.duration_since(last_watchdog) >= interval {
                let _ = sd_notify::notify(false, &[NotifyState::Watchdog]);
                last_watchdog = now;
            }
        }
    }

    collector_handle.request_stop();
    let _ = writer.flush();
    Ok(())
}

#[derive(Debug, Serialize)]
struct DigestReport {
    generated_at: DateTime<Utc>,
    log_path: String,
    event_count: usize,
    time_range: Option<(DateTime<Utc>, DateTime<Utc>)>,
    integrity: IntegrityStatus,
    alert_summary: AlertSummary,
    top_commands: Vec<(String, usize)>,
    top_paths: Vec<(String, usize)>,
    anomalies: Vec<String>,
}

#[derive(Debug, Serialize)]
enum IntegrityStatus {
    Verified,
    NoKeyProvided,
    Failed(String),
}

#[derive(Debug, Default, Serialize)]
struct AlertSummary {
    total: usize,
    by_severity: HashMap<String, usize>,
    by_category: HashMap<String, usize>,
    top_rules: Vec<(String, usize)>,
}

fn run_digest(
    log_path: &std::path::Path,
    key_path: Option<&std::path::Path>,
    format: &str,
    since: Option<String>,
    until: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Parse time range
    let since: Option<DateTime<Utc>> = since.map(|s| s.parse()).transpose()?;
    let until: Option<DateTime<Utc>> = until.map(|s| s.parse()).transpose()?;

    // Read log file
    let file = File::open(log_path)?;
    let reader = BufReader::new(file);

    let mut events: Vec<CollectorEvent> = Vec::new();
    let mut parse_errors = 0;

    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<CollectorEvent>(&line) {
            Ok(event) => {
                // Apply time filter
                let ts = event.event.timestamp;
                if let Some(s) = since {
                    if ts < s {
                        continue;
                    }
                }
                if let Some(u) = until {
                    if ts > u {
                        continue;
                    }
                }
                events.push(event);
            }
            Err(_) => {
                parse_errors += 1;
            }
        }
    }

    // Verify integrity if key provided
    let integrity = if let Some(key_path) = key_path {
        let key = std::fs::read(key_path)?;
        let schema_events: Vec<_> = events.iter().map(|e| e.event.clone()).collect();
        match verify_chain(&schema_events, &key) {
            Ok(()) => IntegrityStatus::Verified,
            Err(e) => IntegrityStatus::Failed(format!("{:?}", e)),
        }
    } else {
        IntegrityStatus::NoKeyProvided
    };

    // Compute statistics
    let mut command_counts: HashMap<String, usize> = HashMap::new();
    let mut path_counts: HashMap<String, usize> = HashMap::new();
    let mut alert_summary = AlertSummary::default();
    let mut rule_counts: HashMap<String, usize> = HashMap::new();

    let detector = detector::Detector::new();

    for event in &events {
        // Count commands
        if let Some(proc) = &event.proc {
            if let Some(cmd) = proc.cmdline.first() {
                *command_counts.entry(cmd.clone()).or_insert(0) += 1;
            }
        }

        // Count paths
        let path = event.file.path.to_string_lossy().to_string();
        // Truncate to directory for grouping
        let dir = std::path::Path::new(&path)
            .parent()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|| path.clone());
        *path_counts.entry(dir).or_insert(0) += 1;

        // Evaluate for alerts
        let input = event_to_detector_input(event);
        let alerts = detector.detect(&input);
        for alert in alerts {
            alert_summary.total += 1;
            let sev = format!("{:?}", alert.severity);
            *alert_summary.by_severity.entry(sev).or_insert(0) += 1;
            let cat = format!("{:?}", alert.category);
            *alert_summary.by_category.entry(cat).or_insert(0) += 1;
            *rule_counts.entry(alert.rule_id).or_insert(0) += 1;
        }
    }

    // Sort and take top N
    let mut top_commands: Vec<_> = command_counts.into_iter().collect();
    top_commands.sort_by(|a, b| b.1.cmp(&a.1));
    top_commands.truncate(10);

    let mut top_paths: Vec<_> = path_counts.into_iter().collect();
    top_paths.sort_by(|a, b| b.1.cmp(&a.1));
    top_paths.truncate(10);

    let mut top_rules: Vec<_> = rule_counts.into_iter().collect();
    top_rules.sort_by(|a, b| b.1.cmp(&a.1));
    top_rules.truncate(10);
    alert_summary.top_rules = top_rules;

    // Time range
    let time_range = if events.is_empty() {
        None
    } else {
        let first = events.first().unwrap().event.timestamp;
        let last = events.last().unwrap().event.timestamp;
        Some((first, last))
    };

    // Anomalies
    let mut anomalies = Vec::new();
    if parse_errors > 0 {
        anomalies.push(format!("{} lines failed to parse", parse_errors));
    }
    if matches!(integrity, IntegrityStatus::Failed(_)) {
        anomalies.push("Hash chain integrity verification failed".to_string());
    }

    let report = DigestReport {
        generated_at: Utc::now(),
        log_path: log_path.to_string_lossy().to_string(),
        event_count: events.len(),
        time_range,
        integrity,
        alert_summary,
        top_commands,
        top_paths,
        anomalies,
    };

    // Output
    match format {
        "json" => {
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        _ => {
            print_markdown_report(&report);
        }
    }

    Ok(())
}

fn event_to_detector_input(event: &CollectorEvent) -> detector::DetectorInput {
    if let Some(proc) = &event.proc {
        if !proc.cmdline.is_empty() {
            let comm = proc.cmdline.first().cloned().unwrap_or_default();
            return detector::DetectorInput::Exec {
                pid: proc.pid,
                uid: proc.uid,
                comm,
                argv: proc.cmdline.clone(),
                cwd: proc.cwd.as_ref().map(|p| p.to_string_lossy().to_string()),
            };
        }
    }

    let op = match event.file.kind {
        collector::FileEventKind::Create => detector::FileOp::Write,
        collector::FileEventKind::Modify => detector::FileOp::Write,
        collector::FileEventKind::Delete => detector::FileOp::Unlink,
    };

    let (pid, uid) = event.proc.as_ref().map(|p| (p.pid, p.uid)).unwrap_or((0, 0));

    detector::DetectorInput::FileOp {
        pid,
        uid,
        op,
        path: event.file.path.to_string_lossy().to_string(),
    }
}

fn print_markdown_report(report: &DigestReport) {
    println!("# Clauditor Digest Report");
    println!();
    println!("**Generated:** {}", report.generated_at);
    println!("**Log:** {}", report.log_path);
    println!("**Events:** {}", report.event_count);
    println!();

    if let Some((start, end)) = report.time_range {
        println!("## Time Range");
        println!("- **Start:** {}", start);
        println!("- **End:** {}", end);
        println!();
    }

    println!("## Integrity");
    match &report.integrity {
        IntegrityStatus::Verified => println!("✅ Hash chain verified"),
        IntegrityStatus::NoKeyProvided => println!("⚠️ No key provided, integrity not checked"),
        IntegrityStatus::Failed(e) => println!("❌ Verification failed: {}", e),
    }
    println!();

    println!("## Alert Summary");
    println!("**Total alerts:** {}", report.alert_summary.total);
    println!();

    if !report.alert_summary.by_severity.is_empty() {
        println!("### By Severity");
        for (sev, count) in &report.alert_summary.by_severity {
            println!("- {}: {}", sev, count);
        }
        println!();
    }

    if !report.alert_summary.by_category.is_empty() {
        println!("### By Category");
        for (cat, count) in &report.alert_summary.by_category {
            println!("- {}: {}", cat, count);
        }
        println!();
    }

    if !report.alert_summary.top_rules.is_empty() {
        println!("### Top Rules");
        for (rule, count) in &report.alert_summary.top_rules {
            println!("- {}: {}", rule, count);
        }
        println!();
    }

    if !report.top_commands.is_empty() {
        println!("## Top Commands");
        for (cmd, count) in &report.top_commands {
            println!("- `{}`: {}", cmd, count);
        }
        println!();
    }

    if !report.top_paths.is_empty() {
        println!("## Top Paths");
        for (path, count) in &report.top_paths {
            println!("- `{}`: {}", path, count);
        }
        println!();
    }

    if !report.anomalies.is_empty() {
        println!("## Anomalies");
        for anomaly in &report.anomalies {
            println!("- ⚠️ {}", anomaly);
        }
        println!();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_wizard_config() {
        let config_str = r#"
[collector]
watch_paths = ["/home/clawdbot"]
target_uid = 1000

[writer]
log_path = "/var/lib/.sysd/.audit/events.log"
fsync = "periodic"
fsync_interval = 100
max_size_bytes = 104857600

[alerter]
min_severity = "medium"
queue_path = "/var/lib/.sysd/.audit/alerts.queue"

[[alerter.channels]]
type = "clawdbot_wake"

[[alerter.channels]]
type = "syslog"
facility = "local0"
"#;

        let config: DaemonConfig = toml::from_str(config_str).expect("config should parse");
        assert_eq!(config.collector.watch_paths.len(), 1);
        assert_eq!(config.collector.watch_paths[0], PathBuf::from("/home/clawdbot"));
        assert_eq!(config.collector.target_uid, 1000);

        let writer = config.writer.to_writer_config();
        assert_eq!(writer.path, PathBuf::from("/var/lib/.sysd/.audit/events.log"));
        assert_eq!(writer.max_size_bytes, 104857600);
        match writer.fsync {
            FsyncPolicy::Periodic(interval) => assert_eq!(interval, 100),
            other => panic!("expected periodic fsync, got {:?}", other),
        }

        assert_eq!(config.alerter.channels.len(), 2);
    }
}
