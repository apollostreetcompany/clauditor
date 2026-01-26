//! Clauditor CLI - Security audit watchdog for Clawdbot
//!
//! Subcommands:
//! - digest: Generate a summary report from logs

use chrono::{DateTime, Utc};
use clap::{Parser, Subcommand};
use collector::CollectorEvent;

use schema::verify_chain;
use serde::Serialize;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "clauditor")]
#[command(about = "Security audit watchdog for Clawdbot", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
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
