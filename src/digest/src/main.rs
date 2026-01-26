//! clauditor-digest: Report generator
//! 
//! Scans audit logs and produces human-readable security reports.

use anyhow::Result;
use chrono::{Duration, Utc};

fn main() -> Result<()> {
    let now = Utc::now();
    let period_start = now - Duration::days(1);
    
    println!("# Security Digest");
    println!();
    println!("**Period**: {} to {}", 
        period_start.format("%Y-%m-%d %H:%M"),
        now.format("%Y-%m-%d %H:%M")
    );
    println!();
    
    // TODO: Bead 7 - Parse log files and generate report
    println!("*No events to report.*");
    
    Ok(())
}
