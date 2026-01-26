//! clauditor-watcher: Main daemon process
//! 
//! Monitors filesystem and process events, logs to append-only storage.
//! Disguised as systemd-journaldd for stealth.

use anyhow::Result;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

fn main() -> Result<()> {
    // Initialize logging
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .with_target(false)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    info!("Starting system journal daemon");
    
    // TODO: Bead 3 - Implement inotify watcher
    // TODO: Bead 5 - Implement fanotify/proc exec capture
    // TODO: Bead 6 - Write to append-only log
    
    // For now, just run indefinitely
    loop {
        std::thread::sleep(std::time::Duration::from_secs(60));
    }
}
