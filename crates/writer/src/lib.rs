//! Append-only log writer for clauditor.
//!
//! Features:
//! - O_APPEND mode for kernel-guaranteed atomic appends
//! - fsync policy (none, periodic, every)
//! - Log rotation support
//! - chattr +a integration (checked, not applied)

use chrono::Utc;
use collector::CollectorEvent;
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

/// Fsync policy for the writer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FsyncPolicy {
    /// Never fsync (fastest, least durable)
    None,
    /// Fsync every N writes
    Periodic(u32),
    /// Fsync after every write (slowest, most durable)
    Every,
}

impl Default for FsyncPolicy {
    fn default() -> Self {
        FsyncPolicy::Periodic(100)
    }
}

/// Configuration for the writer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WriterConfig {
    /// Path to the log file
    pub path: PathBuf,
    /// Fsync policy
    #[serde(default)]
    pub fsync: FsyncPolicy,
    /// Maximum file size before rotation (0 = no rotation)
    #[serde(default)]
    pub max_size_bytes: u64,
}

/// Append-only log writer.
pub struct AppendWriter {
    file: BufWriter<File>,
    config: WriterConfig,
    write_count: u32,
    bytes_written: u64,
}

impl AppendWriter {
    /// Create a new append-only writer.
    pub fn new(config: WriterConfig) -> io::Result<Self> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .custom_flags(libc::O_APPEND)
            .open(&config.path)?;

        // Get current file size
        let bytes_written = file.metadata()?.len();

        Ok(Self {
            file: BufWriter::new(file),
            config,
            write_count: 0,
            bytes_written,
        })
    }

    /// Write an event to the log.
    pub fn write_event(&mut self, event: &CollectorEvent) -> io::Result<()> {
        let line = serde_json::to_string(event)?;
        writeln!(self.file, "{}", line)?;

        self.bytes_written += line.len() as u64 + 1;
        self.write_count += 1;

        // Apply fsync policy
        match self.config.fsync {
            FsyncPolicy::None => {}
            FsyncPolicy::Every => {
                self.file.flush()?;
                self.file.get_ref().sync_data()?;
            }
            FsyncPolicy::Periodic(n) if self.write_count % n == 0 => {
                self.file.flush()?;
                self.file.get_ref().sync_data()?;
            }
            FsyncPolicy::Periodic(_) => {}
        }

        // Check for rotation
        if self.config.max_size_bytes > 0 && self.bytes_written >= self.config.max_size_bytes {
            self.rotate()?;
        }

        Ok(())
    }

    /// Rotate the log file.
    fn rotate(&mut self) -> io::Result<()> {
        self.file.flush()?;

        // Generate rotated filename with timestamp
        let timestamp = Utc::now().format("%Y%m%d_%H%M%S");
        let rotated = self.config.path.with_extension(format!("{}.log", timestamp));

        // Close current file by dropping the writer
        drop(std::mem::replace(
            &mut self.file,
            BufWriter::new(File::create("/dev/null")?),
        ));

        // Rename current to rotated
        std::fs::rename(&self.config.path, &rotated)?;

        // Open new file
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .custom_flags(libc::O_APPEND)
            .open(&self.config.path)?;

        self.file = BufWriter::new(file);
        self.bytes_written = 0;
        self.write_count = 0;

        Ok(())
    }

    /// Flush all buffered data.
    pub fn flush(&mut self) -> io::Result<()> {
        self.file.flush()?;
        self.file.get_ref().sync_data()
    }

    /// Check if the file has the append-only attribute (chattr +a).
    /// Returns Ok(true) if +a is set, Ok(false) if not, Err if check fails.
    pub fn check_append_only(path: impl AsRef<Path>) -> io::Result<bool> {
        use std::process::Command;

        let path = path.as_ref();
        if !path.exists() {
            return Ok(false);
        }

        // Use lsattr to check attributes
        let output = Command::new("lsattr")
            .arg("-d")
            .arg(path)
            .output()?;

        if !output.status.success() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "lsattr failed",
            ));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        // lsattr output format: "----a--------e----- /path/to/file"
        // The 'a' attribute is typically at position 4
        Ok(stdout.starts_with("----a") || stdout.contains("a"))
    }

    /// Get the number of bytes written since creation/rotation.
    pub fn bytes_written(&self) -> u64 {
        self.bytes_written
    }

    /// Get the path to the log file.
    pub fn path(&self) -> &Path {
        &self.config.path
    }
}

impl Drop for AppendWriter {
    fn drop(&mut self) {
        let _ = self.flush();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use collector::{CollectorEvent, FileEvent, FileEventKind, ProcInfo};
    use schema::{Event, EventKind};

    fn sample_event() -> CollectorEvent {
        let event = Event::new_genesis(
            b"test-key",
            Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap(),
            123,
            1000,
            EventKind::Message,
            "sess-1",
        );
        CollectorEvent {
            event,
            file: FileEvent {
                kind: FileEventKind::Create,
                path: PathBuf::from("/tmp/test.txt"),
            },
            proc: Some(ProcInfo {
                pid: 123,
                uid: 1000,
                cmdline: vec!["test".to_string()],
                cwd: Some(PathBuf::from("/home/test")),
            }),
        }
    }

    #[test]
    fn write_and_read_events() {
        let temp = tempfile::tempdir().unwrap();
        let log_path = temp.path().join("events.log");

        let config = WriterConfig {
            path: log_path.clone(),
            fsync: FsyncPolicy::Every,
            max_size_bytes: 0,
        };

        let mut writer = AppendWriter::new(config).unwrap();
        let event = sample_event();
        writer.write_event(&event).unwrap();
        writer.flush().unwrap();

        // Read back
        let content = std::fs::read_to_string(&log_path).unwrap();
        assert!(!content.is_empty());

        let parsed: CollectorEvent = serde_json::from_str(content.trim()).unwrap();
        assert_eq!(parsed.event.pid, 123);
        assert_eq!(parsed.file.kind, FileEventKind::Create);
    }

    #[test]
    fn append_mode_works() {
        let temp = tempfile::tempdir().unwrap();
        let log_path = temp.path().join("append.log");

        // Write first event
        {
            let config = WriterConfig {
                path: log_path.clone(),
                fsync: FsyncPolicy::None,
                max_size_bytes: 0,
            };
            let mut writer = AppendWriter::new(config).unwrap();
            writer.write_event(&sample_event()).unwrap();
        }

        // Write second event (new writer instance)
        {
            let config = WriterConfig {
                path: log_path.clone(),
                fsync: FsyncPolicy::None,
                max_size_bytes: 0,
            };
            let mut writer = AppendWriter::new(config).unwrap();
            writer.write_event(&sample_event()).unwrap();
        }

        // Should have 2 lines
        let content = std::fs::read_to_string(&log_path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2);
    }

    #[test]
    fn rotation_works() {
        let temp = tempfile::tempdir().unwrap();
        let log_path = temp.path().join("rotate.log");

        let config = WriterConfig {
            path: log_path.clone(),
            fsync: FsyncPolicy::None,
            max_size_bytes: 100, // Small limit to trigger rotation
        };

        let mut writer = AppendWriter::new(config).unwrap();
        
        // Write events until rotation
        for _ in 0..10 {
            writer.write_event(&sample_event()).unwrap();
        }

        // Check that rotated files exist
        let entries: Vec<_> = std::fs::read_dir(temp.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .collect();
        
        // Should have at least 2 files (current + rotated)
        assert!(entries.len() >= 2, "expected rotation to create multiple files");
    }
}
