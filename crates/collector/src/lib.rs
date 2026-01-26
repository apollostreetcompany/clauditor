use chrono::Utc;
use inotify::{Inotify, WatchDescriptor, WatchMask};
use schema::{Event, EventKind};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileEventKind {
    Create,
    Modify,
    Delete,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEvent {
    pub kind: FileEventKind,
    pub path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcInfo {
    pub pid: u32,
    pub uid: u32,
    pub cmdline: Vec<String>,
    pub cwd: Option<PathBuf>,
}

impl ProcInfo {
    pub fn from_pid(pid: u32) -> Option<Self> {
        let cmdline = read_cmdline(pid)?;
        let cwd = read_cwd(pid);
        let uid = read_uid(pid).unwrap_or(0);
        Some(Self {
            pid,
            uid,
            cmdline,
            cwd,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectorEvent {
    pub event: Event,
    pub file: FileEvent,
    pub proc: Option<ProcInfo>,
}

pub struct DevCollector {
    inotify: Inotify,
    buffer: Vec<u8>,
    session_id: String,
    key: Vec<u8>,
    last_event: Option<Event>,
    watch_paths: HashMap<WatchDescriptor, PathBuf>,
    default_pid: u32,
    default_uid: u32,
}

impl DevCollector {
    pub fn new(session_id: impl Into<String>, key: Vec<u8>) -> io::Result<Self> {
        let inotify = Inotify::init()?;
        Ok(Self {
            inotify,
            buffer: vec![0u8; 4096],
            session_id: session_id.into(),
            key,
            last_event: None,
            watch_paths: HashMap::new(),
            default_pid: std::process::id(),
            default_uid: unsafe { libc::geteuid() as u32 },
        })
    }

    pub fn add_watch(&mut self, path: impl AsRef<Path>) -> io::Result<WatchDescriptor> {
        let path = path.as_ref().to_path_buf();
        let mask = WatchMask::CREATE
            | WatchMask::MODIFY
            | WatchMask::DELETE
            | WatchMask::MOVED_FROM
            | WatchMask::MOVED_TO
            | WatchMask::CLOSE_WRITE;
        let wd = self.inotify.watches().add(&path, mask)?;
        self.watch_paths.insert(wd.clone(), path);
        Ok(wd)
    }

    pub fn read_available(&mut self) -> io::Result<Vec<CollectorEvent>> {
        let mut output = Vec::new();
        let events = self.inotify.read_events_blocking(&mut self.buffer)?;

        for event in events {
            let kind = match mask_to_kind(event.mask) {
                Some(kind) => kind,
                None => continue,
            };

            let base = match self.watch_paths.get(&event.wd) {
                Some(path) => path.clone(),
                None => continue,
            };

            let path = match event.name {
                Some(name) => base.join(name),
                None => base.clone(),
            };

            let proc_info = ProcInfo::from_pid(self.default_pid);
            let (pid, uid) = match &proc_info {
                Some(info) => (info.pid, info.uid),
                None => (self.default_pid, self.default_uid),
            };

            let timestamp = Utc::now();
            let schema_event = match &self.last_event {
                None => Event::new_genesis(
                    &self.key,
                    timestamp,
                    pid,
                    uid,
                    EventKind::Message,
                    self.session_id.clone(),
                ),
                Some(prev) => Event::new_next(
                    &self.key,
                    prev,
                    timestamp,
                    pid,
                    uid,
                    EventKind::Message,
                    self.session_id.clone(),
                ),
            };

            self.last_event = Some(schema_event.clone());

            output.push(CollectorEvent {
                event: schema_event,
                file: FileEvent { kind, path },
                proc: proc_info,
            });
        }

        Ok(output)
    }
}

/// Collector with start/stop lifecycle.
/// Runs the DevCollector in a background thread and delivers events via callback.
pub struct Collector {
    stop_flag: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl Collector {
    /// Start collecting file events.
    /// `watch_paths` - directories to watch
    /// `on_event` - callback invoked for each event (must be Send + 'static)
    pub fn start<F>(
        session_id: impl Into<String>,
        key: Vec<u8>,
        watch_paths: Vec<PathBuf>,
        on_event: F,
    ) -> io::Result<Self>
    where
        F: Fn(CollectorEvent) + Send + 'static,
    {
        let session_id = session_id.into();
        let stop_flag = Arc::new(AtomicBool::new(false));
        let stop_clone = Arc::clone(&stop_flag);

        let handle = thread::spawn(move || {
            let mut collector = match DevCollector::new(&session_id, key) {
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

            while !stop_clone.load(Ordering::Relaxed) {
                match collector.read_available() {
                    Ok(events) => {
                        for event in events {
                            on_event(event);
                        }
                    }
                    Err(e) => {
                        eprintln!("read error: {e}");
                        break;
                    }
                }
            }
        });

        Ok(Self {
            stop_flag,
            handle: Some(handle),
        })
    }

    /// Signal the collector to stop and wait for the thread to finish.
    pub fn stop(mut self) {
        self.stop_flag.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }

    /// Check if the collector is still running.
    pub fn is_running(&self) -> bool {
        self.handle.as_ref().map_or(false, |h| !h.is_finished())
    }
}

impl Drop for Collector {
    fn drop(&mut self) {
        self.stop_flag.store(true, Ordering::Relaxed);
    }
}

fn mask_to_kind(mask: inotify::EventMask) -> Option<FileEventKind> {
    if mask.contains(inotify::EventMask::CREATE) || mask.contains(inotify::EventMask::MOVED_TO) {
        return Some(FileEventKind::Create);
    }
    if mask.contains(inotify::EventMask::DELETE) || mask.contains(inotify::EventMask::MOVED_FROM) {
        return Some(FileEventKind::Delete);
    }
    if mask.contains(inotify::EventMask::MODIFY) || mask.contains(inotify::EventMask::CLOSE_WRITE) {
        return Some(FileEventKind::Modify);
    }
    None
}

fn read_cmdline(pid: u32) -> Option<Vec<String>> {
    let path = format!("/proc/{pid}/cmdline");
    let data = std::fs::read(path).ok()?;
    if data.is_empty() {
        return Some(Vec::new());
    }
    let parts = data
        .split(|b| *b == 0)
        .filter(|chunk| !chunk.is_empty())
        .map(|chunk| String::from_utf8_lossy(chunk).to_string())
        .collect::<Vec<_>>();
    Some(parts)
}

fn read_cwd(pid: u32) -> Option<PathBuf> {
    let path = format!("/proc/{pid}/cwd");
    std::fs::read_link(path).ok()
}

fn read_uid(pid: u32) -> Option<u32> {
    let path = format!("/proc/{pid}/status");
    let status = std::fs::read_to_string(path).ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            let uid_str = rest.split_whitespace().next()?;
            return uid_str.parse::<u32>().ok();
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{File, OpenOptions};
    use std::io::Write;
    #[test]
    fn emits_create_modify_delete_events() {
        let temp = tempfile::tempdir().unwrap();
        let file_path = temp.path().join("sample.txt");

        let mut collector = DevCollector::new("sess-1", b"test-key".to_vec()).unwrap();
        collector.add_watch(temp.path()).unwrap();

        File::create(&file_path).unwrap();
        let events = collector.read_available().unwrap();
        assert!(events.iter().any(|event| {
            event.file.kind == FileEventKind::Create && event.file.path == file_path
        }));

        let mut handle = OpenOptions::new().append(true).open(&file_path).unwrap();
        writeln!(handle, "hello").unwrap();
        drop(handle);

        let events = collector.read_available().unwrap();
        assert!(events.iter().any(|event| {
            event.file.kind == FileEventKind::Modify && event.file.path == file_path
        }));

        std::fs::remove_file(&file_path).unwrap();
        let events = collector.read_available().unwrap();
        assert!(events.iter().any(|event| {
            event.file.kind == FileEventKind::Delete && event.file.path == file_path
        }));
    }
}
