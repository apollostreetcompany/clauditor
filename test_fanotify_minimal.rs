//! Minimal fanotify test matching clauditor's setup
//! Compile: rustc test_fanotify_minimal.rs -o /tmp/test_fan
//! Run: sudo /tmp/test_fan

use std::ffi::CString;
use std::os::unix::io::FromRawFd;
use std::os::unix::io::AsRawFd;

const FAN_CLASS_NOTIF: libc::c_uint = 0x00;
const FAN_UNLIMITED_QUEUE: libc::c_uint = 0x10;
const FAN_UNLIMITED_MARKS: libc::c_uint = 0x20;
const FAN_CLOEXEC: libc::c_uint = 0x01;

const FAN_MARK_ADD: libc::c_uint = 0x01;
const FAN_MARK_MOUNT: libc::c_uint = 0x10;

const FAN_OPEN: u64 = 0x20;
const FAN_CLOSE_WRITE: u64 = 0x08;
const FAN_CLOSE_NOWRITE: u64 = 0x10;
const FAN_CLOSE: u64 = FAN_CLOSE_WRITE | FAN_CLOSE_NOWRITE;
const FAN_OPEN_EXEC: u64 = 0x00001000;

const AT_FDCWD: libc::c_int = -100;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct FanotifyEventMetadata {
    event_len: u32,
    vers: u8,
    reserved: u8,
    metadata_len: u16,
    mask: u64,
    fd: i32,
    pid: i32,
}

fn main() {
    println!("=== Minimal fanotify test (matching clauditor) ===");
    println!("UID: {}, EUID: {}", unsafe { libc::getuid() }, unsafe { libc::geteuid() });
    
    // Same flags as clauditor
    let flags = FAN_CLASS_NOTIF | FAN_UNLIMITED_QUEUE | FAN_UNLIMITED_MARKS | FAN_CLOEXEC;
    let event_flags = libc::O_RDONLY | libc::O_LARGEFILE;
    
    let fd = unsafe { libc::fanotify_init(flags, event_flags as u32) };
    if fd < 0 {
        let err = std::io::Error::last_os_error();
        eprintln!("fanotify_init FAILED: {} (errno={})", err, err.raw_os_error().unwrap_or(-1));
        std::process::exit(1);
    }
    println!("fanotify_init OK: fd={}", fd);
    
    // Same mask as clauditor
    let mask = FAN_OPEN | FAN_CLOSE | FAN_OPEN_EXEC;
    let mark_flags = FAN_MARK_ADD | FAN_MARK_MOUNT;
    
    // Mark "/" like clauditor does
    let path = CString::new("/").unwrap();
    let ret = unsafe {
        libc::fanotify_mark(fd, mark_flags, mask, AT_FDCWD, path.as_ptr())
    };
    if ret < 0 {
        let err = std::io::Error::last_os_error();
        eprintln!("fanotify_mark('/') FAILED: {} (errno={})", err, err.raw_os_error().unwrap_or(-1));
        unsafe { libc::close(fd); }
        std::process::exit(1);
    }
    println!("fanotify_mark('/') OK: flags={:#x} mask={:#x}", mark_flags, mask);
    
    // Also mark /home/clawdbot
    let path2 = CString::new("/home/clawdbot").unwrap();
    let ret = unsafe {
        libc::fanotify_mark(fd, mark_flags, mask, AT_FDCWD, path2.as_ptr())
    };
    if ret < 0 {
        let err = std::io::Error::last_os_error();
        eprintln!("fanotify_mark('/home/clawdbot') FAILED: {} (errno={})", err, err.raw_os_error().unwrap_or(-1));
    } else {
        println!("fanotify_mark('/home/clawdbot') OK");
    }
    
    println!("\nWaiting for events...");
    println!("Try: touch /tmp/test_$$ OR cat /etc/passwd");
    println!("Press Ctrl+C to exit\n");
    
    let mut buffer = vec![0u8; 8192];
    let mut event_count = 0u32;
    
    loop {
        let n = unsafe {
            libc::read(fd, buffer.as_mut_ptr() as *mut libc::c_void, buffer.len())
        };
        
        if n < 0 {
            let err = std::io::Error::last_os_error();
            eprintln!("read FAILED: {} (errno={})", err, err.raw_os_error().unwrap_or(-1));
            break;
        }
        
        println!("read() returned {} bytes", n);
        
        let mut offset = 0usize;
        while offset + std::mem::size_of::<FanotifyEventMetadata>() <= n as usize {
            let meta = unsafe {
                std::ptr::read(buffer.as_ptr().add(offset) as *const FanotifyEventMetadata)
            };
            
            if meta.event_len == 0 {
                break;
            }
            
            // Get path from fd
            let path = if meta.fd >= 0 {
                let fd_path = format!("/proc/self/fd/{}", meta.fd);
                std::fs::read_link(&fd_path).ok()
            } else {
                None
            };
            
            // Get UID from /proc/pid/status
            let uid = if meta.pid > 0 {
                let status_path = format!("/proc/{}/status", meta.pid);
                std::fs::read_to_string(&status_path)
                    .ok()
                    .and_then(|s| {
                        s.lines()
                            .find(|l| l.starts_with("Uid:"))
                            .and_then(|l| l.split_whitespace().nth(1))
                            .and_then(|u| u.parse::<u32>().ok())
                    })
            } else {
                None
            };
            
            event_count += 1;
            println!(
                "EVENT #{}: pid={} mask={:#x} uid={:?} path={:?}",
                event_count, meta.pid, meta.mask, uid, path
            );
            
            // Close event fd
            if meta.fd >= 0 {
                unsafe { libc::close(meta.fd); }
            }
            
            offset += meta.event_len as usize;
        }
        
        if event_count >= 10 {
            println!("\nGot 10 events, stopping.");
            break;
        }
    }
    
    unsafe { libc::close(fd); }
}
