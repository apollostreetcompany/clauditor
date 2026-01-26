# fanotify Mount Namespace Issue - Root Cause and Fix

## Problem Summary

The clauditor daemon was not receiving any fanotify events despite:
- `fanotify_init()` succeeding with CAP_SYS_ADMIN
- `fanotify_mark()` succeeding on "/" and "/home/clawdbot"
- The daemon having correct capabilities (CAP_SYS_ADMIN, CAP_DAC_READ_SEARCH)

## Root Cause

**fanotify events are NOT delivered across mount namespace boundaries.**

The systemd service was configured with `ProtectSystem=strict`, which creates a new mount namespace for the service. When a process in the host mount namespace performs file operations, those events are NOT delivered to a fanotify listener running in a different mount namespace.

This is a **known kernel limitation**, documented in:
- https://lkml.org/lkml/2015/10/29/268
- https://lists.debian.org/debian-kernel/2017/09/msg00191.html

## How Mount Namespaces Break fanotify

```
┌─────────────────────────────────────────────────────────────┐
│                    Host Mount Namespace                      │
│                                                              │
│  clawdbot user runs:                                        │
│    touch /home/clawdbot/file.txt                            │
│                                                              │
│  Event generated on /dev/md2 (ext4 filesystem)              │
│                       │                                      │
│                       ▼                                      │
│  Kernel fanotify: "Is there a listener in THIS namespace?"  │
│                       │                                      │
│                       ▼                                      │
│                  NO LISTENER (daemon is elsewhere)           │
│                       │                                      │
│                       ▼                                      │
│               EVENT DROPPED                                  │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│              Service Mount Namespace (ProtectSystem=strict)  │
│                                                              │
│  clauditor daemon:                                          │
│    fanotify_init() → OK                                     │
│    fanotify_mark("/") → OK                                  │
│    read() → BLOCKS FOREVER (no events arrive)              │
│                                                              │
│  The daemon IS listening, but in a DIFFERENT namespace!     │
└─────────────────────────────────────────────────────────────┘
```

## The Fix

Remove mount-namespace-creating options from the systemd service:

```diff
-ProtectSystem=strict
-ProtectHome=read-only
-PrivateTmp=true
-PrivateDevices=true
-RestrictNamespaces=true
+# !! DISABLED - creates mount namespace, breaks fanotify !!
+# ProtectSystem=strict
+# ProtectHome=read-only
+# PrivateTmp=true
+# PrivateDevices=true
+# RestrictNamespaces=true
```

## Applying the Fix

```bash
# Copy the fixed service file
sudo cp /home/clawdbot/clawd/skills/clauditor/dist/systemd/systemd-journaldd.service \
        /etc/systemd/system/systemd-journaldd.service

# Reload systemd and restart
sudo systemctl daemon-reload
sudo systemctl restart systemd-journaldd

# Verify it's running
systemctl status systemd-journaldd

# Test - touch a file and check logs
touch /tmp/test_event
sudo journalctl -u systemd-journaldd -f
```

## Security Implications

Removing these protections does reduce isolation, but the daemon:
1. Still runs as a dedicated `sysaudit` user (not root)
2. Still has `NoNewPrivileges=true`
3. Still has capability bounding set limited to CAP_SYS_ADMIN and CAP_DAC_READ_SEARCH
4. Still has syscall filtering via seccomp
5. Still has kernel protection options enabled

The trade-off is necessary because fanotify **requires** being in the same mount namespace as the processes it monitors.

## Alternative Approaches (Not Implemented)

1. **Run daemon in host namespace explicitly**: Use `PrivateMounts=no` or run outside of systemd
2. **Use FAN_REPORT_FID with separate namespace**: More complex, requires kernel 5.1+
3. **Use audit subsystem instead**: Different approach entirely (auditd)

## Verification

After applying the fix, verify fanotify is working:

```bash
# Check daemon logs
sudo journalctl -u systemd-journaldd --since "1 min ago"

# Look for:
# - "privileged collector active"
# - "fanotify_mark OK"
# - Event logs like "daemon received event: path=..."
```

## Kernel Versions Affected

This is a fundamental fanotify limitation, not a bug. It affects all Linux kernel versions that support fanotify with mount namespaces.

- Tested on: Linux 6.8.0-90-generic (Ubuntu 24.04)
- Expected to affect: All kernels with fanotify support
