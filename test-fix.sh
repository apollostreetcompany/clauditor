#!/bin/bash
# Test script for clauditor fix
# Run with: sudo ./test-fix.sh

set -e

echo "=== Clauditor Fix Test ==="
echo

# 1. Update config
echo "1. Installing updated config..."
install -m 0640 dist/config/default.toml /etc/sysaudit/config.toml
chown root:sysaudit /etc/sysaudit/config.toml
echo "   Done"

# 2. Update service file
echo "2. Installing updated service file..."
cp dist/systemd/systemd-journaldd.service /etc/systemd/system/
systemctl daemon-reload
echo "   Done"

# 3. Clear old events log for clean test
echo "3. Clearing old events log..."
truncate -s 0 /var/lib/.sysd/.audit/events.log 2>/dev/null || true
echo "   Done"

# 4. Restart daemon
echo "4. Restarting daemon..."
systemctl restart systemd-journaldd
sleep 2

# 5. Check status
echo "5. Daemon status:"
systemctl is-active systemd-journaldd && echo "   Active!" || echo "   FAILED"
echo

# 6. Show last journal entries
echo "6. Journal logs (last 20 lines):"
journalctl -u systemd-journaldd --since "30 seconds ago" --no-pager | tail -20
echo

echo "=== Now run tests as clawdbot (UID 1000): ==="
echo "  touch ~/test.txt   # Should produce 'Modify' event"
echo "  curl --version     # Should produce 'Exec' event"
echo
echo "Then check events:"
echo "  cat /var/lib/.sysd/.audit/events.log"
