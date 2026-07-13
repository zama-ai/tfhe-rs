#!/usr/bin/env bash
set -euo pipefail

# Wait for any running apt/dpkg process to release locks.
# Prevents race with boot-time unattended-upgrades on cloud instances.

MAX_WAIT=120
WAITED=0

while sudo fuser /var/lib/dpkg/lock-frontend /var/lib/apt/lists/lock >/dev/null 2>&1; do
  if [ "$WAITED" -ge "$MAX_WAIT" ]; then
    echo "ERROR: apt lock still held after ${MAX_WAIT}s" >&2
    exit 1
  fi
  echo "Waiting for apt lock to be released... (${WAITED}s elapsed)"
  sleep 5
  WAITED=$((WAITED + 5))
done

# Kill the automatic update timers to prevent them from re-acquiring locks
sudo systemctl mask --now unattended-upgrades 2>/dev/null || true
sudo systemctl stop unattended-upgrades 2>/dev/null || true
sudo systemctl disable --now apt-daily.timer apt-daily-upgrade.timer 2>/dev/null || true
