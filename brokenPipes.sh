#!/usr/bin/env bash

# Configuration
LOG_FILE="/var/log/pipe-sentinel.log"
CHECK_INTERVAL=5 # Seconds between sweeps

# Ensure script is run as root
if [[ $EUID -ne 0 ]]; then
   echo "[-] Error: This script must be run as root." >&2
   exit 1
fi

log_message() {
    local level="$1"
    local msg="$2"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $msg" | tee -a "$LOG_FILE"
}

log_message "INFO" "Starting Zero Trust Pipe Sentinel service..."

# Main loop running in background
while true; do
    # 1. Scan kernel/system logs via journalctl for recent Broken Pipe (EPIPE) errors
    # We grep specifically for typical broken pipe indicators in system or application streams
    BROKEN_PIPES=$(journalctl -k --since "10s ago" --grep="Broken pipe\|EPIPE" --no-pager 2>/dev/null || true)

    if [[ -n "$BROKEN_PIPES" ]]; then
        log_message "WARN" "Broken pipe event detected in kernel/system logs:"
        while IFS=read -r line; do
            log_message "DETAIL" "$line"
        done <<< "$BROKEN_PIPES"

        # Action: Clear dead/stale temporary sockets or orphan descriptors causing pipe breaks
        log_message "INFO" "Executing cleanup of dangling sockets or orphaned descriptor files..."
        find /tmp -type s -name "*.sock" -xtype l -delete 2>/dev/null || true
    fi

    # 2. Check for zombie or hung processes holding broken/unresponsive IPC channels
    # Identifying processes in uninterruptible sleep (D state) or defunct zombies related to custom services
    ZOMBIES=$(ps -eo pid,stat,cmd | awk '$2 ~ /Z/ {print $1, $3}')
    if [[ -n "$ZOMBIES" ]]; then
        log_message "WARN" "Zombie processes detected (potential blocked IPC pipes):"
        while IFS=read -r zproc; do
            log_message "DETAIL" "Zombie Process Info: $zproc"
        done <<< "$ZOMBIES"
    fi

    sleep "$CHECK_INTERVAL"
done
