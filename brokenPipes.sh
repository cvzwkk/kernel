#!/usr/bin/env bash

# Configuration
LOG_FILE="/var/log/pipe-sentinel.log"
CHECK_INTERVAL=5 # Seconds between sweeps

if [[ $EUID -ne 0 ]]; then
   echo "[-] Error: This script must be run as root." >&2
   exit 1
fi

log_message() {
    local level="$1"
    local msg="$2"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $msg" | tee -a "$LOG_FILE"
}

log_message "INFO" "Starting Advanced Zero Trust Pipe Sentinel service..."

while true; do
    # ----------------------------------------------------
    # Method 1: Kernel & Systemd Journal Pipe Error Scan
    # ----------------------------------------------------
    BROKEN_PIPES=$(journalctl -k --since "10s ago" --grep="Broken pipe|EPIPE|sigpipe" --no-pager 2>/dev/null || true)
    if [[ -n "$BROKEN_PIPES" ]]; then
        log_message "WARN" "Kernel-level EPIPE / SIGPIPE event detected:"
        while IFS=read -r line; do
            log_message "DETAIL" "$line"
        done <<< "$BROKEN_PIPES"
    fi

    # ----------------------------------------------------
    # Method 2: Scan for Orphaned/Dangling Unix Sockets
    # (Fixes broken IPC pipes where client crashed leaving dead socket files)
    # ----------------------------------------------------
    STALE_SOCKETS=$(find /tmp /run -type s -xtype l 2>/dev/null || true)
    if [[ -n "$STALE_SOCKETS" ]]; then
        log_message "WARN" "Stale Unix domain sockets found (causes broken IPC pipes):"
        while IFS=read -r sock; do
            log_message "FIX" "Removing dead socket link: $sock"
            rm -f "$sock"
        done <<< "$STALE_SOCKETS"
    fi

    # ----------------------------------------------------
    # Method 3: Monitor Hung/Close-Wait Socket Congestion
    # (High volumes of CLOSE_WAIT or FIN_WAIT can break client-server pipes)
    # ----------------------------------------------------
    CLOSE_WAIT_COUNT=$(ss -t -a 'state close-wait' 2>/dev/null | wc -l || echo 0)
    if [[ "$CLOSE_WAIT_COUNT" -gt 15 ]]; then
        log_message "WARN" "High count of CLOSE_WAIT sockets detected ($CLOSE_WAIT_COUNT). Potential hung IPC/network pipes."
        # Optional safe action: log warning or notify process group
    fi

    # ----------------------------------------------------
    # Method 4: Zombie Process Cleanup
    # ----------------------------------------------------
    ZOMBIES=$(ps -eo pid,stat,cmd | awk '$2 ~ /Z/ {print $1, $3}')
    if [[ -n "$ZOMBIES" ]]; then
        log_message "WARN" "Zombie processes detected holding block/pipe states:"
        while IFS=read -r zproc; do
            log_message "DETAIL" "Zombie Process Info: $zproc"
        done <<< "$ZOMBIES"
    fi

    sleep "$CHECK_INTERVAL"
done
