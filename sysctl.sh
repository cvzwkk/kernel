#!bin/bash
sysctl() {
echo "# Set the kernel panic timeout to 10 seconds
kernel.panic=10
# Randomize the memory layout of the kernel to make it harder for attackers
kernel.randomize_va_space=2
# Enable kernel executable space protection
kernel.exec-shield = 2
# Use PID as core filename
kernel.core_uses_pid = 1
# Restrict access to kernel log buffer
kernel.dmesg_restrict = 1
# Restrict access to kernel pointers
kernel.kptr_restrict = 2
# Panic the system if a kernel oops occurs
kernel.panic_on_oops = 60
# Restrict access to perf events
kernel.perf_event_paranoid = 3
# Disable the sysrq key
kernel.sysrq = 0
# Disable unprivileged access to BPF (Berkeley Packet Filter) system calls
kernel.unprivileged_bpf_disabled = 1
# Set the ptrace scope to only allow tracing of direct child processes
kernel.yama.ptrace_scope = 2
# Increase the maximum number of process IDs to 65536
kernel.pid_max = 65536
# Reduce swapping
vm.swappiness = 10
# Set the ratio of memory pages allowed to get dirty to 60%
vm.dirty_ratio = 60
# Set the ratio of memory pages allowed to remain dirty to 2%
vm.dirty_background_ratio = 2
# Disable automatic loading of line disciplines for tty devices
dev.tty.ldisc_autoload = 0
# Increase the maximum number of open files to 65535
fs.file-max = 65535
# Set FIFOs protection level to 2 (only owner can read/write)
fs.protected_fifos = 2
# Disable setuid dumps
fs.suid_dumpable = 0
# Enable protection of hardlinks against modification
fs.protected_hardlinks=0
# Enable protection of symbolic links against exploitation
fs.protected_symlinks=0
# Enable Fair Queue packet scheduler as the default queuing discipline
net.core.default_qdisc = fq
# Set the default receive buffer size for all protocols to 256KB
net.core.rmem_default = 262144
# Set the maximum receive buffer size for all protocols to 16MB
net.core.rmem_max = 16777216
# Set the default send buffer size for all protocols to 256KB
net.core.wmem_default = 262144
# Set the maximum send buffer size for all protocols to 16MB
net.core.wmem_max = 16777216
# Set the maximum length of the listen queue backlog
net.core.somaxconn = 32768
# Set the maximum number of packets that can be queued on the input side of each network interface
net.core.netdev_max_backlog = 16384
# Set the default weight of all network interfaces to 64
net.core.dev_weight = 64
# Set the maximum socket buffer size allocatable to a single socket
net.core.optmem_max = 65535
# Enable hardened Berkeley Packet Filter (BPF) JIT compiler
net.core.bpf_jit_harden = 2
# Set the maximum receive buffer size for TCP connections to 8MB
net.ipv4.tcp_rmem_max = 8388608
# Set the maximum send buffer size for TCP connections to 8MB
net.ipv4.tcp_wmem_max = 8388608
# Set the maximum length of the listen queue backlog for all protocols to 5000
net.core.netdev_max_backlog = 5000
#Set the default receive buffer size for TCP connections
net.ipv4.tcp_rmem = 4096 87380 6291456
#Set the maximum receive buffer size for TCP connections to 16MB
net.ipv4.tcp_rmem_max = 16777216
#Set the maximum number of sockets allowed to queue up for accepting connections to 500
net.core.somaxconn = 500
#Enable TCP window scaling
net.ipv4.tcp_window_scaling = 1
#Enable TCP timestamps
net.ipv4.tcp_timestamps = 1
#Enable TCP selective acknowledgements
net.ipv4.tcp_sack = 1
#Enable TCP Fast Open
net.ipv4.tcp_fastopen = 3
#Increase TCP maximum syn backlog
net.ipv4.tcp_max_syn_backlog = 4096
#Increase the maximum number of open file descriptors
fs.file-max = 2097152
#Increase the maximum amount of memory allocated to each socket receive buffer
net.core.rmem_max = 16777216
#Increase the maximum amount of memory allocated to each socket send buffer
net.core.wmem_max = 16777216
#Increase the default amount of memory allocated to each socket receive buffer
net.core.rmem_default = 16777216
#Increase the default amount of memory allocated to each socket send buffer
net.core.wmem_default = 16777216
#Enable low latency mode
net.core.busy_poll = 50
#Decrease the amount of time a connection spends in the 'TIME_WAIT' state
net.ipv4.tcp_fin_timeout = 10
#Enable TCP keepalive
net.ipv4.tcp_keepalive_time = 1200
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_keepalive_probes = 3
#Enable SYN cookies
net.ipv4.tcp_syncookies = 1
#Enable automatic congestion control
net.ipv4.tcp_congestion_control = cubic
#Enable explicit congestion notification
net.ipv4.tcp_ecn = 2
#Disable TCP slow start after idle for 120 seconds
net.ipv4.tcp_slow_start_after_idle = 0
#Enable TCP window scaling
net.ipv4.tcp_window_scaling = 1
#Enable TCP selective acknowledgments
net.ipv4.tcp_sack = 1
#Enable TCP Fast Open
net.ipv4.tcp_fastopen = 3
#Enable TCP timestamps
net.ipv4.tcp_timestamps = 1
#Increase TCP buffer limits
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
#Increase the maximum number of open files and file descriptors
ulimit -n 1000000
#Increase the maximum number of user processes
ulimit -u 2048
#Increase the maximum number of memory map areas a process may have
vm.max_map_count = 262144" > /etc/sysctl.conf
}
sysctl
