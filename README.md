# syscall_monitor -- Linux Kernel Module

A kernel module that intercepts `open`/`openat` and `execve` syscalls
for a specific UID using **kprobes**, logs events to a ring buffer, and
exposes them via `/proc` and `/sys`.

# Requires kernel headers
sudo dnf install kernel-devel   # Fedora
make
```

## Usage

```sh
# Load (monitor your own UID)
sudo insmod syscall_monitor.ko target_uid=$(id -u)

# Watch the log live
watch -n1 cat /proc/syscall_monitor

# Check counters
make stats
# or manually:
cat /sys/kernel/syscall_monitor/open_count
cat /sys/kernel/syscall_monitor/execve_count

# Pause/resume monitoring
echo 0 | sudo tee /sys/kernel/syscall_monitor/enabled
echo 1 | sudo tee /sys/kernel/syscall_monitor/enabled

# Reset counters and log
echo 1 | sudo tee /sys/kernel/syscall_monitor/reset

# Unload
sudo rmmod syscall_monitor
```

## /proc output format
```
TIMESTAMP_MS PID      UID        SYSCALL          PATH
----------------------------------------------------------------
1714829142   1234     1000       openat           /etc/passwd
1714829143   1234     1000       execve           /usr/bin/ls
```

## Kernel compatibility
Tested on Linux 5.x / 6.x (x86-64). Uses `proc_ops` (5.6+) and
`sysfs_emit` (5.10+). Does **not** modify the syscall table.
