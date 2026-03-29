#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <linux/spinlock.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/string.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Sajal");
MODULE_DESCRIPTION("Per-UID syscall monitor: intercepts open/openat/execve "
                   "and exposes logs via /proc and stats via /sys");
MODULE_VERSION("1.0");

static unsigned int target_uid = 1000;
module_param(target_uid, uint, 0644);
MODULE_PARM_DESC(target_uid, "UID to monitor (default: 1000)");

#define LOG_ENTRIES  512
#define PATH_LEN     128

struct log_entry {
    ktime_t    ts;
    pid_t      pid;
    uid_t      uid;
    char       syscall[16];
    char       path[PATH_LEN];
};

static struct log_entry ring[LOG_ENTRIES];
static unsigned int     ring_head;   /* next write index */
static unsigned int     ring_count;  /* entries written so far */
static DEFINE_SPINLOCK(ring_lock);

static void ring_push(const char *syscall, const char *path)
{
    unsigned long flags;
    spin_lock_irqsave(&ring_lock, flags);

    unsigned int idx = ring_head % LOG_ENTRIES;
    ring[idx].ts  = ktime_get_real();
    ring[idx].pid = task_pid_nr(current);
    ring[idx].uid = from_kuid(&init_user_ns, current_uid());
    strncpy(ring[idx].syscall, syscall, sizeof(ring[idx].syscall) - 1);
    strncpy(ring[idx].path,    path,    sizeof(ring[idx].path)    - 1);

    ring_head++;
    if (ring_count < LOG_ENTRIES) ring_count++;

    spin_unlock_irqrestore(&ring_lock, flags);
}

static atomic64_t cnt_open   = ATOMIC64_INIT(0);
static atomic64_t cnt_execve = ATOMIC64_INIT(0);
static int        enabled    = 1;

static bool should_monitor(void)
{
    if (!enabled) return false;
    uid_t uid = from_kuid(&init_user_ns, current_uid());
    return (target_uid == (unsigned int)-1) || (uid == target_uid);
}

static int handler_pre_openat(struct kprobe *p, struct pt_regs *regs)
{
    if (!should_monitor()) return 0;

    atomic64_inc(&cnt_open);

    struct pt_regs *inner = (struct pt_regs *)regs->di;
    const char __user *upath = (const char __user *)inner->si;
    char path[PATH_LEN] = "<unknown>";
    if (upath)
        strncpy_from_user(path, upath, sizeof(path) - 1);

    ring_push("openat", path);
    return 0;
}

static int handler_pre_execve(struct kprobe *p, struct pt_regs *regs)
{
    if (!should_monitor()) return 0;

    atomic64_inc(&cnt_execve);

    struct pt_regs *inner = (struct pt_regs *)regs->di;
    const char __user *upath = (const char __user *)inner->di;
    char path[PATH_LEN] = "<unknown>";
    if (upath)
        strncpy_from_user(path, upath, sizeof(path) - 1);

    ring_push("execve", path);
    return 0;
}

static struct kprobe kp_openat = {
    .symbol_name = "__x64_sys_openat",
    .pre_handler = handler_pre_openat,
};

static struct kprobe kp_execve = {
    .symbol_name = "__x64_sys_execve",
    .pre_handler = handler_pre_execve,
};

static int proc_show(struct seq_file *m, void *v)
{
    unsigned long flags;
    spin_lock_irqsave(&ring_lock, flags);

    unsigned int total  = ring_count;
    unsigned int start  = (ring_head >= LOG_ENTRIES)
                          ? ring_head % LOG_ENTRIES : 0;

    seq_printf(m, "%-12s %-8s %-10s %-16s %s\n",
               "TIMESTAMP_MS", "PID", "UID", "SYSCALL", "PATH");
    seq_puts(m, "----------------------------------------------------------------\n");

    for (unsigned int i = 0; i < total; i++) {
        unsigned int idx = (start + i) % LOG_ENTRIES;
        s64 ms = ktime_to_ms(ring[idx].ts);
        seq_printf(m, "%-12lld %-8d %-10u %-16s %s\n",
                   (long long)ms,
                   ring[idx].pid,
                   ring[idx].uid,
                   ring[idx].syscall,
                   ring[idx].path);
    }

    spin_unlock_irqrestore(&ring_lock, flags);
    return 0;
}

static int proc_open_fn(struct inode *inode, struct file *file)
{
    return single_open(file, proc_show, NULL);
}

static const struct proc_ops proc_fops = {
    .proc_open    = proc_open_fn,
    .proc_read    = seq_read,
    .proc_lseek   = seq_lseek,
    .proc_release = single_release,
};

static struct proc_dir_entry *proc_entry;

static struct kobject *sysmon_kobj;

static ssize_t open_count_show(struct kobject *kobj,
                                struct kobj_attribute *attr, char *buf)
{
    return sysfs_emit(buf, "%lld\n", atomic64_read(&cnt_open));
}
static struct kobj_attribute attr_open_count =
    __ATTR(open_count, 0444, open_count_show, NULL);

static ssize_t execve_count_show(struct kobject *kobj,
                                  struct kobj_attribute *attr, char *buf)
{
    return sysfs_emit(buf, "%lld\n", atomic64_read(&cnt_execve));
}
static struct kobj_attribute attr_execve_count =
    __ATTR(execve_count, 0444, execve_count_show, NULL);

static ssize_t uid_show(struct kobject *kobj,
                         struct kobj_attribute *attr, char *buf)
{
    return sysfs_emit(buf, "%u\n", target_uid);
}
static struct kobj_attribute attr_uid =
    __ATTR(target_uid, 0444, uid_show, NULL);

static ssize_t enabled_show(struct kobject *kobj,
                              struct kobj_attribute *attr, char *buf)
{
    return sysfs_emit(buf, "%d\n", enabled);
}
static ssize_t enabled_store(struct kobject *kobj,
                               struct kobj_attribute *attr,
                               const char *buf, size_t count)
{
    int val;
    if (kstrtoint(buf, 10, &val) || (val != 0 && val != 1))
        return -EINVAL;
    enabled = val;
    pr_info("syscall_monitor: monitoring %s\n", enabled ? "enabled" : "disabled");
    return count;
}
static struct kobj_attribute attr_enabled =
    __ATTR(enabled, 0644, enabled_show, enabled_store);

static ssize_t reset_store(struct kobject *kobj,
                             struct kobj_attribute *attr,
                             const char *buf, size_t count)
{
    atomic64_set(&cnt_open,   0);
    atomic64_set(&cnt_execve, 0);

    unsigned long flags;
    spin_lock_irqsave(&ring_lock, flags);
    ring_head  = 0;
    ring_count = 0;
    spin_unlock_irqrestore(&ring_lock, flags);

    pr_info("syscall_monitor: counters and log reset\n");
    return count;
}
static struct kobj_attribute attr_reset =
    __ATTR(reset, 0200, NULL, reset_store);

static struct attribute *sysmon_attrs[] = {
    &attr_open_count.attr,
    &attr_execve_count.attr,
    &attr_uid.attr,
    &attr_enabled.attr,
    &attr_reset.attr,
    NULL,
};
static struct attribute_group sysmon_group = {
    .attrs = sysmon_attrs,
};

static int __init sysmon_init(void)
{
    int ret;

    ret = register_kprobe(&kp_openat);
    if (ret < 0) {
        pr_err("syscall_monitor: register_kprobe openat failed: %d\n", ret);
        return ret;
    }

    ret = register_kprobe(&kp_execve);
    if (ret < 0) {
        pr_err("syscall_monitor: register_kprobe execve failed: %d\n", ret);
        unregister_kprobe(&kp_openat);
        return ret;
    }

    proc_entry = proc_create("syscall_monitor", 0444, NULL, &proc_fops);
    if (!proc_entry) {
        pr_err("syscall_monitor: proc_create failed\n");
        unregister_kprobe(&kp_openat);
        unregister_kprobe(&kp_execve);
        return -ENOMEM;
    }

    sysmon_kobj = kobject_create_and_add("syscall_monitor", kernel_kobj);
    if (!sysmon_kobj) {
        pr_err("syscall_monitor: kobject_create failed\n");
        remove_proc_entry("syscall_monitor", NULL);
        unregister_kprobe(&kp_openat);
        unregister_kprobe(&kp_execve);
        return -ENOMEM;
    }

    ret = sysfs_create_group(sysmon_kobj, &sysmon_group);
    if (ret) {
        kobject_put(sysmon_kobj);
        remove_proc_entry("syscall_monitor", NULL);
        unregister_kprobe(&kp_openat);
        unregister_kprobe(&kp_execve);
        return ret;
    }

    pr_info("syscall_monitor: loaded — monitoring UID %u\n", target_uid);
    pr_info("syscall_monitor: log   -> /proc/syscall_monitor\n");
    pr_info("syscall_monitor: stats -> /sys/kernel/syscall_monitor/\n");
    return 0;
}

static void __exit sysmon_exit(void)
{
    unregister_kprobe(&kp_execve);
    unregister_kprobe(&kp_openat);
    remove_proc_entry("syscall_monitor", NULL);
    sysfs_remove_group(sysmon_kobj, &sysmon_group);
    kobject_put(sysmon_kobj);
    pr_info("syscall_monitor: unloaded\n");
}

module_init(sysmon_init);
module_exit(sysmon_exit);
