#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# chmodsnoop Trace chmod() syscalls.
#           For Linux, uses BCC, eBPF. Embedded C.
#
# USAGE: chmodsnoop [-h]
#
# Copyright 2021 Zhongqiu Han 13301259660@163.com.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 27-may-2021   Zhongqiu Han   Created this.

from __future__ import print_function
from bcc import BPF
import argparse

# arguments
examples = """examples:
    ./chmodsnoop           # trace all chmod() syscalls
"""
parser = argparse.ArgumentParser(
    description="Trace chmod() syscalls",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
args = parser.parse_args()
debug = 0

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <uapi/linux/limits.h>
#include <linux/sched.h>
#include <linux/pid_namespace.h>

struct val_t {
    const char *fname;
    short mode;
};

struct data_t {
    u32 pid;
    u64 ts_ns;
    int ret;
    char comm[TASK_COMM_LEN];
    char fname[NAME_MAX];
    u64 nsid;
    short mode;
};

BPF_HASH(args_filename, u32, const char *);
BPF_HASH(infotmp, u32, struct val_t);
BPF_PERF_OUTPUT(events);

int syscall__entry(struct pt_regs *ctx, int dfd, const char __user *filename, umode_t mode)
{
    struct val_t val = {};
    u32 pid = bpf_get_current_pid_tgid();

    FILTER
    val.fname = filename;
    val.mode = mode;
    infotmp.update(&pid, &val);

    return 0;
};

int trace_return(struct pt_regs *ctx, int dfd, const char __user *filename, umode_t mode)
{
    struct task_struct *task = (typeof(task))bpf_get_current_task();
    u32 pid = bpf_get_current_pid_tgid();
    struct val_t *valp;

    valp = infotmp.lookup(&pid);
    if (valp == 0) {
        // missed entry
        return 0;
    }

    struct data_t data = {.pid = pid};
    bpf_probe_read_user(&data.fname, sizeof(data.fname), (void *)valp->fname);
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.ts_ns = bpf_ktime_get_ns();
    data.mode = valp->mode;
    data.nsid = task->nsproxy->pid_ns_for_children->ns.inum;
    data.ret = PT_REGS_RC(ctx);

    events.perf_submit(ctx, &data, sizeof(data));
    infotmp.delete(&pid);
    args_filename.delete(&pid);

    return 0;
}
"""
bpf_text = bpf_text.replace('FILTER', '')


# initialize BPF
b = BPF(text=bpf_text)

# for POSIX compliance, all architectures implement these
# system calls but the name of the actual entry point may
# be different for which we must check if the entry points
# actually exist before attaching the probes
syscall_fnname = b.get_syscall_fnname("chmod")
if BPF.ksymname(syscall_fnname) != -1:
    b.attach_kprobe(event=syscall_fnname, fn_name="syscall__entry")
    b.attach_kretprobe(event=syscall_fnname, fn_name="trace_return")

syscall_fnname = b.get_syscall_fnname("chmodat")
if BPF.ksymname(syscall_fnname) != -1:
    b.attach_kprobe(event=syscall_fnname, fn_name="syscall__entry")
    b.attach_kretprobe(event=syscall_fnname, fn_name="trace_return")

syscall_fnname = b.get_syscall_fnname("fchmodat")
if BPF.ksymname(syscall_fnname) != -1:
    b.attach_kprobe(event=syscall_fnname, fn_name="syscall__entry")
    b.attach_kretprobe(event=syscall_fnname, fn_name="trace_return")

start_ts = 0
prev_ts = 0
delta = 0

# header
print("%-6s %-16s %4s %3s %s %6s %16s" % ("PID", "COMM", "FD", "ERR", "PATH", "MODE", "NS"))

# process event
def print_event(cpu, data, size):
    event = b["events"].event(data)
    global start_ts
    global prev_ts
    global delta
    global cont

    # split return value into FD and errno columns
    if event.ret >= 0:
        fd_s = event.ret
        err = 0
    else:
        fd_s = -1
        err = - event.ret

    if start_ts == 0:
        start_ts = event.ts_ns

    print("%-6d %-16s %4d %3d %s %6s %16ld" % (event.pid,
        event.comm.decode('utf-8', 'replace'), fd_s, err,
        event.fname.decode('utf-8', 'replace'), oct(event.mode), event.nsid))

# loop with callback to print_event
b["events"].open_perf_buffer(print_event, page_cnt=64)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
