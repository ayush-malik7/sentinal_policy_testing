#!/usr/bin/python3
import argparse
import os
import subprocess
import sys
import time
from bcc import BPF

BPF_PROGRAM = r"""
#include <linux/sched.h>

struct event_t {
    u32 pid;
    u32 ppid;
    u32 uid;
    u32 filename_maybe_truncated;
    char comm[TASK_COMM_LEN];
    char parent_comm[TASK_COMM_LEN];
    char filename[128];
};

BPF_PERF_OUTPUT(events);

TRACEPOINT_PROBE(syscalls, sys_enter_execve)
{
    struct event_t event = {};
    struct task_struct *task =
        (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent = NULL;

    if (!task)
        return 0;

    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = (u32)bpf_get_current_uid_gid();

    if (bpf_get_current_comm(event.comm, sizeof(event.comm)) != 0)
        return 0;

    if (bpf_probe_read_kernel(
            &parent, sizeof(parent), &task->real_parent) != 0)
        return 0;

    if (!parent)
        return 0;

    if (bpf_probe_read_kernel(
            &event.ppid, sizeof(event.ppid), &parent->tgid) != 0)
        return 0;

    if (bpf_probe_read_kernel_str(
            event.parent_comm, sizeof(event.parent_comm),
            parent->comm) <= 0)
        return 0;

    // filename is a user-space pointer supplied to execve.
    int length = bpf_probe_read_user_str(
        event.filename, sizeof(event.filename),
        (const void *)args->filename);

    if (length <= 0)
        return 0;

    event.filename_maybe_truncated =
        (length == sizeof(event.filename));

    events.perf_submit(args, &event, sizeof(event));
    return 0;
}
"""

parser = argparse.ArgumentParser()
parser.add_argument("--seconds", type=int, default=20)
parser.add_argument("--self-test", action="store_true")
parser.add_argument("--demo", action="store_true")
args = parser.parse_args()
if args.seconds <= 0:
    parser.error("--seconds must be positive")

APP_PARENTS = {"nginx", "apache2", "httpd", "node", "php-fpm"}
SHELLS = {"sh", "bash", "dash", "zsh", "ksh"}
NETWORK_TOOLS = {"nc", "ncat", "netcat"}

counts = {"received": 0, "alerts": 0, "lost": 0, "long_paths": 0}
RED = "\033[31m" if sys.stdout.isatty() else ""
RESET = "\033[0m" if RED else ""

def text(value):
    return bytes(value).split(b"\0", 1)[0].decode("utf-8", errors="replace")

def on_event(cpu, data, size):
    event = events.event(data)
    counts["received"] += 1

    parent = text(event.parent_comm)
    caller = text(event.comm)
    filename = text(event.filename)

    details = (
        f"pid={event.pid} ppid={event.ppid} uid={event.uid} "
        f"parent={parent!r} caller={caller!r} file={filename!r}"
    )

    # Show only three ordinary events to keep output manageable.
    if counts["received"] <= 3:
        print("[EVENT] " + details, flush=True)

    if event.filename_maybe_truncated:
        counts["long_paths"] += 1
        return

    target = os.path.basename(filename)
    application_parent = (
        parent in APP_PARENTS or parent.startswith("python")
    )

    if not application_parent:
        return

    if target in SHELLS:
        reason = "Suspicious shell execution attempt"
    elif target in NETWORK_TOOLS:
        reason = "Network utility execution attempt from application"
    else:
        return

    counts["alerts"] += 1
    print(f"{RED}[ALERT] {reason}: {details}{RESET}", flush=True)

def on_lost(count):
    counts["lost"] += count

def run_self_test():
    test = r"""
import os

directory = "/tmp/sentinel-check-" + os.urandom(6).hex()
os.mkdir(directory, 0o700)
executable = directory + "/sh"

try:
    os.symlink("/bin/sh", executable)

    with open("/proc/self/comm") as stream:
        name = stream.read().strip()

    child = os.fork()
    if child == 0:
        try:
            os.execv(executable, ["sh", "-c", "exit 0"])
        except OSError:
            os._exit(1)

    print(
        f"SELF-TEST expected_file={executable!r} parent={name!r} "
        f"parent_pid={os.getpid()} child_pid={child}",
        flush=True
    )

    with open("/proc/self/status") as stream:
        for line in stream:
            if line.startswith(("NStgid:", "NSpid:")):
                print("SELF-TEST parent " + line.strip(), flush=True)

    _, status = os.waitpid(child, 0)
    if status != 0:
        raise SystemExit("Test shell failed")
finally:
    if os.path.lexists(executable):
        os.unlink(executable)
    os.rmdir(directory)
"""
    subprocess.run(
        [sys.executable, "-S", "-c", test],
        check=True,
        timeout=5
    )

print("Compiling and attaching the probe...", flush=True)
b = BPF(text=BPF_PROGRAM)

try:
    events = b["events"]
    events.open_perf_buffer(on_event, lost_cb=on_lost)

    deadline = time.monotonic() + args.seconds
    print(
        f"Attached. Monitoring for {args.seconds} seconds; stops automatically.",
        flush=True
    )

    if args.self_test:
        run_self_test()

    if args.demo:
        demo_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "phase4_demo.py"
        )
        subprocess.run(
            [sys.executable, "-S", demo_path],
            check=True,
            timeout=8
        )

    while time.monotonic() < deadline:
        b.perf_buffer_poll(timeout=100)

except KeyboardInterrupt:
    print("Interrupted.", flush=True)
finally:
    for cpu in range(len(events)):
        del events[cpu]
    b.cleanup()
    print(
        f"Stopped. received={counts['received']} "
        f"alerts={counts['alerts']} perf_lost={counts['lost']} "
        f"possibly_truncated_paths={counts['long_paths']}",
        flush=True
    )
