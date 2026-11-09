# Sentinel

**Research direction:** Reactive, Specification-Guided Testing of Linux Execution Policies

**Current status: working execution-monitoring prototype.** Policy testing, enforcement and guided generation are planned.

## What works

A restricted C probe observes `syscalls:sys_enter_execve` through Python BCC. It collects process TGID (shown as PID), parent TGID, real UID, caller name, parent name and requested filename. It reads parent information through `task_struct->real_parent` and sends records through a perf buffer.

Python flags selected application parents requesting shell or network-tool execution. The terminal displays the first three received events and every matching alert. UID alone is not an alert condition.

## Setup

Use Linux with suitable eBPF support, kernel headers and root privileges. On Ubuntu, install the distribution BCC packages:

    sudo apt update
    sudo apt install -y python3-bpfcc bpfcc-tools
    /usr/bin/python3 -c 'from bcc import BPF; print("BCC import OK")'

The development environment used Ubuntu on WSL2. Where the kernel provides embedded headers, `sudo modprobe kheaders` can expose `/sys/kernel/kheaders.tar.xz`. Support depends on the actual kernel. Importing BCC alone does not verify probe loading.

See the [BCC installation guide](https://github.com/iovisor/bcc/blob/master/INSTALL.md). Dependencies and kernel versions are not yet pinned for portable reproduction.

## Run

From the repository directory:

    sudo /usr/bin/python3 -u phase3_sentinel.py --demo

The demo exercises a harmless `true` program, a shell, and a shell sending a fixed message through a local loopback socket. Expected decisions are no alert for the harmless case and alerts for both shell cases. Background activity can add events and alerts. Match the unique printed filenames with the alerts.

After attachment, the default monitoring period is 20 seconds. Startup and cleanup add to elapsed time. The demo runs before polling, so its messages can appear before queued event messages.

For a separate monitor and test harness, use two terminals in the repository directory:

    sudo /usr/bin/python3 -u phase3_sentinel.py --seconds 60

After it prints `Attached`, run this in the second terminal:

    /usr/bin/python3 -S phase4_demo.py

## Files

- `phase3_sentinel.py`: kernel observer, event reader and alert rules.
- `phase4_demo.py`: controlled demonstration using benign commands.
- `PROJECT_STATE.md`: progress, evidence, limits and next action.

## Evidence and limits

A recorded development run produced `received=45 alerts=2 perf_lost=0 possibly_truncated_paths=0`. Earlier complete output also confirmed the local marker and a clean exit. These demonstrate those cases, not general detection accuracy or performance.

- Events record execution attempts, not successful execution. The monitor does not block programs or inspect network connections to confirm reverse shells.
- Parent and executable names are heuristics. Legitimate shell launches can alert; changed names and aliases can evade rules.
- Possibly truncated 128-byte filenames are counted and skipped by the alert rules. An exact fit can also be flagged.
- Helper-read failures, unchecked submission errors, `execveat` and startup/shutdown gaps limit coverage. Zero reported perf losses does not prove complete capture.
- CPU buffers can deliver records in a different order. The filename is a user-memory snapshot, not verified file identity.
- An earlier user/kernel PID-number difference remains unresolved. Unique demo paths provide the recorded correlation.
- Startup handling remains prototype code. A privileged user can stop the monitor.

## Research roadmap

Can tests guided by a precise execution-policy specification and current state find and explain mismatches more efficiently than valid random tests?

Planned work: one narrow policy contract, an independent expected-result model, workload-scoped enforcement in a disposable environment, independent outcome checks, deterministic tests, valid random and guided generation, reactive selection, failing-sequence reduction and equal-budget evaluation with repeated seeds.

These research components are not implemented. No novelty, security vulnerability or performance improvement has been established.
