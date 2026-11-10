# Sentinel

**Research direction:** Reactive, Specification-Guided Testing of Linux Execution Policies

**Current status: execution-monitoring prototype plus a first Python policy model.** A draft file-object policy and five passing model fixtures are available. Kernel enforcement and guided generation are planned.

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

## Run the policy model

From the repository directory, without sudo:

    /usr/bin/python3 policy_model.py

The model predicts decisions for the [draft file-object policy](docs/policy_contract_v0.md). It identifies a file using device major/minor and inode numbers. Its five fixtures check the original file, another file, a symbolic link, a rename and a fresh copy. Temporary files are removed after the run.

A reported Ubuntu VM run matched all five fixed expected decisions. The fixtures inspect file identities; they never execute the copied programs and load no eBPF policy. `DENY` is an expected policy decision, not evidence of kernel blocking. `ALLOW` means this policy adds no denial; other Linux checks still apply.

## Files

- `phase3_sentinel.py`: kernel observer, event reader and alert rules.
- `phase4_demo.py`: controlled demonstration using benign commands.
- `policy_model.py`: independent policy predictions and five filesystem fixtures.
- `docs/policy_contract_v0.md`: draft rule, scope, identities and expected cases.
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

The first draft contract and a Python model core with five filesystem fixtures are implemented. Remaining work: review security updates and the final supported lab kernel; build independent execution-outcome checks, workload-scoped enforcement, broader deterministic tests, valid random and guided generation, reactive selection, failing-sequence reduction and equal-budget evaluation with repeated seeds.

The remaining research components are not implemented. The five model passes do not verify an enforcer or the full contract. No novelty, security vulnerability or performance improvement has been established.
