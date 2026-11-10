# Sentinel

**Research direction:** Reactive, Specification-Guided Testing of Linux Execution Policies

**Current status: a cgroup-scoped BCC reference enforcer passed its first six fixed execution cases.** Independent measurements confirmed four executions and two EPERM denials. Mutation testing and random-versus-guided evaluation are not implemented.

## First kernel-enforcement result

Recorded on 2026-11-10 in SentinelLab, Ubuntu 24.04, kernel `6.8.0-149-generic`, BCC `0.29.1+ds-1ubuntu7`.

| Case | Baseline without Sentinel | Expected with policy | Observed with policy |
|---|---|---|---|
| Original allowed file | Executed | ALLOW | Executed; correct marker; exit 0 |
| Different file in scope | Executed | DENY | exec failed with EPERM; no marker |
| Symbolic link to allowed file | Executed | ALLOW | Executed; correct marker; exit 0 |
| Allowed file after rename | Executed | ALLOW | Executed; correct marker; exit 0 |
| Fresh copy in scope | Executed | DENY | exec failed with EPERM; no marker |
| Different file outside scope | Executed | ALLOW | Executed; correct marker; exit 0 |

All six baseline executions and all six policy expectations matched in one recorded enforcement run. Outcomes came from an ELF entry marker, a close-on-exec exec-error pipe and child exit status, independently of BPF decision logs. Identity-read errors would invalidate a case; none were reported. The enforcer detached, temporary workload group was removed and the service exited successfully.

This is a small deterministic result, not an accuracy percentage, performance benchmark or proof of the whole contract. Earlier-denial composition, mutants and generator effectiveness are untested. See [the result record](docs/enforcement_results_v0.md) for the commands, evidence and remaining limits.

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

## Reproduce the execution checks

Run these commands inside the SentinelLab VM with BPF-LSM active. The controller stays in the delegated service's `controller` subgroup; only fresh in-scope children enter its separate `workload` subgroup. The service has a 45-second runtime limit. Python's system BCC package and the C compiler are required.

First check the fixtures and independent outcome measurement without loading BPF:

    sudo systemd-run --unit=sentinel-enforcement-check --uid=root --wait --pipe --collect --property=Delegate=yes --property=DelegateSubgroup=controller --property=RuntimeMaxSec=45s /usr/bin/python3 -u "$HOME/runtime-sentinel/enforcement_check.py" --baseline

Then run the same baseline followed by the scoped reference enforcer:

    sudo systemd-run --unit=sentinel-enforcement-check --uid=root --wait --pipe --collect --property=Delegate=yes --property=DelegateSubgroup=controller --property=RuntimeMaxSec=45s /usr/bin/python3 -u "$HOME/runtime-sentinel/enforcement_check.py" --enforce

The second command deliberately denies the two in-scope non-allowed files with EPERM. It adds no policy denial for the controller or the outside-scope fixture. The probe is temporary and detached during cleanup. Both commands require an existing `~/runtime-sentinel` checkout containing the model and scope-reader modules.

## Run the policy model

From the repository directory, without sudo:

    /usr/bin/python3 policy_model.py

The model predicts decisions for the [draft file-object policy](docs/policy_contract_v0.md). It identifies a file using device major/minor and inode numbers. Its five fixtures check the original file, another file, a symbolic link, a rename and a fresh copy. Temporary files are removed after the run.

A reported Ubuntu VM run matched all five fixed expected decisions. The fixtures inspect file identities; they never execute the copied programs and load no eBPF policy. `DENY` is an expected policy decision, not evidence of kernel blocking. `ALLOW` means this policy adds no denial; other Linux checks still apply.

## Check the LSM cgroup identifier

The reported lab test boot used Ubuntu 24.04, kernel `6.8.0-149-generic` and BCC `0.29.1+ds-1ubuntu7`, with `bpf` in the active LSM list. This was a one-time GRUB test selection; a persistent lab boot default has not been configured. The existing observer demo also passed on this kernel: 118 received events, two matching demo alerts, zero reported perf losses, the loopback marker and a clean exit.

From the repository directory, run the canonical identifier diagnostic:

    sudo /usr/bin/python3 -u scope_handle_check.py

Then run it in a separate temporary service cgroup:

    sudo systemd-run --unit=sentinel-handle-check --uid=root --wait --pipe --collect --property=RuntimeMaxSec=20s /usr/bin/python3 -u "$PWD/scope_handle_check.py"

The Python reader uses `name_to_handle_at()` to obtain the cgroup v2 file-handle ID. It checks the eight-byte ID format used by the [Linux BPF self-tests](https://kernel.googlesource.com/pub/scm/linux/kernel/git/torvalds/linux/+/5920da4455a393490309d6483636b9749ec785fd/tools/testing/selftests/bpf/cgroup_helpers.c). The LSM probe records `bpf_get_current_cgroup_id()` for a harmless child. PASS requires the two cgroup IDs to match for that child's PID; the directory inode is printed only for diagnosis, with no fallback to it.

Both reported runs passed. Recorded IDs were 8922 in the SSH session and 9692 in the temporary service. These are historical observations, not configuration constants. Resolve the ID of each live test cgroup again.

The LSM hook is attached system-wide and returns the incoming BPF decision unchanged. Running its loader in a service changes process membership, not the hook's attachment scope. These checks verify lookup and observation for the tested children; they do not test an inside/outside filter, blocking, prior-denial composition, namespaces or concurrent migration. The separate enforcement harness keeps its controller outside the controlled workload cgroup.

## Files

- `phase3_sentinel.py`: kernel observer, event reader and alert rules.
- `phase4_demo.py`: controlled demonstration using benign commands.
- `policy_model.py`: independent policy predictions and five filesystem fixtures.
- `scope_handle_check.py`: canonical file-handle/kernel cgroup-ID comparison.
- `scope_filter_check.py`: observation-only inside/outside LSM scope classification.
- `enforcement_check.py`: baseline and six-case kernel enforcement checks with independent outcomes.
- `docs/enforcement_results_v0.md`: first recorded kernel-enforcement result and reproduction details.
- `scope_identity_check.py`: earlier inode comparison diagnostic; not the policy's cgroup-ID lookup.
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

The draft contract, Python model, cgroup lookup and scope checks, independent execution-outcome harness and first scoped reference enforcer are implemented. Next: detect a deliberately inserted, scope-preserving fault, repeat its failing case, and build a reproducible mutant evaluation before integrating a real engine. Later work includes supported state transitions, valid random and coverage-guided generation, reduction and equal-budget evaluation over repeated seeds. Persistent lab boot selection and remaining package updates also need review.

Mutants, generators, reduction and comparative research evaluation are not implemented. The fixed-case enforcement result does not verify the full contract. No novelty, security vulnerability or performance improvement has been established.
