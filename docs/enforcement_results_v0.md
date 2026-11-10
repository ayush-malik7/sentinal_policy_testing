# First fixed-case kernel-enforcement result

Recorded: 2026-11-10. This record describes a terminal-observed lab run, not a performance or random/guided evaluation.

## Lab and implementation

- SentinelLab VirtualBox clone, Ubuntu 24.04; running kernel 6.8.0-149-generic.
- System BCC Python/library packages: 0.29.1+ds-1ubuntu7. BPF-LSM was active.
- Source: enforcement_check.py, importing policy_model.py and scope_handle_check.py. The checkpoint containing this record also records the source for reproduction. The preceding published checkpoint was 741fca9.
- Hook: bprm_check_security. Policy scope: the exact registered, live workload cgroup v2 ID.
- File identity: device major number, device minor number and inode number. The allowed file stayed open until the experiment ended.
- Controller: /system.slice/sentinel-enforcement-check.service/controller. In-scope children entered the sibling workload group before exec. The outside-scope child remained in the controller group.
- Filesystem operations were completed during fixture setup; no concurrent file mutations, namespace changes or policy updates were tested.

## What was measured

Each fixture first executed with no Sentinel BPF program loaded. A fresh token printed by the controlled native ELF program, empty exec-error pipe and exit 0 established successful execution.

The same prepared fixtures were then checked under the reference policy. A denied case required execv to fail with EPERM, no ELF entry marker and the harness's dedicated exit status 125. That status is a reporting convention; errno 1 is the actual EPERM error. Other errors, missing markers or timeouts invalidate a case instead of counting as a correct denial. Kernel file-identity read errors also invalidate the experiment.

BPF decision logs were not used as the outcome oracle.

| Case | Scope | Baseline | Model expectation | Observed under policy |
|---|---|---|---|---|
| allow_original | Inside | Marker; exit 0 | ALLOW | Marker; exit 0 |
| deny_other | Inside | Marker; exit 0 | DENY | EPERM; no marker; harness exit 125 |
| allow_symlink | Inside | Marker; exit 0 | ALLOW | Marker; exit 0 |
| allow_renamed | Inside | Marker; exit 0 | ALLOW | Marker; exit 0 |
| deny_copy | Inside | Marker; exit 0 | DENY | EPERM; no marker; harness exit 125 |
| allow_outside_scope | Outside | Marker; exit 0 | ALLOW | Marker; exit 0 |

Result: six of six baseline executions and six of six expected policy decisions matched in one enforcement run. The two actual denials were inside the selected workload cgroup. Four cases actually executed.

## Recorded run identifiers and cleanup

- Standalone baseline invocation: 5afc77815672411c8d71d28081690b15; workload ID 13544; service exit 0.
- Enforcement invocation: 7306c594df674957a5560a888f7c1c10; fresh workload ID 14728; service exit 0.
- Enforcement run terminal summary: ENFORCEMENT PASS: 6/6 matched the model.
- Reference enforcer detached and temporary workload cgroup removed.
- Reported enforcement service runtime: 6.153 seconds. This includes setup, compilation, baselines, enforcement and cleanup; it is not an enforcement-overhead measurement.
- Cgroup IDs above are historical evidence only. Resolve fresh IDs for every live test group; do not put these numbers into configuration.

Before this run, scope_filter_check.py classified outside PID 36846 in cgroup 11134 as in_scope=0 and inside PID 36847 in cgroup 11152 as in_scope=1. Both exited 0, the probe detached and the workload group was removed. That observation-only result supported scope classification, not blocking.

## Reproduce

Upload or check out all source files into ~/runtime-sentinel on the SentinelLab VM. Root, the system BCC package, matching kernel headers, a C compiler, active BPF-LSM and systemd delegation are required. The prepared lab has a recovery snapshot. These commands add no persistent policy or boot changes.

Baseline only, without loading BPF:

    sudo systemd-run --unit=sentinel-enforcement-check --uid=root --wait --pipe --collect --property=Delegate=yes --property=DelegateSubgroup=controller --property=RuntimeMaxSec=45s /usr/bin/python3 -u "$HOME/runtime-sentinel/enforcement_check.py" --baseline

Baseline followed by deliberate, workload-scoped blocking:

    sudo systemd-run --unit=sentinel-enforcement-check --uid=root --wait --pipe --collect --property=Delegate=yes --property=DelegateSubgroup=controller --property=RuntimeMaxSec=45s /usr/bin/python3 -u "$HOME/runtime-sentinel/enforcement_check.py" --enforce

The controller stays outside the controlled workload group. Each child has a three-second wait limit and the whole service a 45-second runtime limit. Do not infer successful cleanup from the six-case summary alone: check the detach/removal messages and successful service exit too.

## Limits and next experiment

This is a single six-case deterministic result. It does not establish 100 percent policy correctness, completeness, performance improvement, a new vulnerability, novelty, or an advantage over random testing. There was no real-engine comparison.

Actual earlier-BPF-denial composition, hardlinks, multiple allowed entries, executable inode reuse, concurrent mutation/migration, namespace changes and instrumentation failure paths were not tested. Some of those operations are outside the current v0 contract.

Follow-up: the [single-mutant experiment](mutant_inode_results_v0.md) ignored inode while retaining device and exact scope checks. In two fresh trials, the same-filesystem different-file and copy cases executed unexpectedly; the correct reference passed its six controls in each trial. This detected one deliberately inserted fault, not a vulnerability in Linux or another product.

Before testing any mutant that removes scope checking, add a separate immutable experiment boundary that enrolls only the intended test children, including the outside-scope control. The controller and other host processes must remain outside that boundary. The future random/guided evaluation needs fixed valid inputs, equal budgets, repeated seeds and explicit reporting of undetected runs.
