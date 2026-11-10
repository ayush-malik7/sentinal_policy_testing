# First single-mutant detection

Recorded: 2026-11-10. One deliberate inode-comparison fault was detected in two fresh fixed-order trials on the real lab kernel. This is a deterministic diagnostic, not a random/guided evaluation.

## Fault and oracle

The reference compares device major number, device minor number and inode number. The diagnostic makes exactly one checked C-source replacement: it removes the inode comparison. The device comparison, exact cgroup lookup, incoming-BPF-return handling and identity-read error counter remain in the source. No policy-model expectation is changed.

On the same device, a different file and a fresh copy have different inodes. The model expects their in-scope exec attempts to be denied. The faulty comparison wrongly accepts them. The reference and mutant are loaded separately; each reference probe detaches before its corresponding mutant loads.

Each trial uses fresh filesystem fixtures and a fresh workload cgroup. The allowed file stays open for the trial's lifetime. Baseline executions first establish that all six fixtures can run. Actual decisions are collected through the ELF program's fresh token marker, the close-on-exec exec-error pipe and child exit status, independently of BPF decision logs.

The script records every model mismatch before checking this planted fault's expected signature. An unexpected signature or instrumentation error stops the diagnostic for investigation. This signature check is not a generator or a selection strategy.

## Recorded results

| Measurement | Trial 1 | Trial 2 | Total |
|---|---|---|---|
| Baseline executions succeeded | 6/6 | 6/6 | 12/12 |
| Correct-reference decisions matched | 6/6 | 6/6 | 12/12 |
| Mutant cases checked | 6 | 6 | 12 |
| Mutant mismatches | 2 | 2 | 4 observations |

| Case | Model expectation | Reference, both trials | Mutant, both trials |
|---|---|---|---|
| allow_original | ALLOW | Executed | Executed |
| deny_other | DENY | EPERM; no marker | Executed; mismatch |
| allow_symlink | ALLOW | Executed | Executed |
| allow_renamed | ALLOW | Executed | Executed |
| deny_copy | DENY | EPERM; no marker | Executed; mismatch |
| allow_outside_scope | ALLOW | Executed | Executed |

All executed cases produced their correct markers, exit 0 and no exec error. Reference denials reported EPERM through the error pipe and used harness exit 125. No identity-read error invalidated a case.

The first mismatch was at position 2 of the fixed six-case mutant sequence in each trial, excluding the baseline and reference checks. This position is descriptive evidence, not a seeded random/guided tests-to-first-detection result.

Conclusion: the harness repeatedly detected one planted fault, witnessed by two case types. Four mismatch observations do not mean four faults, and two fresh trials do not mean two mutants or two random seeds.

## Lab and cleanup

- SentinelLab, Ubuntu 24.04; successful run printed kernel 6.8.0-149-generic. Recorded system BCC packages are 0.29.1+ds-1ubuntu7.
- Correct reference and six-case result were published in commit 7194e41. The checkpoint containing this record also includes mutant_inode_check.py.
- Controller: /system.slice/sentinel-enforcement-check.service/controller. Only in-scope test children entered the selected workload group.
- Fresh workload IDs were 10042 and 10060. These are historical observations, not reusable configuration; every live group is resolved again through its file handle.
- Both reference and both mutant probes detached. Both temporary workload groups were removed. Service exit status was 0.
- Whole service runtime was 21.293 seconds, including compilation, all baselines, reference checks, mutant checks and cleanup. It is not an enforcement-overhead measurement.
- A preceding launch on kernel 6.14.0-33-generic stopped at the version guard before loading BPF. Its failure is not counted as a detection.

## Reproduce

Keep mutant_inode_check.py beside enforcement_check.py, policy_model.py and scope_handle_check.py in ~/runtime-sentinel. This diagnostic requires the verified kernel 6.8.0-149-generic, active BPF-LSM, system BCC, matching kernel headers, a C compiler and cgroup v2 delegation.

    sudo systemd-run --unit=sentinel-enforcement-check --uid=root --wait --pipe --collect --property=Delegate=yes --property=DelegateSubgroup=controller --property=RuntimeMaxSec=90s /usr/bin/python3 -u "$HOME/runtime-sentinel/mutant_inode_check.py"

The 90 seconds is a maximum service runtime, not an expected duration. The script reuses the original service name to satisfy the reference delegation guard. It changes no existing source file or persistent boot setting.

## Limits and next work

No Linux/product vulnerability, novelty, general mutation score or random/guided advantage is established. The signature is known for this deliberately inserted fault. Actual earlier-denial composition remains untested; preserving its source branch is not a runtime composition test.

Next, define a small set of distinguishable fault operators with witnesses inside the supported contract. A mutant that cannot be exercised by the chosen domain must be labelled accordingly instead of silently counted as detected or omitted. For example, ignoring device identity cannot be distinguished by these all-on-one-device fixtures.

Before a scope-removing mutant, add a separate immutable experiment boundary enrolling only the intended test children, including the outside-scope control. Exclude the controller and other host processes. Then define valid shared inputs and coverage features before implementing random/guided selection. Guidance must not consult mutant labels or known triggering-case names. Use equal budgets and repeated seeds, and retain undetected runs in the analysis.
