# Requested-path/file-object fault result

Recorded: 2026-11-10. The pathname mutant was detected in two fresh fixed-order trials. This is a second planted fault family, tested separately from the inode mutant; it is not random/guided evaluation.

## Fault and correct control

The contract identifies an allowed file using device major/minor and inode. A symbolic link or rename can change the pathname used to reach that object without changing its file identity.

The new diagnostic adds registered_path[128] to the policy value used by both generated C programs. Their map layout is 144 bytes, compared with the original 16-byte identity value. The correct control keeps the original device/inode decision and ignores that extra path field. It therefore checks the new layout before the mutant is graded; it is not byte-for-byte identical to the earlier published C.

The mutant replaces the identity decision with comparison of bprm->filename against A's original registered pathname. It retains the exact cgroup lookup and incoming-BPF-return gate. Its kernel pointer/string reads are checked, its comparison is bounded to 128 bytes, and read failures/truncation invalidate the experiment. Userspace qualifies absolute fixture paths at no more than 126 bytes so a terminating NUL fits unambiguously.

The correct control and mutant use the same model expectations. Actual verdicts come from the native ELF token, close-on-exec exec-error pipe and child exit status. Every mismatch is recorded before checking this fault's expected signature. The signature is diagnostic knowledge about a planted fault, not a generator or a selection strategy.

## Recorded observations

| Case | Model | Correct control, both trials | Path mutant, both trials |
|---|---|---|---|
| allow_original | ALLOW | Executed | Executed |
| deny_other | DENY | EPERM | EPERM |
| allow_symlink | ALLOW | Executed | EPERM: false denial |
| allow_renamed | ALLOW | Executed | EPERM: false denial |
| deny_copy | DENY | EPERM | EPERM |
| allow_outside_scope | ALLOW | Executed | Executed |

| Measurement | Trial 1 | Trial 2 | Total |
|---|---|---|---|
| Baseline executions succeeded | 6/6 | 6/6 | 12/12 |
| Correct-control decisions matched | 6/6 | 6/6 | 12/12 |
| Mutant checks | 6 | 6 | 12 |
| Mutant mismatches | 2 | 2 | 4 false-denial observations |

All executed cases reached the correct ELF marker, exited 0 and reported no exec error. Denials required EPERM, no entry marker and harness status 125. No identity/path read error invalidated a case. First mismatch was position 3 of each fixed mutant sequence, excluding the baseline and control checks. It is not a random/guided tests-to-first-detection result.

## Lab, source and cleanup

- Successful run printed kernel 6.8.0-149-generic in SentinelLab, Ubuntu 24.04. Recorded system BCC packages are 0.29.1+ds-1ubuntu7.
- Unit: sentinel-enforcement-check.service; invocation 5894d0539ea143c0a1cbc6c6ca581f69.
- Fresh workload IDs: 11418 and 11436. These historical IDs are not reusable policy settings.
- The controller stayed outside the workload group. Both reference and both mutant probes detached, both temporary groups were removed and the service exited 0.
- Whole-service runtime: 16.361 seconds, including setup, compilation, baselines, controls, mutant checks and cleanup. It is not an enforcement-overhead measurement or a comparison with the inode diagnostic's runtime.
- The earlier inode result was published in 81b8ec9. The checkpoint containing this record includes mutant_path_check.py and docs/fault_catalog_v0.md.

The successful run demonstrates BCC compilation, verifier acceptance and the observed pathname behaviour on this lab kernel. It does not establish behaviour on other kernels or arbitrary paths.

## Reproduce

Keep mutant_path_check.py beside enforcement_check.py, mutant_inode_check.py, policy_model.py and scope_handle_check.py in ~/runtime-sentinel. The diagnostic reuses the inode module's fixture qualification and independent outcome helper; it does not load that module's mutant. Root, the verified kernel, active BPF-LSM, system BCC, matching headers, a C compiler and cgroup v2 delegation are required.

    sudo systemd-run --unit=sentinel-enforcement-check --uid=root --wait --pipe --collect --property=Delegate=yes --property=DelegateSubgroup=controller --property=RuntimeMaxSec=90s /usr/bin/python3 -u "$HOME/runtime-sentinel/mutant_path_check.py"

The 90 seconds is a maximum runtime. The script changes no existing source file or persistent boot configuration. Check detachment/removal messages and successful service exit as well as the detection summary.

## Limits and follow-up

This is one planted pathname fault, repeated twice. The inode and pathname diagnostics together cover two fault families in four separate fresh trials, not a joint seeded experiment. No general mutation score, novelty, Linux/product vulnerability or guided-testing advantage is established. A product intentionally enforcing pathname rules has a different contract; this experiment does not show a defect in such a product.

Actual earlier-BPF-denial composition, broader faults, stateful generators and random/guided evaluation remain untested. The fault catalog separates observed results from proposed or unexercised operators. Next, add a same-basename different-object witness before grading a basename-based mutant; the current alias cases alone do not distinguish that fault adequately from full-path comparison. An independent immutable experiment boundary is still required before any scope-removing mutant.
