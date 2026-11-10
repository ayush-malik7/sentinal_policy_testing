# Sentinel project state

**Title:** Sentinel: Reactive, Specification-Guided Testing of Linux Execution Policies
**Repository:** https://github.com/ayush-malik7/sentinal_policy_testing
**Checkpoint:** 2026-11-10

## Verified baseline

- Current monitor and demo source reviewed on 2026-11-09.
- Git 2.53.0 reported; local repository initialized on branch `main`.
- `origin` configured to the repository above. Baseline published on 2026-11-09, commit `644af5a`.
- BCC execve-entry observation, checked parent metadata reads, perf transport and Python name rules are implemented.
- Bounded monitoring, self-test and three-case local demo are implemented.
- Historical output recorded 45 received events, two alerts and zero reported perf losses. Earlier complete output verified the loopback marker and clean shutdown. 
- Ubuntu VM demo verified at source commit db12bc0: received=124, alerts=2, perf_lost=0, possibly_truncated_paths=0. The normal case produced no alert; both shell cases alerted. The loopback marker arrived and automatic shutdown completed. Four compiler warnings from included kernel headers were recorded; the probe loaded and attached. This demonstration is not an accuracy or performance benchmark.

## Environment and limits

Original environment: Ubuntu WSL2, BCC 0.35.0 and kernel 6.18.33.2-microsoft-standard-WSL2. Embedded headers were available after loading kheaders. BPF-LSM was compiled in but inactive.

Source Ubuntu VM before cloning, verified on 2026-11-10: Ubuntu 24.04.2 LTS, kernel 6.14.0-33-generic, Git 2.43.0. BCC imports successfully; kernel build directory and BTF are present. CONFIG_BPF_LSM=y, but the active LSM list does not include bpf. Access through MobaXterm SSH is working. The package versions and later SentinelLab LSM verification are recorded below. Pending system updates and the final lab kernel still need review.

The observer does not prove execution success, prevention or policy correctness. It has name/path heuristics, truncation and event-loss gaps, no execveat coverage or network confirmation, and an unresolved user/kernel PID-number difference. Root can stop it. A Python policy-model core and five filesystem fixtures are implemented. The execution-outcome harness, reference enforcer, generator, reducer and research evaluation remain pending.

## SentinelLab LSM verification (2026-11-10)

- Lab: SentinelLab, a VirtualBox full clone.
- Snapshot: baseline-before-policy-changes, confirmed created.
- Verified kernel: 6.14.0-33-generic.
- Python reported while recording: 3.12.3.
- BCC packages reported: 0.29.1+ds-1ubuntu7.
- BPF-LSM active after reboot; all seven previous security modules retained.
- GRUB backup: /etc/default/grub.sentinel-before-bpf.
- Temporary bprm_check_security probe: counter=1; true exited 0; probe detached.
- This verifies basic attachment and activity, not policy correctness or performance.
- Blocking rules and research evaluation remain pending. The model checkpoint below records the later Python model work.

## Python policy-model checkpoint (2026-11-10)

- `docs/policy_contract_v0.md` records the draft cgroup-scoped file-object allowlist.
- `policy_model.py` calculates expected decisions independently of any enforcer.
- File identity uses device major number, device minor number and inode number, read through Python `os.stat`. Each fixture keeps the chosen file open during its operations.
- Reported Ubuntu VM results: allow_original=ALLOW, deny_other=DENY, allow_symlink=ALLOW, allow_renamed=ALLOW, deny_copy=DENY. All five matched the fixed contract expectations, and temporary files were removed.
- These fixtures inspect real filesystem identities but do not execute the copied ELF programs, create a test cgroup or load an enforcement probe. Kernel blocking has not been tested.
- Scope, prior-denial and supported-case facts are inputs to the model. These five fixtures use the supported, in-scope, no-prior-denial setting; they do not validate kernel cgroup membership or BPF denial chaining.

## Research question and scope

Can valid tests guided by a precise policy specification and current state find and explain execution-policy mismatches more efficiently than valid random testing?

Start with one allow/deny policy family, a dedicated workload and benign executables. Define path versus file-object identity and supported operations explicitly. Keep the expected-result model separate from the enforcer. Classify ordinary filesystem errors, unsupported semantics, model errors and flaky results separately from confirmed mismatches.

## Milestones and next actions

1. Completed: published the five-file baseline on `main`, commit `644af5a`.
2. Completed: checked WSL and Ubuntu VM environments and reproduced the observer demonstration in Ubuntu. SentinelLab full clone and baseline snapshot are complete. BPF-LSM activation and a temporary BCC LSM probe test passed. Next: review pending security updates and choose the final supported lab kernel before building the controlled execution-outcome harness and reference enforcer.
3. Completed: wrote a draft file-object contract and passed five Python model fixtures. Planned next: build independent execution-outcome checks and a workload-scoped reference enforcer after the environment review.
4. Expand to approximately 15-20 deterministic cases and validate the harness with explicitly labelled faults in our own reference implementation.
5. Compare deterministic, valid random and guided tests under equal budgets with repeated seeds. Add reactive selection and a reducer gradually; retain raw JSON/CSV and negative results.
6. Review related work before claiming novelty. Investigate a small FLORAS example separately as a possible methodological connection. Add one real-engine adapter only after checking documented semantics. Defer concurrency and policy updates.

Update this file after completed phases. Label plans and unverified work clearly.
