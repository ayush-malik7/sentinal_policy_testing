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

## GA kernel and cgroup-ID lookup checks (2026-11-10)

- The user confirmed a fresh pre-kernel-change snapshot and approved the GA kernel installation and test boot. No kernel packages were removed.
- Running test kernel: 6.8.0-149-generic. Matching kernel headers are installed. This boot was selected once with grub-reboot; persistent lab boot selection remains pending.
- Active LSM list reported: lockdown,capability,landlock,yama,apparmor,bpf.
- CONFIG_BPF=y, CONFIG_BPF_SYSCALL=y, CONFIG_BPF_LSM=y, CONFIG_SECURITY=y and CONFIG_DEBUG_INFO_BTF=y were verified in the installed kernel configuration.
- CONFIG_INTEGRITY=y, CONFIG_IMA=y and CONFIG_EVM=y were also verified. IMA/EVM are not separately listed in the reported active LSM list on this kernel; their policy enforcement has not been audited by these checks.
- BCC Python/library packages remain 0.29.1+ds-1ubuntu7. Kernel 7.0 was only simulated, not installed through this work.
- GCC/Make development tools and Perl were installed for Guest Additions. Its 7.1.10 vboxguest/vboxsf module files have 6.8.0-149 vermagic. Its vboxvideo build failed on an undeclared drm_fb_helper_alloc_info; that graphics build issue remains unresolved. The actual display device is 15ad:0405 and the booted VM uses Ubuntu's vmwgfx driver. Complete Guest Additions feature validation is not claimed.
- Observer demo on 6.8: received=118, alerts=2, perf_lost=0, possibly_truncated_paths=0. Normal true produced no matching alert; shell and loopback cases alerted, the marker arrived and shutdown completed.
- Canonical lookup now uses name_to_handle_at on the cgroup v2 directory, following the Linux BPF self-test method for its eight-byte cgroup ID. An unexpected handle size or syscall error stops the check; there is no inode fallback. The executable-file identity model remains device major/minor plus inode.

| Canonical test context | Child PID | Userspace file-handle ID | LSM-observed ID | Outcome |
|---|---:|---:|---:|---|
| SSH session-6.scope | 21837 | 8922 | 8922 | PASS; child exit 0; probe detached |
| sentinel-handle-check.service | 21894 | 9692 | 9692 | PASS; child exit 0; probe detached; service exit 0 |

- IDs and PIDs above are recorded evidence for those runs, not reusable policy bindings. Directory inode values coincided but were diagnostic only in these canonical checks.
- scope_identity_check.py is retained as the earlier inode-comparison diagnostic. scope_handle_check.py is the canonical lookup diagnostic.
- These tests validate real LSM attachment and identifier agreement for the tested children. A kernel scope filter, independent execution-outcome harness, blocking and prior-denial composition tests remain pending. Launching the diagnostic in a service did not restrict its LSM hook to that cgroup.
- The last build-tools installation reported 535 other package upgrades pending. A fully patched user-space baseline is not claimed. No accuracy or performance benchmark was performed.

## Research question and scope

Can valid tests guided by a precise policy specification and current state find and explain execution-policy mismatches more efficiently than valid random testing?

Start with one allow/deny policy family, a dedicated workload and benign executables. Define path versus file-object identity and supported operations explicitly. Keep the expected-result model separate from the enforcer. Classify ordinary filesystem errors, unsupported semantics, model errors and flaky results separately from confirmed mismatches.

## Milestones and next actions

1. Completed: published the five-file baseline on `main`, commit `644af5a`.
2. Completed: checked WSL and Ubuntu VM environments, prepared the SentinelLab clone and snapshot, activated BPF-LSM, installed and test-booted Ubuntu GA 6.8.0-149, reproduced the observer demo and verified canonical cgroup-ID lookup. Pending: persistent lab boot selection and review of other package updates.
3. Completed: wrote a draft file-object contract, passed five Python model fixtures and verified file-handle/kernel cgroup-ID agreement in two contexts. Next: implement an observation-only kernel scope filter with the controller outside a dedicated workload cgroup, then independent execution-outcome checks and a workload-scoped reference enforcer.
4. Expand to approximately 15-20 deterministic cases and validate the harness with explicitly labelled faults in our own reference implementation.
5. Compare deterministic, valid random and guided tests under equal budgets with repeated seeds. Add reactive selection and a reducer gradually; retain raw JSON/CSV and negative results.
6. Review related work before claiming novelty. Investigate a small FLORAS example separately as a possible methodological connection. Add one real-engine adapter only after checking documented semantics. Defer concurrency and policy updates.

Update this file after completed phases. Label plans and unverified work clearly.
