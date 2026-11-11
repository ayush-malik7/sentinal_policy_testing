# Sentinel project state

**Title:** Sentinel: Reactive, Specification-Guided Testing of Linux Execution Policies
**Repository:** https://github.com/ayush-malik7/sentinal_policy_testing
**Checkpoint:** 2026-11-11

## Selection preview and pre-data protocol (2026-11-11)

- The seven-case basename result and source were published in 8c98221. This checkpoint records selection_plan.py and docs/pilot_protocol_v0.md before kernel pilot data.
- The VM preview for seed 0 selected four distinct cases per method. Declared feature counts were random=39/52 and guided=46/52. This preview loaded no BPF program, executed no fixture and measured no detection outcome.
- Coverage consists of single facts and pairs from scope, object equality, pathname equality, basename equality and setup operation. IDs, temporary names and concrete inode numbers are not coverage tokens. A neutral-case-ID relabelling check preserved selections locally.
- Fixed settings: uniform random versus greedy feature novelty; both without replacement; common seven-case domain; budget four; seeds 0..29; exactly two fresh repetitions per seed. Mutant labels, verdicts and witness names are not selector inputs.
- The protocol keeps non-detection within budget as >4, retains failures and flaky/inconclusive outcomes, and requires logical-trace comparison across repetitions rather than equality of ephemeral identifiers.
- Local checks covered deterministic distinct-case plans, invalid inputs and filesystem-related feature declarations against the seven fixture layouts. Actual cgroup qualification, the common three-mutant runner and kernel pilot remain unimplemented. The prior seven-case diagnostic did not run ignore_inode on case seven.
- Next: common-runner implementation, source/data reporting and a small smoke test, followed by the frozen thirty-seed pilot. Semantic preview coverage is not comparative detection evidence; this remains a finite selection pilot, not stateful sequence generation.

## Same-basename comparison (2026-11-11)

- The pathname diagnostic and fault catalog were published in 8ce2650. This checkpoint adds mutant_basename_check.py and its result record.
- Kernel: 6.8.0-149-generic. Two fresh trials used workload IDs 13106 and 13124. The reference, full-path mutant and basename mutant shared a 160-byte policy-value layout; the correct control retained the device/inode decision.
- New fixture: deny_same_basename. The allowed file and copy were both named program_a, on device 8:2, with different inodes 3670097 and 3670098. The model expectation remained DENY.
- Each trial passed seven baseline executions and seven correct-reference controls. On the new witness, reference and full-path mutant denied; basename mutant allowed. Both mutants also falsely denied the existing symlink and rename cases.
- Controlled fixture exec attempts: 56 total, comprising 14 baseline, 14 reference, 14 full-path and 14 basename checks. Full-path mismatch observations: four false denials. Basename mismatch observations: four false denials and two false allows.
- First mismatch was fixed position 3 for both mutants; position 7 distinguished them. This is not evidence of improved detection speed or seeded generator effectiveness.
- All six probes detached, both workload groups were removed, and service exit status was 0. The 24.261-second runtime covered the whole experiment, not enforcement overhead.
- Inode numbers recurred between completed trial lifetimes. Each trial read and registered its own current identities; A stayed open while policies could use it. No stale policy was tested across deletion/recreation.
- Source and result: mutant_basename_check.py and docs/mutant_basename_results_v0.md. Three planted fault families now have kernel witnesses; the inode mutant has not been tested on the new seventh case. Earlier-denial composition and random/guided comparison remain untested.

## Pathname fault detection (2026-11-10)

- The first inode fault and its source/result were published in commit 81b8ec9. This checkpoint adds mutant_path_check.py, the pathname result and the fault catalog.
- Recorded run: invocation 5894d0539ea143c0a1cbc6c6ca581f69, kernel 6.8.0-149-generic; controller remained in the service's controller subgroup.
- Both generated C programs carry a registered_path[128] field in a 144-byte policy value. The correct control retains the original device/inode comparison; the mutant compares the requested pathname with A's original pathname. Scope and incoming-return gates remain in both sources.
- Two fresh trials used workload IDs 11418 and 11436. Each passed six baselines and six correct-reference checks. Each mutant run wrongly denied allow_symlink and allow_renamed with EPERM; the other four decisions matched.
- Controlled fixture exec attempts: 12 baseline, 12 reference and 12 mutant. There were four pathname-fault mismatch observations, all false denials. First mismatch was fixed-sequence position 3, excluding baseline/reference checks; this is not seeded tests-to-detection.
- Both reference and both mutant probes detached, both workload groups were removed and service exit status was 0. Whole-service runtime was 16.361 seconds, not policy overhead.
- Result: docs/mutant_path_results_v0.md. Across the two separate fault diagnostics, two fault families were each detected in two fresh trials. No random/guided comparison, general mutation score or product vulnerability is established.

## First single-mutant detection (2026-11-10)

- Reference enforcement source and its first six-case result were published in commit 7194e41.
- New diagnostic: mutant_inode_check.py. It removes only the C inode comparison, retaining device checks, exact cgroup lookup and incoming-return handling. Model predictions remain unchanged.
- Recorded kernel: 6.8.0-149-generic. A preceding launch on 6.14.0-33 stopped at the version guard before loading BPF.
- Two fresh fixed-order trials used live workload IDs 10042 and 10060. Each passed six baselines and six correct-reference checks, then recorded two mutant mismatches: deny_other and deny_copy expected DENY but actually executed.
- Controlled fixture exec attempts: 12 baseline, 12 reference and 12 mutant. The mutant produced four mismatch observations across those 12 checks; these are two witnesses repeated for one planted fault, not four distinct faults.
- First mismatch was at position 2 in each fixed six-case mutant sequence, excluding baseline and reference checks. This is not a random/guided tests-to-detection measurement.
- All reference/mutant probes detached, both temporary workload groups were removed and the service exited 0. Its 21.293-second runtime includes the full experiment and is not an enforcement-overhead measurement.
- Results: docs/mutant_inode_results_v0.md. The checkpoint containing this record also includes mutant_inode_check.py; the preceding reference checkpoint was 7194e41. Broader mutants, random/guided selection and comparative evaluation remain pending.

## First scoped enforcement result (2026-11-10)

- Observation-only scope test: outside child PID 36846 had cgroup ID 11134 and in_scope=0; inside child PID 36847 had cgroup ID 11152 and in_scope=1. Both executed, and cleanup completed.
- Standalone baseline: all six ELF fixtures produced their correct markers and exited 0 without loading a BPF program.
- Enforcement run: invocation 7306c594df674957a5560a888f7c1c10, kernel 6.8.0-149-generic, fresh workload cgroup ID 14728. The run repeated and passed all six baselines, then passed all six expected enforcement decisions.
- Original, symlink, renamed original and outside-scope different file executed. In-scope different file and fresh copy failed exec with EPERM, produced no marker, and used harness exit status 125 to report the exec error.
- Outcomes were checked through the executable marker, exec-error pipe and child status. The kernel identity-read error counter did not invalidate any case. The enforcer detached, workload group was removed and service exited 0.
- These identifiers are historical evidence, not policy configuration. This first fixed-case run was not a comparative evaluation. Prior-denial composition and guided generation remain untested; the later single-mutant checkpoint above records one repeated planted-fault detection.
- Full result record and commands: docs/enforcement_results_v0.md. The tested source and this six-case result were published in commit 7194e41; the preceding published checkpoint was 741fca9.

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

The observer does not prove execution success, prevention or policy correctness. It has name/path heuristics, truncation and event-loss gaps, no execveat coverage or network confirmation, and an unresolved user/kernel PID-number difference. Root can stop it. A Python policy-model core, independent execution-outcome harness and scoped reference enforcer are implemented. The fixed reference checks matched their expectations and three planted fault families have kernel witnesses. A pure-Python random/guided selection preview is implemented, with a pre-data protocol. The common kernel pilot, broader evaluated faults, stateful generators and reducer remain pending.

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
- At this earlier attachment checkpoint, blocking rules and research evaluation were pending. The later checkpoints record model, scope and fixed-case enforcement results.

## Python policy-model checkpoint (2026-11-10)

- `docs/policy_contract_v0.md` records the draft cgroup-scoped file-object allowlist.
- `policy_model.py` calculates expected decisions independently of any enforcer.
- File identity uses device major number, device minor number and inode number, read through Python `os.stat`. Each fixture keeps the chosen file open during its operations.
- Reported Ubuntu VM results: allow_original=ALLOW, deny_other=DENY, allow_symlink=ALLOW, allow_renamed=ALLOW, deny_copy=DENY. All five matched the fixed contract expectations, and temporary files were removed.
- These fixtures inspect real filesystem identities but do not execute the copied ELF programs, create a test cgroup or load an enforcement probe. Kernel blocking has not been tested.
- Scope, prior-denial and supported-case facts are inputs to the model. These five fixtures use the supported, in-scope, no-prior-denial setting; they do not validate kernel cgroup membership or BPF denial chaining.

## GA kernel and cgroup-ID lookup checks (2026-11-10)

- A fresh pre-kernel-change snapshot was created before the GA kernel installation and test boot. No kernel packages were removed.
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
- These lookup tests validated real LSM attachment and identifier agreement for the tested children. Launching the diagnostic in a service did not restrict its LSM hook to that cgroup. The later scope/enforcement checkpoint records the inside/outside classifier and six actual execution checks; prior-denial composition remains untested.
- The last build-tools installation reported 535 other package upgrades pending. A fully patched user-space baseline is not claimed. No accuracy or performance benchmark was performed.

## Research question and scope

Can valid tests guided by a precise policy specification and current state find and explain execution-policy mismatches more efficiently than valid random testing?

Start with one allow/deny policy family, a dedicated workload and benign executables. Define path versus file-object identity and supported operations explicitly. Keep the expected-result model separate from the enforcer. Classify ordinary filesystem errors, unsupported semantics, model errors and flaky results separately from confirmed mismatches.

## Milestones and next actions

1. Completed: published the five-file baseline on `main`, commit `644af5a`.
2. Completed: checked WSL and Ubuntu VM environments, prepared the SentinelLab clone and snapshot, activated BPF-LSM, installed and test-booted Ubuntu GA 6.8.0-149, reproduced the observer demo and verified canonical cgroup-ID lookup. Pending: persistent lab boot selection and review of other package updates.
3. Completed: model/cgroup checks, independent kernel enforcement, three witnessed planted-fault families, a selector preview and a pre-data pilot protocol. Next: implement and smoke-test the common kernel runner, qualify all three mutants on the seven-case domain, and collect the repeated thirty-seed pilot under the fixed rules. Stateful generation and broader faults follow. Add an immutable experiment boundary before any scope-removing mutant. Guidance must not read mutant labels or known witness names.
4. Expand to approximately 15-20 deterministic cases and validate the harness with explicitly labelled faults in our own reference implementation.
5. Compare deterministic, valid random and guided tests under equal budgets with repeated seeds. Add reactive selection and a reducer gradually; retain raw JSON/CSV and negative results.
6. Review related work before claiming novelty. Investigate a small FLORAS example separately as a possible methodological connection. Add one real-engine adapter only after checking documented semantics. Defer concurrency and policy updates.

Update this file after completed phases. Label plans and unverified work clearly.
