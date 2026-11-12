# Sentinel project state

**Title:** Sentinel: Reactive, Specification-Guided Testing of Linux Execution Policies
**Repository:** https://github.com/ayush-malik7/sentinal_policy_testing
**Checkpoint:** 2026-11-11

## Completed thirty-seed main pilot (2026-11-11)

- Main collection ran once from 8c6780a40ead4b797773bac5f9c6c8402d0d9e7c with the protocol/planner frozen in 1189529 and calibrated kernel source unchanged from 9fb5bfa. The launcher and experimental source files match the uploaded archive byte-for-byte.
- Dataset: exactly seeds 0..29, one main worker invocation per seed and two fresh repetitions inside each worker. All 30 reports are valid, with no invalid, inconclusive or missing seeds. Calibration and smoke are prerequisites and are excluded from the main observations.
- At the four-test budget, ignore_inode was detected by random in 29/30 seeds and guided in 30/30; requested_path_identity in 25/30 versus 30/30; basename_identity in 28/30 versus 30/30.
- Guided earlier/tied/later counts were 5/19/6 for ignore_inode, 7/12/11 for requested_path_identity and 3/16/11 for basename_identity. Both-censored counts were zero. All three guided cumulative detection counts were lower than random at step 2, so the end-of-budget improvement does not establish faster first detection.
- Independent offline checking verified raw exit/errno/marker evidence and re-applied the supported scope/file-object expectation from recorded fixture identities. Both complete logical repetitions agreed in every strategy/mutant cell. Main totals: 420 baseline + 420 reference + 1,440 mutant observations = 2,280 controlled attempts; all controls matched. Cleanup records certify 240 detached probes and 60 removed workload cgroups.
- Audit: results/pilot_batch_v0/batch.jsonl, SHA-256 152d3f583605189c9c9fdf98824b911d001a0e9f13c55d74b3e9fcc5135cccf1. Source hashes, generated C-text hashes, prerequisite hashes, each raw report hash and all 30 distinct worker invocations were checked. No unaccounted pilot report was present.
- Environment: kernel 6.8.0-149-generic, Python 3.12.3, BCC packages 0.29.1+ds-1ubuntu7. Batch elapsed time was 1071.526 seconds; whole-worker durations summed to 1048.615 seconds. These include compilation/qualification/confirmation/cleanup and are not enforcement overhead.
- Read-only analysis: analyse_pilot_v0.py. Curated summary, per-seed and paired CSV/JSON: results/pilot_analysis_v0/. Figure: docs/figures/pilot_v0_detection.png. Full result and reproduction: [pilot_results_v0.md](docs/pilot_results_v0.md). The analysis preserves null censoring; it does not assign an undetected run a detection time of 5.
- The result shows higher four-test-budget detection for guidance and frequent earlier random detections within the frozen seven-case, three-fault development pilot. It does not establish a general advantage, novelty or a production/Linux vulnerability. Neither 60 confirmation repetitions nor 180 strategy/mutant cells are additional independent seeds.
- Next: review and publish raw data with this analysis checkpoint. Keep v0 immutable; qualify broader faults and specify any stateful next-version evaluation separately. Prior-denial composition and real-engine integration remain pending.

## Seed-0 smoke test (2026-11-11)

- Calibration, the common runner and nine passing pure-Python tests were published in 9fb5bfa. Before publication, the raw calibration report validated against current source/program hashes and the actual environment. Its SHA-256 was d95b8810e8b12a13f9248d81452e6ba9bfe343a66c9f18f7e1729e19bc885aa9.
- Reported smoke run: kernel 6.8.0-149-generic; protocol sentinel-fixture-selection-v0; seed 0; service invocation 75a9b82f09104239a627d3a80a7fc2ef. Fresh workload IDs were 13008 and 13026.
- Both fresh repetitions passed baseline 7/7 and reference 7/7. For ignore_inode, first mismatch was random=1 and guided=1. For requested_path_identity, random=2 and guided=4. For basename_identity, random=1 and guided=1. The complete logical traces agreed across repetitions for all six mutant/strategy cells.
- Total controlled fixture exec attempts: 76 = 14 baseline + 14 reference + 48 mutant measurements. All four selected cases continued after first detection. All eight probes detached, both workload groups were removed, and service exit status was 0. Whole-service runtime was 36.226 seconds, not enforcement overhead.
- This seed favoured random for the pathname fault and tied for the other two faults. It does not establish a general strategy advantage. The semantic preview's larger guided token count did not imply earlier pathname-fault detection.
- Raw smoke report: results/smoke_seed0_20261111T101821Z_cb3e1c3c.jsonl. Source and calibration prerequisite were committed before this run. The existing raw report is staged separately from this documentation-only patch.
- Documentation: [selection_smoke_results_v0.md](docs/selection_smoke_results_v0.md). The planner, frozen protocol and calibrated runner remain unchanged. The one-seed smoke measurement is separate from main-pilot data.
- Next: validate and publish the smoke report, then run fresh main experiments for all fixed seeds 0..29, with two fresh repetitions inside each run and four distinct cases per method. Do not reuse the smoke trace as main seed 0, tune the selectors after this result, retry for favourable outcomes, or silently remove invalid/flaky seeds.

## Common-runner calibration (2026-11-11)

- The frozen planner and protocol were published in 1189529 before this run. selection_kernel.py adds a shared runner; this checkpoint leaves selection_plan.py and docs/pilot_protocol_v0.md unchanged.
- Reported run: kernel 6.8.0-149-generic; protocol sentinel-fixture-selection-v0; service invocation d1b9fc651d1a4d5b83ac9bd1e0fa6d42. Fresh workload IDs were 10150 and 10228. These IDs are historical evidence, not reusable bindings.
- Each repetition passed all seven baselines and all seven reference cases. Ignore-inode mismatches were deny_other, deny_copy and deny_same_basename. Requested-path mismatches were allow_symlink and allow_renamed. Basename mismatches were allow_symlink, allow_renamed and deny_same_basename. Both repetitions produced the same expected fault signatures.
- Controlled fixture exec attempts: 70 total = 14 baseline + 14 reference + 14 for each of three mutants. All eight policy probes detached, both workload groups were removed, and the service exited 0. Whole-service runtime was 40.620 seconds; this includes setup, compilation and cleanup and is not enforcement overhead.
- The common runner qualifies fixture features, checks child membership before exec, records independent exec outcomes and writes unique JSONL reports. Smoke/pilot modes require committed, unchanged experimental inputs and validated prerequisite reports with matching source/program hashes and environment.
- Calibration report: results/calibration_seedNone_20261111T014845Z_e2fa36c1.jsonl. Commit the existing VM report alongside the exact runner; this documentation patch does not create or replace either file. Report: [calibration_results_v0.md](docs/calibration_results_v0.md).
- The persistent GRUB default now names Ubuntu, with Linux 6.8.0-149-generic in Advanced options for Ubuntu. The generated default and syntax check passed; reboot confirmed this kernel and active BPF-LSM. Other package-update review remains pending.
- tests/test_selection_kernel.py contains nine pure-Python selector/report checks. Its synthetic reports are unit-test fixtures, not experimental evidence. These tests do not load BPF.
- Next: preserve and commit this calibration checkpoint, then run the separate seed-0 smoke test. No random/guided effectiveness result or thirty-seed pilot result has been collected. Earlier-denial composition and broader/stateful evaluation remain untested.

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

The observer does not prove execution success, prevention or policy correctness. It has name/path heuristics, truncation and event-loss gaps, no execveat coverage or network confirmation, and an unresolved user/kernel PID-number difference. Root can stop it. A Python policy-model core, independent execution-outcome harness and scoped reference enforcer are implemented. The fixed reference checks matched their expectations and three planted fault families have kernel witnesses. The frozen selector/protocol and common kernel runner are implemented. The runner passed seven-case calibration and a seed-0 smoke experiment, both in two fresh repetitions. The thirty-seed pilot is complete, with verified raw/derived results and explicit censoring. Broader evaluated faults, stateful generators and reducer remain pending.

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
2. Completed: checked WSL and Ubuntu VM environments, prepared the SentinelLab clone and snapshot, activated BPF-LSM, installed Ubuntu GA 6.8.0-149, selected it as the persistent lab default and verified it after reboot, reproduced the observer demo and verified canonical cgroup-ID lookup. Pending: review of other package updates and requalification after experimental environment changes.
3. Completed: model/cgroup checks, independent kernel enforcement, three witnessed planted-fault families, a selector preview, a pre-data pilot protocol and common-runner calibration of all three mutants on all seven cases in two fresh repetitions. The calibrated source and report were published in 9fb5bfa, and the seed-0 smoke test passed with repeatable measurements. Its record was published in db044e8, and the thirty-seed main pilot has now completed from 8c6780a. Next: publish and review the raw data, descriptive tables and reproducible analysis. Stateful generation and broader faults follow. Add an immutable experiment boundary before any scope-removing mutant. Guidance must not read mutant labels or known witness names.
4. Expand to approximately 15-20 deterministic cases and validate the harness with explicitly labelled faults in our own reference implementation.
5. Completed: a finite random/guided comparison over thirty paired seeds, with two confirmation repetitions and equal four-case budgets. Preserve the result, including slower guided detections and censored random runs. Next: specify broader next-version tests, stateful reactive selection and a reducer; retain raw data and negative results.
6. Review related work before claiming novelty. Investigate a small FLORAS example separately as a possible methodological connection. Add one real-engine adapter only after checking documented semantics. Defer concurrency and policy updates.

Update this file after completed phases. Label plans and unverified work clearly.
