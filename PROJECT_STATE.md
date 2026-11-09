# Sentinel project state

**Title:** Sentinel: Reactive, Specification-Guided Testing of Linux Execution Policies
**Repository:** https://github.com/ayush-malik7/sentinal_policy_testing
**Checkpoint:** 2026-11-09

## Verified baseline

- Current monitor and demo source reviewed on 2026-11-09.
- Git 2.53.0 reported; local repository initialized on branch `main`.
- `origin` configured to the repository above. Baseline published on 2026-11-09, commit `644af5a`.
- BCC execve-entry observation, checked parent metadata reads, perf transport and Python name rules are implemented.
- Bounded monitoring, self-test and three-case local demo are implemented.
- Historical output recorded 45 received events, two alerts and zero reported perf losses. Earlier complete output verified the loopback marker and clean shutdown. No new kernel run or benchmark is claimed at this checkpoint.

## Environment and limits

Earlier reports identified Ubuntu WSL2, BCC 0.35.0 and kernel 6.18.33.2-microsoft-standard-WSL2. Embedded headers became available after loading kheaders. Current kernel configuration, active LSMs, BTF and tools still need checking.

The observer does not prove execution success, prevention or policy correctness. It has name/path heuristics, truncation and event-loss gaps, no execveat coverage or network confirmation, and an unresolved user/kernel PID-number difference. Root can stop it. No policy model, reference enforcer, generator, reducer or research evaluation exists yet.

## Research question and scope

Can valid tests guided by a precise policy specification and current state find and explain execution-policy mismatches more efficiently than valid random testing?

Start with one allow/deny policy family, a dedicated workload and benign executables. Define path versus file-object identity and supported operations explicitly. Keep the expected-result model separate from the enforcer. Classify ordinary filesystem errors, unsupported semantics, model errors and flaky results separately from confirmed mismatches.

## Milestones and next actions

1. Completed: published the five-file baseline on `main`, commit `644af5a`.
2. Check the current environment before choosing enforcement tooling. Use a disposable VM with a pinned supported kernel if required.
3. Define one narrow contract and five manually reviewed fixtures; then build independent execution-outcome checks and a workload-scoped reference enforcer.
4. Expand to approximately 15-20 deterministic cases and validate the harness with explicitly labelled faults in our own reference implementation.
5. Compare deterministic, valid random and guided tests under equal budgets with repeated seeds. Add reactive selection and a reducer gradually; retain raw JSON/CSV and negative results.
6. Review related work before claiming novelty. Investigate a small FLORAS example separately as a possible methodological connection. Add one real-engine adapter only after checking documented semantics. Defer concurrency and policy updates.

Update this file after completed phases. Label plans and unverified work clearly.
