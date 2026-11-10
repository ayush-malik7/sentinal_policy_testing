# Sentinel fault catalog v0

This catalog separates observed results from proposed experiments. It is not
a mutation score or a claim that all listed faults have implementations.

## Scope of the experiment

The current contract controls direct execution of prepared native ELF files
inside one exact cgroup v2. It identifies the allowed file using device
major/minor and inode. The trusted controller stays outside the workload.
The allowed file remains open, and fixture operations finish before exec.
There are no concurrent mutations, namespace changes or live policy updates.

For every fault, the expected model stays unchanged. The observed outcome
comes from the ELF marker, exec-error pipe and child status. A BPF log alone
does not establish execution or denial.

## Proposed operators and witnesses

| Operator | Mistake | Witness under the file-object contract | Status |
|---|---|---|---|
| ignore_inode | Compare device alone | Same-device different file or copy executes despite expected DENY | Observed: one fault detected in two fresh trials; source/result published in 81b8ec9 |
| requested_path_identity | Compare the supplied pathname with A's original pathname | Symlink or renamed A is denied despite expected ALLOW | Observed: detected in two fresh trials; mutant_path_check.py and its result are included in this checkpoint |
| basename_identity | Compare only a requested filename's last component | Fresh different file with the same basename as A executes | Observed: seven-case diagnostic distinguished it from full-path comparison in two fresh trials; result included in this checkpoint |
| caller_executable_identity | Inspect the caller's executable instead of the requested executable | Controlled native A attempts exec of B; target B should be denied | Proposed: requires a native A-to-B sequence and hook-timing validation |
| skip_scope | Apply A's rule outside its selected cgroup | Different file outside scope is denied despite expected ALLOW | Blocked until an independent experiment boundary is implemented and tested |
| ancestor_scope | Apply an exact-cgroup policy to its descendants | Different file in a nested descendant is denied despite being outside exact scope | Proposed: nested-group witness and independent experiment boundary required |
| clear_prior_denial | Replace an earlier BPF denial with an allow | Earlier BPF denies A; reference must preserve denial | Proposed: controlled companion probe, attachment-order check and independent boundary required |
| ignore_device | Compare inode alone | Different files on different devices share an inode number | Unexercised: current single-device fixtures cannot distinguish it |

The target is a small useful fault set, not an arbitrary count of eight.
Two mutations may be equivalent within a restricted input domain. Report
that limitation and the case-by-fault detection matrix; do not count extra
operator names as extra behavioral coverage.

These are deliberate mistakes relative to this project's file-object
contract. A product intentionally implementing a pathname-based contract
has different semantics; this catalog does not identify a vulnerability in it.

## Preconditions for expanding the scope

Before introducing a scope-removing fault, add an immutable outer boundary
around intended test children, including the outside-scope control. Exclude
the controller and unrelated host processes. A numeric PID alone must not
remain enrolled after it becomes reusable; enrollment and child reaping need
an explicit lifecycle protocol. These protections belong to the experiment,
outside the policy logic that mutations may change.

## Rules for the later generator comparison

1. Define a shared valid input domain and coverage features before collecting results.
2. Qualify fixtures and check the correct reference before grading a mutant.
3. Guidance may use model-state or feature coverage, not mutant labels or known witness names.
4. Use equal budgets, repeated seeds and explicit reporting of undetected runs.
5. Record all mismatches. Repeat unexpected outcomes on fresh setup before confirming them.
6. Keep harness errors, unsupported operations and inconclusive outcomes separate from policy mismatches.

Each recorded diagnostic uses two fresh fixed-order trials. The latest
compares the full-path and basename faults on seven cases; the earlier inode
diagnostic used six. These are not random seeds and do not measure an
advantage of guided selection.
Stateful sequences need defined transition
semantics and independent outcome checks before they enter the evaluation.
