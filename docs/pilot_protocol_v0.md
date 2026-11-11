# Finite fixture-selection pilot v0

Status: fixed selection/evaluation rules before pilot kernel data. Date: 2026-11-11.
The common kernel runner and its smoke validation are not implemented yet.
The preceding published checkpoint is 8c98221. Existing fixed fault witnesses
are known development data, not a held-out evaluation set.

## Question and limits

Under the same four-case budget, does semantic-feature-guided selection find
the three validated, scope-preserving mutants sooner or more often than
uniform selection without replacement?

This is a small fixture-selection pilot over seven existing families. It is
not stateful filesystem-sequence generation, a production-engine evaluation,
or evidence of novelty. Coverage state belongs to the selector; the file-object
oracle remains the existing pure expected_decision function. A result that
does not favour guidance must still be reported.

## Fixed comparison settings

| Setting | Planned value |
|---|---|
| Protocol ID | sentinel-fixture-selection-v0 |
| Valid fixture catalog | The seven cases in selection_plan.py |
| Per-strategy budget | Four distinct cases, without replacement |
| Seeds | Integers 0 through 29 |
| Fresh repetitions | Exactly two per seed; do not count them as independent seeds |
| Strategies | random and guided |
| Initial mutants | ignore_inode, requested_path_identity, basename_identity |
| Oracle | Existing file-object contract; no altered expected answers |
| Actual outcome evidence | ELF token, exec-error pipe and child exit status |
| Primary output | First mismatch step 1..4, or >4 if none observed |

The initial three faults are a pilot subset of the catalog, not the final
five-to-eight-fault research target. More faults need qualified witnesses;
scope-removing faults require the independent experiment boundary first.

## Shared valid input domain

Both methods receive exactly the same seven candidates. All use controlled
native ELF files on one filesystem, with A pinned and the controller outside
the workload cgroup. No new operation or contract exception is introduced.

The kernel runner must materialise each candidate and verify its declared
features against real fixture facts before grading a mutant: actual device/
inode equality, original and requested path equality, basename equality,
known setup operation and intended cgroup placement. It must establish
successful baselines and correct-reference controls first. A qualification
failure invalidates the run; it is not a detected mutant.

The existing seven-case diagnostic has not run ignore_inode on case seven.
The common pilot implementation must validate the reference and all three
fault operators on the full seven-case pool before pilot measurement begins.
Any added map metadata must have a matching correct control and be recorded.

## Coverage definitions

Every case supplies five semantic facts, independent of a mutant:

1. Scope: inside or outside the exact workload group.
2. Object: same as A or different, using the model's file identity.
3. Path: requested pathname equals the original registered pathname or differs.
4. Basename: requested filename's final component equals A's original name or differs.
5. Setup: direct, symlink, rename or copy, as the fixture rule defines.

Coverage tokens are each single fact and every pair of facts from different
dimensions, with equal weight. The universe contains only combinations
present in this fixed valid catalog, not impossible states. It is semantic
input coverage, not kernel branch coverage or a measure of policy correctness.
Concrete inode numbers, temporary paths and case IDs are never tokens.

The declarations in selection_plan.py are predictions about fixture setup.
Its preview assumes qualification succeeds; it does not verify filesystem
state, run processes, load BPF or establish coverage of actual executions.

## Selection rules

Random: choose uniformly from remaining candidates at every step.

Guided: choose a remaining candidate with the most single/pair tokens not
covered by previous valid selections. Break ties uniformly. Update coverage
after each valid selection. Both methods remove each chosen candidate, so
the random baseline is not weakened by repeated samples.

Each selector uses its own random.Random(seed). Catalog order and feature
definitions are fixed. For any seed/strategy, its four-case plan is identical
for all three mutants. No mutant ID, BPF decision, mismatch, expected killing
case name or planted-fault signature enters selection. Report the Python
version because reproducibility includes the random-library implementation.

The known fault witnesses influenced development of the catalog. That is
a validity limitation even though the selector cannot read mutant labels.
Do not tune features, weights, seeds or budget after viewing pilot outcomes.
Version any changed protocol and retain the old results.

## Execution, confirmation and reporting

Freeze the source and protocol in Git before the kernel pilot. First run a
small smoke experiment to validate the common runner and raw-report format.
A smoke run is not the thirty-seed result. Record commit, source hashes,
kernel/BCC/Python versions, seed, strategy, selected order, expected/observed
decisions and cleanup status. Existing untracked helper downloads are not
experimental inputs and must not be silently substituted for tracked code.

For each seed, qualify a fresh pool with baseline and correct-reference
checks. Run policy programs separately, preserve the cgroup/ret gates and
detach between them. Use the same qualified pool and same four-case budget
for both selectors. Continue all four planned cases so raw traces retain
the full equal-budget evidence; record the first mismatch's actual position.

Run each seed experiment exactly twice, with fresh fixtures and groups.
Compare the logical case order and expected/observed outcomes for each
strategy, mutant and step, not ephemeral PIDs, cgroup IDs, paths, inode values
or random marker tokens. If the two logical traces disagree, label the
affected seed/mutant pair flaky/inconclusive. A qualification, instrumentation
or cleanup failure invalidates the repetition and must be reported; it is
not a policy mismatch. Keep both raw traces. Report harness errors, model
errors and unsupported inputs separately. Do not retry until a favourable
result appears or silently remove failed seeds. The exact report/runner
lifecycle must be checked in the smoke stage before collecting main results.

Report per-mutant detection counts at steps 1..4, first mismatch positions
or >4, and raw per-seed traces. Keep undetected runs as censored observations,
never as an invented detection at step 5. Report invalid/flaky counts beside
the planned thirty-seed denominator. Do not compare only detected-run means.
Compilation, qualification, confirmation and cleanup costs must be identified
separately from the mutant-execution budget. Whole-service runtime is not
kernel enforcement overhead.

## Immediate next step

The VM preview for seed zero completed with four distinct cases per method:
39/52 declared coverage items for random and 46/52 for guided. This was plan
inspection only, not fixture execution or detection measurement. It is not
evidence that guided selection finds faults better.

Publish this protocol and the unchanged planner before implementing the
common kernel runner. Validate that runner with a small smoke test, then
collect the repeated thirty-seed pilot without changing these selection
rules. The smoke data is kept separate from the main results.
