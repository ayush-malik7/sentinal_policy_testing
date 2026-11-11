# Seed-0 selection smoke test v0

Recorded: 2026-11-11. Protocol: sentinel-fixture-selection-v0. Mode: smoke.
Source/calibration publication: 9fb5bfa. Kernel: 6.8.0-149-generic.

## First detection positions

| Planted fault | Random, repetition 1 | Guided, repetition 1 | Random, repetition 2 | Guided, repetition 2 |
|---|---:|---:|---:|---:|
| ignore_inode | 1 | 1 | 1 | 1 |
| requested_path_identity | 2 | 4 | 2 | 4 |
| basename_identity | 1 | 1 | 1 | 1 |

A position counts selected mutant tests, starting at 1, within each strategy's
four-case budget. It does not count baseline/reference qualification or BPF
compilations. The runner continues all four selected cases after detection.
All six strategy/mutant cells detected a mismatch within budget. No cell was
censored in this smoke run. Smaller positions mean earlier detection.

Random found the pathname fault two selections earlier for seed 0. Both methods
tied on the other two faults. The complete logical case/outcome traces agreed
between repetitions; matching first positions alone is not the full agreement
check. This is one seed with two confirmation repetitions, not two seeds.

## Frozen plans

The unchanged selection_plan.py source produces these seed-0 plans:

| Selection | Random | Guided |
|---|---|---|
| 1 | deny_same_basename | deny_same_basename |
| 2 | allow_renamed | allow_outside_scope |
| 3 | deny_copy | allow_original |
| 4 | allow_original | allow_symlink |

The pathname mutant incorrectly denies the renamed object at random position 2
and the symlink at guided position 4. A same-basename copy detects both the
ignore-inode and basename faults at position 1. The selector receives semantic
features and covered-token state; these known signatures are not selector
inputs. The same plans apply to all three mutants.

The earlier preview reported declared feature coverage of random=39/52 and
guided=46/52. Those are semantic-input token counts, not a detection metric.
Here, greater declared guided coverage did not produce earlier detection of
the pathname fault. Preserve this unfavourable result and the frozen rules.

## Controls, scope and cleanup

Each fresh repetition first passed all seven executions without a Sentinel
probe and all seven model comparisons under the correct reference enforcer.
The three mutants each received both four-case plans on the same qualified
pool. The random/guided sequence execution order inside each mutant phase
was reversed in repetition 2; selected case orders were unchanged. The
controller remained outside the workload.

| Measurement | Across both repetitions |
|---|---:|
| Successful baseline executions | 14/14 |
| Reference model matches | 14/14 |
| Selected mutant exec attempts | 48 |
| All controlled fixture exec attempts | 76 |
| Policy probes detached | 8 |
| Temporary workload cgroups removed | 2 |

Outcomes use native ELF markers, exec-error pipes and child status, separately
from BPF decision logic. The service printed SMOKE PASS and exited 0. Its
whole-service runtime was 36.226 seconds, including qualification, compilation,
execution and cleanup; this is not policy overhead or tests-to-detection time.

Service invocation: 75a9b82f09104239a627d3a80a7fc2ef. Fresh workload IDs: 13008
and 13026. Witness identities on device 8:2 were allowed inode 3670108 and target
inode 3670109 in both completed fixture lifetimes. Each repetition registered
its own current identities with A held open. Repeated numeric inode values do
not establish a stale-policy collision; stale-policy reuse is outside this run.

## Raw evidence and reproduction

Raw smoke report: [results/smoke_seed0_20261111T101821Z_cb3e1c3c.jsonl](../results/smoke_seed0_20261111T101821Z_cb3e1c3c.jsonl).
The table transcribes the reported console output. The linked JSONL contains
per-attempt raw outcomes, plans, hashes, prerequisites and cleanup events and
must be committed separately from this documentation patch.

Calibration prerequisite: [results/calibration_seedNone_20261111T014845Z_e2fa36c1.jsonl](../results/calibration_seedNone_20261111T014845Z_e2fa36c1.jsonl),
validated before publication with SHA-256
d95b8810e8b12a13f9248d81452e6ba9bfe343a66c9f18f7e1729e19bc885aa9.
The smoke runner checked that evidence against its source/program hashes,
kernel, Python and BCC environment before loading policy probes.

Run the smoke command only for an intentionally separate diagnostic rerun;
each execution creates a new report. The recorded smoke is already complete.

```bash
sudo systemd-run --unit=sentinel-enforcement-check --uid=root --wait --pipe --collect --property=Delegate=yes --property=DelegateSubgroup=controller --property=RuntimeMaxSec=90s --property=TimeoutStopSec=10s /usr/bin/python3 -u /home/ayush/runtime-sentinel/selection_kernel.py --smoke --seed 0 --calibration /home/ayush/runtime-sentinel/results/calibration_seedNone_20261111T014845Z_e2fa36c1.jsonl
```

## Next: the main pilot

Validate and commit the smoke record without altering calibrated inputs.
Main mode uses --pilot and requires both the calibration and smoke reports.
Run fresh main experiments for every seed 0..29, including a fresh seed-0 run;
the smoke trace is not a main-pilot observation. Each main run contains exactly
two fresh repetitions and both methods' equal four-case budgets.

Retain every raw trace and invalid, unsupported or flaky outcome. Keep the
planned thirty-seed denominator. A missing detection remains >4 with a null
first-mismatch position, never an invented detection at 5. Do not select
favourable reruns, tune feature weights or change budgets after these outcomes.

This seven-case development domain and three known, scope-preserving faults
are a limited pilot. The smoke result establishes neither a general strategy
advantage nor novelty, a mutation score for a broader engine, or a vulnerability.
Stateful generation, broader faults, previous-denial composition and production
engine evaluation remain later work.
