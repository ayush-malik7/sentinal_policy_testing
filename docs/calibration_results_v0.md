# Common-runner calibration v0

Recorded: 2026-11-11. Mode: calibration. Protocol: sentinel-fixture-selection-v0.

## Result

The reported SentinelLab console run completed two fresh repetitions on kernel
6.8.0-149-generic with the same expected signatures. This qualifies the common
runner on the existing seven-case domain before a seeded smoke test.

| Phase | Repetition 1 | Repetition 2 | Across both |
|---|---|---|---|
| Baseline without Sentinel probe | 7/7 successful execs | 7/7 successful execs | 14/14 |
| Correct reference | 7/7 model matches | 7/7 model matches | 14/14 |
| ignore_inode | 3 false allows | 3 false allows | 6 false-allow observations |
| requested_path_identity | 2 false denials | 2 false denials | 4 false-denial observations |
| basename_identity | 2 false denials, 1 false allow | 2 false denials, 1 false allow | 4 false denials, 2 false allows |

Each phase executes all seven cases per repetition: 70 controlled fixture exec
attempts in total. Repeated observations do not count as additional fault
families. These are known planted faults, not product or Linux vulnerabilities.

## Mismatch signatures

| Operator | Cases differing from the unchanged model |
|---|---|
| ignore_inode | deny_other, deny_copy, deny_same_basename |
| requested_path_identity | allow_symlink, allow_renamed |
| basename_identity | allow_symlink, allow_renamed, deny_same_basename |

All other cases matched their model expectations. The ignore-inode operator is
now qualified on deny_same_basename; earlier six-case results did not establish
that observation. Mutant signatures validate calibration only. The selector
receives model facts and covered tokens, not these labels or execution verdicts.

An ALLOW outcome requires the expected native ELF marker, child exit 0 and no
exec error. A DENY outcome requires EPERM from exec, no marker and harness exit
125. Other errors invalidate the run. The child checks actual cgroup membership
before attempting exec; the controller stays outside the workload.

## Run record and cleanup

- Service invocation: d1b9fc651d1a4d5b83ac9bd1e0fa6d42.
- Fresh workload IDs: 10150 and 10228. These are historical values.
- All eight policy probes detached; both workload groups were removed.
- The service exited 0 and printed CALIBRATION PASS.
- Whole-service runtime: 40.620 seconds, including compilation, setup, all
  phases and cleanup. This is not enforcement overhead or a detection metric.
- Source: selection_kernel.py, using the existing model, fixture and enforcer
  helpers. The policy map uses the shared 160-byte identity/path/basename layout.
- The planner and protocol were published in 1189529 before this run. Both
  remain byte-for-byte unchanged. The calibration may name that earlier HEAD
  while recording an untracked runner: exact source and generated-program
  hashes in its header bind the executed bytes, not a later commit identifier.

Raw record: [results/calibration_seedNone_20261111T014845Z_e2fa36c1.jsonl](../results/calibration_seedNone_20261111T014845Z_e2fa36c1.jsonl).
The numbers above transcribe the reported console output; inspect this JSONL
for individual markers, errors, outcomes, hashes and cleanup events. Commit the
existing VM report with the calibrated source. This documentation patch does not
supply or replace the raw report. Timestamps with Z in report names are UTC.

## Reproduce

Use SentinelLab with the qualified kernel, active BPF-LSM, cgroup v2 delegation,
system Python/BCC and matching build tools. From the Ubuntu terminal:

```bash
sudo systemd-run --unit=sentinel-enforcement-check --uid=root --wait --pipe --collect --property=Delegate=yes --property=DelegateSubgroup=controller --property=RuntimeMaxSec=90s --property=TimeoutStopSec=10s /usr/bin/python3 -u /home/ayush/runtime-sentinel/selection_kernel.py --calibrate
```

A rerun creates a different report name and fresh identifiers. Preserve both;
never replace the historical report with a rerun under its old filename.

Pure-Python tests require no sudo and load no BPF:

```bash
cd ~/runtime-sentinel
/usr/bin/python3 -m unittest discover -s tests -p test_selection_kernel.py -v
```

The nine tests check missing/corrupted observations, failed cleanup, incomplete
reports, source changes, censored outcomes, repetition disagreement and frozen
selection properties. Their synthetic reports are parser fixtures, not kernel
evidence. They do not replace this real calibration or the upcoming smoke run.

## Next experiment and limits

First commit the calibrated runner, tests, documentation and existing raw
report. Smoke mode requires committed, unchanged experimental inputs. Run a
separate seed-0 smoke experiment with --smoke --seed 0 and --calibration pointing
to this JSONL. Before loading BPF, the runner checks its raw calibration evidence
and matching source/program hashes, kernel, Python and BCC versions.

The frozen plans select four distinct cases per strategy. The smoke runner
checks seven baselines and seven references in each of two fresh repetitions,
then executes both plans on each of the three mutants. This is 76 controlled
fixture attempts if it completes. Both repetitions must agree logically; fresh
PIDs, inode values, markers and cgroup IDs are not required to match numerically.
Invalid, flaky and censored outcomes remain visible in reports.

No smoke result, thirty-seed comparison or guided-selection advantage has been
measured by this calibration. The finite development fixtures are known in
advance. Prior-denial composition, deletion/recreation with stale policies,
stateful generation, broader faults and production-engine adapters remain
outside this result. The original protocol's pre-runner status paragraph is
preserved as the historical frozen checkpoint, not current project status.
