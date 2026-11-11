# Collecting the frozen thirty-seed pilot

Status: collection procedure prepared after smoke publication db044e8. This
document records a launcher, not collected main-pilot results. Selection rules
remain the unchanged sentinel-fixture-selection-v0 protocol from 1189529;
the calibrated kernel runner remains unchanged from 9fb5bfa.

## What is collected

selection_batch.py starts the existing selection_kernel.py --pilot worker for
each seed 0..29, in ascending order, once. Each worker performs the prescribed
two fresh repetitions, seven-case baseline/reference qualification and both
four-case selection plans on the three scope-preserving mutants. The smoke
trace is a prerequisite and is never reused as a main seed-0 observation.

If all runs complete, the planned totals are 30 seeds, 60 fresh repetitions
and 2,280 controlled fixture exec attempts: 420 baseline, 420 reference and
1,440 selected mutant attempts. These are planned counts, not observations.
First detection is measured only within the four selected mutant cases.

The controller and policy logic are the already calibrated implementation.
No selector rules, fixtures, model expectations, kernel programs or cgroup
scope gates are changed by the launcher. Each worker still has the existing
90-second runtime bound and 10-second stop timeout. The launcher adds a
PartOf dependency so stopping the parent also stops its current worker.

## Files and provenance

The launcher checks the published calibration and smoke reports, including
their exact SHA-256 values, against current source/program hashes and the
actual kernel, Python and BCC environment. The runner's experimental inputs
must be committed and clean. The launcher itself must be committed before
--run. It records its own hash and starting commit in the batch audit, and
checks source, prerequisite and commit stability before dispatching each seed.

All collection is sequential because the verified runner uses one fixed
worker service name. Do not run other sentinel-enforcement-check diagnostics
while collecting this batch. The launcher refuses an existing worker unit.

Created files, owned by the project user:

- results/pilot_batch_v0/batch.jsonl: planned seeds, dispatch commands, outcomes,
  report hashes, invalid/inconclusive cases and final counts.
- results/pilot_batch_v0/seed_00.console.txt through seed_29.console.txt:
  each dispatched worker's console output, including failures.
- results/pilot_seedN_TIMESTAMP_NONCE.jsonl: fresh raw reports from the existing
  runner. A worker that stops before opening its report still has a dispatch
  entry and console log in the batch audit.

The fixed audit directory is created exclusively. Any existing main-pilot
report or audit prevents a new batch start, protecting against accidental
restarts and favourable retries. Keep any such files and inspect them rather
than deleting them to make the check pass.

## Install, test and check readiness

Apply add_selection_batch.patch, then run the pure-Python tests from the repo:

```bash
cd ~/runtime-sentinel
/usr/bin/python3 -m unittest discover -s tests -p 'test_selection*.py' -v
```

There are 20 tests: the existing nine report/selector tests and eleven batch
tests. Synthetic records are clearly labelled and are not experimental data.
The tests start no services and load no BPF. Local passing tests do not establish
that the VM's service manager will accept or execute the batch command.

Run the VM readiness check:

```bash
sudo /usr/bin/python3 ~/runtime-sentinel/selection_batch.py --check
```

This reads environment, Git and prerequisite evidence, checks worker
availability and requires an empty main dataset. It loads no BPF and creates
no result files. It permits the new launcher to be untracked during readiness
checking. A successful check is not main-pilot data collection.

Stage only selection_batch.py, tests/test_selection_batch.py and this document.
Commit and push them before starting the main batch. No other existing source
file needs editing. Preserve all raw data and the existing calibration/smoke.

## Start the detached collection

After readiness and publication, run this command once in SentinelLab:

```bash
sudo systemd-run --unit=sentinel-pilot-batch --uid=root --property=Type=exec --property=RuntimeMaxSec=60min --property=TimeoutStopSec=30s /usr/bin/python3 -u /home/ayush/runtime-sentinel/selection_batch.py --run
```

This returns after starting the parent service. The service manager owns the
batch independently of MobaXterm. The VM must stay running; a VM shutdown or
host suspend can interrupt or delay collection. The outer 60-minute bound is
a limit, not an expected runtime. The 36.226-second smoke run suggests about
20 minutes for thirty similar runs, with additional provenance checks and
normal VM variation. This is an estimate, not a benchmark result.

Inspect progress without starting another batch:

```bash
sudo journalctl -u sentinel-pilot-batch.service -n 20 --no-pager -o cat
```

The journal prints one start and result per seed and the audit path. Full
worker details remain in each seed's console file and raw JSONL. Reconnecting
MobaXterm only requires inspecting progress; do not repeat the start command.

Inspect the latest durable audit event:

```bash
tail -n 1 ~/runtime-sentinel/results/pilot_batch_v0/batch.jsonl
```

While collection is running this may be a dispatch or seed_result event. A
completed batch has a final event with planned_seed_count=30. A fully valid
batch reports seed_results=30, counts containing valid=30, and no seeds without
a result. Preserve and report every other outcome instead of treating it as
successful or silently excluding it.

## Failure and stopping rules

The launcher never retries a seed. A fully completed, validated report is
counted valid, including censored no-detection outcomes. A reported repetition
disagreement is retained as inconclusive and collection can continue when the
expected cleanup records are present. Its raw data still needs final analysis.
Invalid evidence, missing reports, source drift or uncertain cleanup stops
further dispatch. Missing seed results remain visible beside the planned
thirty-seed denominator. An interrupted dispatch stays visible even if it has
no seed_result entry or complete raw report.

To stop intentionally:

```bash
sudo systemctl stop sentinel-pilot-batch.service
```

The worker is linked to the parent by PartOf. Its own timeout also bounds
execution. The launcher only explicitly stops a worker whose description
matches its own invocation. Retain the partial audit, logs and raw reports;
do not restart, retry or change the method to obtain a favourable result.

After collection, validate and analyse the raw data separately. Report per
mutant/strategy counts detected by steps 1..4, censored observations, invalid
or flaky seeds and the planned denominator. Never invent a detection at step 5
or use a detected-only mean. Two repetitions confirm one seed, not two samples.

## Service documentation

- [Ubuntu Noble systemd-run](https://manpages.ubuntu.com/manpages/noble/man1/systemd-run.1.html):
  detached service execution, --wait, --pipe and --collect.
- [Ubuntu Noble systemd.unit](https://manpages.ubuntu.com/manpages/noble/man5/systemd.unit.5.html):
  the one-way stop/restart propagation of PartOf.
