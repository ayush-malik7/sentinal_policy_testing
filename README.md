# Sentinel

Sentinel tests a Linux rule that allows one executable file inside a chosen
workload group and denies other files. The question is: **can choosing tests
from policy features find broken rules with fewer tests than choosing randomly?**

The first pilot compares random selection with a feature-guided selector over
seven prepared cases and three deliberately inserted faults. Each method gets
four distinct cases per seed, across thirty seeds.

## Main result

| Planted fault | Random: detected by test 4 | Guided: detected by test 4 |
|---|---:|---:|
| Ignore inode | 29/30 | 30/30 |
| Requested pathname | 25/30 | 30/30 |
| Basename | 28/30 | 30/30 |

Guided detected every fault by test four. **Random detected more seeds by
test two for every fault.** For the pathname fault, guided was earlier in
7 seeds, tied in 12 and later in 11. This shows a trade-off between finding
faults within the budget and finding them sooner, rather than a general
advantage for either method.

![Faults detected within four selected tests](docs/figures/pilot_v0_detection.png)

The [pilot report](docs/pilot_results_v0.md) contains the full distributions,
controls and limitations. Each seed has two fresh confirmation repetitions;
these do not count as extra independent samples. The main dataset contains
2,280 execution attempts, and all thirty seed reports passed validation.

## What the code does

The Python model predicts whether the policy should add a denial. The eBPF LSM
enforcer applies that rule only to processes in the exact chosen cgroup. Executable
markers, exec errors and child exit status then show what actually happened,
separately from the probe's decision logs.

The rule identifies a file by its device major number, device minor number
and inode. The allowed file stays open during testing. A symlink or rename
can still refer to that file; a separate copy has a different identity.
`ALLOW` means Sentinel adds no denial; other Linux checks still apply.

| Start here | Purpose |
|---|---|
| [policy_model.py](policy_model.py) | Expected policy decisions and five file-identity fixtures |
| [enforcement_check.py](enforcement_check.py) | First scoped enforcement and userspace outcome checks |
| [selection_plan.py](selection_plan.py) | Random and greedy semantic-coverage selection |
| [selection_kernel.py](selection_kernel.py) | Common kernel runner for the reference and three faults |
| [selection_batch.py](selection_batch.py) | Sequential collection of thirty seeds |
| [analyse_pilot_v0.py](analyse_pilot_v0.py) and [tests/](tests/) | Evidence validation and pure-Python checks |

The original observer demo and the smaller diagnostics remain in the repo.
Their development records are linked from the [history index](docs/history/README.md).

## Check the published result

From the repository directory, with Python 3.12 on Linux:

```bash
/usr/bin/python3 analyse_pilot_v0.py --check-derived results/pilot_analysis_v0
/usr/bin/python3 -m unittest discover -s tests -v
```

These commands read the saved evidence and run pure-Python tests. They need
no sudo and load no BPF program. See the [raw reports](results/),
[summary table](results/pilot_analysis_v0/summary.csv) and
[per-seed results](results/pilot_analysis_v0/per_seed.csv).

For the experiment's rules, read the [frozen protocol](docs/pilot_protocol_v0.md)
and [policy contract](docs/policy_contract_v0.md). The
[collection guide](docs/pilot_collection_v0.md) describes the qualified lab;
the published runs used Ubuntu 24.04.2, kernel `6.8.0-149-generic`, Python 3.12.3
and Ubuntu BCC packages `0.29.1+ds-1ubuntu7`, with cgroup v2 and BPF-LSM active.

## Scope of this result

This is a small pilot on known development cases in the project's own reference
enforcer. It selects tests for prepared native ELF executables; it does not yet generate stateful
filesystem sequences or evaluate a production security engine. Actual
earlier-denial composition remains untested. The result does not establish
novelty, a Linux vulnerability or a general performance improvement.

See [PROJECT_STATE.md](PROJECT_STATE.md) for current status and open questions.
