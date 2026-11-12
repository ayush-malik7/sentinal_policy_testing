# Sentinel project state

Updated: 2026-11-12. This page describes the current project; older checkpoint
notes are preserved in the [history index](docs/history/README.md).

## Completed

- A Python decision model for an executable-file allowlist scoped to one cgroup.
- Kernel/userspace cgroup-ID checks, inside/outside scope checks and temporary
  eBPF LSM enforcement with userspace execution evidence.
- Three deliberately faulty enforcers: ignore inode, compare the requested
  pathname, and compare only the basename.
- A frozen thirty-seed comparison of random and feature-guided selection over
  seven prepared cases, with four distinct cases per method and two fresh
  confirmation repetitions per seed.
- Published raw reports, audit logs, reproducible analysis and figures in
  checkpoint `e7a14f5`. The checkpoint also contains 27 pure-Python tests.

Guided detected each fault by test four in 30/30 seeds. Random counts were
29/30, 25/30 and 28/30; random detected more seeds by test two for all three
faults. All thirty reports passed validation. The
[pilot report](docs/pilot_results_v0.md) is the detailed evidence record.

## Qualified experiment environment

| Component | Recorded value |
|---|---|
| Guest system | Ubuntu 24.04.2 LTS in the SentinelLab VirtualBox VM |
| Kernel | `6.8.0-149-generic`, also configured as the lab's boot default |
| Python | 3.12.3 |
| Ubuntu BCC packages | `0.29.1+ds-1ubuntu7` |
| Scope and hook | cgroup v2; BPF-LSM active |
| Frozen protocol and planner | Commit `1189529` |
| Main collection source | Commit `8c6780a40ead4b797773bac5f9c6c8402d0d9e7c` |

These values describe the recorded experiment, rather than a claim that all
system packages are current. Experimental inputs and the v0 dataset stay fixed;
changes to the environment need separate qualification.

## Open research questions

- Does the detection-versus-earliness trade-off hold with additional faults
  and independently chosen cases?
- How should a later contract model filesystem changes, executable identity
  lifetime and processes moving between cgroups?
- Can earlier-denial composition and a production-engine adapter be tested
  with equally clear execution evidence?

Those are separate next-version experiments. The current work does not yet
include stateful test generation or a real-engine evaluation. A scope-removing
mutant also needs an independent outer experiment boundary before execution.
The [fault catalog](docs/fault_catalog_v0.md) records the fault-specific gaps.
