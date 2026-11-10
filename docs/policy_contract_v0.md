# Sentinel execution-policy contract v0

Status: Draft specification. A Python model core and five filesystem fixtures are implemented; a reported VM run matched all five expected decisions. The blocking program is not implemented.

## Purpose

Define expected behaviour before writing an enforcer.
The existing execution observer remains a diagnostic tool.

## Rule and scope

- The harness will create one dedicated cgroup v2 for test processes.
- Only processes in that exact cgroup are controlled by this rule.
- Inside that group, allow execution only of the chosen file object A.
- Deny execution of other supported executable file objects with EPERM.
- Outside that group, preserve the incoming decision without adding a denial.
- Always preserve a denial from an earlier BPF program.
- An allow decision from our rule does not override other Linux security checks.

## File identity

Identify A using device major number, device minor number and inode number.
Do not compare only filenames, process names or file contents.
Bind A before the test operations and keep it open for the policy lifetime.
Renaming A or reaching it through a link does not create another file object.
A fresh copy has another identity, even when its contents match A.

## Initial supported conditions

Use direct execve calls on controlled native ELF executables.
An ELF executable is a normal Linux binary program.
Use a private test directory on one filesystem and a fresh setup for each case.
The harness and policy controller are trusted and remain outside the test cgroup.
File contents and policy bindings stay fixed during each case.

## Five expected cases

These are predictions for review, not results from an implemented enforcer.

| Case | Action | Expected | Reason |
|---|---|---|---|
| allow_original | Execute A | Allow | A is the chosen object |
| deny_other | Execute different executable B | Deny | B is another object |
| allow_symlink | Execute a symbolic link to A | Allow | It resolves to A |
| allow_renamed | Rename A and execute its new name | Allow | Its identity remains A |
| deny_copy | Copy A to a fresh file and execute the copy | Deny | The copy is another object |

## Planned decision flow

```mermaid
flowchart TD
    A["Execution security check"] --> B{"Earlier BPF denial?"}
    B -->|Yes| C["Preserve denial"]
    B -->|No| D{"Inside test cgroup?"}
    D -->|No| E["Add no denial"]
    D -->|Yes| F{"File object is A?"}
    F -->|Yes| E
    F -->|No| G["Deny with EPERM"]
```

The arrows show the order of decisions in the planned LSM program.

## Outcome verification

First confirm that each fixture can execute without our enforcer.
Then record the actual exec error and a marker printed by the test executable.
An allowed test should reach its marker and finish successfully.
A denied test should report EPERM and should not reach its marker.
Other filesystem errors, timeouts and unsupported cases need separate investigation.
An observer event or a missing alert is not sufficient proof of an outcome.

## Initial limits

Scripts, execveat, descriptor-based execution and namespace changes are outside v0.
Concurrent mutations, deletion/recreation, inode reuse and policy updates are outside v0.
This contract does not claim protection against privileged tampering.
Security updates and the final supported lab kernel still need review before evaluation.

## Implemented model and its limits

`policy_model.py` compares file identities obtained through Python `os.stat`.
Its fixtures copy `/usr/bin/true` into private directories, perform the five
specified operations and compare predictions with fixed expected answers.
The fixtures never execute these copied ELF programs or attach an eBPF policy.

The model accepts `in_scope`, `earlier_denial` and `supported` as supplied facts.
It does not discover kernel cgroup membership or previous BPF decisions.
The five fixtures exercise supported, in-scope cases with no earlier denial.
Passing them checks those examples, not kernel enforcement or the full contract.

## Next step

Review pending security updates and choose the final supported lab kernel.
Build a controlled execution-outcome harness with baseline runs, exec errors and
entry markers, then add the workload-scoped reference enforcer.
