#!/usr/bin/python3
"""Detect one deliberately inserted, scope-preserving inode-comparison fault.

Each of two fresh trials runs baseline, correct reference, then mutant.
Only the C inode comparison is removed; model expectations do not change.
This diagnostic is not random/guided generation or a vulnerability finding.
Run in the same delegated service as enforcement_check.py, with a 90s cap.
"""

from contextlib import ExitStack
import os
from pathlib import Path
import platform
import secrets
import subprocess
import tempfile

import enforcement_check as reference
from policy_model import file_identity
from scope_handle_check import cgroup_id_from_handle


VERIFIED_KERNEL = "6.8.0-149-generic"
TRIALS = 2
EXPECTED_MISMATCHES = {"deny_other", "deny_copy"}
INODE_COMPARISON = "allowed->inode == (u64)number &&\n        "


def make_mutant(program):
    """Make exactly one checked change to the reference C, never to the model."""
    if program.count(INODE_COMPARISON) != 1:
        raise RuntimeError("Reference comparison differs; no mutant was loaded.")
    return program.replace(INODE_COMPARISON, "", 1)


def record_outcome(case, result, token, label):
    """Use actual execution evidence, then compare with the original oracle."""
    actual = reference.actual_decision(result, token)
    match = actual == case["expected"]
    print(
        f"[{label}] {case['name']}: expected={case['expected']} actual={actual} "
        f"match={match} exit={result['exit']} exec_error={result['error']!r}",
        flush=True,
    )
    return match


def run_policy_cases(cases, workload, workload_id, program, label):
    """Record all model mismatches without using BPF verdicts as the oracle."""
    from bcc import BPF

    print(f"Compiling {label}...", flush=True)
    probe = BPF(text=program)
    mismatches = set()
    try:
        policies = probe["policies"]
        errors = probe["read_errors"]
        for case in cases:
            identity = case["allowed"]
            key = policies.Key(workload_id)
            policies[key] = policies.Leaf(identity.inode, identity.major, identity.minor)
            try:
                token = "SENTINEL_MUTANT_" + secrets.token_hex(16)
                result = reference.run_child(
                    case["target"], token, workload if case["in_scope"] else None
                )
                if int(errors[errors.Key(0)].value) != 0:
                    raise RuntimeError("INSTRUMENTATION ERROR: kernel identity read failed.")
                if not record_outcome(case, result, token, label):
                    mismatches.add(case["name"])
            finally:
                del policies[key]
    finally:
        # The reference must detach before the mutant can be tested.
        probe.cleanup()
        print(f"{label} detached.", flush=True)
    return mismatches


def qualify_fixtures(cases):
    """This one fault requires same-device, different-inode deny fixtures."""
    names = [case["name"] for case in cases]
    expected = {
        "allow_original", "deny_other", "allow_symlink", "allow_renamed",
        "deny_copy", "allow_outside_scope",
    }
    if len(names) != 6 or set(names) != expected:
        raise RuntimeError("The six reference fixtures changed; review this diagnostic.")
    for case in cases:
        target = file_identity(case["target"])
        allowed = case["allowed"]
        if (target.major, target.minor) != (allowed.major, allowed.minor):
            raise RuntimeError("UNSUPPORTED: this diagnostic requires same-device fixtures.")
        if case["name"] in EXPECTED_MISMATCHES and target.inode == allowed.inode:
            raise RuntimeError("PRECONDITION ERROR: deny fixture is not a different inode.")


def run_trial(number, root, binary, directory, mutant, controller):
    workload = root / f"workload-{number}"
    workload.mkdir()
    try:
        workload_id = cgroup_id_from_handle(workload)
        controller_id = cgroup_id_from_handle(
            reference.MOUNT / controller.lstrip("/")
        )
        if workload_id == controller_id:
            raise RuntimeError("Controller and workload IDs unexpectedly match.")
        print(f"TRIAL {number}: fresh workload ID={workload_id}", flush=True)
        with tempfile.TemporaryDirectory(prefix=f"trial-{number}-", dir=directory) as folder:
            with ExitStack() as stack:
                cases = reference.prepare_cases(Path(folder), binary, stack)
                qualify_fixtures(cases)

                reference.run_cases(cases, workload)
                print(f"TRIAL {number}: BASELINE PASS 6/6", flush=True)

                reference_mismatches = run_policy_cases(
                    cases, workload, workload_id, reference.BPF_PROGRAM,
                    f"TRIAL {number} REFERENCE",
                )
                if reference_mismatches:
                    raise RuntimeError(
                        "REFERENCE CONTROL FAILED: " + ", ".join(sorted(reference_mismatches))
                    )
                print(f"TRIAL {number}: REFERENCE PASS 6/6", flush=True)

                mismatches = run_policy_cases(
                    cases, workload, workload_id, mutant, f"TRIAL {number} MUTANT"
                )
                # Check this planted fault's signature after collecting every case.
                if mismatches != EXPECTED_MISMATCHES:
                    raise RuntimeError(
                        "UNEXPECTED MUTANT RESULT: all observed mismatches="
                        + repr(sorted(mismatches)) + "; investigate before grading."
                    )
                print(
                    f"TRIAL {number}: PLANTED FAULT DETECTED; mismatches="
                    + ", ".join(sorted(mismatches)), flush=True,
                )
        if reference.membership() != controller:
            raise RuntimeError("Controller membership changed unexpectedly.")
    finally:
        workload.rmdir()
        print(f"TRIAL {number}: temporary workload removed.", flush=True)


def main():
    if os.geteuid() != 0:
        raise RuntimeError("Use the documented root systemd service.")
    kernel = platform.release()
    print("Kernel:", kernel, flush=True)
    if kernel != VERIFIED_KERNEL:
        raise RuntimeError(
            f"This diagnostic is qualified for {VERIFIED_KERNEL}; "
            "send the current kernel output before continuing. No BPF was loaded."
        )
    if not (reference.MOUNT / "cgroup.controllers").is_file():
        raise RuntimeError("The expected cgroup v2 mount is unavailable.")
    active = Path("/sys/kernel/security/lsm").read_text().strip().split(",")
    if "bpf" not in active:
        raise RuntimeError("BPF-LSM must be active; no BPF was loaded.")
    controller = reference.membership()
    root = reference.delegated_root(controller)
    mutant = make_mutant(reference.BPF_PROGRAM)
    print("Controller cgroup:", controller, flush=True)
    print("Fault: ignore inode; preserve device, cgroup and incoming-ret checks.", flush=True)
    with tempfile.TemporaryDirectory(prefix="sentinel-inode-mutant-") as folder:
        directory = Path(folder)
        binary = reference.build_marker(directory)
        for number in range(1, TRIALS + 1):
            run_trial(number, root, binary, directory, mutant, controller)
    print("DETECTION CONFIRMED: one planted fault detected in two fresh trials.", flush=True)
    print("This is not a random/guided comparison or a Linux vulnerability finding.", flush=True)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        raise SystemExit("Interrupted.")
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        raise SystemExit("CHECK STOPPED: " + str(error))
