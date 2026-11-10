#!/usr/bin/python3
"""Detect a requested-path/file-object confusion fault in two fresh trials.

The original sources and model remain unchanged. Both generated C programs
carry a registered pathname: the correct control ignores it, while the mutant
uses it instead of file identity. This is a planted-fault diagnostic, not a
random/guided comparison or a finding about a production path-based engine.
Run in the reference delegated service with a 90-second runtime cap.
"""

from contextlib import ExitStack
import os
from pathlib import Path
import platform
import secrets
import subprocess
import tempfile

import enforcement_check as reference
import mutant_inode_check as inode_check
from policy_model import file_identity
from scope_handle_check import cgroup_id_from_handle


PATH_BYTES = 128
EXPECTED_MISMATCHES = {"allow_symlink", "allow_renamed"}
STRUCT_TAIL = "    u32 minor;\n};"
IDENTITY_CHECK = """    if (allowed->inode == (u64)number &&
        allowed->major == MAJOR(device) && allowed->minor == MINOR(device))
        return 0;
    return -EPERM;
"""
PATH_CHECK = r"""    const char *name = NULL;
    char requested[128] = {};
    if (bpf_probe_read_kernel(&name, sizeof(name), &bprm->filename) != 0 || !name)
        goto read_failure;
    int length = bpf_probe_read_kernel_str(requested, sizeof(requested), name);
    if (length <= 0 || length >= sizeof(requested))
        goto read_failure;

    // Deliberate fault: compare requested names, not resolved file objects.
#pragma unroll
    for (int i = 0; i < 128; i++) {
        if (requested[i] != allowed->registered_path[i])
            return -EPERM;
        if (requested[i] == '\0')
            return 0;
    }
    return -EPERM;
"""


def make_programs(program):
    """Give both controls the same map ABI, then change one decision block."""
    if program.count(STRUCT_TAIL) != 1 or program.count(IDENTITY_CHECK) != 1:
        raise RuntimeError("Reference source differs; no test probe was loaded.")
    control = program.replace(
        STRUCT_TAIL, "    u32 minor;\n    char registered_path[128];\n};", 1
    )
    return control, control.replace(IDENTITY_CHECK, PATH_CHECK, 1)


def bind_paths(cases):
    """Recover and verify the known fixtures' original A registration path."""
    inode_check.qualify_fixtures(cases)
    for case in cases:
        # prepare_cases creates A at program_a before symlink/rename/copy setup.
        registered = case["target"].parent / "program_a"
        if case["name"] == "allow_renamed":
            if os.path.lexists(registered) or file_identity(case["target"]) != case["allowed"]:
                raise RuntimeError("PRECONDITION ERROR: renamed A fixture changed.")
        elif file_identity(registered) != case["allowed"]:
            raise RuntimeError("PRECONDITION ERROR: original A binding changed.")
        for path in (registered, case["target"]):
            if not path.is_absolute() or len(os.fsencode(path)) > PATH_BYTES - 2:
                raise RuntimeError("UNSUPPORTED: fixture paths must be absolute and <=126 bytes.")
        case["registered_path"] = os.fsencode(registered)


def run_policy_cases(cases, workload, workload_id, program, label):
    from bcc import BPF

    print(f"Compiling {label}...", flush=True)
    probe = BPF(text=program)
    mismatches = set()
    try:
        policies, errors = probe["policies"], probe["read_errors"]
        for case in cases:
            identity = case["allowed"]
            binding = policies.Leaf()
            binding.inode = identity.inode
            binding.major, binding.minor = identity.major, identity.minor
            binding.registered_path = case["registered_path"]
            key = policies.Key(workload_id)
            policies[key] = binding
            try:
                token = "SENTINEL_PATH_" + secrets.token_hex(16)
                result = reference.run_child(
                    case["target"], token, workload if case["in_scope"] else None
                )
                if int(errors[errors.Key(0)].value) != 0:
                    raise RuntimeError("INSTRUMENTATION ERROR: kernel identity/path read failed.")
                if not inode_check.record_outcome(case, result, token, label):
                    mismatches.add(case["name"])
            finally:
                del policies[key]
    finally:
        probe.cleanup()
        print(f"{label} detached.", flush=True)
    return mismatches


def run_trial(number, root, binary, directory, control, mutant, controller):
    workload = root / f"workload-{number}"
    workload.mkdir()
    try:
        workload_id = cgroup_id_from_handle(workload)
        controller_id = cgroup_id_from_handle(reference.MOUNT / controller.lstrip("/"))
        if workload_id == controller_id:
            raise RuntimeError("Controller and workload IDs unexpectedly match.")
        print(f"TRIAL {number}: fresh workload ID={workload_id}", flush=True)
        with tempfile.TemporaryDirectory(prefix=f"trial-{number}-", dir=directory) as folder:
            with ExitStack() as stack:
                cases = reference.prepare_cases(Path(folder), binary, stack)
                bind_paths(cases)
                reference.run_cases(cases, workload)
                print(f"TRIAL {number}: BASELINE PASS 6/6", flush=True)
                failures = run_policy_cases(
                    cases, workload, workload_id, control, f"TRIAL {number} REFERENCE"
                )
                if failures:
                    raise RuntimeError("REFERENCE CONTROL FAILED: " + repr(sorted(failures)))
                print(f"TRIAL {number}: REFERENCE PASS 6/6", flush=True)
                mismatches = run_policy_cases(
                    cases, workload, workload_id, mutant, f"TRIAL {number} PATH MUTANT"
                )
                # Collect every mismatch before checking this fault's signature.
                if mismatches != EXPECTED_MISMATCHES:
                    raise RuntimeError("UNEXPECTED MUTANT RESULT: " + repr(sorted(mismatches)))
                print(
                    f"TRIAL {number}: PATH FAULT DETECTED; false denials="
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
    if kernel != inode_check.VERIFIED_KERNEL:
        raise RuntimeError(
            f"Use verified kernel {inode_check.VERIFIED_KERNEL}; no BPF was loaded."
        )
    if not (reference.MOUNT / "cgroup.controllers").is_file():
        raise RuntimeError("The expected cgroup v2 mount is unavailable.")
    active = Path("/sys/kernel/security/lsm").read_text().strip().split(",")
    if "bpf" not in active:
        raise RuntimeError("BPF-LSM must be active; no BPF was loaded.")
    controller = reference.membership()
    root = reference.delegated_root(controller)
    control, mutant = make_programs(reference.BPF_PROGRAM)
    print("Controller cgroup:", controller, flush=True)
    print("Fault: use original requested pathname instead of file-object identity.", flush=True)
    with tempfile.TemporaryDirectory(prefix="sentinel-path-mutant-") as folder:
        directory = Path(folder)
        binary = reference.build_marker(directory)
        for number in (1, 2):
            run_trial(number, root, binary, directory, control, mutant, controller)
    print("DETECTION CONFIRMED: path/object fault detected in two fresh trials.", flush=True)
    print("This is not a random/guided comparison or a production-engine vulnerability finding.", flush=True)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        raise SystemExit("Interrupted.")
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        raise SystemExit("CHECK STOPPED: " + str(error))
