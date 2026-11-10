#!/usr/bin/python3
"""Distinguish full-path and basename identity faults using seven fixtures.

Two fresh trials run baseline, correct control, path mutant and basename
mutant. The new witness is another file named program_a in another folder.
The original model and source files are unchanged. This is a fixed diagnostic,
not random/guided evaluation or a production-engine vulnerability finding.
Run in the reference delegated service with a 90-second runtime cap.
"""

from contextlib import ExitStack
import os
from pathlib import Path
import platform
import secrets
import shutil
import subprocess
import tempfile

import enforcement_check as reference
import mutant_inode_check as inode_check
import mutant_path_check as path_check
from policy_model import expected_decision, file_identity
from scope_handle_check import cgroup_id_from_handle


BASENAME_BYTES = 16
PATH_FAILURES = {"allow_symlink", "allow_renamed"}
BASENAME_FAILURES = PATH_FAILURES | {"deny_same_basename"}
PATH_TAIL = "    char registered_path[128];\n};"
BASENAME_CHECK = r"""    const char *name = NULL;
    char requested[128] = {};
    char basename[16] = {};
    if (bpf_probe_read_kernel(&name, sizeof(name), &bprm->filename) != 0 || !name)
        goto read_failure;
    int length = bpf_probe_read_kernel_str(requested, sizeof(requested), name);
    if (length <= 0 || length >= (int)sizeof(requested))
        goto read_failure;

    // Constant indices scan backward; the first slash found is the last one.
    int start = 0;
#pragma unroll
    for (int i = 127; i >= 0; i--) {
        if (i < length - 1 && requested[i] == '/') {
            start = i + 1;
            break;
        }
    }
    if (start < 0 || start >= length - 1 || start >= (int)sizeof(requested))
        goto read_failure;
    int count = bpf_probe_read_kernel_str(basename, sizeof(basename), name + start);
    if (count <= 0 || count >= (int)sizeof(basename))
        goto read_failure;

    // Deliberate fault: equal last components do not identify a file object.
#pragma unroll
    for (int i = 0; i < 16; i++) {
        if (basename[i] != allowed->registered_basename[i])
            return -EPERM;
        if (basename[i] == '\0')
            return 0;
    }
    return -EPERM;
"""


def make_programs(program):
    """Use one 160-byte map layout for the correct control and both faults."""
    control, path_mutant = path_check.make_programs(program)
    extended = []
    for source in (control, path_mutant):
        if source.count(PATH_TAIL) != 1:
            raise RuntimeError("Reference map layout differs; no probe was loaded.")
        extended.append(source.replace(
            PATH_TAIL,
            "    char registered_path[128];\n    char registered_basename[16];\n};",
            1,
        ))
    control, path_mutant = extended
    if control.count(path_check.IDENTITY_CHECK) != 1:
        raise RuntimeError("Reference identity check differs; no probe was loaded.")
    basename_mutant = control.replace(path_check.IDENTITY_CHECK, BASENAME_CHECK, 1)
    return control, path_mutant, basename_mutant


def prepare_cases(directory, binary, stack):
    cases = reference.prepare_cases(directory, binary, stack)
    path_check.bind_paths(cases)
    folder = directory / "deny_same_basename"
    folder.mkdir()
    allowed_path = folder / "program_a"
    other = folder / "other"
    other.mkdir()
    target = other / "program_a"
    shutil.copy2(binary, allowed_path)
    shutil.copy2(binary, target)
    stack.enter_context(allowed_path.open("rb"))
    allowed, target_identity = file_identity(allowed_path), file_identity(target)
    if (target.name != allowed_path.name or target == allowed_path
            or target_identity.inode == allowed.inode
            or (target_identity.major, target_identity.minor) != (allowed.major, allowed.minor)
            or expected_decision(allowed, target_identity) != "DENY"):
        raise RuntimeError("PRECONDITION ERROR: same-basename witness is invalid.")
    cases.append({
        "name": "deny_same_basename", "target": target, "allowed": allowed,
        "expected": "DENY", "in_scope": True,
        "registered_path": os.fsencode(allowed_path),
    })
    for case in cases:
        registered = Path(os.fsdecode(case["registered_path"]))
        for path in (registered, case["target"]):
            if (not path.is_absolute() or len(os.fsencode(path)) > 126
                    or not path.name or len(os.fsencode(path.name)) > BASENAME_BYTES - 2):
                raise RuntimeError("UNSUPPORTED: absolute paths <=126 bytes; names <=14 bytes.")
        case["registered_basename"] = os.fsencode(registered.name)
        prediction = expected_decision(
            case["allowed"], file_identity(case["target"]), in_scope=case["in_scope"]
        )
        if prediction != case["expected"]:
            raise RuntimeError("MODEL ERROR: " + case["name"])
    print(f"WITNESS allowed={str(allowed_path)!r} identity={allowed}", flush=True)
    print(f"WITNESS target={str(target)!r} identity={target_identity}", flush=True)
    print(f"WITNESS: same basename {target.name!r}, different paths and inodes.", flush=True)
    return cases


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
            binding.registered_basename = case["registered_basename"]
            key = policies.Key(workload_id)
            policies[key] = binding
            try:
                token = "SENTINEL_BASENAME_" + secrets.token_hex(16)
                result = reference.run_child(
                    case["target"], token, workload if case["in_scope"] else None
                )
                if int(errors[errors.Key(0)].value) != 0:
                    raise RuntimeError("INSTRUMENTATION ERROR: kernel identity/name read failed.")
                if not inode_check.record_outcome(case, result, token, label):
                    mismatches.add(case["name"])
            finally:
                del policies[key]
    finally:
        probe.cleanup()
        print(f"{label} detached.", flush=True)
    return mismatches


def run_trial(number, root, binary, directory, programs, controller):
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
                cases = prepare_cases(Path(folder), binary, stack)
                reference.run_cases(cases, workload)
                print(f"TRIAL {number}: BASELINE PASS 7/7", flush=True)
                phases = (
                    ("REFERENCE", programs[0], set()),
                    ("PATH MUTANT", programs[1], PATH_FAILURES),
                    ("BASENAME MUTANT", programs[2], BASENAME_FAILURES),
                )
                for name, program, expected in phases:
                    mismatches = run_policy_cases(
                        cases, workload, workload_id, program, f"TRIAL {number} {name}"
                    )
                    # Grade only after every case has been measured and the probe detached.
                    if mismatches != expected:
                        raise RuntimeError(
                            f"UNEXPECTED {name} RESULT: " + repr(sorted(mismatches))
                        )
                    print(
                        f"TRIAL {number}: {name} CHECKED; mismatches="
                        + repr(sorted(mismatches)), flush=True,
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
        raise RuntimeError(f"Use verified kernel {inode_check.VERIFIED_KERNEL}; no BPF was loaded.")
    if not (reference.MOUNT / "cgroup.controllers").is_file():
        raise RuntimeError("The expected cgroup v2 mount is unavailable.")
    if "bpf" not in Path("/sys/kernel/security/lsm").read_text().strip().split(","):
        raise RuntimeError("BPF-LSM must be active; no BPF was loaded.")
    controller = reference.membership()
    root = reference.delegated_root(controller)
    programs = make_programs(reference.BPF_PROGRAM)
    print("Controller cgroup:", controller, flush=True)
    print("Fault: trust a requested basename instead of file-object identity.", flush=True)
    with tempfile.TemporaryDirectory(prefix="sentinel-basename-") as folder:
        directory = Path(folder)
        binary = reference.build_marker(directory)
        for number in (1, 2):
            run_trial(number, root, binary, directory, programs, controller)
    print("DETECTION CONFIRMED: same-basename witness distinguished the two name faults twice.", flush=True)
    print("This is a fixed diagnostic, not random/guided evaluation or a product vulnerability finding.", flush=True)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        raise SystemExit("Interrupted.")
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        raise SystemExit("CHECK STOPPED: " + str(error))
