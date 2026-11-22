#!/usr/bin/python3
"""AI-agent cgroup sandbox demo using Sentinel's BPF-LSM file-object enforcer.

Demonstrates how an untrusted tool-running agent placed inside a dedicated
cgroup v2 is allowed to run an approved native tool (matched by device + inode)
but blocked with EPERM when attempting to launch an unapproved shell or a
same-basename copy, while the outside controller remains unrestricted.

Use --model-only anywhere without root/BPF, or --enforce inside the
delegated SentinelLab systemd service.
"""

import argparse
from contextlib import ExitStack
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import tempfile

import enforcement_check as enforcer
from policy_model import expected_decision, file_identity
from scope_handle_check import cgroup_id_from_handle


def prepare_agent_scenarios(directory, binary, stack):
    """Build 4 concrete scenarios for an untrusted agent inside a cgroup."""
    folder = directory / "agent_sandbox"
    folder.mkdir()

    approved_tool = folder / "approved_tool"
    shutil.copy2(binary, approved_tool)
    stack.enter_context(approved_tool.open("rb"))
    allowed_id = file_identity(approved_tool)

    unapproved_shell = folder / "sh_copy"
    shutil.copy2(binary, unapproved_shell)

    same_name_dir = folder / "untrusted"
    same_name_dir.mkdir()
    same_name_copy = same_name_dir / "approved_tool"
    shutil.copy2(binary, same_name_copy)

    controller_tool = folder / "controller_diag"
    shutil.copy2(binary, controller_tool)

    scenarios = [
        {
            "name": "agent_runs_approved_tool",
            "target": approved_tool,
            "allowed": allowed_id,
            "in_scope": True,
            "expected": expected_decision(allowed_id, file_identity(approved_tool), in_scope=True),
        },
        {
            "name": "agent_spawns_unapproved_shell",
            "target": unapproved_shell,
            "allowed": allowed_id,
            "in_scope": True,
            "expected": expected_decision(allowed_id, file_identity(unapproved_shell), in_scope=True),
        },
        {
            "name": "agent_runs_same_basename_copy",
            "target": same_name_copy,
            "allowed": allowed_id,
            "in_scope": True,
            "expected": expected_decision(allowed_id, file_identity(same_name_copy), in_scope=True),
        },
        {
            "name": "controller_outside_agent_cgroup",
            "target": controller_tool,
            "allowed": allowed_id,
            "in_scope": False,
            "expected": expected_decision(allowed_id, file_identity(controller_tool), in_scope=False),
        },
    ]
    return scenarios


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--model-only", action="store_true", help="Check model predictions without BPF/root.")
    modes.add_argument("--enforce", action="store_true", help="Run live cgroup + BPF-LSM enforcement.")
    args = parser.parse_args()

    if not args.enforce:
        with tempfile.TemporaryDirectory(prefix="sentinel-agent-model-") as tmp, ExitStack() as stack:
            folder = Path(tmp)
            binary = enforcer.build_marker(folder)
            scenarios = prepare_agent_scenarios(folder, binary, stack)
            for sc in scenarios:
                print(f"[MODEL] {sc['name']}: in_scope={sc['in_scope']} expected={sc['expected']}")
        print("MODEL-ONLY PASS: 4 agent scenarios verified without loading BPF.")
        return

    if os.geteuid() != 0 or not (enforcer.MOUNT / "cgroup.controllers").is_file():
        raise RuntimeError("Run --enforce inside the delegated root systemd service on cgroup v2.")
    if "bpf" not in Path("/sys/kernel/security/lsm").read_text().strip().split(","):
        raise RuntimeError("BPF-LSM must be active for --enforce.")

    controller = enforcer.membership()
    root = enforcer.delegated_root(controller)
    workload = root / "agent-workload"
    workload.mkdir()
    probe = None
    try:
        workload_id = cgroup_id_from_handle(workload)
        from bcc import BPF
        probe = BPF(text=enforcer.BPF_PROGRAM)
        policies, errors = probe["policies"], probe["read_errors"]

        with tempfile.TemporaryDirectory(prefix="sentinel-agent-") as tmp, ExitStack() as stack:
            folder = Path(tmp)
            binary = enforcer.build_marker(folder)
            scenarios = prepare_agent_scenarios(folder, binary, stack)

            for sc in scenarios:
                key = policies.Key(workload_id)
                identity = sc["allowed"]
                policies[key] = policies.Leaf(identity.inode, identity.major, identity.minor)
                try:
                    token = "SENTINEL_AGENT_" + secrets.token_hex(12)
                    result = enforcer.run_child(
                        sc["target"], token, workload if sc["in_scope"] else None
                    )
                    if int(errors[errors.Key(0)].value) != 0:
                        raise RuntimeError("Kernel file-identity read failed.")
                    actual = enforcer.actual_decision(result, token)
                    match = actual == sc["expected"]
                    print(
                        f"[ENFORCE] {sc['name']}: expected={sc['expected']} "
                        f"actual={actual} match={match} exit={result['exit']}"
                    )
                    if not match:
                        raise RuntimeError(f"Mismatch on {sc['name']}")
                finally:
                    del policies[key]
        print("AGENT SANDBOX PASS: 4/4 scenarios matched the file-object contract.")
    finally:
        try:
            if probe is not None:
                probe.cleanup()
        finally:
            workload.rmdir()


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        raise SystemExit("AGENT DEMO STOPPED: " + str(error))
