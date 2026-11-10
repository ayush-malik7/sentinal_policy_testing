#!/usr/bin/python3
"""Compare a child's kernel cgroup ID with its inherited cgroup's inode.

This temporary BCC LSM probe adds no denial. This check covers one child
in the controller's cgroup; a separate test group and blocking come later.
"""

import os
from pathlib import Path
import platform
import subprocess

from bcc import BPF


BPF_PROGRAM = r"""
struct linux_binprm;

// Key: process TGID. Value: cgroup ID observed during an execution check.
BPF_HASH(observed, u32, u64, 256);

LSM_PROBE(bprm_check_security, struct linux_binprm *bprm, int ret)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 cgroup_id = bpf_get_current_cgroup_id();

    observed.update(&pid, &cgroup_id);

    // Preserve the incoming decision, including an earlier BPF denial.
    return ret;
}
"""


def main():
    if os.geteuid() != 0:
        raise RuntimeError("Run with sudo and /usr/bin/python3.")

    mount = Path("/sys/fs/cgroup")
    if not (mount / "cgroup.controllers").is_file():
        raise RuntimeError("The expected cgroup v2 interface is unavailable.")

    memberships = [
        line[3:] for line in Path("/proc/self/cgroup").read_text().splitlines()
        if line.startswith("0::")
    ]
    if len(memberships) != 1:
        raise RuntimeError("Expected one cgroup v2 membership entry.")

    cgroup_path = memberships[0]
    if not cgroup_path.startswith("/") or ".." in Path(cgroup_path).parts:
        raise RuntimeError("Unexpected cgroup namespace path; stop for review.")

    directory = mount / cgroup_path.lstrip("/")
    expected = directory.stat().st_ino

    print("Kernel:", platform.release(), flush=True)
    print("Controller cgroup:", cgroup_path, flush=True)
    print("Directory inode:", expected, flush=True)
    print("Compiling and attaching the temporary LSM probe...", flush=True)

    b = BPF(text=BPF_PROGRAM)
    try:
        table = b["observed"]
        # A normal child inherits this process's cgroup membership.
        child = subprocess.Popen(["/usr/bin/true"])
        try:
            status = child.wait(timeout=3)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait(timeout=3)
            raise RuntimeError("The harmless child exceeded its time limit.")

        print("Child PID:", child.pid, flush=True)
        print("Child exit status:", status, flush=True)
        if status != 0:
            raise RuntimeError("The harmless child did not exit successfully.")

        try:
            actual = int(table[table.Key(child.pid)].value)
        except KeyError:
            raise RuntimeError("No LSM observation found for this child's PID.")

        print("Kernel-observed cgroup ID:", actual, flush=True)
        if actual != expected:
            raise RuntimeError("Kernel ID and directory inode differ; stop for review.")

        print("[PASS] The child's kernel cgroup ID matches the directory inode.",
              flush=True)
    finally:
        b.cleanup()
        print("Temporary LSM probe detached.", flush=True)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        raise SystemExit("Interrupted.")
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        raise SystemExit("CHECK STOPPED: " + str(error))
