#!/usr/bin/python3
"""Compare an LSM cgroup ID with a userspace cgroup file-handle ID.

Reference: Linux tools/testing/selftests/bpf/cgroup_helpers.c reads an
8-byte cgroup ID using name_to_handle_at(). This interpretation is for
cgroup v2, not arbitrary filesystem file handles. The inode is diagnostic
only. Namespace changes and concurrent process migrations are not tested.

Reference source:
https://kernel.googlesource.com/pub/scm/linux/kernel/git/torvalds/linux/+/5920da4455a393490309d6483636b9749ec785fd/tools/testing/selftests/bpf/cgroup_helpers.c
"""

import ctypes as ct
import os
from pathlib import Path
import platform
import subprocess


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


class _CgroupFileHandle(ct.Structure):
    # Linux file_handle header followed by space for its 8-byte payload.
    _fields_ = [
        ("handle_bytes", ct.c_uint),
        ("handle_type", ct.c_int),
        ("cgroup_id", ct.c_uint64),
    ]


def cgroup_id_from_handle(directory):
    """Read the cgroup v2 ID through libc; never fall back to st_ino."""
    if _CgroupFileHandle.cgroup_id.offset != 8 or ct.sizeof(_CgroupFileHandle) != 16:
        raise RuntimeError("Unsupported C file-handle structure layout.")

    libc = ct.CDLL(None, use_errno=True)
    try:
        lookup = libc.name_to_handle_at
    except AttributeError:
        raise RuntimeError("libc does not provide name_to_handle_at.")

    lookup.argtypes = [
        ct.c_int, ct.c_char_p, ct.POINTER(_CgroupFileHandle),
        ct.POINTER(ct.c_int), ct.c_int,
    ]
    lookup.restype = ct.c_int

    handle = _CgroupFileHandle()
    handle.handle_bytes = 8
    mount_id = ct.c_int()
    # AT_FDCWD = -100; flags = 0, matching the Linux self-test method.
    result = lookup(-100, os.fsencode(directory), ct.byref(handle),
                    ct.byref(mount_id), 0)
    if result != 0:
        error = ct.get_errno()
        raise OSError(error, os.strerror(error), str(directory))
    if handle.handle_bytes != 8:
        raise RuntimeError("Cgroup file handle is not the expected 8 bytes.")
    if handle.cgroup_id == 0:
        raise RuntimeError("The cgroup file handle returned an invalid zero ID.")
    return int(handle.cgroup_id)


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
    info = directory.stat()
    if info.st_dev != mount.stat().st_dev:
        raise RuntimeError("The directory is on a different filesystem; stop for review.")
    expected = cgroup_id_from_handle(directory)

    print("Kernel:", platform.release(), flush=True)
    print("Controller cgroup:", cgroup_path, flush=True)
    print("Directory inode (diagnostic only):", info.st_ino, flush=True)
    print("Userspace file-handle cgroup ID:", expected, flush=True)
    print("Compiling and attaching the temporary LSM probe...", flush=True)

    from bcc import BPF

    b = BPF(text=BPF_PROGRAM)
    try:
        table = b["observed"]
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
            raise RuntimeError("Kernel cgroup ID and file-handle ID differ; stop for review.")

        print("[PASS] The kernel cgroup ID matches the userspace file-handle ID.",
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
