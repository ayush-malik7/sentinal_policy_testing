#!/usr/bin/python3
"""Six bounded execution checks for Sentinel's file-object contract.

Default/--baseline runs no BPF program and adds no denials. --enforce first
checks those same fixtures without Sentinel, then loads a reference policy
for one live workload cgroup. Run through the documented delegated service.
Execution evidence comes from an ELF marker and a close-on-exec error pipe,
not from the policy's maps or printed decisions. This is not a benchmark.
"""

import argparse
from contextlib import ExitStack
import errno
import os
from pathlib import Path
import platform
import secrets
import shutil
import signal
import subprocess
import tempfile
import time

from policy_model import FIXTURES, expected_decision, file_identity, prepare_target
from scope_handle_check import cgroup_id_from_handle


UNIT = "sentinel-enforcement-check.service"
MOUNT = Path("/sys/fs/cgroup")

MARKER_SOURCE = r"""
#include <string.h>
#include <unistd.h>
int main(int argc, char **argv)
{
    if (argc != 2)
        return 2;
    size_t length = strlen(argv[1]);
    if (write(STDOUT_FILENO, argv[1], length) != (ssize_t)length)
        return 3;
    return 0;
}
"""

BPF_PROGRAM = r"""
#include <linux/binfmts.h>
#include <linux/fs.h>
#include <linux/kdev_t.h>
#include <uapi/linux/errno.h>

struct identity_t {
    u64 inode;
    u32 major;
    u32 minor;
};

// No entry means this policy adds no denial for that cgroup.
BPF_HASH(policies, u64, struct identity_t, 1);
BPF_ARRAY(read_errors, u64, 1);

LSM_PROBE(bprm_check_security, struct linux_binprm *bprm, int ret)
{
    // ret is from an earlier BPF program at this hook, not every LSM.
    if (ret != 0)
        return ret;

    u64 group = bpf_get_current_cgroup_id();
    struct identity_t *allowed = policies.lookup(&group);
    if (!allowed)
        return 0;

    struct file *file = NULL;
    struct inode *inode = NULL;
    struct super_block *super = NULL;
    unsigned long number = 0;
    dev_t device = 0;

    if (!bprm)
        goto read_failure;
    if (bpf_probe_read_kernel(&file, sizeof(file), &bprm->file) != 0 || !file)
        goto read_failure;
    if (bpf_probe_read_kernel(&inode, sizeof(inode), &file->f_inode) != 0 || !inode)
        goto read_failure;
    if (bpf_probe_read_kernel(&number, sizeof(number), &inode->i_ino) != 0)
        goto read_failure;
    if (bpf_probe_read_kernel(&super, sizeof(super), &inode->i_sb) != 0 || !super)
        goto read_failure;
    if (bpf_probe_read_kernel(&device, sizeof(device), &super->s_dev) != 0)
        goto read_failure;

    if (allowed->inode == (u64)number &&
        allowed->major == MAJOR(device) && allowed->minor == MINOR(device))
        return 0;
    return -EPERM;

read_failure:
    {
        u32 zero = 0;
        u64 *errors = read_errors.lookup(&zero);
        if (errors)
            __sync_fetch_and_add(errors, 1);
    }
    // A read failure denies in the selected group, but invalidates the test.
    return -EPERM;
}
"""


def membership():
    entries = [line[3:] for line in Path("/proc/self/cgroup").read_text().splitlines()
               if line.startswith("0::")]
    if len(entries) != 1 or not entries[0].startswith("/"):
        raise RuntimeError("Expected one absolute cgroup v2 membership path.")
    if ".." in Path(entries[0]).parts:
        raise RuntimeError("Unsupported cgroup namespace path.")
    return entries[0]


def delegated_root(controller):
    result = subprocess.run(
        ["/usr/bin/systemctl", "show", UNIT, "--property=ControlGroup",
         "--property=Delegate", "--property=DelegateSubgroup"],
        capture_output=True, text=True, check=True, timeout=3,
    )
    values = dict(line.split("=", 1) for line in result.stdout.splitlines()
                  if "=" in line)
    root = values.get("ControlGroup", "")
    if (values.get("Delegate") != "yes"
            or values.get("DelegateSubgroup") != "controller"
            or not root.startswith("/") or not root.endswith("/" + UNIT)
            or ".." in Path(root).parts
            or controller != root + "/controller"):
        raise RuntimeError("Use the documented delegated systemd service command.")
    return MOUNT / root.lstrip("/")


def build_marker(directory):
    source = directory / "entry_marker.c"
    binary = directory / "entry_marker"
    source.write_text(MARKER_SOURCE, encoding="utf-8")
    subprocess.run(["/usr/bin/cc", "-O2", "-Wall", "-Wextra", "-o",
                    str(binary), str(source)], check=True, timeout=10)
    with binary.open("rb") as stream:
        if stream.read(4) != b"\x7fELF":
            raise RuntimeError("The compiler did not produce an ELF fixture.")
    return binary


def prepare_cases(directory, binary, stack):
    fixtures = [(name, operation, expected, True)
                for name, operation, expected in FIXTURES]
    fixtures.append(("allow_outside_scope", "other", "ALLOW", False))
    cases = []
    for name, operation, expected, in_scope in fixtures:
        folder = directory / name
        folder.mkdir()
        a, b = folder / "program_a", folder / "program_b"
        shutil.copy2(binary, a)
        shutil.copy2(binary, b)
        # Keep each allowed object alive until the entire experiment ends.
        stack.enter_context(a.open("rb"))
        allowed = file_identity(a)
        target = prepare_target(operation, a, b, folder)
        prediction = expected_decision(allowed, file_identity(target),
                                       in_scope=in_scope)
        if prediction != expected:
            raise RuntimeError(f"MODEL ERROR: {name}: expected {expected}, got {prediction}.")
        cases.append({"name": name, "target": target, "allowed": allowed,
                      "expected": expected, "in_scope": in_scope})
    return cases


def run_child(target, token, workload=None):
    """Collect actual exec errno, entry marker and exit status independently."""
    marker_read, marker_write = os.pipe2(os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        error_read, error_write = os.pipe2(os.O_CLOEXEC | os.O_NONBLOCK)
    except BaseException:
        os.close(marker_read)
        os.close(marker_write)
        raise
    try:
        pid = os.fork()
    except BaseException:
        for fd in (marker_read, marker_write, error_read, error_write):
            os.close(fd)
        raise
    if pid == 0:
        try:
            os.close(marker_read)
            os.close(error_read)
            if workload is not None:
                fd = os.open(str(workload / "cgroup.procs"), os.O_WRONLY)
                try:
                    value = str(os.getpid()).encode("ascii")
                    if os.write(fd, value) != len(value):
                        raise RuntimeError("Incomplete cgroup membership write.")
                finally:
                    os.close(fd)
            os.dup2(marker_write, 1)
            if marker_write != 1:
                os.close(marker_write)
        except BaseException:
            os.write(error_write, b"SETUP_ERROR")
            os._exit(126)
        try:
            os.execv(str(target), [str(target), token])
        except OSError as error:
            os.write(error_write, ("EXEC_ERRNO:" + str(error.errno)).encode("ascii"))
            os._exit(125)
        except BaseException:
            os.write(error_write, b"EXEC_HARNESS_ERROR")
            os._exit(126)

    os.close(marker_write)
    os.close(error_write)
    reaped = False
    try:
        deadline = time.monotonic() + 3
        while True:
            done, status = os.waitpid(pid, os.WNOHANG)
            if done == pid:
                reaped = True
                break
            if time.monotonic() >= deadline:
                raise RuntimeError("HARNESS ERROR: child execution timed out.")
            time.sleep(0.01)
        # Pipes stay nonblocking: a leaked write descriptor cannot hang us.
        marker = os.read(marker_read, 4096)
        error = os.read(error_read, 4096)
        code = os.waitstatus_to_exitcode(status)
        return {"pid": pid, "exit": code, "marker": marker, "error": error}
    finally:
        try:
            if not reaped:
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                os.waitpid(pid, 0)
        finally:
            os.close(marker_read)
            os.close(error_read)


def actual_decision(result, token):
    if result["exit"] == 0 and result["marker"] == token.encode("ascii") and not result["error"]:
        return "ALLOW"
    denied = ("EXEC_ERRNO:" + str(errno.EPERM)).encode("ascii")
    if result["exit"] == 125 and result["error"] == denied and result["marker"] == b"":
        return "DENY"
    raise RuntimeError(
        "HARNESS/PRECONDITION ERROR: "
        f"exit={result['exit']}, error={result['error']!r}, marker={result['marker']!r}."
    )


def run_cases(cases, workload, policies=None, errors=None, workload_id=None):
    enforcing = policies is not None
    for case in cases:
        armed = False
        try:
            if enforcing:
                identity = case["allowed"]
                policies[policies.Key(workload_id)] = policies.Leaf(
                    identity.inode, identity.major, identity.minor)
                armed = True
            token = "SENTINEL_ENTRY_" + secrets.token_hex(16)
            # Membership is fixture setup completed before the exec attempt.
            result = run_child(case["target"], token,
                               workload if case["in_scope"] else None)
            if errors is not None and int(errors[errors.Key(0)].value) != 0:
                raise RuntimeError("INSTRUMENTATION ERROR: kernel file-identity read failed.")
            actual = actual_decision(result, token)
            expected = case["expected"] if enforcing else "ALLOW"
            mode = "ENFORCE" if enforcing else "BASELINE"
            print(f"[{mode}] {case['name']}: expected={expected} actual={actual} "
                  f"exit={result['exit']} exec_error={result['error']!r}", flush=True)
            if actual != expected:
                label = "CANDIDATE MISMATCH; repeat before confirmation" if enforcing else "PRECONDITION ERROR"
                raise RuntimeError(f"{label}: {case['name']}.")
        finally:
            if armed:
                del policies[policies.Key(workload_id)]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--baseline", action="store_true", help="No BPF load; this is the default.")
    modes.add_argument("--enforce", action="store_true", help="Baseline, then a scoped reference enforcer.")
    args = parser.parse_args()
    if os.geteuid() != 0 or not (MOUNT / "cgroup.controllers").is_file():
        raise RuntimeError("Use the documented root service on the cgroup v2 lab VM.")
    if args.enforce:
        active = Path("/sys/kernel/security/lsm").read_text().strip().split(",")
        if "bpf" not in active:
            raise RuntimeError("The BPF LSM must be active for --enforce.")
    controller = membership()
    root = delegated_root(controller)
    workload = root / "workload"
    workload.mkdir()
    probe = None
    try:
        workload_id = cgroup_id_from_handle(workload)
        controller_id = cgroup_id_from_handle(MOUNT / controller.lstrip("/"))
        if workload_id == controller_id:
            raise RuntimeError("Controller and workload IDs unexpectedly match.")
        print("Kernel:", platform.release(), flush=True)
        print("Controller cgroup:", controller, flush=True)
        print("Workload file-handle ID:", workload_id, flush=True)
        with tempfile.TemporaryDirectory(prefix="sentinel-exec-") as folder, ExitStack() as stack:
            directory = Path(folder)
            binary = build_marker(directory)
            cases = prepare_cases(directory, binary, stack)
            run_cases(cases, workload)
            print(f"BASELINE PASS: {len(cases)}/{len(cases)} executed with the correct marker.", flush=True)
            if args.enforce:
                from bcc import BPF
                print("Compiling the scoped reference enforcer...", flush=True)
                probe = BPF(text=BPF_PROGRAM)
                run_cases(cases, workload, probe["policies"], probe["read_errors"], workload_id)
                print(f"ENFORCEMENT PASS: {len(cases)}/{len(cases)} matched the model.", flush=True)
            else:
                print("Baseline only: no BPF program was loaded and no Sentinel denial was added.", flush=True)
        if membership() != controller:
            raise RuntimeError("Controller membership changed unexpectedly.")
    finally:
        try:
            if probe is not None:
                probe.cleanup()
                print("Reference enforcer detached.", flush=True)
        finally:
            workload.rmdir()
            print("Temporary workload cgroup removed.", flush=True)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        raise SystemExit("Interrupted.")
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        raise SystemExit("CHECK STOPPED: " + str(error))
