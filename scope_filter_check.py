#!/usr/bin/python3
"""Test a kernel scope flag without adding execution denials.

Run only in the provided systemd service with Delegate=yes and
DelegateSubgroup=controller. The controller stays outside the selected
workload cgroup. Only fresh test children may be moved into that group.
"""

import os
from pathlib import Path
import platform
import signal
import subprocess
import time

from scope_handle_check import cgroup_id_from_handle


UNIT = "sentinel-scope-filter-check.service"
MOUNT = Path("/sys/fs/cgroup")

BPF_PROGRAM = r"""
struct linux_binprm;

struct observation_t {
    u64 cgroup_id;
    u32 in_scope;
    int prior_ret;
};

// Zero means that no workload group has been selected.
BPF_ARRAY(target_cgroup, u64, 1);
BPF_HASH(observed, u32, struct observation_t, 256);

LSM_PROBE(bprm_check_security, struct linux_binprm *bprm, int ret)
{
    u32 index = 0;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 *target = target_cgroup.lookup(&index);
    struct observation_t event = {};

    event.cgroup_id = bpf_get_current_cgroup_id();
    event.prior_ret = ret;
    if (target && *target != 0 && event.cgroup_id == *target)
        event.in_scope = 1;

    observed.update(&pid, &event);

    // Classification only: add no denial and preserve any earlier one.
    return ret;
}
"""


def membership():
    entries = [
        line[3:] for line in Path("/proc/self/cgroup").read_text().splitlines()
        if line.startswith("0::")
    ]
    if len(entries) != 1:
        raise RuntimeError("Expected one cgroup v2 membership entry.")
    path = entries[0]
    if not path.startswith("/") or ".." in Path(path).parts:
        raise RuntimeError("Unsupported cgroup namespace path.")
    return path


def delegated_root(controller_path):
    result = subprocess.run(
        ["/usr/bin/systemctl", "show", UNIT,
         "--property=ControlGroup", "--property=Delegate",
         "--property=DelegateSubgroup"],
        capture_output=True, text=True, check=True, timeout=3,
    )
    properties = dict(
        line.split("=", 1) for line in result.stdout.splitlines() if "=" in line
    )
    root_path = properties.get("ControlGroup", "")
    if (properties.get("Delegate") != "yes"
            or properties.get("DelegateSubgroup") != "controller"
            or not root_path.startswith("/")
            or not root_path.endswith("/" + UNIT)
            or ".." in Path(root_path).parts
            or controller_path != root_path.rstrip("/") + "/controller"):
        raise RuntimeError("Use the provided delegated systemd service command.")
    return MOUNT / root_path.lstrip("/")


def run_child(workload=None):
    """Run true, moving only the new child when a workload group is given."""
    pid = os.fork()
    if pid == 0:
        try:
            if workload is not None:
                fd = os.open(str(workload / "cgroup.procs"), os.O_WRONLY)
                try:
                    data = str(os.getpid()).encode("ascii")
                    if os.write(fd, data) != len(data):
                        raise RuntimeError("Incomplete cgroup membership write.")
                finally:
                    os.close(fd)
            os.execv("/usr/bin/true", ["true"])
        except BaseException as error:
            os.write(2, ("Child setup/exec failed: " + str(error) + "\n").encode())
            os._exit(127)

    reaped = False
    try:
        deadline = time.monotonic() + 3
        while True:
            done, status = os.waitpid(pid, os.WNOHANG)
            if done == pid:
                reaped = True
                code = os.waitstatus_to_exitcode(status)
                if code != 0:
                    raise RuntimeError(f"Child {pid} exited with {code}.")
                return pid
            if time.monotonic() >= deadline:
                raise RuntimeError(f"Child {pid} exceeded its time limit.")
            time.sleep(0.01)
    finally:
        if not reaped:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            os.waitpid(pid, 0)


def check_observation(table, label, pid, expected_id, expected_scope):
    try:
        event = table[table.Key(pid)]
    except KeyError:
        raise RuntimeError(f"No LSM observation found for {label} PID {pid}.")
    actual_id = int(event.cgroup_id)
    actual_scope = int(event.in_scope)
    print(
        f"OBSERVED {label}: pid={pid} cgroup_id={actual_id} "
        f"in_scope={actual_scope} incoming_ret={event.prior_ret} child_exit=0",
        flush=True,
    )
    if actual_id != expected_id or actual_scope != expected_scope:
        raise RuntimeError(
            f"{label}: expected cgroup_id={expected_id}, in_scope={expected_scope}."
        )
    print(f"[PASS] {label}", flush=True)


def main():
    if os.geteuid() != 0:
        raise RuntimeError("Run through the provided root systemd service.")
    if not (MOUNT / "cgroup.controllers").is_file():
        raise RuntimeError("The expected cgroup v2 mount is unavailable.")

    controller_path = membership()
    root = delegated_root(controller_path)
    controller = MOUNT / controller_path.lstrip("/")
    workload = root / "workload"
    probe = None
    created = False
    try:
        # These are setup operations, before the two execution cases.
        workload.mkdir()
        created = True
        controller_id = cgroup_id_from_handle(controller)
        workload_id = cgroup_id_from_handle(workload)
        if controller_id == workload_id:
            raise RuntimeError("Controller and workload IDs unexpectedly match.")

        print("Kernel:", platform.release(), flush=True)
        print("Controller cgroup:", controller_path, flush=True)
        print("Controller file-handle ID:", controller_id, flush=True)
        print("Workload cgroup:", "/" + str(workload.relative_to(MOUNT)), flush=True)
        print("Workload file-handle ID:", workload_id, flush=True)
        print("Compiling and attaching the observation-only LSM probe...", flush=True)

        from bcc import BPF

        probe = BPF(text=BPF_PROGRAM)
        selected = probe["target_cgroup"]
        selected[selected.Key(0)] = selected.Leaf(workload_id)
        observed = probe["observed"]

        outside_pid = run_child()
        check_observation(observed, "outside", outside_pid, controller_id, 0)

        inside_pid = run_child(workload)
        check_observation(observed, "inside", inside_pid, workload_id, 1)

        if membership() != controller_path:
            raise RuntimeError("Controller membership changed unexpectedly.")
        print("Controller remained outside the workload cgroup.", flush=True)
    finally:
        try:
            if probe is not None:
                probe.cleanup()
                print("Temporary LSM probe detached.", flush=True)
        finally:
            if created:
                workload.rmdir()
                print("Temporary workload cgroup removed.", flush=True)

    print("[PASS] Both kernel scope flags matched; this probe added no denials.",
          flush=True)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        raise SystemExit("Interrupted.")
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        raise SystemExit("CHECK STOPPED: " + str(error))
