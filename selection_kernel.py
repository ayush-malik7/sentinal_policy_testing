#!/usr/bin/python3
"""Calibrate, smoke-test and run one seed of the frozen selection pilot.

No selector rules or existing sources are changed. Only scope-preserving
mutants are used. Raw JSONL reports retain outcomes and cleanup events.
Calibration is not comparative pilot data. Run in the delegated lab service.
"""

import argparse
from collections import Counter
from contextlib import ExitStack
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import secrets
import signal
import subprocess
import tempfile
import time
import traceback

import enforcement_check as reference
import mutant_basename_check as fixtures
import mutant_inode_check as inode_check
import mutant_path_check as path_check
import policy_model
import scope_handle_check
import selection_plan as selection


ROOT = Path(__file__).resolve().parent
SCHEMA = "sentinel-selection-kernel-v0"
FROZEN_COMMIT = "1189529"
REPETITIONS = 2
INPUTS = (
    "selection_kernel.py", "selection_plan.py", "policy_model.py",
    "enforcement_check.py", "mutant_inode_check.py", "mutant_path_check.py",
    "mutant_basename_check.py", "scope_handle_check.py", "docs/pilot_protocol_v0.md",
)
SIGNATURES = {
    "ignore_inode": {"deny_other", "deny_copy", "deny_same_basename"},
    "requested_path_identity": {"allow_symlink", "allow_renamed"},
    "basename_identity": {"allow_symlink", "allow_renamed", "deny_same_basename"},
}


class RunFailure(RuntimeError):
    def __init__(self, kind, message):
        super().__init__(message)
        self.kind = kind


def git(*arguments):
    # Trust only this task's repository for read-only root metadata queries.
    result = subprocess.run(
        ["/usr/bin/git", "-c", f"safe.directory={ROOT}", "-C", str(ROOT), *arguments],
        check=True, capture_output=True, timeout=5,
    )
    return result.stdout


def source_hashes():
    return {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in INPUTS}


def make_programs():
    control, path_mutant, basename_mutant = fixtures.make_programs(reference.BPF_PROGRAM)
    return {
        "reference": control,
        "ignore_inode": inode_check.make_mutant(control),
        "requested_path_identity": path_mutant,
        "basename_identity": basename_mutant,
    }


def environment(programs, mode):
    if platform.release() != inode_check.VERIFIED_KERNEL:
        raise RunFailure("unsupported", f"Use verified kernel {inode_check.VERIFIED_KERNEL}; no BPF loaded.")
    if not (reference.MOUNT / "cgroup.controllers").is_file():
        raise RunFailure("unsupported", "Expected cgroup v2 mount is missing.")
    if "bpf" not in Path("/sys/kernel/security/lsm").read_text().strip().split(","):
        raise RunFailure("unsupported", "BPF-LSM is not active; no BPF loaded.")
    modules = (reference, fixtures, inode_check, path_check, policy_model,
               scope_handle_check, selection)
    for module in modules:
        expected = ROOT / (module.__name__ + ".py")
        if Path(module.__file__).resolve() != expected:
            raise RunFailure("provenance_error", "Imported input is outside this checkout: " + module.__name__)
    for name in ("selection_plan.py", "docs/pilot_protocol_v0.md"):
        if (ROOT / name).read_bytes() != git("show", f"{FROZEN_COMMIT}:{name}"):
            raise RunFailure("provenance_error", "Frozen input differs from 1189529: " + name)
    if (selection.PROTOCOL != "sentinel-fixture-selection-v0"
            or selection.DEFAULT_BUDGET != 4 or selection.SEEDS != tuple(range(30))):
        raise RunFailure("provenance_error", "Loaded selection settings differ from protocol v0.")
    tracked = set(git("ls-files", "--", *INPUTS).decode().splitlines())
    untracked = sorted(set(INPUTS) - tracked)
    dirty = sorted(set(git("diff", "--name-only", "HEAD", "--", *INPUTS).decode().splitlines())
                   | set(git("diff", "--cached", "--name-only", "--", *INPUTS).decode().splitlines()))
    if mode != "calibration" and (untracked or dirty):
        raise RunFailure("provenance_error", "Commit experimental inputs before smoke/pilot: "
                         + repr({"untracked": untracked, "modified": dirty}))
    packages = subprocess.run(
        ["/usr/bin/dpkg-query", "-W", "-f=${binary:Package} ${Version}\n",
         "python3-bpfcc", "libbpfcc", "bpfcc-tools"],
        capture_output=True, text=True, check=True, timeout=5,
    ).stdout.strip().splitlines()
    import bcc
    return {
        "git_commit": git("rev-parse", "HEAD").decode().strip(),
        "untracked_inputs": untracked, "modified_inputs": dirty,
        "source_hashes": source_hashes(),
        "program_hashes": {name: hashlib.sha256(code.encode()).hexdigest()
                           for name, code in programs.items()},
        "kernel": platform.release(), "python": platform.python_version(),
        "bcc_packages": packages, "bcc_location": bcc.__file__,
    }


class Journal:
    def __init__(self, mode, seed):
        folder = ROOT / "results"
        if folder.is_symlink():
            raise RunFailure("report_error", "results must not be a symbolic link.")
        owner = ROOT.stat()
        try:
            folder.mkdir(mode=0o755)
        except FileExistsError:
            if not folder.is_dir():
                raise RunFailure("report_error", "results is not a directory.")
        else:
            os.chown(folder, owner.st_uid, owner.st_gid)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        self.path = folder / f"{mode}_seed{seed}_{stamp}_{secrets.token_hex(4)}.jsonl"
        self.stream = self.path.open("x", encoding="utf-8")
        os.fchmod(self.stream.fileno(), 0o644)
        os.fchown(self.stream.fileno(), owner.st_uid, owner.st_gid)
        self.counts = Counter()

    def emit(self, event, **fields):
        record = {"event": event, **fields}
        self.stream.write(json.dumps(record, sort_keys=True) + "\n")
        self.stream.flush()
        os.fsync(self.stream.fileno())
        if event == "observation":
            self.counts[fields["phase"]] += 1

    def close(self):
        self.stream.close()


def validate_evidence(path, mode, current):
    try:
        records = [json.loads(line) for line in path.read_text().splitlines()]
    except (ValueError, OSError) as error:
        raise RunFailure("provenance_error", "Unreadable or incomplete evidence: " + str(path)) from error
    if (not records or records[0].get("event") != "header"
            or records[-1].get("event") != "final"):
        raise RunFailure("provenance_error", "Incomplete evidence report: " + str(path))
    header, final = records[0], records[-1]
    if (header.get("schema") != SCHEMA or header.get("mode") != mode
            or header.get("protocol") != selection.PROTOCOL
            or header.get("budget") != 4 or header.get("repetitions") != 2
            or final.get("status") != "valid" or final.get("repetitions_completed") != 2
            or final.get("errors") or final.get("flaky_mutants")):
        raise RunFailure("provenance_error", "Evidence is not a completed valid " + mode)
    for key in ("source_hashes", "program_hashes", "kernel", "python", "bcc_packages"):
        if header["environment"].get(key) != current[key]:
            raise RunFailure("provenance_error", "Evidence input/environment changed: " + key)
    if mode == "calibration" and not final.get("calibrated_all_seven"):
        raise RunFailure("provenance_error", "Calibration does not cover all seven cases.")
    expected_plans = {} if mode == "calibration" else {
        strategy: [step.__dict__ for step in selection.build_plan(header.get("seed"), strategy)]
        for strategy in selection.STRATEGIES
    }
    if header.get("plans") != expected_plans:
        raise RunFailure("provenance_error", "Evidence header differs from the frozen plans.")
    rows = [record for record in records if record.get("event") == "observation"]
    wanted = {"baseline": 14, "reference": 14,
              "calibration" if mode == "calibration" else "measurement": 42 if mode == "calibration" else 48}
    counts = dict(Counter(row.get("phase") for row in rows))
    if (counts != wanted or final.get("observation_counts") != wanted
            or sum(record.get("event") == "attempt" for record in records) != len(rows)):
        raise RunFailure("provenance_error", "Evidence has missing or extra fixture attempts.")
    expected_by_case = {name: expected for name, _, expected in policy_model.FIXTURES}
    expected_by_case.update(allow_outside_scope="ALLOW", deny_same_basename="DENY")
    for row in rows:
        raw = {"exit": row.get("exit_status"),
               "marker": row.get("observed_marker", "").encode(),
               "error": row.get("exec_error", "").encode()}
        try:
            actual = reference.actual_decision(raw, row["expected_token"])
        except (KeyError, RuntimeError) as error:
            raise RunFailure("provenance_error", "Evidence contains an invalid execution outcome.") from error
        wanted_expected = "ALLOW" if row["phase"] == "baseline" else expected_by_case.get(row.get("case_id"))
        if (row.get("status") != "valid" or row.get("identity_read_errors") != 0
                or row.get("actual") != actual or row.get("expected") != wanted_expected
                or row.get("match") != (actual == wanted_expected)):
            raise RunFailure("provenance_error", "Evidence verdict disagrees with its raw outcome.")
    measured = []
    for repetition in (1, 2):
        removed = [record for record in records if record.get("event") == "workload_removed"
                   and record.get("repetition") == repetition]
        detached = [record for record in records if record.get("event") == "detach"
                    and record.get("repetition") == repetition]
        if (len(removed) != 1 or not removed[0].get("success") or len(detached) != 4
                or {record.get("phase") for record in detached} != set(SIGNATURES) | {"reference"}
                or not all(record.get("success") for record in detached)):
            raise RunFailure("provenance_error", "Evidence does not establish successful cleanup.")
        for phase in ("baseline", "reference"):
            group = [row for row in rows if row.get("repetition") == repetition and row["phase"] == phase]
            if (len(group) != 7 or {row["case_id"] for row in group} != set(expected_by_case)
                    or not all(row["match"] for row in group)):
                raise RunFailure("provenance_error", "Evidence qualification is incomplete.")
        cells = {}
        for mutant in SIGNATURES:
            if mode == "calibration":
                group = [row for row in rows if row.get("repetition") == repetition
                         and row["phase"] == "calibration" and row.get("mutant") == mutant]
                if (len(group) != 7 or {row["case_id"] for row in group} != set(expected_by_case)
                        or {row["case_id"] for row in group if not row["match"]} != SIGNATURES[mutant]):
                    raise RunFailure("provenance_error", "Evidence has an invalid calibration signature.")
            else:
                for strategy in selection.STRATEGIES:
                    group = [row for row in rows if row.get("repetition") == repetition
                             and row["phase"] == "measurement" and row.get("mutant") == mutant
                             and row.get("strategy") == strategy]
                    plan = selection.build_plan(header.get("seed"), strategy)
                    if (len(group) != 4 or [row["case_id"] for row in group] != [step.case_id for step in plan]
                            or [row.get("step") for row in group] != [1, 2, 3, 4]):
                        raise RunFailure("provenance_error", "Evidence differs from its frozen selection plan.")
                    cells[(mutant, strategy)] = group
        measured.append(cells)
    if mode != "calibration":
        comparisons, flaky = compare_repetitions(measured)
        if flaky or comparisons != final.get("comparisons"):
            raise RunFailure("provenance_error", "Evidence summary disagrees with its repeated traces.")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run_child(target, token, workload, expected_group):
    """Verify /proc membership before exec; collect errno and marker separately."""
    pairs = []
    try:
        for _ in range(2):
            pairs.append(os.pipe2(os.O_CLOEXEC | os.O_NONBLOCK))
        pid = os.fork()
    except BaseException:
        for pair in pairs:
            for fd in pair:
                os.close(fd)
        raise
    (marker_read, marker_write), (error_read, error_write) = pairs
    if pid == 0:
        def fail(payload, code):
            try:
                os.write(error_write, payload[:512])
            finally:
                os._exit(code)
        try:
            os.close(marker_read)
            os.close(error_read)
            if workload is not None:
                fd = os.open(str(workload / "cgroup.procs"), os.O_WRONLY)
                try:
                    value = str(os.getpid()).encode("ascii")
                    if os.write(fd, value) != len(value):
                        raise RuntimeError("Incomplete membership write.")
                finally:
                    os.close(fd)
            if reference.membership() != expected_group:
                raise RuntimeError("Child cgroup membership differs from the fixture.")
            os.dup2(marker_write, 1)
            if marker_write != 1:
                os.close(marker_write)
        except BaseException as error:
            fail(("SETUP_ERROR:" + str(error)).encode("utf-8", errors="replace"), 126)
        try:
            os.execv(str(target), [str(target), token])
        except OSError as error:
            fail(("EXEC_ERRNO:" + str(error.errno)).encode("ascii"), 125)
        except BaseException as error:
            fail(("EXEC_HARNESS_ERROR:" + str(error)).encode("utf-8", errors="replace"), 126)
    os.close(marker_write)
    os.close(error_write)
    try:
        deadline = time.monotonic() + 3
        while True:
            state = os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            if state is not None:
                break
            if time.monotonic() >= deadline:
                raise RunFailure("harness_error", f"Child {pid} exceeded three seconds.")
            time.sleep(0.01)
        code = state.si_status if state.si_code == os.CLD_EXITED else -state.si_status
        return {"pid": pid, "exit": code,
                "marker": os.read(marker_read, 4096), "error": os.read(error_read, 4096)}
    finally:
        try:
            # Keep the child waitable until this final cleanup. Its PID cannot
            # be reused between a successful wait and a later timeout kill.
            try:
                state = os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            except ChildProcessError:
                state = "already_reaped"
            if state is None:
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            if state != "already_reaped":
                os.waitpid(pid, 0)
        finally:
            os.close(marker_read)
            os.close(error_read)


def qualify_features(cases):
    specs = {spec.case_id: spec for spec in selection.CASES}
    if len(cases) != 7 or {case["name"] for case in cases} != set(specs):
        raise RunFailure("qualification_error", "Fixture catalog differs from the frozen seven cases.")
    operations = {name: operation for name, operation, _ in policy_model.FIXTURES}
    operations.update(allow_outside_scope="other", deny_same_basename="copy")
    result = []
    for case in cases:
        target, registered = case["target"], Path(os.fsdecode(case["registered_path"]))
        operation = operations[case["name"]]
        if target.is_symlink() != (operation == "symlink"):
            raise RunFailure("qualification_error", "Symlink setup differs: " + case["name"])
        actual = selection.CaseSpec(
            case["name"], case["in_scope"],
            policy_model.file_identity(target) == case["allowed"],
            target == registered, target.name == registered.name,
            "direct" if operation in {"original", "other"} else operation,
        )
        if actual.facts() != specs[case["name"]].facts():
            raise RunFailure("qualification_error", "Declared features differ: " + case["name"])
        prediction = policy_model.expected_decision(
            case["allowed"], policy_model.file_identity(target), in_scope=case["in_scope"]
        )
        if prediction != case["expected"]:
            raise RunFailure("model_error", "Model/fixture expectation differs: " + case["name"])
        with target.open("rb") as stream:
            if stream.read(4) != b"\x7fELF":
                raise RunFailure("unsupported", "Target is not the controlled ELF fixture.")
        result.append({"case_id": case["name"], "facts": dict(actual.facts()),
                       "expected": prediction, "allowed_identity": list(case["allowed"]),
                       "target_identity": list(policy_model.file_identity(target)),
                       "target": str(target), "registered_path": str(registered)})
    return result


def observe(case, phase, group, controller, journal, repetition, mutant=None,
            strategy=None, step=None, errors=None, expected=None):
    token = "SENTINEL_PILOT_" + secrets.token_hex(16)
    expected_group = "/" + str(group.relative_to(reference.MOUNT)) if case["in_scope"] else controller
    info = {"repetition": repetition, "phase": phase, "mutant": mutant,
            "strategy": strategy, "step": step, "case_id": case["name"],
            "expected": case["expected"] if expected is None else expected,
            "expected_group": expected_group}
    journal.emit("attempt", **info)
    raw = run_child(case["target"], token, group if case["in_scope"] else None, expected_group)
    row = {**info, "pid": raw["pid"], "exit_status": raw["exit"],
           "expected_token": token, "observed_marker": raw["marker"].decode("utf-8", errors="replace"),
           "exec_error": raw["error"].decode("utf-8", errors="replace"),
           "identity_read_errors": int(errors[errors.Key(0)].value) if errors is not None else 0}
    try:
        if row["identity_read_errors"]:
            raise RunFailure("instrumentation_error", "Kernel identity/name read failed.")
        row["actual"] = reference.actual_decision(raw, token)
        row["status"] = "valid"
    except BaseException as error:
        row.update(status="invalid", error=str(error))
        journal.emit("observation", **row)
        if isinstance(error, RunFailure):
            raise
        raise RunFailure("harness_error", str(error)) from error
    row["match"] = row["actual"] == row["expected"]
    journal.emit("observation", **row)
    return row


def policy_phase(program, label, sequences, group, group_id, controller, journal, repetition):
    from bcc import BPF
    print(f"REPETITION {repetition}: compiling {label}...", flush=True)
    load_started = time.monotonic()
    journal.emit("phase_start", repetition=repetition, phase=label)
    probe = None
    collected = []
    try:
        probe = BPF(text=program)
        policies, errors = probe["policies"], probe["read_errors"]
        journal.emit("phase_loaded", repetition=repetition, phase=label,
                     load_seconds=time.monotonic() - load_started)
        for phase, strategy, sequence in sequences:
            rows = []
            for index, case in enumerate(sequence, 1):
                identity = case["allowed"]
                binding = policies.Leaf()
                binding.inode = identity.inode
                binding.major, binding.minor = identity.major, identity.minor
                binding.registered_path = case["registered_path"]
                binding.registered_basename = case["registered_basename"]
                key = policies.Key(group_id)
                policies[key] = binding
                try:
                    rows.append(observe(case, phase, group, controller, journal, repetition,
                                        label, strategy, index, errors))
                finally:
                    del policies[key]
            collected.append((strategy, rows))
    finally:
        if probe is not None:
            try:
                probe.cleanup()
            except BaseException:
                journal.emit("detach", repetition=repetition, phase=label, success=False)
                raise
            journal.emit("detach", repetition=repetition, phase=label, success=True)
            print(f"REPETITION {repetition}: {label} detached.", flush=True)
    return collected


def first_mismatch(rows):
    return next((index for index, row in enumerate(rows, 1) if not row["match"]), None)


def logical_trace(rows):
    return tuple((row["case_id"], row["expected"], row["actual"],
                  row["exit_status"], row["exec_error"]) for row in rows)


def run_repetition(number, mode, seed, root, controller, binary, folder, programs, plans, journal):
    group = root / f"workload-{number}"
    group.mkdir()
    cells = {}
    try:
        group_id = scope_handle_check.cgroup_id_from_handle(group)
        controller_id = scope_handle_check.cgroup_id_from_handle(reference.MOUNT / controller.lstrip("/"))
        if group_id == controller_id:
            raise RunFailure("qualification_error", "Controller and workload IDs match.")
        journal.emit("repetition_start", repetition=number, workload_id=group_id,
                     workload_path=str(group), controller_id=controller_id)
        print(f"REPETITION {number}: fresh workload ID={group_id}", flush=True)
        with tempfile.TemporaryDirectory(prefix=f"pool-{number}-", dir=folder) as temporary:
            with ExitStack() as stack:
                cases = fixtures.prepare_cases(Path(temporary), binary, stack)
                journal.emit("features", repetition=number, cases=qualify_features(cases))
                for index, case in enumerate(cases, 1):
                    row = observe(case, "baseline", group, controller, journal, number,
                                  step=index, expected="ALLOW")
                    if not row["match"]:
                        raise RunFailure("qualification_error", "Baseline failed: " + case["name"])
                print(f"REPETITION {number}: BASELINE PASS 7/7", flush=True)
                reference_rows = policy_phase(
                    programs["reference"], "reference", [("reference", None, cases)],
                    group, group_id, controller, journal, number,
                )[0][1]
                if any(not row["match"] for row in reference_rows):
                    raise RunFailure("reference_mismatch", "Correct-reference qualification failed.")
                print(f"REPETITION {number}: REFERENCE PASS 7/7", flush=True)
                indexed = {case["name"]: case for case in cases}
                for mutant in SIGNATURES:
                    if mode == "calibration":
                        sequences = [("calibration", None, cases)]
                    else:
                        # Counterbalance execution order, not the frozen selection plans.
                        order = selection.STRATEGIES if (seed + number) % 2 else tuple(reversed(selection.STRATEGIES))
                        sequences = [("measurement", strategy,
                                      [indexed[step.case_id] for step in plans[strategy]]) for strategy in order]
                    measured = policy_phase(programs[mutant], mutant, sequences, group,
                                            group_id, controller, journal, number)
                    for strategy, rows in measured:
                        if mode == "calibration":
                            mismatches = {row["case_id"] for row in rows if not row["match"]}
                            print(f"REPETITION {number}: {mutant} mismatches={sorted(mismatches)}", flush=True)
                            if mismatches != SIGNATURES[mutant]:
                                raise RunFailure("calibration_error", "Unexpected signature: " + mutant)
                        else:
                            cells[(mutant, strategy)] = rows
                            position = first_mismatch(rows)
                            shown = ">4" if position is None else str(position)
                            print(f"REPETITION {number}: {mutant} {strategy}: first_mismatch={shown}", flush=True)
        if reference.membership() != controller:
            raise RunFailure("qualification_error", "Controller membership changed.")
    finally:
        try:
            group.rmdir()
        except BaseException:
            journal.emit("workload_removed", repetition=number, success=False)
            raise
        journal.emit("workload_removed", repetition=number, success=True)
        print(f"REPETITION {number}: workload removed.", flush=True)
    return cells


def compare_repetitions(repetitions):
    comparisons = []
    flaky = set()
    for mutant in SIGNATURES:
        for strategy in selection.STRATEGIES:
            key = (mutant, strategy)
            first, second = repetitions[0][key], repetitions[1][key]
            if logical_trace(first) != logical_trace(second):
                flaky.add(mutant)
            comparisons.append({"mutant": mutant, "strategy": strategy,
                                "first_mismatch": first_mismatch(first),
                                "repetition_positions": [first_mismatch(first), first_mismatch(second)]})
    for cell in comparisons:
        cell["status"] = "flaky" if cell["mutant"] in flaky else "valid"
        cell["censored"] = cell["first_mismatch"] is None if cell["status"] == "valid" else None
    return comparisons, sorted(flaky)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--calibrate", dest="mode", action="store_const", const="calibration")
    modes.add_argument("--smoke", dest="mode", action="store_const", const="smoke")
    modes.add_argument("--pilot", dest="mode", action="store_const", const="pilot")
    parser.add_argument("--seed", type=int, choices=selection.SEEDS, default=0)
    parser.add_argument("--calibration", type=Path)
    parser.add_argument("--smoke-report", type=Path)
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise RunFailure("unsupported", "Use the provided root delegated service command.")
    programs = make_programs()
    meta = environment(programs, args.mode)
    controller = reference.membership()
    root = reference.delegated_root(controller)
    evidence = {}
    if args.mode != "calibration":
        if args.calibration is None:
            raise RunFailure("provenance_error", "Provide the valid calibration report.")
        evidence["calibration_sha256"] = validate_evidence(args.calibration, "calibration", meta)
    if args.mode == "pilot":
        if args.smoke_report is None:
            raise RunFailure("provenance_error", "Provide the valid smoke report.")
        evidence["smoke_sha256"] = validate_evidence(args.smoke_report, "smoke", meta)
    plans = {} if args.mode == "calibration" else {
        strategy: selection.build_plan(args.seed, strategy) for strategy in selection.STRATEGIES
    }
    seed = None if args.mode == "calibration" else args.seed
    journal = Journal(args.mode, seed)
    started = time.monotonic()
    journal.emit("header", schema=SCHEMA, protocol=selection.PROTOCOL, mode=args.mode,
                 seed=seed, budget=selection.DEFAULT_BUDGET, repetitions=REPETITIONS,
                 run_id=journal.path.stem, controller_group=controller,
                 started_at_utc=datetime.now(timezone.utc).isoformat(),
                 invocation_id=os.environ.get("INVOCATION_ID"),
                 environment=meta, prerequisites=evidence,
                 plans={name: [step.__dict__ for step in steps] for name, steps in plans.items()})
    print(f"Mode: {args.mode}; kernel: {meta['kernel']}; protocol: {selection.PROTOCOL}", flush=True)
    print("Raw report:", journal.path, flush=True)
    repetitions, errors, comparisons, flaky = [], [], [], []
    previous_handler = signal.getsignal(signal.SIGTERM)

    def stop(signum, frame):
        raise KeyboardInterrupt(f"Service stop signal {signum}.")

    signal.signal(signal.SIGTERM, stop)
    try:
        with tempfile.TemporaryDirectory(prefix="sentinel-selection-") as temporary:
            folder = Path(temporary)
            binary = reference.build_marker(folder)
            for number in range(1, REPETITIONS + 1):
                repetitions.append(run_repetition(number, args.mode, args.seed, root,
                                                   controller, binary, folder, programs, plans, journal))
        if args.mode != "calibration":
            comparisons, flaky = compare_repetitions(repetitions)
    except BaseException as error:
        errors.append({"kind": getattr(error, "kind", "interrupted" if isinstance(error, KeyboardInterrupt)
                                         else "harness_error"),
                       "message": str(error), "traceback": traceback.format_exc()})
    finally:
        try:
            if source_hashes() != meta["source_hashes"]:
                errors.append({"kind": "provenance_error", "message": "Input bytes changed during the run."})
        except BaseException as error:
            errors.append({"kind": "provenance_error", "message": str(error)})
        status = "invalid" if errors else "inconclusive" if flaky else "valid"
        try:
            journal.emit("final", schema=SCHEMA, status=status,
                         repetitions_completed=len(repetitions), errors=errors,
                         finished_at_utc=datetime.now(timezone.utc).isoformat(),
                         whole_run_seconds=time.monotonic() - started,
                         calibrated_all_seven=args.mode == "calibration" and status == "valid",
                         comparisons=comparisons, flaky_mutants=flaky,
                         observation_counts=dict(journal.counts))
        finally:
            journal.close()
            signal.signal(signal.SIGTERM, previous_handler)
    if status != "valid":
        print(f"{args.mode.upper()} {status.upper()}: report retained at {journal.path}", flush=True)
        for error in errors:
            print(error["kind"] + ": " + error["message"], flush=True)
        return 1
    if args.mode == "calibration":
        print("CALIBRATION PASS: three mutants qualified on seven cases in two fresh repetitions.", flush=True)
        print("Calibration only: no random/guided effectiveness result.", flush=True)
    else:
        for cell in comparisons:
            shown = ">4" if cell["first_mismatch"] is None else str(cell["first_mismatch"])
            print(f"{cell['mutant']} {cell['strategy']}: first_mismatch={shown}; repeated=True", flush=True)
        print(f"{args.mode.upper()} PASS: one seed; this is not the thirty-seed result.", flush=True)
    print("Complete raw report:", journal.path, flush=True)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (RunFailure, OSError, subprocess.SubprocessError) as error:
        raise SystemExit("CHECK STOPPED: " + str(error))
