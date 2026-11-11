#!/usr/bin/python3
"""Collect the frozen thirty-seed pilot once, using the existing kernel runner.

--check reads prerequisites without loading BPF or creating result files.
--run must execute in sentinel-pilot-batch.service. Each worker is the existing
delegated sentinel-enforcement-check.service, linked to the parent by PartOf.
The fixed audit directory prevents accidental restarts or favourable retries.
"""

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import secrets
import signal
import subprocess
import time

import selection_kernel as runner


ROOT = Path(__file__).resolve().parent
PARENT = "sentinel-pilot-batch.service"
WORKER = "sentinel-enforcement-check.service"
AUDIT = ROOT / "results" / "pilot_batch_v0"
CALIBRATION = ROOT / "results" / "calibration_seedNone_20261111T014845Z_e2fa36c1.jsonl"
SMOKE = ROOT / "results" / "smoke_seed0_20261111T101821Z_cb3e1c3c.jsonl"
KNOWN_HASHES = {
    "calibration_sha256": "d95b8810e8b12a13f9248d81452e6ba9bfe343a66c9f18f7e1729e19bc885aa9",
    "smoke_sha256": "a07cd3780ca05a16ed36413298841fed912192f864067c264c6907d111f69a67",
}


class BatchStop(RuntimeError):
    pass


def stamp():
    return datetime.now(timezone.utc).isoformat()


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def unit_state(name):
    result = subprocess.run(
        ["/usr/bin/systemctl", "show", name, "--property=LoadState",
         "--property=ActiveState", "--property=ControlGroup", "--property=Description"],
        capture_output=True, text=True, timeout=5,
    )
    values = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
    if not values.get("LoadState"):
        raise BatchStop("Could not inspect service state: " + result.stderr.strip())
    return values


def require_free_worker():
    state = unit_state(WORKER)
    if state.get("LoadState") != "not-found" or state.get("ActiveState") != "inactive":
        raise BatchStop("Worker service already exists; inspect it before collection: " + repr(state))


def await_collected_worker(description):
    # --wait observes deactivation; allow a short interval for unit collection.
    deadline = time.monotonic() + 5
    while True:
        state = unit_state(WORKER)
        if state.get("LoadState") == "not-found" and state.get("ActiveState") == "inactive":
            return
        if (state.get("Description") != description
                or state.get("ActiveState") not in {"inactive", "failed"}
                or time.monotonic() >= deadline):
            raise BatchStop("Completed worker was not safely collected: " + repr(state))
        time.sleep(0.1)


def worker_command(seed, description):
    if type(seed) is not int or seed not in runner.selection.SEEDS:
        raise ValueError("Expected a frozen seed from 0 through 29.")
    return [
        "/usr/bin/systemd-run", "--unit=" + WORKER, "--uid=root", "--wait", "--pipe",
        "--collect", "--description=" + description,
        "--property=Delegate=yes", "--property=DelegateSubgroup=controller",
        "--property=RuntimeMaxSec=90s", "--property=TimeoutStopSec=10s",
        "--property=PartOf=" + PARENT,
        "/usr/bin/python3", "-u", str(ROOT / "selection_kernel.py"),
        "--pilot", "--seed", str(seed), "--calibration", str(CALIBRATION),
        "--smoke-report", str(SMOKE),
    ]


def stop_owned_worker(description):
    state = unit_state(WORKER)
    if state.get("LoadState") == "not-found":
        return
    if state.get("Description") != description:
        raise BatchStop("Worker belongs to another invocation; it was not stopped.")
    subprocess.run(["/usr/bin/systemctl", "stop", WORKER], check=True, timeout=20)


def prerequisites():
    if os.geteuid() != 0:
        raise BatchStop("Run the read-only check with sudo, or use the documented batch service.")
    if (ROOT / "results").is_symlink():
        raise BatchStop("The result directory must not be a symbolic link.")
    meta = runner.environment(runner.make_programs(), "pilot")
    hashes = {
        "calibration_sha256": runner.validate_evidence(CALIBRATION, "calibration", meta),
        "smoke_sha256": runner.validate_evidence(SMOKE, "smoke", meta),
    }
    if hashes != KNOWN_HASHES:
        raise BatchStop("Prerequisite report bytes differ from the published, validated reports.")
    if AUDIT.exists() or AUDIT.is_symlink():
        raise BatchStop("A batch audit already exists. Keep it and inspect it; do not restart this batch.")
    if list((ROOT / "results").glob("pilot_seed*.jsonl")):
        raise BatchStop("Main-pilot reports already exist. Keep them; do not create duplicate seed attempts.")
    require_free_worker()
    return meta, hashes


def complete_cleanup(records):
    for repetition in (1, 2):
        detached = [r for r in records if r.get("event") == "detach"
                    and r.get("repetition") == repetition]
        removed = [r for r in records if r.get("event") == "workload_removed"
                   and r.get("repetition") == repetition]
        if (len(detached) != 4 or {r.get("phase") for r in detached}
                != {"reference", *runner.SIGNATURES}
                or not all(r.get("success") is True for r in detached)
                or len(removed) != 1 or removed[0].get("success") is not True):
            return False
    return True


def inspect_report(path, seed, returncode, meta, hashes):
    """Certify valid outcomes; retain other statuses and stop on uncertain cleanup."""
    row = {"seed": seed, "status": "invalid", "returncode": returncode,
           "report": str(path.relative_to(ROOT)), "report_sha256": sha256(path),
           "halt": True}
    records = [json.loads(line) for line in path.read_text().splitlines()]
    if not records or records[0].get("event") != "header" or records[-1].get("event") != "final":
        return {**row, "reason": "Incomplete raw report; cleanup is not certified."}
    header, final = records[0], records[-1]
    if (header.get("mode") != "pilot" or header.get("seed") != seed
            or header.get("prerequisites") != hashes):
        return {**row, "reason": "Report does not belong to this planned seed and prerequisites."}
    for key in ("source_hashes", "program_hashes", "kernel", "python", "bcc_packages"):
        if header.get("environment", {}).get(key) != meta[key]:
            return {**row, "reason": "Report input/environment differs: " + key}
    if not complete_cleanup(records):
        return {**row, "reason": "Expected detach/removal evidence is incomplete."}
    if final.get("status") == "valid" and returncode == 0:
        runner.validate_evidence(path, "pilot", meta)
        return {**row, "status": "valid", "halt": False,
                "comparisons": final["comparisons"]}
    if (final.get("status") == "inconclusive" and returncode != 0
            and final.get("flaky_mutants") and not final.get("errors")):
        return {**row, "status": "inconclusive", "halt": False,
                "reason": "Runner reported repetition disagreement; retain raw data for analysis.",
                "reported_flaky_mutants": final["flaky_mutants"]}
    return {**row, "reason": "Worker reported an invalid or inconsistent run.",
            "reported_status": final.get("status"), "reported_errors": final.get("errors")}


def collect_seeds(dispatch, record, outcomes):
    """Exactly one dispatch per planned seed; never retry or drop a failed row."""
    for seed in runner.selection.SEEDS:
        row = dispatch(seed)
        outcomes.append(row)
        record("seed_result", **row)
        if row["halt"]:
            break


def exclusive_file(path):
    stream = path.open("x", encoding="utf-8")
    owner = ROOT.stat()
    os.fchmod(stream.fileno(), 0o644)
    os.fchown(stream.fileno(), owner.st_uid, owner.st_gid)
    return stream


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--check", action="store_true")
    modes.add_argument("--run", action="store_true")
    args = parser.parse_args()
    meta, hashes = prerequisites()
    if args.check:
        print("CHECK PASS: frozen inputs, calibration, smoke, worker availability and empty main dataset.")
        print("Kernel:", meta["kernel"], "Python:", meta["python"])
        print("Planned seeds: 0..29; two fresh repetitions and four cases per strategy in each worker.")
        print("No BPF loaded and no result files created by this check.")
        return 0
    own_name = Path(__file__).name
    if (runner.git("ls-files", "--", own_name).decode().strip() != own_name
            or runner.git("diff", "HEAD", "--", own_name).strip()):
        raise BatchStop("Commit the batch launcher before collecting main data.")
    parent = unit_state(PARENT).get("ControlGroup", "")
    if not parent.endswith("/" + PARENT) or runner.reference.membership() != parent:
        raise BatchStop("Use the documented detached sentinel-pilot-batch.service command.")
    own_hash = sha256(Path(__file__))
    AUDIT.mkdir(mode=0o755)
    owner = ROOT.stat()
    os.chown(AUDIT, owner.st_uid, owner.st_gid)
    outcomes, errors = [], []
    run_id = secrets.token_hex(8)
    previous_handler = signal.getsignal(signal.SIGTERM)

    def interrupted(signum, frame):
        raise KeyboardInterrupt("Batch stop signal " + str(signum))

    signal.signal(signal.SIGTERM, interrupted)
    with exclusive_file(AUDIT / "batch.jsonl") as manifest:
        def emit(event, **fields):
            manifest.write(json.dumps({"event": event, "at_utc": stamp(), **fields}, sort_keys=True) + "\n")
            manifest.flush()
            os.fsync(manifest.fileno())

        emit("header", schema="sentinel-selection-batch-v0", run_id=run_id,
             planned_seeds=list(runner.selection.SEEDS), environment=meta,
             launcher_sha256=own_hash, prerequisites=hashes)
        print("Batch audit:", AUDIT / "batch.jsonl", flush=True)

        def dispatch(seed):
            description = f"Sentinel pilot v0 {run_id} seed {seed}"
            log_path = AUDIT / f"seed_{seed:02d}.console.txt"
            command = worker_command(seed, description)
            if (runner.git("rev-parse", "HEAD").decode().strip() != meta["git_commit"]
                    or runner.source_hashes() != meta["source_hashes"]
                    or sha256(Path(__file__)) != own_hash
                    or sha256(CALIBRATION) != hashes["calibration_sha256"]
                    or sha256(SMOKE) != hashes["smoke_sha256"]):
                raise BatchStop("Source or commit changed during collection; no next seed launched.")
            require_free_worker()
            if list((ROOT / "results").glob(f"pilot_seed{seed}_*.jsonl")):
                raise BatchStop("This seed already has a main report; no retry attempted.")
            emit("dispatch", seed=seed, command=command, console=str(log_path.relative_to(ROOT)))
            print(f"SEED {seed}: starting one main-pilot attempt.", flush=True)
            try:
                with exclusive_file(log_path) as console:
                    process = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=console,
                                             stderr=subprocess.STDOUT, timeout=115)
                    console.flush()
                    os.fsync(console.fileno())
            except BaseException:
                stop_owned_worker(description)
                raise
            await_collected_worker(description)
            reports = sorted((ROOT / "results").glob(f"pilot_seed{seed}_*.jsonl"))
            if len(reports) != 1:
                row = {"seed": seed, "status": "invalid", "returncode": process.returncode,
                       "halt": True, "reason": "Expected exactly one fresh raw report.",
                       "report_candidates": [str(p.relative_to(ROOT)) for p in reports]}
            else:
                try:
                    row = inspect_report(reports[0], seed, process.returncode, meta, hashes)
                except (ValueError, OSError, KeyError, runner.RunFailure) as error:
                    row = {"seed": seed, "status": "invalid", "returncode": process.returncode,
                           "halt": True, "report": str(reports[0].relative_to(ROOT)),
                           "reason": "Raw evidence validation failed: " + str(error)}
            print(f"SEED {seed}: {row['status']}; report={row.get('report', 'see audit')}", flush=True)
            return row

        try:
            collect_seeds(dispatch, emit, outcomes)
        except BaseException as error:
            errors.append({"kind": type(error).__name__, "message": str(error)})
        finally:
            counts = dict(Counter(row["status"] for row in outcomes))
            dispatched = [row["seed"] for row in outcomes]
            # A dispatch interrupted before seed_result remains visible in the audit.
            without_result = [seed for seed in runner.selection.SEEDS if seed not in dispatched]
            valid = len(outcomes) == 30 and counts == {"valid": 30} and not errors
            emit("final", status="valid" if valid else "incomplete_or_inconclusive",
                 planned_seed_count=30, seed_results=len(outcomes), counts=counts,
                 seeds_without_result=without_result, errors=errors)
            signal.signal(signal.SIGTERM, previous_handler)
    print("BATCH FINISHED:", counts, "; planned seeds=30; seeds without result=", without_result, flush=True)
    print("Audit:", AUDIT / "batch.jsonl", flush=True)
    return 0 if valid else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (BatchStop, runner.RunFailure, OSError, subprocess.SubprocessError) as error:
        raise SystemExit("BATCH STOPPED: " + str(error))
