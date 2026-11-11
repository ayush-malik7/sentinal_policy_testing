#!/usr/bin/python3
"""Read-only verification and descriptive analysis of the completed v0 pilot.

This strict reader targets the single, fully valid frozen thirty-seed batch.
It rejects inconsistent/incomplete inputs rather than silently excluding seeds.
Default: verify and print. --write-dir creates a NEW directory of derived files.
No BPF is loaded, no fixtures execute, and no raw file or Git setting is changed.
"""

import argparse
from collections import Counter, defaultdict
import csv
from datetime import datetime
import hashlib
import importlib
import io
import json
from pathlib import Path
import sys


SEEDS = tuple(range(30))
MUTANTS = ("ignore_inode", "requested_path_identity", "basename_identity")
STRATEGIES = ("random", "guided")
PROTOCOL = "sentinel-fixture-selection-v0"
COMMIT = "8c6780a40ead4b797773bac5f9c6c8402d0d9e7c"
CALIBRATION = "results/calibration_seedNone_20261111T014845Z_e2fa36c1.jsonl"
SMOKE = "results/smoke_seed0_20261111T101821Z_cb3e1c3c.jsonl"
BATCH = "results/pilot_batch_v0/batch.jsonl"
PREREQUISITES = {
    "calibration_sha256": "d95b8810e8b12a13f9248d81452e6ba9bfe343a66c9f18f7e1729e19bc885aa9",
    "smoke_sha256": "a07cd3780ca05a16ed36413298841fed912192f864067c264c6907d111f69a67",
}
# Reviewed/calibrated source bytes, independently checked against the upload.
# A changed experimental implementation requires a separately versioned reader.
SOURCE_HASHES = {
    "docs/pilot_protocol_v0.md": "0fe9977d3ce9ab29f1963615968742ace855f018feb1c56ef7faf465bdd1f5c4",
    "enforcement_check.py": "4f9e0059e5fe2287188129bab8f5265692f4c380def27ec7a44593d7e0a790ea",
    "mutant_basename_check.py": "7ea541aa568da65996331e3af0cf021f5cae2ac687d9a0b4e43fab5e8c2ef628",
    "mutant_inode_check.py": "9a18a540c71eb12e54050fcd07017f4f2a3e96993588b22b918206456c44fdf2",
    "mutant_path_check.py": "0fbedf3d4f8ac3557998609d60b0a8ffd15443b354302b5685cd29731f10dff2",
    "policy_model.py": "3544560bc9cb7c17f120ef75e3249a421542e3de349e4b2f6e987cb6194c3d25",
    "scope_handle_check.py": "ff9a6d126ce729c56dd5f1afc7e60ed5eba8cf3876384b24931ace8a49037904",
    "selection_kernel.py": "c2b207ca9eb79759ff5c2cdc404ce9baf1d762ed40f3f01b32027c9193b5d03c",
    "selection_plan.py": "fa04acd7f57be1c1b9a4927e85ea7b1d9ef5528595f8b9143e92a3d470a8f2ab",
}
LAUNCHER_HASH = "76dbfdc99379e80d060918a5ad53e1ade426a1f48c3b390353504515419740ec"


class InvalidData(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise InvalidData(message)


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_jsonl(path):
    try:
        return [json.loads(line) for line in path.read_text().splitlines()]
    except (OSError, ValueError) as error:
        raise InvalidData("Unreadable JSONL: " + str(path)) from error


def data_path(root, relative):
    rel = Path(relative)
    require(not rel.is_absolute() and ".." not in rel.parts, "Unsafe data path.")
    result = (root / rel).resolve(strict=True)
    require(result.is_relative_to(root) and result.is_file(), "Data file outside root.")
    return result


def classify_actual(row):
    """Reclassify raw userspace evidence without the runner's outcome function."""
    token = row.get("expected_token")
    require(isinstance(token, str) and token.startswith("SENTINEL_PILOT_"), "Missing marker token.")
    if (row.get("exit_status") == 0 and row.get("exec_error") == ""
            and row.get("observed_marker") == token):
        return "ALLOW"
    if (row.get("exit_status") == 125 and row.get("exec_error") == "EXEC_ERRNO:1"
            and row.get("observed_marker") == ""):
        return "DENY"
    raise InvalidData("Raw exit/errno/marker evidence is not an ALLOW or EPERM DENY.")


def model_from_feature(case):
    """Reapply the supported file-object contract, independently of policy_model."""
    scope = case["facts"]["scope"]
    require(scope in {"inside", "outside"}, "Unknown scope fact.")
    return "ALLOW" if scope == "outside" or case["allowed_identity"] == case["target_identity"] else "DENY"


def first_mismatch(rows):
    return next((step for step, row in enumerate(rows, 1)
                 if row["expected"] != row["actual"]), None)


def paired_category(random_position, guided_position):
    if random_position is None and guided_position is None:
        return "both_censored"
    if random_position is None or guided_position is not None and guided_position < random_position:
        return "guided_earlier"
    if guided_position is None or random_position < guided_position:
        return "guided_later"
    return "observed_tie"


def distribution(positions):
    positions = list(positions)
    return {
        "first_at_1": positions.count(1), "first_at_2": positions.count(2),
        "first_at_3": positions.count(3), "first_at_4": positions.count(4),
        "censored_after_4": positions.count(None),
        **{"detected_by_" + str(step): sum(p is not None and p <= step for p in positions)
           for step in range(1, 5)},
    }


def validate_features(records, checker):
    result = {}
    specs = {case.case_id: dict(case.facts()) for case in checker.selection.CASES}
    starts = {r["repetition"]: r for r in records if r.get("event") == "repetition_start"}
    for entry in records:
        if entry.get("event") != "features":
            continue
        repetition = entry["repetition"]
        require(repetition not in result and repetition in starts, "Duplicate/unbound feature record.")
        cases = entry["cases"]
        require(len(cases) == 7 and {c["case_id"] for c in cases} == set(specs), "Wrong fixture catalog.")
        for case in cases:
            require(case["facts"] == specs[case["case_id"]], "Feature differs from frozen catalog.")
            for key in ("allowed_identity", "target_identity"):
                require(len(case[key]) == 3 and all(type(n) is int and n >= 0 for n in case[key]),
                        "Malformed device/inode identity.")
            equal = case["allowed_identity"] == case["target_identity"]
            require((case["facts"]["object"] == "same") == equal, "Object fact disagrees with identity.")
            require((case["facts"]["path"] == "same") == (case["target"] == case["registered_path"]),
                    "Path fact disagrees with recorded paths.")
            require((case["facts"]["basename"] == "same") ==
                    (Path(case["target"]).name == Path(case["registered_path"]).name),
                    "Basename fact disagrees with recorded paths.")
            require(case["expected"] == model_from_feature(case), "Fixture expectation disagrees with contract.")
        require(starts[repetition]["workload_id"] != starts[repetition]["controller_id"],
                "Workload and controller IDs coincide.")
        result[repetition] = {c["case_id"]: c for c in cases}
    require(set(result) == {1, 2}, "Missing repetition features.")
    return result, starts


def independent_rows(records, checker, all_tokens):
    features, starts = validate_features(records, checker)
    header = records[0]
    groups = defaultdict(list)
    counts = Counter()
    observations = [r for r in records if r.get("event") == "observation"]
    for index, entry in enumerate(records):
        if entry.get("event") == "attempt":
            require(index + 1 < len(records) and records[index + 1].get("event") == "observation",
                    "Attempt has no adjacent outcome.")
            following = records[index + 1]
            require(all(following.get(k) == v for k, v in entry.items() if k != "event"),
                    "Attempt and outcome metadata differ.")
    for row in observations:
        counts[row["phase"]] += 1
        actual = classify_actual(row)
        token = row["expected_token"]
        require(token not in all_tokens, "Marker token reused across observations.")
        all_tokens.add(token)
        case = features[row["repetition"]][row["case_id"]]
        expected = "ALLOW" if row["phase"] == "baseline" else model_from_feature(case)
        require(row["expected"] == expected and row["actual"] == actual
                and row["match"] == (expected == actual), "Outcome/model summary disagrees with raw evidence.")
        require(row["status"] == "valid" and row["identity_read_errors"] == 0, "Invalid observation.")
        start = starts[row["repetition"]]
        workload = start["workload_path"].removeprefix("/sys/fs/cgroup")
        group = workload if case["facts"]["scope"] == "inside" else header["controller_group"]
        require(row["expected_group"] == group, "Child's required scope differs from the fixture.")
        if row["phase"] == "measurement":
            groups[row["repetition"], row["mutant"], row["strategy"]].append(row)
    require(dict(counts) == {"baseline": 14, "reference": 14, "measurement": 48}, "Wrong phase counts.")
    return groups, counts


def analyse(root):
    root = root.resolve(strict=True)
    for name, digest in SOURCE_HASHES.items():
        require(sha256(data_path(root, name)) == digest, "Experimental source changed: " + name)
    require(sha256(data_path(root, "selection_batch.py")) == LAUNCHER_HASH, "Batch source changed.")
    # Inputs are imported only after their bytes match the reviewed baseline.
    sys.path.insert(0, str(root))
    checker = importlib.import_module("selection_kernel")
    require(set(checker.INPUTS) == set(SOURCE_HASHES), "Checker input list changed.")
    audit_path = data_path(root, BATCH)
    audit = read_jsonl(audit_path)
    require(len(audit) == 62 and audit[0].get("event") == "header"
            and audit[-1].get("event") == "final", "Incomplete or unexpected batch audit.")
    header, final = audit[0], audit[-1]
    require(header["schema"] == "sentinel-selection-batch-v0" and header["planned_seeds"] == list(SEEDS),
            "Wrong batch schema or planned seeds.")
    require([(r["event"], r.get("seed")) for r in audit[1:-1]] ==
            [(event, seed) for seed in SEEDS for event in ("dispatch", "seed_result")],
            "Missing, duplicated or reordered seed attempts.")
    require(final["status"] == "valid" and final["counts"] == {"valid": 30}
            and final["planned_seed_count"] == final["seed_results"] == 30
            and final["seeds_without_result"] == final["errors"] == [],
            "Batch is incomplete/invalid; retain it for separate failure analysis.")
    meta = header["environment"]
    require(meta["kernel"] == "6.8.0-149-generic" and meta["python"] == "3.12.3",
            "Recorded kernel/Python differ from this frozen batch.")
    require(meta["git_commit"] == COMMIT and meta["modified_inputs"] == meta["untracked_inputs"] == [],
            "Recorded commit or source cleanliness differs.")
    require(meta["source_hashes"] == SOURCE_HASHES and header["launcher_sha256"] == LAUNCHER_HASH,
            "Audit source hashes do not match reviewed bytes.")
    programs = checker.make_programs()
    require(meta["program_hashes"] == {name: hashlib.sha256(code.encode()).hexdigest()
                                       for name, code in programs.items()}, "Generated kernel-program hash changed.")
    require(header["prerequisites"] == PREREQUISITES, "Prerequisites differ.")
    require(checker.validate_evidence(data_path(root, CALIBRATION), "calibration", meta)
            == PREREQUISITES["calibration_sha256"], "Calibration verification failed.")
    require(checker.validate_evidence(data_path(root, SMOKE), "smoke", meta)
            == PREREQUISITES["smoke_sha256"], "Smoke verification failed.")
    per_seed, manifest, tokens, invocations, report_paths = [], [], set(), set(), set()
    totals, runtimes, cleanup = Counter(), [], Counter()
    for seed in SEEDS:
        dispatch, result = audit[1 + 2 * seed:3 + 2 * seed]
        require(result["status"] == "valid" and result["returncode"] == 0 and result["halt"] is False,
                "Seed has a failed or inconclusive result.")
        command = dispatch["command"]
        require(command[command.index("--seed") + 1] == str(seed) and "--pilot" in command
                and "--smoke" not in command, "Dispatch does not run the planned main seed.")
        console = data_path(root, dispatch["console"])
        report = data_path(root, result["report"])
        require(report not in report_paths, "Raw report reused for two seeds.")
        report_paths.add(report)
        require(checker.validate_evidence(report, "pilot", meta) == result["report_sha256"],
                "Raw seed report hash/verification failed.")
        records = read_jsonl(report)
        first, last = records[0], records[-1]
        require(first["seed"] == seed and first["mode"] == "pilot" and first["protocol"] == PROTOCOL
                and first["environment"] == meta and first["prerequisites"] == PREREQUISITES,
                "Seed metadata differs from the audited experiment.")
        require(first["invocation_id"] not in invocations, "Worker invocation reused.")
        invocations.add(first["invocation_id"])
        groups, counts = independent_rows(records, checker, tokens)
        totals.update(counts)
        runtimes.append(last["whole_run_seconds"])
        cleanup.update(r["event"] for r in records if r.get("event") in {"detach", "workload_removed"})
        for mutant in MUTANTS:
            for strategy in STRATEGIES:
                a, b = groups[1, mutant, strategy], groups[2, mutant, strategy]
                logical = lambda rows: [(r["case_id"], r["expected"], r["actual"],
                                         r["exit_status"], r["exec_error"]) for r in rows]
                require(logical(a) == logical(b), "Repeated logical trace disagrees.")
                position = first_mismatch(a)
                expected_plan = [step.case_id for step in checker.selection.build_plan(seed, strategy)]
                require([r["case_id"] for r in a] == expected_plan
                        and [r["step"] for r in a] == [1, 2, 3, 4], "Measured plan differs from frozen plan.")
                reported = next(c for c in last["comparisons"]
                                if c["mutant"] == mutant and c["strategy"] == strategy)
                require(reported["first_mismatch"] == position and reported["repetition_positions"] == [position] * 2,
                        "First-mismatch summary disagrees with the raw repeated trace.")
                require(reported in result["comparisons"], "Audit summary differs from raw summary.")
                per_seed.append({"seed": seed, "mutant": mutant, "strategy": strategy,
                                 "first_mismatch": position, "censored": position is None,
                                 "repetition_1_first": position, "repetition_2_first": first_mismatch(b),
                                 "selected_cases": "|".join(expected_plan),
                                 "expected_sequence": "|".join(r["expected"] for r in a),
                                 "actual_sequence": "|".join(r["actual"] for r in a),
                                 "raw_report": result["report"], "raw_sha256": result["report_sha256"]})
        manifest.append({"seed": seed, "report": result["report"], "sha256": result["report_sha256"],
                         "console": dispatch["console"], "console_sha256": sha256(console)})
    require(report_paths == set((root / "results").glob("pilot_seed*.jsonl")),
            "Unaccounted main-pilot reports exist; do not choose favourable attempts.")
    require(dict(totals) == {"baseline": 420, "reference": 420, "measurement": 1440},
            "Overall execution counts differ from the protocol.")
    require(dict(cleanup) == {"detach": 240, "workload_removed": 60},
            "Overall cleanup evidence differs from the protocol.")
    summaries, paired = [], []
    indexed = {(row["seed"], row["mutant"], row["strategy"]): row for row in per_seed}
    for mutant in MUTANTS:
        for strategy in STRATEGIES:
            summaries.append({"mutant": mutant, "strategy": strategy, "planned_seeds": 30,
                              "valid_seeds": 30, **distribution(indexed[s, mutant, strategy]["first_mismatch"]
                                                                for s in SEEDS)})
        pairs = Counter(paired_category(indexed[s, mutant, "random"]["first_mismatch"],
                                        indexed[s, mutant, "guided"]["first_mismatch"]) for s in SEEDS)
        paired.append({"mutant": mutant, **{key: pairs[key] for key in
                       ("guided_earlier", "observed_tie", "guided_later", "both_censored")}})
    summary = {
        "schema": "sentinel-pilot-analysis-v0", "protocol": PROTOCOL, "recorded_commit": COMMIT,
        "validation": "passed", "planned_seeds": 30, "valid_seeds": 30,
        "invalid_seeds": 0, "inconclusive_seeds": 0, "missing_seeds": [],
        "fresh_repetitions": 60, "observation_counts": dict(totals),
        "controlled_exec_attempts": sum(totals.values()), "cleanup_events": dict(cleanup),
        "distributions": summaries, "paired_comparisons": paired,
        "environment": meta, "prerequisites": PREREQUISITES,
        "audit_sha256": sha256(audit_path), "launcher_sha256": LAUNCHER_HASH,
        "raw_reports": manifest,
        "batch_elapsed_seconds": (datetime.fromisoformat(final["at_utc"])
                                  - datetime.fromisoformat(header["at_utc"])).total_seconds(),
        "summed_worker_seconds": round(sum(runtimes), 6),
        "analysis_source_sha256": sha256(Path(__file__).resolve()),
        "statistical_scope": "Descriptive paired-seed counts on seven development fixtures and three planted faults; no pooled independent-sample inference.",
    }
    return summary, per_seed


def csv_text(rows):
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=list(rows[0]), lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    return output.getvalue()


def derived_files(summary, per_seed):
    return {"summary.json": json.dumps(summary, indent=2, sort_keys=True) + "\n",
            "per_seed.csv": csv_text(per_seed),
            "summary.csv": csv_text(summary["distributions"]),
            "paired.csv": csv_text(summary["paired_comparisons"])}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent)
    action = parser.add_mutually_exclusive_group()
    action.add_argument("--write-dir", type=Path)
    action.add_argument("--check-derived", type=Path)
    args = parser.parse_args()
    summary, rows = analyse(args.root)
    files = derived_files(summary, rows)
    if args.write_dir:
        args.write_dir.mkdir(parents=True, exist_ok=False)
        for name, content in files.items():
            with (args.write_dir / name).open("x", encoding="utf-8", newline="") as stream:
                stream.write(content)
    if args.check_derived:
        for name, content in files.items():
            require((args.check_derived / name).read_text() == content, "Derived file differs: " + name)
    print("VALIDATION PASS: 30 unique main seeds; two agreeing repetitions per seed; 2,280 raw outcomes checked.")
    for row in summary["distributions"]:
        print(f"{row['mutant']} {row['strategy']}: by-step counts="
              + str([row['detected_by_' + str(n)] for n in range(1, 5)])
              + f"; censored={row['censored_after_4']}")
    if args.check_derived:
        print("DERIVED FILES MATCH: summary.json, per_seed.csv, summary.csv and paired.csv.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (RuntimeError, OSError, ValueError, KeyError) as error:
        raise SystemExit("ANALYSIS STOPPED: " + str(error))
