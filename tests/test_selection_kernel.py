"""Pure-Python report/selector checks. Synthetic records are never kernel data."""

from collections import Counter
from copy import deepcopy
from dataclasses import replace
import json
from pathlib import Path
import sys
import tempfile
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import selection_kernel as runner
import selection_plan as selection
import policy_model


UNIT_ENVIRONMENT = {
    "source_hashes": {"unit_test_only": "not experimental evidence"},
    "program_hashes": {}, "kernel": "UNIT_TEST_NOT_A_KERNEL",
    "python": "unit-test", "bcc_packages": [],
}
EXPECTED = {name: expected for name, _, expected in policy_model.FIXTURES}
EXPECTED.update(allow_outside_scope="ALLOW", deny_same_basename="DENY")


def synthetic_row(repetition, phase, case_id, step, mutant=None, strategy=None, actual=None):
    expected = "ALLOW" if phase == "baseline" else EXPECTED[case_id]
    if actual is None:
        actual = expected
    token = "UNIT_TEST_ONLY_TOKEN"
    return {
        "event": "observation", "repetition": repetition, "phase": phase,
        "mutant": mutant, "strategy": strategy, "step": step, "case_id": case_id,
        "expected": expected, "actual": actual, "status": "valid",
        "identity_read_errors": 0, "match": actual == expected,
        "exit_status": 0 if actual == "ALLOW" else 125,
        "expected_token": token, "observed_marker": token if actual == "ALLOW" else "",
        "exec_error": "" if actual == "ALLOW" else "EXEC_ERRNO:1",
    }


def synthetic_report(mode):
    """Create parser fixtures, explicitly incompatible with any real VM report."""
    plans = {} if mode == "calibration" else {
        strategy: selection.build_plan(0, strategy) for strategy in selection.STRATEGIES
    }
    records = [{"event": "header", "schema": runner.SCHEMA,
                "protocol": selection.PROTOCOL, "mode": mode,
                "seed": None if mode == "calibration" else 0,
                "budget": 4, "repetitions": 2, "environment": deepcopy(UNIT_ENVIRONMENT),
                "plans": {name: [step.__dict__ for step in plan] for name, plan in plans.items()}}]
    repetitions = []
    for repetition in (1, 2):
        cells = {}
        for phase in ("baseline", "reference"):
            for index, case_id in enumerate(EXPECTED, 1):
                row = synthetic_row(repetition, phase, case_id, index,
                                    "reference" if phase == "reference" else None)
                records.extend([{"event": "attempt"}, row])
        for mutant in runner.SIGNATURES:
            if mode == "calibration":
                for index, case_id in enumerate(EXPECTED, 1):
                    actual = EXPECTED[case_id]
                    if case_id in runner.SIGNATURES[mutant]:
                        actual = "ALLOW" if actual == "DENY" else "DENY"
                    records.extend([{"event": "attempt"},
                                    synthetic_row(repetition, "calibration", case_id,
                                                  index, mutant, actual=actual)])
            else:
                for strategy, plan in plans.items():
                    # All-censored outcomes intentionally exercise no-detection reporting.
                    rows = [synthetic_row(repetition, "measurement", step.case_id,
                                          index, mutant, strategy)
                            for index, step in enumerate(plan, 1)]
                    cells[(mutant, strategy)] = rows
                    for row in rows:
                        records.extend([{"event": "attempt"}, row])
        for label in ("reference", *runner.SIGNATURES):
            records.append({"event": "detach", "repetition": repetition,
                            "phase": label, "success": True})
        records.append({"event": "workload_removed", "repetition": repetition, "success": True})
        repetitions.append(cells)
    comparisons, flaky = ([], []) if mode == "calibration" else runner.compare_repetitions(repetitions)
    records.append({"event": "final", "status": "valid", "repetitions_completed": 2,
                    "calibrated_all_seven": mode == "calibration", "errors": [],
                    "comparisons": comparisons, "flaky_mutants": flaky,
                    "observation_counts": dict(Counter(
                        row["phase"] for row in records if row["event"] == "observation"))})
    return records


class ReportTests(unittest.TestCase):
    def validate(self, records, mode="calibration", environment=None):
        with tempfile.TemporaryDirectory(prefix="sentinel-parser-unit-") as folder:
            path = Path(folder) / "SYNTHETIC_UNIT_TEST_ONLY.jsonl"
            path.write_text("".join(json.dumps(row) + "\n" for row in records))
            return runner.validate_evidence(path, mode, environment or UNIT_ENVIRONMENT)

    def test_complete_synthetic_calibration_is_parsed(self):
        self.assertEqual(len(self.validate(synthetic_report("calibration"))), 64)

    def test_missing_outcome_cannot_be_hidden_by_valid_footer(self):
        records = synthetic_report("calibration")
        index = next(i for i, row in enumerate(records) if row["event"] == "observation")
        del records[index]
        with self.assertRaises(runner.RunFailure):
            self.validate(records)

    def test_raw_marker_corruption_is_not_an_allow(self):
        records = synthetic_report("calibration")
        row = next(row for row in records if row["event"] == "observation" and row["actual"] == "ALLOW")
        row["observed_marker"] = "WRONG_UNIT_TEST_MARKER"
        with self.assertRaises(runner.RunFailure):
            self.validate(records)

    def test_failed_cleanup_invalidates_evidence(self):
        records = synthetic_report("calibration")
        next(row for row in records if row["event"] == "detach")["success"] = False
        with self.assertRaises(runner.RunFailure):
            self.validate(records)

    def test_truncated_report_and_changed_inputs_are_rejected(self):
        records = synthetic_report("calibration")
        with self.assertRaises(runner.RunFailure):
            self.validate(records[:-1])
        changed = deepcopy(UNIT_ENVIRONMENT)
        changed["source_hashes"] = {"unit_test_only": "changed"}
        with self.assertRaises(runner.RunFailure):
            self.validate(records, environment=changed)

    def test_no_detection_is_censored_not_invented(self):
        records = synthetic_report("smoke")
        self.validate(records, mode="smoke")
        for cell in records[-1]["comparisons"]:
            self.assertIsNone(cell["first_mismatch"])
            self.assertTrue(cell["censored"])

    def test_disagreement_marks_the_whole_seed_mutant_pair_flaky(self):
        records = synthetic_report("smoke")
        repetitions = []
        for repetition in (1, 2):
            repetitions.append({
                (mutant, strategy): [deepcopy(row) for row in records
                                     if row.get("event") == "observation"
                                     and row.get("phase") == "measurement"
                                     and row.get("repetition") == repetition
                                     and row.get("mutant") == mutant
                                     and row.get("strategy") == strategy]
                for mutant in runner.SIGNATURES for strategy in selection.STRATEGIES
            })
        mutant = next(iter(runner.SIGNATURES))
        row = repetitions[1][(mutant, "random")][0]
        row["actual"] = "DENY" if row["actual"] == "ALLOW" else "ALLOW"
        cells, flaky = runner.compare_repetitions(repetitions)
        self.assertEqual(flaky, [mutant])
        self.assertTrue(all(cell["status"] == "flaky" for cell in cells if cell["mutant"] == mutant))


class SelectionTests(unittest.TestCase):
    def test_distinct_reproducible_equal_budget_plans(self):
        for seed in selection.SEEDS:
            for strategy in selection.STRATEGIES:
                plan = selection.build_plan(seed, strategy)
                self.assertEqual(plan, selection.build_plan(seed, strategy))
                self.assertEqual(len(plan), 4)
                self.assertEqual(len({step.case_id for step in plan}), 4)

    def test_neutral_case_names_do_not_change_selection(self):
        original = selection.CASES
        names = {case.case_id: f"neutral_{i}" for i, case in enumerate(original)}
        try:
            for seed in selection.SEEDS:
                for strategy in selection.STRATEGIES:
                    selection.CASES = original
                    expected = [names[step.case_id] for step in selection.build_plan(seed, strategy)]
                    selection.CASES = tuple(replace(case, case_id=names[case.case_id]) for case in original)
                    self.assertEqual([step.case_id for step in selection.build_plan(seed, strategy)], expected)
        finally:
            selection.CASES = original


if __name__ == "__main__":
    unittest.main()
