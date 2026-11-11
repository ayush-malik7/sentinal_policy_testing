"""Pure-Python orchestration checks; no system services or BPF are started."""

from copy import deepcopy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import selection_batch as batch
from test_selection_kernel import synthetic_report, UNIT_ENVIRONMENT


class CollectionTests(unittest.TestCase):
    def collect(self, dispatch):
        outcomes, recorded = [], []
        batch.collect_seeds(dispatch, lambda event, **row: recorded.append((event, row)), outcomes)
        return outcomes, recorded

    def test_every_seed_is_dispatched_exactly_once(self):
        seen = []

        def dispatch(seed):
            seen.append(seed)
            return {"seed": seed, "status": "valid", "halt": False}

        outcomes, recorded = self.collect(dispatch)
        self.assertEqual(seen, list(range(30)))
        self.assertEqual(len(outcomes), 30)
        self.assertEqual([row["seed"] for _, row in recorded], seen)

    def test_reported_inconclusive_seed_is_retained_without_retry(self):
        seen = []

        def dispatch(seed):
            seen.append(seed)
            return {"seed": seed, "status": "inconclusive" if seed == 7 else "valid", "halt": False}

        outcomes, recorded = self.collect(dispatch)
        self.assertEqual(seen, list(range(30)))
        self.assertEqual(outcomes[7]["status"], "inconclusive")
        self.assertEqual(len(recorded), 30)

    def test_unsafe_failure_stops_next_dispatch_and_retains_failed_seed(self):
        seen = []

        def dispatch(seed):
            seen.append(seed)
            return {"seed": seed, "status": "invalid" if seed == 3 else "valid", "halt": seed == 3}

        outcomes, recorded = self.collect(dispatch)
        self.assertEqual(seen, [0, 1, 2, 3])
        self.assertEqual(outcomes[-1]["status"], "invalid")
        self.assertEqual([row["seed"] for _, row in recorded], seen)
        self.assertEqual([s for s in range(30) if s not in seen], list(range(4, 30)))

    def test_command_uses_bounded_delegated_main_mode_and_both_prerequisites(self):
        command = batch.worker_command(12, "unit-test only")
        self.assertIn("--property=PartOf=" + batch.PARENT, command)
        self.assertIn("--property=DelegateSubgroup=controller", command)
        self.assertIn("--property=RuntimeMaxSec=90s", command)
        self.assertIn("--pilot", command)
        self.assertNotIn("--smoke", command)
        self.assertEqual(command[command.index("--seed") + 1], "12")
        self.assertEqual(command[command.index("--calibration") + 1], str(batch.CALIBRATION))
        self.assertEqual(command[command.index("--smoke-report") + 1], str(batch.SMOKE))
        for invalid in (-1, 30, True, "0"):
            with self.assertRaises(ValueError):
                batch.worker_command(invalid, "unit-test only")

    def test_collected_unit_race_is_waited_for_without_starting_another_worker(self):
        states = [{"LoadState": "loaded", "ActiveState": "inactive", "Description": "ours"},
                  {"LoadState": "not-found", "ActiveState": "inactive"}]
        with patch.object(batch, "unit_state", side_effect=states), patch.object(batch.time, "sleep") as sleep:
            batch.await_collected_worker("ours")
        sleep.assert_called_once_with(0.1)

    def test_another_invocations_worker_is_never_stopped(self):
        state = {"LoadState": "loaded", "ActiveState": "active", "Description": "someone else"}
        with patch.object(batch, "unit_state", return_value=state), patch.object(batch.subprocess, "run") as run:
            with self.assertRaises(batch.BatchStop):
                batch.stop_owned_worker("ours")
            run.assert_not_called()


class EvidenceTests(unittest.TestCase):
    def inspect(self, mutate=None, returncode=0):
        records = synthetic_report("pilot")
        records[0]["prerequisites"] = dict(batch.KNOWN_HASHES)
        if mutate:
            mutate(records)
        with tempfile.TemporaryDirectory(prefix="sentinel-batch-unit-") as folder:
            path = Path(folder) / "SYNTHETIC_PILOT_UNIT_ONLY.jsonl"
            path.write_text("".join(json.dumps(row) + "\n" for row in records))
            with patch.object(batch, "ROOT", Path(folder)):
                return batch.inspect_report(path, 0, returncode, deepcopy(UNIT_ENVIRONMENT), batch.KNOWN_HASHES)

    def test_valid_censored_report_preserves_null_positions(self):
        row = self.inspect()
        self.assertEqual(row["status"], "valid")
        self.assertFalse(row["halt"])
        self.assertTrue(all(cell["first_mismatch"] is None and cell["censored"]
                            for cell in row["comparisons"]))

    def test_wrong_seed_or_prerequisite_cannot_be_counted_valid(self):
        for field, value in (("seed", 1), ("prerequisites", {})):
            row = self.inspect(lambda records: records[0].update({field: value}))
            self.assertEqual(row["status"], "invalid")
            self.assertTrue(row["halt"])

    def test_missing_cleanup_halts_collection(self):
        def corrupt(records):
            next(row for row in records if row.get("event") == "detach")["success"] = False
        row = self.inspect(corrupt)
        self.assertEqual(row["status"], "invalid")
        self.assertTrue(row["halt"])

    def test_valid_footer_does_not_override_corrupt_raw_outcome(self):
        def corrupt(records):
            next(row for row in records if row.get("event") == "observation")["observed_marker"] = "WRONG"
        with self.assertRaises(batch.runner.RunFailure):
            self.inspect(corrupt)

    def test_nonzero_worker_exit_cannot_be_certified_valid(self):
        row = self.inspect(returncode=1)
        self.assertEqual(row["status"], "invalid")
        self.assertTrue(row["halt"])


if __name__ == "__main__":
    unittest.main()
