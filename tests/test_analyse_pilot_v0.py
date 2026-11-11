"""Outcome and censoring checks for the descriptive reader; no BPF or services."""

import csv
import io
from pathlib import Path
import sys
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import analyse_pilot_v0 as analysis


class AnalysisTests(unittest.TestCase):
    def row(self, exit_status=0, error="", marker="SENTINEL_PILOT_UNIT"):
        return {"exit_status": exit_status, "exec_error": error, "observed_marker": marker,
                "expected_token": "SENTINEL_PILOT_UNIT"}

    def test_independent_raw_classifier_requires_exact_exec_evidence(self):
        self.assertEqual(analysis.classify_actual(self.row()), "ALLOW")
        self.assertEqual(analysis.classify_actual(self.row(125, "EXEC_ERRNO:1", "")), "DENY")
        for row in (self.row(marker="WRONG"), self.row(125, "EXEC_ERRNO:2", ""),
                    self.row(126, "CHILD_SETUP_ERROR", ""), self.row(-9, "", "")):
            with self.assertRaises(analysis.InvalidData):
                analysis.classify_actual(row)

    def test_contract_uses_scope_and_device_inode_identity(self):
        case = {"facts": {"scope": "inside"}, "allowed_identity": [8, 2, 10],
                "target_identity": [8, 2, 10]}
        self.assertEqual(analysis.model_from_feature(case), "ALLOW")
        case["target_identity"] = [8, 2, 11]
        self.assertEqual(analysis.model_from_feature(case), "DENY")
        case["facts"]["scope"] = "outside"
        self.assertEqual(analysis.model_from_feature(case), "ALLOW")

    def test_first_mismatch_keeps_no_detection_as_none(self):
        rows = [{"expected": "DENY", "actual": "DENY"} for _ in range(4)]
        self.assertIsNone(analysis.first_mismatch(rows))
        rows[-1]["actual"] = "ALLOW"
        self.assertEqual(analysis.first_mismatch(rows), 4)

    def test_censoring_is_not_invented_as_a_fourth_or_fifth_detection(self):
        result = analysis.distribution([1, 2, 3, 4, None])
        self.assertEqual(result["censored_after_4"], 1)
        self.assertEqual(result["first_at_4"], 1)
        self.assertEqual(result["detected_by_4"], 4)
        self.assertEqual([result["detected_by_" + str(i)] for i in range(1, 5)], [1, 2, 3, 4])

    def test_two_censored_observations_do_not_claim_a_detection_time_tie(self):
        self.assertEqual(analysis.paired_category(None, None), "both_censored")
        self.assertEqual(analysis.paired_category(None, 4), "guided_earlier")
        self.assertEqual(analysis.paired_category(4, None), "guided_later")
        self.assertEqual(analysis.paired_category(2, 2), "observed_tie")
        self.assertEqual(analysis.paired_category(2, 4), "guided_later")
        self.assertEqual(analysis.paired_category(4, 2), "guided_earlier")

    def test_csv_preserves_censored_position_as_an_empty_field(self):
        text = analysis.csv_text([{"seed": 0, "first_mismatch": None, "censored": True}])
        row = next(csv.DictReader(io.StringIO(text)))
        self.assertEqual(row["first_mismatch"], "")
        self.assertEqual(row["censored"], "True")

    def test_data_paths_cannot_escape_the_input_root(self):
        with self.assertRaises(analysis.InvalidData):
            analysis.data_path(Path(__file__).resolve().parent, "../outside")
        with self.assertRaises(analysis.InvalidData):
            analysis.data_path(Path(__file__).resolve().parent, "/tmp/outside")


if __name__ == "__main__":
    unittest.main()
