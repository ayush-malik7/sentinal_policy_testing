"""Pure-Python checks for v1 semantic selection and AI-agent sandbox scenarios."""

from contextlib import ExitStack
from dataclasses import replace
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import agent_sandbox_demo as agent_demo
import enforcement_check as enforcer
import selection_plan as v0
import selection_plan_v1 as v1


class V1SelectionTests(unittest.TestCase):
    def test_v1_produces_four_distinct_reproducible_cases(self):
        for seed in v0.SEEDS:
            plan = v1.build_plan_v1(seed)
            self.assertEqual(plan, v1.build_plan_v1(seed))
            self.assertEqual(len(plan), 4)
            self.assertEqual(len({step.case_id for step in plan}), 4)

    def test_v1_does_not_depend_on_case_id_strings(self):
        original = v0.CASES
        names = {case.case_id: f"neutral_{i}" for i, case in enumerate(original)}
        try:
            for seed in v0.SEEDS:
                v0.CASES = original
                expected = [names[step.case_id] for step in v1.build_plan_v1(seed)]
                v0.CASES = tuple(replace(c, case_id=names[c.case_id]) for c in original)
                self.assertEqual([step.case_id for step in v1.build_plan_v1(seed)], expected)
        finally:
            v0.CASES = original

    def test_v1_comparison_reaches_full_detection_within_budget(self):
        summary = v1.compare_against_v0()
        for mutant, rows in summary.items():
            self.assertEqual(rows["v1_guided"]["by_4"], 30, f"{mutant} missed a seed in v1")
            self.assertEqual(rows["v1_guided"]["censored"], 0)


class AgentSandboxModelTests(unittest.TestCase):
    def test_agent_scenarios_match_expected_contract(self):
        with tempfile.TemporaryDirectory(prefix="sentinel-agent-unit-") as tmp, ExitStack() as stack:
            folder = Path(tmp)
            binary = enforcer.build_marker(folder)
            scenarios = agent_demo.prepare_agent_scenarios(folder, binary, stack)
            self.assertEqual(
                [(s["name"], s["expected"]) for s in scenarios],
                [
                    ("agent_runs_approved_tool", "ALLOW"),
                    ("agent_spawns_unapproved_shell", "DENY"),
                    ("agent_runs_same_basename_copy", "DENY"),
                    ("controller_outside_agent_cgroup", "ALLOW"),
                ],
            )


if __name__ == "__main__":
    unittest.main()
