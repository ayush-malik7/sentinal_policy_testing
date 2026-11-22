#!/usr/bin/python3
"""v1 semantic-boundary-weighted selector; never modifies frozen v0 selection_plan.py.

v0 guided selection gave equal weight (1) to every single/pair token, causing all
7 cases to tie at 15 tokens on step 1 and delaying boundary cases until step 3-4.
v1 weights contract-boundary pairs (object vs. path/basename disagreements and
in-scope object differences) higher, using only CaseSpec semantic facts—never
mutant labels, execution verdicts, or case IDs.
"""

import argparse
from dataclasses import replace
import random

import selection_plan as v0


PROTOCOL = "sentinel-fixture-selection-v1"
SIGNATURES = {
    "ignore_inode": {"deny_other", "deny_copy", "deny_same_basename"},
    "requested_path_identity": {"allow_symlink", "allow_renamed"},
    "basename_identity": {"allow_symlink", "allow_renamed", "deny_same_basename"},
}


def token_weight(token):
    """Weight semantic tokens from contract-boundary principles alone."""
    if token[0] == "pair":
        _, k1, v1, k2, v2 = token
        pair = {(k1, v1), (k2, v2)}
        # Boundary 1: file object and name/path disagree (tests alias/copy confusion).
        if pair in (
            {("object", "same"), ("path", "different")},
            {("object", "same"), ("basename", "different")},
            {("object", "different"), ("basename", "same")},
        ):
            return 3
        # Boundary 2: inside scope with a different object (tests inode/object check).
        if pair == {("scope", "inside"), ("object", "different")}:
            return 2
    return 1


def build_plan_v1(seed, budget=v0.DEFAULT_BUDGET):
    """Select distinct cases by maximizing newly covered weighted semantic tokens."""
    if not isinstance(seed, int) or seed not in v0.SEEDS:
        raise ValueError("Seed must be an integer from 0 through 29.")
    if not isinstance(budget, int) or not 1 <= budget <= len(v0.CASES):
        raise ValueError("Budget must be between 1 and 7.")

    rng = random.Random(seed)
    remaining = list(v0.CASES)
    covered = set()
    result = []
    for _ in range(budget):
        scores = {
            case: sum(token_weight(t) for t in (v0.coverage_tokens(case) - covered))
            for case in remaining
        }
        best = max(scores.values())
        candidates = [case for case in remaining if scores[case] == best]
        chosen = rng.choice(candidates)
        tokens = v0.coverage_tokens(chosen)
        new_count = len(tokens - covered)
        covered.update(tokens)
        result.append(v0.Step(chosen.case_id, new_count, len(covered)))
        remaining.remove(chosen)
    return tuple(result)


def first_hit(plan, signature):
    for step_idx, step in enumerate(plan, 1):
        if step.case_id in signature:
            return step_idx
    return None


def compare_against_v0():
    """Simulate all 30 seeds against the 3 fault signatures (pure Python)."""
    strategies = {
        "v0_random": lambda s: v0.build_plan(s, "random"),
        "v0_guided": lambda s: v0.build_plan(s, "guided"),
        "v1_guided": lambda s: build_plan_v1(s),
    }
    summary = {}
    for mutant, sig in SIGNATURES.items():
        summary[mutant] = {}
        for name, planner in strategies.items():
            hits = [first_hit(planner(s), sig) for s in v0.SEEDS]
            summary[mutant][name] = {
                f"by_{k}": sum(h is not None and h <= k for h in hits)
                for k in range(1, 5)
            }
            summary[mutant][name]["censored"] = hits.count(None)
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=0, choices=v0.SEEDS)
    parser.add_argument("--compare-v0", action="store_true")
    args = parser.parse_args()

    if args.compare_v0:
        summary = compare_against_v0()
        print("30-seed simulation (detected out of 30 at steps 1..4):")
        for mutant, rows in summary.items():
            print(f"\nFault: {mutant}")
            print("  strategy   | by 1 | by 2 | by 3 | by 4 | >4")
            for strat, stats in rows.items():
                print(
                    f"  {strat:10s} | {stats['by_1']:4d} | {stats['by_2']:4d} | "
                    f"{stats['by_3']:4d} | {stats['by_4']:4d} | {stats['censored']:2d}"
                )
        return

    print(f"Protocol: {PROTOCOL}; Seed: {args.seed}")
    for idx, step in enumerate(build_plan_v1(args.seed), 1):
        print(
            f"  {idx}. {step.case_id}: new_tokens={step.new_tokens} "
            f"covered={step.covered_tokens}/{len(v0.UNIVERSE)}"
        )


if __name__ == "__main__":
    main()
