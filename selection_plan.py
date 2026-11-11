#!/usr/bin/python3
"""Preview a finite fixture-selection pilot; never load BPF or execute fixtures.

Both selectors sample without replacement. Guidance sees semantic features
and its own coverage state, never mutant identities or execution outcomes.
The eventual kernel runner must validate these declared features against
the actual prepared fixtures before using a plan for measurement.
"""

import argparse
from dataclasses import dataclass
from itertools import combinations
import random


PROTOCOL = "sentinel-fixture-selection-v0"
DEFAULT_BUDGET = 4
SEEDS = tuple(range(30))
STRATEGIES = ("random", "guided")


@dataclass(frozen=True)
class CaseSpec:
    case_id: str
    in_scope: bool
    same_object: bool
    same_path: bool
    same_basename: bool
    setup: str

    def facts(self):
        return (
            ("scope", "inside" if self.in_scope else "outside"),
            ("object", "same" if self.same_object else "different"),
            ("path", "same" if self.same_path else "different"),
            ("basename", "same" if self.same_basename else "different"),
            ("setup", self.setup),
        )


# The case IDs join to the existing fixtures; they are never coverage tokens.
# "direct" means no alias/rename/copy-of-A transformation of the target.
CASES = (
    CaseSpec("allow_original", True, True, True, True, "direct"),
    CaseSpec("deny_other", True, False, False, False, "direct"),
    CaseSpec("allow_symlink", True, True, False, False, "symlink"),
    CaseSpec("allow_renamed", True, True, False, False, "rename"),
    CaseSpec("deny_copy", True, False, False, False, "copy"),
    CaseSpec("allow_outside_scope", False, False, False, False, "direct"),
    CaseSpec("deny_same_basename", True, False, False, True, "copy"),
)


@dataclass(frozen=True)
class Step:
    case_id: str
    new_tokens: int
    covered_tokens: int


def coverage_tokens(case):
    """Equal-weight single facts and pairs, excluding names and outcome labels."""
    facts = case.facts()
    singles = {("single", key, value) for key, value in facts}
    pairs = {
        ("pair", first[0], first[1], second[0], second[1])
        for first, second in combinations(facts, 2)
    }
    return frozenset(singles | pairs)


UNIVERSE = frozenset().union(*(coverage_tokens(case) for case in CASES))


def build_plan(seed, strategy, budget=DEFAULT_BUDGET):
    """Plan valid assumed-successful selections, independent of any mutant."""
    if strategy not in STRATEGIES:
        raise ValueError("Unknown strategy: " + strategy)
    if not isinstance(seed, int) or seed not in SEEDS:
        raise ValueError("Pilot seed must be an integer from 0 through 29.")
    if not isinstance(budget, int) or not 1 <= budget <= len(CASES):
        raise ValueError("Budget must be between 1 and 7.")
    rng = random.Random(seed)
    remaining = list(CASES)
    covered = set()
    result = []
    for _ in range(budget):
        candidates = remaining
        if strategy == "guided":
            novelty = {
                case: len(coverage_tokens(case) - covered) for case in remaining
            }
            best = max(novelty.values())
            candidates = [case for case in remaining if novelty[case] == best]
        # Both methods have seeded tie/choice randomness and no replacement.
        chosen = rng.choice(candidates)
        tokens = coverage_tokens(chosen)
        new = len(tokens - covered)
        covered.update(tokens)
        result.append(Step(chosen.case_id, new, len(covered)))
        remaining.remove(chosen)
    return tuple(result)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=0, choices=SEEDS)
    args = parser.parse_args()
    print("PREVIEW ONLY: no BPF, no fixture execution, no detection measurement.")
    print("Protocol:", PROTOCOL)
    print(f"Seed: {args.seed}; catalog: {len(CASES)}; budget: {DEFAULT_BUDGET} distinct cases")
    print(f"Coverage universe: {len(UNIVERSE)} semantic single/pair tokens")
    for strategy in STRATEGIES:
        print(f"\n{strategy.upper()} plan:")
        for index, step in enumerate(build_plan(args.seed, strategy), 1):
            print(
                f"  {index}. {step.case_id}: new_tokens={step.new_tokens} "
                f"covered={step.covered_tokens}/{len(UNIVERSE)}"
            )
    print("\nPlans are reproducible selections, not kernel-test results.")


if __name__ == "__main__":
    main()
