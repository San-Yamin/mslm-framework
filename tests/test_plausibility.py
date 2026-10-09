import unittest

import _bootstrap  # noqa: F401
from mslm.risk import (
    ChainStep,
    assess_chain_plausibility,
    calculate_ccrs,
    capped_sum,
    compare_aggregations,
    maximum_cvss,
    mean_cvss,
    score_plausible_chain,
    sequential_product,
)
from mslm.scenarios import CHAIN_STEPS


class AggregatorComparisonTests(unittest.TestCase):
    def test_baselines_and_ccrs_are_reported_together(self):
        comparison = compare_aggregations([7.5, 7.2])
        self.assertEqual(comparison.maximum, 7.5)
        self.assertEqual(comparison.mean, 7.35)
        self.assertEqual(comparison.capped_sum, 10.0)
        self.assertAlmostEqual(comparison.sequential_product, 5.4)
        self.assertAlmostEqual(comparison.ccrs, 9.3)

    def test_scalar_helpers(self):
        self.assertEqual(maximum_cvss([6.5, 6.2]), 6.5)
        self.assertAlmostEqual(mean_cvss([8.1, 5.9]), 7.0)
        self.assertEqual(capped_sum([8.1, 5.9, 7.5]), 10.0)
        self.assertAlmostEqual(sequential_product([5.0, 5.0]), 2.5)

    def test_empty_and_invalid_inputs_rejected(self):
        for helper in (maximum_cvss, mean_cvss, capped_sum, sequential_product):
            with self.subTest(helper=helper.__name__):
                with self.assertRaises(ValueError):
                    helper([])


class CcrsBehaviourTests(unittest.TestCase):
    def test_permutation_invariance(self):
        self.assertEqual(
            calculate_ccrs([8.1, 5.9, 7.5]).raw_score,
            calculate_ccrs([7.5, 8.1, 5.9]).raw_score,
        )

    def test_same_multiset_same_score_regardless_of_path_label(self):
        # CCRS cannot distinguish different attack paths with equal severities.
        self.assertEqual(
            calculate_ccrs([7.5, 7.2]).raw_score,
            calculate_ccrs([7.2, 7.5]).raw_score,
        )

    def test_unreachable_or_irrelevant_vulnerability_still_raises_ccrs(self):
        # This documents the metric's honest limitation rather than hiding it.
        base = calculate_ccrs([7.5]).raw_score
        inflated = calculate_ccrs([7.5, 5.9]).raw_score
        self.assertGreater(inflated, base)
        self.assertAlmostEqual(inflated - base, 1.475)


class PlausibilityTests(unittest.TestCase):
    def test_declared_paper_chains_are_plausible(self):
        for chain, steps in CHAIN_STEPS.items():
            with self.subTest(chain=chain):
                assessment = assess_chain_plausibility(chain, steps)
                self.assertTrue(assessment.plausible, assessment.gaps)
                self.assertGreaterEqual(assessment.step_count, 2)
                self.assertEqual(len(assessment.trust_boundaries), assessment.step_count)

    def test_missing_metadata_fails_the_gate(self):
        steps = [
            ChainStep("V1", 7.5, "", "user -> app", "evidence a"),
            ChainStep("V6", 7.2, "some precondition", "", "evidence b"),
        ]
        assessment = assess_chain_plausibility("X", steps)
        self.assertFalse(assessment.plausible)
        self.assertTrue(any("prerequisite" in gap for gap in assessment.gaps))
        self.assertTrue(any("trust boundary" in gap for gap in assessment.gaps))

    def test_single_step_is_not_a_chain(self):
        assessment = assess_chain_plausibility(
            "X", [ChainStep("V1", 7.5, "p", "b", "e")]
        )
        self.assertFalse(assessment.plausible)

    def test_implausible_chain_is_not_scored(self):
        with self.assertRaises(ValueError):
            score_plausible_chain(assess_chain_plausibility("X", []))

    def test_plausible_chain_score_matches_ccrs(self):
        assessment = assess_chain_plausibility("C1", CHAIN_STEPS["C1"])
        self.assertAlmostEqual(
            score_plausible_chain(assessment).raw_score,
            calculate_ccrs([7.5, 7.2]).raw_score,
        )


if __name__ == "__main__":
    unittest.main()
