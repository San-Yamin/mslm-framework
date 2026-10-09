import unittest

import _bootstrap  # noqa: F401
from mslm.risk import PAPER_CHAINS, Severity, calculate_ccrs, classify


class RiskTests(unittest.TestCase):
    def test_paper_chain_c1(self):
        self.assertAlmostEqual(calculate_ccrs(PAPER_CHAINS["C1"]).raw_score, 9.3)

    def test_paper_chain_c2(self):
        self.assertAlmostEqual(calculate_ccrs(PAPER_CHAINS["C2"]).raw_score, 8.775)

    def test_paper_chain_c3(self):
        self.assertAlmostEqual(calculate_ccrs(PAPER_CHAINS["C3"]).raw_score, 9.221)

    def test_paper_chain_c4_is_capped_for_deployment(self):
        result = calculate_ccrs(PAPER_CHAINS["C4"])
        self.assertAlmostEqual(result.raw_score, 9.95345)
        self.assertEqual(result.deployment_score, 9.8)

    def test_single_score_is_unchanged(self):
        self.assertEqual(calculate_ccrs([6.5]).raw_score, 6.5)

    def test_zero_scores(self):
        result = calculate_ccrs([0, 0])
        self.assertEqual(result.raw_score, 0)
        self.assertEqual(result.amplification_percent, 0)

    def test_empty_rejected(self):
        with self.assertRaises(ValueError):
            calculate_ccrs([])

    def test_out_of_range_rejected(self):
        for scores in ([-0.1], [10.1]):
            with self.subTest(scores=scores), self.assertRaises(ValueError):
                calculate_ccrs(scores)

    def test_invalid_cap_rejected(self):
        with self.assertRaises(ValueError):
            calculate_ccrs([5], deployment_cap=0)

    def test_classification_boundaries(self):
        cases = {
            0: Severity.LOW,
            3.9: Severity.LOW,
            4: Severity.MEDIUM,
            6.9: Severity.MEDIUM,
            7: Severity.HIGH,
            8.9: Severity.HIGH,
            9: Severity.CRITICAL,
            10: Severity.CRITICAL,
        }
        for score, expected in cases.items():
            with self.subTest(score=score):
                self.assertEqual(classify(score), expected)

