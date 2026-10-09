import unittest

import _bootstrap  # noqa: F401
from mslm.scenarios import (
    CHAIN_INDICATORS,
    build_attack_trial,
    build_control_trial,
)


class ScenarioTraceabilityTests(unittest.TestCase):
    def stages(self, trial, control):
        return {stage.control: stage for stage in trial.stages}

    def test_every_chain_attack_matches_expected_layer(self):
        for chain in CHAIN_INDICATORS:
            with self.subTest(chain=chain):
                trial = build_attack_trial(chain, 0, 2026)
                self.assertTrue(trial.matched_expectation)
                self.assertEqual(trial.outcome, "block")
                self.assertTrue(trial.first_blocking_layer)

    def test_every_chain_control_is_accepted(self):
        for chain in CHAIN_INDICATORS:
            with self.subTest(chain=chain):
                trial = build_control_trial(chain, 0, 2026)
                self.assertTrue(trial.matched_expectation)
                self.assertEqual(trial.outcome, "allow")
                self.assertEqual(trial.first_blocking_layer, "")

    def test_c1_runs_real_l1_analysis_and_detects_v1_v6(self):
        trial = build_attack_trial("C1", 0, 2026)
        onboarding = self.stages(trial, None)["L1.onboarding"]
        self.assertFalse(onboarding.blocked is False and not onboarding.evidence)
        detected = set(onboarding.evidence["vulnerability_ids"])
        self.assertEqual(detected, {"V1", "V6"})
        self.assertIn("L1.AUTH.CUSTOM", onboarding.evidence["rule_ids"])
        self.assertIn("L1.AUTHZ.MISSING", onboarding.evidence["rule_ids"])
        self.assertEqual(trial.first_blocking_layer, "L1")

    def test_c4_runs_real_l1_analysis_and_detects_all_four_indicators(self):
        trial = build_attack_trial("C4", 0, 2026)
        onboarding = self.stages(trial, None)["L1.onboarding"]
        detected = set(onboarding.evidence["vulnerability_ids"])
        self.assertEqual(detected, {"V1", "V2", "V3", "V6"})
        self.assertEqual(trial.first_blocking_layer, "L1")

    def test_c4_short_circuits_at_l1_and_does_not_claim_later_layers(self):
        trial = build_attack_trial("C4", 0, 2026)
        layers = {stage.layer for stage in trial.stages}
        self.assertEqual(layers, {"L1"})
        self.assertNotIn("L2", layers)
        self.assertNotIn("L3", layers)

    def test_c2_blocks_on_ownership_and_minimises_response(self):
        trial = build_attack_trial("C2", 0, 2026)
        stages = self.stages(trial, None)
        self.assertIn("L2.enforcement", stages)
        self.assertIn("ownership", stages["L2.enforcement"].reason)
        evidence = stages["L2.minimization"].evidence
        self.assertFalse(evidence["cvv_present"])
        self.assertFalse(evidence["password_present"])
        self.assertTrue(str(evidence["pan"]).startswith("*"))
        self.assertEqual(trial.first_blocking_layer, "L2")

    def test_c3_l1_detects_weak_crypto_but_approves_then_l3_blocks_tamper(self):
        trial = build_attack_trial("C3", 0, 2026)
        stages = self.stages(trial, None)
        onboarding = stages["L1.onboarding"]
        self.assertEqual(onboarding.decision, "approve")
        self.assertEqual(onboarding.evidence["vulnerability_ids"], ["V4"])
        self.assertIn("L3.enforcement", stages)
        self.assertIn("claims do not match", stages["L3.enforcement"].reason)
        self.assertEqual(trial.first_blocking_layer, "L3")

    def test_attack_inputs_actually_vary(self):
        for chain in CHAIN_INDICATORS:
            with self.subTest(chain=chain):
                variations = {
                    tuple(sorted(build_attack_trial(chain, i, 2026).input_variation.items()))
                    for i in range(25)
                }
                self.assertGreater(len(variations), 1)

    def test_trials_are_deterministic_for_a_fixed_seed(self):
        first = [build_attack_trial("C2", i, 2026).as_row() for i in range(5)]
        second = [build_attack_trial("C2", i, 2026).as_row() for i in range(5)]
        self.assertEqual(first, second)

    def test_trace_rows_contain_required_fields(self):
        row = build_attack_trial("C1", 0, 2026).as_row()
        for key in (
            "trial_id",
            "chain",
            "kind",
            "seed",
            "indicators",
            "expected_layer",
            "outcome",
            "first_blocking_layer",
            "matched_expectation",
            "input_variation",
            "stage_trace",
        ):
            self.assertIn(key, row)

    def test_unknown_chain_rejected(self):
        with self.assertRaises(ValueError):
            build_attack_trial("C9", 0, 2026)


if __name__ == "__main__":
    unittest.main()
