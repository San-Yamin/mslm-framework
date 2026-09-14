import tempfile
import unittest
from pathlib import Path

import _bootstrap  # noqa: F401
from mslm.experiments import main, run_benchmark, run_effectiveness


class ExperimentTests(unittest.TestCase):
    def test_effectiveness_is_deterministic(self):
        self.assertEqual(run_effectiveness(5, 2026), run_effectiveness(5, 2026))

    def test_all_encoded_attacks_blocked_at_expected_layer(self):
        rows = run_effectiveness(10, 2026)
        self.assertEqual({row["blocked"] for row in rows}, {10})
        self.assertEqual({row["unexpected_approvals"] for row in rows}, {0})
        self.assertEqual({row["legitimate_controls_accepted"] for row in rows}, {10})
        self.assertTrue(all(row["block_rate_ci95_low_percent"] < 100 for row in rows))

    def test_benchmark_returns_distribution(self):
        row = run_benchmark(10)[0]
        self.assertGreaterEqual(row["p99_us"], row["median_us"])
        self.assertEqual(row["iterations"], 10)
        self.assertGreater(row["absolute_overhead_mean_us"], 0)

    def test_cli_writes_machine_readable_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            result = main(
                [
                    "--iterations",
                    "2",
                    "--benchmark-iterations",
                    "10",
                    "--output",
                    directory,
                ]
            )
            self.assertEqual(result, 0)
            for name in ("experiment.json", "effectiveness.csv", "performance.csv", "ccrs.csv"):
                self.assertTrue((Path(directory) / name).exists())
