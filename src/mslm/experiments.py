"""Reproducible MSLM effectiveness and performance experiments."""

import argparse
import csv
import json
import platform
import statistics
import sys
import time
from math import sqrt
from dataclasses import asdict
from pathlib import Path
from typing import Dict, Iterable, List

from .audit import AuditLog
from .l2 import Principal, Role
from .l3 import KeyRing, PriceTokenService, ReplayStore
from .pipeline import MSLMGateway, TransactionRequest
from .risk import (
    PAPER_CHAINS,
    assess_chain_plausibility,
    calculate_ccrs,
    compare_aggregations,
    score_plausible_chain,
)
from .scenarios import (
    CHAIN_EXPECTED_LAYER,
    CHAIN_INDICATORS,
    CHAIN_STEPS,
    Trial,
    build_attack_trial,
    build_control_trial,
)

CHAINS = ("C1", "C2", "C3", "C4")


def _gateway() -> MSLMGateway:
    keys = KeyRing()
    keys.add("merchant-1", "key-1", b"k" * 32, active=True)
    gateway = MSLMGateway(PriceTokenService(keys, ReplayStore()), AuditLog())
    gateway.set_merchant_approval("merchant-1", True)
    return gateway


def run_trials(iterations: int, seed: int) -> List[Trial]:
    """Build one traceable attack trial and one matched control per chain.

    Each trial executes real security controls: the L1 analyzer runs over an
    actual merchant submission, L2 ownership/minimisation run over an actual
    request, and L3 verifies an actual signed claim.
    """
    if iterations < 1:
        raise ValueError("iterations must be positive")
    trials: List[Trial] = []
    for index in range(iterations):
        for chain in CHAINS:
            trials.append(build_attack_trial(chain, index, seed))
            trials.append(build_control_trial(chain, index, seed))
    return trials


def _variation_key(trial: Trial) -> str:
    return json.dumps(trial.input_variation, sort_keys=True, separators=(",", ":"))


def aggregate_effectiveness(trials: List[Trial], iterations: int) -> List[Dict[str, object]]:
    """Aggregate traceable trials per chain with an honest block-rate interval."""
    if iterations < 1:
        raise ValueError("iterations must be positive")
    rows: List[Dict[str, object]] = []
    for chain in CHAINS:
        attacks = [t for t in trials if t.chain == chain and t.kind == "attack"]
        controls = [t for t in trials if t.chain == chain and t.kind == "control"]
        blocked = sum(1 for t in attacks if t.outcome == "block")
        matched = sum(1 for t in attacks if t.matched_expectation)
        controls_accepted = sum(1 for t in controls if t.matched_expectation)
        low, high = _wilson_interval(blocked, iterations)
        rows.append(
            {
                "chain": chain,
                "iterations": iterations,
                "blocked": blocked,
                "unexpected_approvals": iterations - blocked,
                "block_rate_percent": round(100.0 * blocked / iterations, 3),
                "block_rate_ci95_low_percent": round(100.0 * low, 3),
                "block_rate_ci95_high_percent": round(100.0 * high, 3),
                "legitimate_controls_accepted": controls_accepted,
                "expected_first_layer": CHAIN_EXPECTED_LAYER[chain],
                "first_layer_matches_all": matched == iterations,
                "indicators": "|".join(CHAIN_INDICATORS[chain]),
                "distinct_attack_inputs": len({_variation_key(t) for t in attacks}),
            }
        )
    return rows


def run_effectiveness(iterations: int, seed: int) -> List[Dict[str, object]]:
    """Build trials and aggregate them per chain."""
    return aggregate_effectiveness(run_trials(iterations, seed), iterations)


def _wilson_interval(successes: int, trials: int, z: float = 1.959964) -> tuple:
    proportion = successes / trials
    denominator = 1.0 + z * z / trials
    centre = (proportion + z * z / (2 * trials)) / denominator
    margin = (
        z
        * sqrt(proportion * (1 - proportion) / trials + z * z / (4 * trials * trials))
        / denominator
    )
    return max(0.0, centre - margin), min(1.0, centre + margin)


def _percentile(values: List[float], percent: float) -> float:
    ordered = sorted(values)
    position = min(len(ordered) - 1, int(round((len(ordered) - 1) * percent)))
    return ordered[position]


def run_benchmark(iterations: int) -> List[Dict[str, object]]:
    """Measure L2+L3 gateway latency using perf_counter_ns."""
    if iterations < 10:
        raise ValueError("benchmark_iterations must be at least 10")
    latencies_us: List[float] = []
    baseline_us: List[float] = []
    for index in range(iterations):
        baseline_started = time.perf_counter_ns()
        # A matched control performs request-field access and constructs the
        # success result, but omits L2/L3 security operations.
        baseline_request = ("merchant-1", "user-1", f"bench-{index}", 5_000, "USD")
        if baseline_request[3] < 0:
            raise RuntimeError("unreachable invalid control request")
        baseline_us.append((time.perf_counter_ns() - baseline_started) / 1_000.0)
        gateway = _gateway()
        now = 1_800_000_000 + index
        merchant = Principal("merchant-operator", Role.MERCHANT, "merchant-1")
        user = Principal("user-1", Role.USER)
        claims, signature = gateway.issue_token(
            merchant,
            merchant_id="merchant-1",
            user_id="user-1",
            order_id=f"bench-{index}",
            amount_minor=5_000,
            currency="USD",
            now=now,
        )
        request = TransactionRequest(
            "merchant-1", "user-1", f"bench-{index}", 5_000, "USD", claims, signature
        )
        started = time.perf_counter_ns()
        decision = gateway.process(user, request, now=now)
        elapsed = time.perf_counter_ns() - started
        if not decision.approved:
            raise RuntimeError("valid benchmark transaction was unexpectedly blocked")
        latencies_us.append(elapsed / 1_000.0)
    secured_mean = statistics.mean(latencies_us)
    baseline_mean = statistics.mean(baseline_us)
    return [
        {
            "operation": "L2+L3 valid payment verification",
            "iterations": iterations,
            "mean_us": round(secured_mean, 3),
            "median_us": round(statistics.median(latencies_us), 3),
            "p95_us": round(_percentile(latencies_us, 0.95), 3),
            "p99_us": round(_percentile(latencies_us, 0.99), 3),
            "min_us": round(min(latencies_us), 3),
            "max_us": round(max(latencies_us), 3),
            "control_mean_us": round(baseline_mean, 3),
            "absolute_overhead_mean_us": round(secured_mean - baseline_mean, 3),
            "overhead_percent_vs_control": round(
                100.0 * (secured_mean - baseline_mean) / baseline_mean, 3
            ),
        }
    ]


def risk_rows() -> List[Dict[str, object]]:
    rows = []
    for chain, scores in PAPER_CHAINS.items():
        result = calculate_ccrs(scores)
        comparison = compare_aggregations(scores)
        row = asdict(result)
        row["severity"] = result.severity.value
        row["chain"] = chain
        row["mean_cvss"] = comparison.mean
        row["capped_sum"] = comparison.capped_sum
        row["sequential_product"] = comparison.sequential_product
        rows.append(row)
    return rows


def plausibility_rows() -> List[Dict[str, object]]:
    """Explicit chain-plausibility evidence for C1-C4 (Reviewers I.1, III.1)."""
    rows = []
    for chain, steps in CHAIN_STEPS.items():
        assessment = assess_chain_plausibility(chain, steps)
        rows.append(
            {
                "chain": chain,
                "step_count": assessment.step_count,
                "plausible": assessment.plausible,
                "prerequisites": " | ".join(assessment.prerequisites),
                "trust_boundaries": " | ".join(assessment.trust_boundaries),
                "evidence": " | ".join(assessment.evidence),
                "ccrs": score_plausible_chain(assessment).raw_score if assessment.plausible else None,
                "gaps": " | ".join(assessment.gaps),
                "notes": assessment.notes,
            }
        )
    return rows


def _write_csv(path: Path, rows: Iterable[Dict[str, object]]) -> None:
    materialized = list(rows)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(materialized[0]))
        writer.writeheader()
        writer.writerows(materialized)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iterations", type=int, default=1000)
    parser.add_argument("--benchmark-iterations", type=int, default=10000)
    parser.add_argument("--seed", type=int, default=2026)
    parser.add_argument("--output", type=Path, default=Path("results"))
    args = parser.parse_args(argv)
    args.output.mkdir(parents=True, exist_ok=True)

    started = time.time()
    trials = run_trials(args.iterations, args.seed)
    effectiveness = aggregate_effectiveness(trials, args.iterations)
    performance = run_benchmark(args.benchmark_iterations)
    risks = risk_rows()
    plausibility = plausibility_rows()
    trial_rows = [trial.as_row() for trial in trials]
    report = {
        "schema_version": "1.0",
        "framework_version": "0.2.0",
        "generated_at_unix": started,
        "duration_seconds": round(time.time() - started, 6),
        "parameters": {
            "iterations_per_chain": args.iterations,
            "benchmark_iterations": args.benchmark_iterations,
            "seed": args.seed,
        },
        "environment": {
            "python": sys.version,
            "platform": platform.platform(),
            "processor": platform.processor() or "not reported",
        },
        "ccrs": risks,
        "plausibility": plausibility,
        "effectiveness": effectiveness,
        "performance": performance,
        "limitations": [
            "Synthetic controlled attacks exercising the encoded controls; not OWASP Juice Shop traffic",
            "C1/C4 are blocked by the L1 gate, so later layers are not reached in those trials",
            "L1 analyses Python AST only; mini-app JavaScript/TypeScript is out of scope",
            "In-memory replay store; no distributed storage latency",
            "Microbenchmark excludes network, database and TLS overhead",
        ],
    }
    with (args.output / "experiment.json").open("w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, sort_keys=True)
    _write_csv(args.output / "effectiveness.csv", effectiveness)
    _write_csv(args.output / "performance.csv", performance)
    _write_csv(args.output / "ccrs.csv", risks)
    _write_csv(args.output / "plausibility.csv", plausibility)
    _write_csv(args.output / "trials.csv", trial_rows)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
