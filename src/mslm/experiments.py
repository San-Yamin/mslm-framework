"""Reproducible MSLM effectiveness and performance experiments."""

import argparse
import csv
import json
import platform
import random
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
from .risk import PAPER_CHAINS, calculate_ccrs


def _gateway() -> MSLMGateway:
    keys = KeyRing()
    keys.add("merchant-1", "key-1", b"k" * 32, active=True)
    gateway = MSLMGateway(PriceTokenService(keys, ReplayStore()), AuditLog())
    gateway.set_merchant_approval("merchant-1", True)
    return gateway


def run_effectiveness(iterations: int, seed: int) -> List[Dict[str, object]]:
    """Execute attack variations against the relevant enforced layer."""
    if iterations < 1:
        raise ValueError("iterations must be positive")
    rng = random.Random(seed)
    rows: List[Dict[str, object]] = []
    chains = ("C1", "C2", "C3", "C4")
    blocked_by = {"C1": "L1", "C2": "L2", "C3": "L3", "C4": "L1"}
    blocked_counts = {chain: 0 for chain in chains}
    legitimate_accepted = {chain: 0 for chain in chains}

    for index in range(iterations):
        for chain in chains:
            gateway = _gateway()
            now = 1_800_000_000 + index
            merchant = Principal("merchant-operator", Role.MERCHANT, "merchant-1")
            victim = Principal("user-victim", Role.USER)
            claims, signature = gateway.issue_token(
                merchant,
                merchant_id="merchant-1",
                user_id="user-victim",
                order_id=f"order-{index}",
                amount_minor=10_000,
                currency="USD",
                now=now,
            )
            request = TransactionRequest(
                "merchant-1",
                "user-victim",
                f"order-{index}",
                10_000,
                "USD",
                claims,
                signature,
            )
            principal = victim
            if chain == "C1":
                gateway.set_merchant_approval("merchant-1", False)
            elif chain == "C2":
                principal = Principal(f"attacker-{rng.randrange(1_000_000)}", Role.USER)
            elif chain == "C3":
                request = TransactionRequest(
                    request.merchant_id,
                    request.user_id,
                    request.order_id,
                    rng.randrange(1, 9_999),
                    request.currency,
                    request.claims,
                    request.signature,
                )
            else:
                gateway.set_merchant_approval("merchant-1", False)
                principal = Principal(f"attacker-{index}", Role.USER)
                request = TransactionRequest(
                    request.merchant_id,
                    request.user_id,
                    request.order_id,
                    1,
                    request.currency,
                    request.claims,
                    request.signature,
                )
            decision = gateway.process(principal, request, now=now)
            if not decision.approved and decision.blocked_at == blocked_by[chain]:
                blocked_counts[chain] += 1

            control_gateway = _gateway()
            control_claims, control_signature = control_gateway.issue_token(
                merchant,
                merchant_id="merchant-1",
                user_id="user-victim",
                order_id=f"control-{chain}-{index}",
                amount_minor=10_000,
                currency="USD",
                now=now,
            )
            control = TransactionRequest(
                "merchant-1",
                "user-victim",
                f"control-{chain}-{index}",
                10_000,
                "USD",
                control_claims,
                control_signature,
            )
            if control_gateway.process(victim, control, now=now).approved:
                legitimate_accepted[chain] += 1

    for chain in chains:
        blocked = blocked_counts[chain]
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
                "legitimate_controls_accepted": legitimate_accepted[chain],
                "expected_first_layer": blocked_by[chain],
            }
        )
    return rows


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
        row = asdict(result)
        row["severity"] = result.severity.value
        row["chain"] = chain
        rows.append(row)
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
    effectiveness = run_effectiveness(args.iterations, args.seed)
    performance = run_benchmark(args.benchmark_iterations)
    risks = risk_rows()
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
        "effectiveness": effectiveness,
        "performance": performance,
        "limitations": [
            "Synthetic controlled attacks; not OWASP Juice Shop traffic",
            "In-memory replay store; no distributed storage latency",
            "Microbenchmark excludes network, database and TLS overhead",
        ],
    }
    with (args.output / "experiment.json").open("w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, sort_keys=True)
    _write_csv(args.output / "effectiveness.csv", effectiveness)
    _write_csv(args.output / "performance.csv", performance)
    _write_csv(args.output / "ccrs.csv", risks)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
